"""Match Sigma-style rules against synthetic JSON security events."""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any


class RuleError(ValueError):
    """A rule file is missing a field or uses a condition the engine cannot run."""


def parse_time(value: str) -> datetime:
    if not isinstance(value, str):
        raise RuleError(f"TimeCreated must be a string, got {value!r}")
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def parse_timespan(spec: str) -> timedelta:
    if not isinstance(spec, str) or len(spec) < 2 or spec[-1] not in ("m", "h"):
        raise RuleError(f"timespan must look like 5m or 1h, got {spec!r}")
    count = int(spec[:-1])
    return timedelta(minutes=count) if spec[-1] == "m" else timedelta(hours=count)


def _field_and_modifier(key: str) -> tuple[str, str | None]:
    if "|" not in key:
        return key, None
    field, modifier = key.split("|", 1)
    if modifier not in {"contains", "startswith", "endswith", "re"}:
        raise RuleError(f"unsupported field modifier {modifier!r} on {key!r}")
    return field, modifier


def _equals(actual: Any, expected: Any) -> bool:
    if isinstance(actual, str) and isinstance(expected, str):
        return actual.casefold() == expected.casefold()
    return actual == expected


def match_value(actual: Any, modifier: str | None, expected: Any) -> bool:
    """OR across a list of expected values. AND is handled by the caller, per field."""
    if isinstance(expected, list):
        return any(match_value(actual, modifier, item) for item in expected)
    if actual is None:
        return False
    if modifier is None:
        return _equals(actual, expected)
    actual_text = str(actual)
    expected_text = str(expected)
    folded_actual = actual_text.casefold()
    folded_expected = expected_text.casefold()
    if modifier == "contains":
        return folded_expected in folded_actual
    if modifier == "startswith":
        return folded_actual.startswith(folded_expected)
    if modifier == "endswith":
        return folded_actual.endswith(folded_expected)
    if modifier == "re":
        return re.search(expected_text, actual_text, re.IGNORECASE) is not None
    raise RuleError(f"unsupported modifier {modifier}")


def match_selection(event: dict[str, Any], selection: dict[str, Any]) -> bool:
    if not selection:
        raise RuleError("a selection cannot be empty")
    for key, expected in selection.items():
        field, modifier = _field_and_modifier(key)
        if not match_value(event.get(field), modifier, expected):
            return False
    return True


def _tokenize(condition: str) -> list[str]:
    padded = condition.replace("(", " ( ").replace(")", " ) ")
    tokens = padded.split()
    if not tokens:
        raise RuleError("detection condition is empty")
    return tokens


class _Parser:
    def __init__(self, tokens: list[str]) -> None:
        self.tokens = tokens
        self.index = 0

    def peek(self) -> str | None:
        if self.index >= len(self.tokens):
            return None
        return self.tokens[self.index]

    def eat(self, expected: str | None = None) -> str:
        token = self.peek()
        if token is None or (expected is not None and token != expected):
            raise RuleError(f"unexpected token {token!r} in condition")
        self.index += 1
        return token

    def parse(self) -> Any:
        node = self._parse_or()
        if self.peek() is not None:
            raise RuleError(f"unexpected token {self.peek()!r} in condition")
        return node

    def _parse_or(self) -> Any:
        node = self._parse_and()
        while self.peek() == "or":
            self.eat("or")
            node = ("or", node, self._parse_and())
        return node

    def _parse_and(self) -> Any:
        node = self._parse_not()
        while self.peek() == "and":
            self.eat("and")
            node = ("and", node, self._parse_not())
        return node

    def _parse_not(self) -> Any:
        if self.peek() == "not":
            self.eat("not")
            return ("not", self._parse_not())
        return self._parse_primary()

    def _parse_primary(self) -> Any:
        if self.peek() == "(":
            self.eat("(")
            node = self._parse_or()
            self.eat(")")
            return node
        name = self.eat()
        if name in {"and", "or", "not", ")"}:
            raise RuleError(f"expected a selection name, got {name!r}")
        return ("sel", name)


def compile_condition(condition: str, selection_names: set[str]) -> Any:
    tree = _Parser(_tokenize(condition)).parse()

    def check(node: Any) -> None:
        kind = node[0]
        if kind == "sel":
            if node[1] not in selection_names:
                raise RuleError(
                    f"condition refers to unknown selection {node[1]!r}"
                )
        elif kind == "not":
            check(node[1])
        else:
            check(node[1])
            check(node[2])

    check(tree)
    return tree


def _eval_tree(node: Any, event: dict[str, Any], selections: dict[str, Any]) -> bool:
    kind = node[0]
    if kind == "sel":
        return match_selection(event, selections[node[1]])
    if kind == "not":
        return not _eval_tree(node[1], event, selections)
    if kind == "and":
        return _eval_tree(node[1], event, selections) and _eval_tree(
            node[2], event, selections
        )
    if kind == "or":
        return _eval_tree(node[1], event, selections) or _eval_tree(
            node[2], event, selections
        )
    raise RuleError(f"unknown condition node {kind}")


def event_matches(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    return _eval_tree(rule["_tree"], event, rule["_selections"])


def _window_hit(times: list[datetime], span: timedelta, threshold: int) -> int:
    ordered = sorted(times)
    best = 0
    for start in range(len(ordered)):
        end = start
        while end < len(ordered) and ordered[end] <= ordered[start] + span:
            end += 1
        best = max(best, end - start)
        if best >= threshold:
            return best
    return best


def correlate(rule: dict[str, Any], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    spec = rule.get("correlation")
    if not spec:
        return [event for event in events if event_matches(rule, event)]

    if spec.get("type", "event_count") != "event_count":
        raise RuleError("only correlation type event_count is supported")
    group_by = spec.get("group_by") or []
    if not group_by:
        raise RuleError("correlation.group_by needs at least one field")
    threshold = int(spec["threshold"])
    span = parse_timespan(spec["timespan"]) if spec.get("timespan") else None

    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for event in events:
        if not event_matches(rule, event):
            continue
        key = tuple(event.get(field) for field in group_by)
        grouped.setdefault(key, []).append(event)

    alerts = []
    for key, group in grouped.items():
        if span is None:
            count = len(group)
        else:
            count = _window_hit([parse_time(event["TimeCreated"]) for event in group], span, threshold)
        if count >= threshold:
            alerts.append(
                {
                    "group": dict(zip(group_by, key)),
                    "count": count,
                    "threshold": threshold,
                }
            )
    return alerts


def normalize_rule(data: dict[str, Any], source: str) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise RuleError(f"{source} must be a YAML mapping")
    for key in ("title", "id", "detection"):
        if key not in data:
            raise RuleError(f"{source} is missing {key}")
    detection = data["detection"]
    if not isinstance(detection, dict) or "condition" not in detection:
        raise RuleError(f"{source} is missing detection.condition")
    selections = {
        name: body
        for name, body in detection.items()
        if name != "condition" and isinstance(body, dict)
    }
    if not selections:
        raise RuleError(f"{source} has no selections")
    data["_source"] = source
    data["_selections"] = selections
    data["_tree"] = compile_condition(str(detection["condition"]), set(selections))
    for name, body in selections.items():
        for key in body:
            _field_and_modifier(str(key))
            if str(key).endswith("|re"):
                pattern = body[key]
                patterns = pattern if isinstance(pattern, list) else [pattern]
                for item in patterns:
                    re.compile(str(item))
    if "correlation" in data:
        correlate(data, [])
    return data
