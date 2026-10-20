FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Test every rule, then write dist/ only if the suite passes.
CMD ["python", "-m", "dac", "deploy"]
