# Sentinel demo container.
# Build:  docker build -t sentinel-agent .
# Run:    docker run --rm -e GOOGLE_API_KEY=$GOOGLE_API_KEY sentinel-agent
FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Default: run every demo scenario and print Sentinel's verdicts.
CMD ["python", "scenarios/run_scenarios.py"]
