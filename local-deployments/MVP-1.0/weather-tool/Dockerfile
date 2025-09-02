FROM python:3.11-slim

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends curl jq && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY weather_tool.py .

EXPOSE 5000

CMD ["uvicorn", "weather_tool:app", "--host", "0.0.0.0", "--port", "5000"]
