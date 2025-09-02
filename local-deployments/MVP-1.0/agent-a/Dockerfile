FROM python:3.11-slim

# Install system deps (curl, jq useful for debugging)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl jq && rm -rf /var/lib/apt/lists/*

# Copy app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agent_a.py .

# Expose port
EXPOSE 8000

# Start FastAPI app
CMD ["uvicorn", "agent_a:app", "--host", "0.0.0.0", "--port", "8000"]
