from fastapi import FastAPI, Query

app = FastAPI()

# --- MCP Agent Manifest ---
@app.get("/agent/manifest")
def manifest():
    return {
        "name": "agent-a",
        "spiffe_id": "spiffe://192.168.2.4.nip.io/ns/agent/sa/agents-sa",
        "intents": ["query_weather"]
    }

# --- Intent Handler ---
@app.get("/query")
def query_weather(city: str = Query(...)):
    # Kagenti ensures identity + token exchange before this gets called
    return {
        "city": city,
        "temp": 22,
        "condition": "sunny",
        "source": "Agent A"
    }
