from fastapi import FastAPI, Query, HTTPException
import requests
import os
import logging
from spiffe.workloadapi.workload_api_client import WorkloadApiClient

app = FastAPI()

# --- Config ---
SPIFFE_ID = os.getenv("SPIFFE_ID_AGENT_A", "")
KEYCLOAK_URL = os.getenv(
    "KEYCLOAK_URL",
    ""
)
WEATHER_TOOL_URL = os.getenv("WEATHER_TOOL_URL", "")
SOCKET_PATH = os.getenv("SPIRE_SOCKET", "")
JWT_SVID_FILE = os.getenv("JWT_SVID_FILE", "")

print("SPIFFE_ID: ",SPIFFE_ID)
print("KEYCLOAK_URL: ",KEYCLOAK_URL)
print("WEATHER_TOOL_URL: ",WEATHER_TOOL_URL)
print("SOCKET_PATH: ",SOCKET_PATH)
print("JWT_SVID_FILE: ",JWT_SVID_FILE)

# --- Helpers ---

def fetch_and_write_svid(audience: str = "keycloak") -> str:
    """
    Fetch JWT-SVID from Workload API socket and write to file.
    """

   

    client = WorkloadApiClient(socket_path=SOCKET_PATH)
    jwt_svid = client.fetch_jwt_svid([audience])
    token = jwt_svid.token

    with open(JWT_SVID_FILE, "w") as f:
        f.write(token)
    logging.info(f"New JWT-SVID written to {JWT_SVID_FILE}")

    return token


def exchange_token_with_keycloak(jwt_svid: str) -> str:
    """
    Exchange JWT-SVID for a Keycloak access token (aud=WeatherTool).
    """
    data = {
        "grant_type": "client_credentials",
        "client_id": SPIFFE_ID,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": jwt_svid,
        "scope": "openid",
        "audience": "WeatherTool",
    }
    resp = requests.post(
        KEYCLOAK_URL,
        data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    if resp.status_code != 200:
        raise RuntimeError(f"Keycloak error: {resp.status_code} {resp.text}")
    return resp.json()["access_token"]


def call_weather_tool(access_token: str, city: str) -> dict:
    """
    Call Weather Tool service with Bearer token.
    """
    url = f"{WEATHER_TOOL_URL}?city={city}"
    headers = {"Authorization": f"Bearer {access_token}"}
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)
    return resp.json()

# --- API ---

@app.get("/query")
def handle_query(city: str = Query(..., description="City to get weather for")):
    """
    Entry point for chatbot queries.
    """
    try:
        # 1. Get JWT-SVID from SPIRE socket
        jwt_svid = fetch_and_write_svid(audience="http://localhost:8081/realms/Demo")

        logging.info(f"New JWT-SVID {jwt_svid}")

        # 2. Exchange for access_token in Keycloak
        access_token = exchange_token_with_keycloak(jwt_svid)
        logging.info(f"Access_token {access_token}")


        # 3. Call Weather Tool with access_token
        result = call_weather_tool(access_token, city)

        return {"city": city, "weather": result}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
