from fastapi import FastAPI, Query, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt
import requests
import os
import logging

app = FastAPI()
security = HTTPBearer()

# Config
KEYCLOAK_REALM_URL = os.getenv(
    "KEYCLOAK_REALM_URL",
    "http://keycloak.keycloak.svc.cluster.local:8080/realms/Demo"
)
JWKS_URL = f"{KEYCLOAK_REALM_URL}/protocol/openid-connect/certs"
EXPECTED_AUDIENCE = os.getenv("EXPECTED_AUDIENCE", "WeatherTool")

logging.debug("KEYCLOAK_REALM_URL",KEYCLOAK_REALM_URL)
logging.debug("JWKS_URL",JWKS_URL)
logging.info("EXPECTED_AUDIENCE",EXPECTED_AUDIENCE)

# Fetch JWKS once at startup
jwks = requests.get(JWKS_URL).json()

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        # Decode & validate JWT
        claims = jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            audience=EXPECTED_AUDIENCE
        )
        return claims
    except Exception as e:
        logging.error(f"Token validation failed: {str(e)}")
        raise HTTPException(status_code=401, detail=f"Token validation failed: {str(e)}")

@app.get("/weather")
def get_weather(city: str = Query(...), claims: dict = Depends(verify_token)):
    # For demo: return mock weather
    return {
        "city": city,
        "temp": 22,
        "condition": "sunny",
        "validated_sub": claims.get("sub")
    }
