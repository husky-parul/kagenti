#!/usr/bin/env python3
"""
Automate the Keycloak demo setup using the provided wrapper class, then
enable Token Exchange by creating a client policy and attaching it to the
'token-exchange' permission for the ExampleTool client.

It follows the structure of demo_keycloak_config.py, but adds:
  - serviceAccountsEnabled + authorizationServicesEnabled on ExampleTool
  - a client policy 'tool-exchange' that includes your Agent SPIFFE ID
  - attaches that policy to the 'token-exchange' scope permission

Usage:

  APP_DOMAIN="$(hostname -I | awk '{print $1}').nip.io" \
  python setup_keycloak_demo.py \
    --kc-url http://127.0.0.1:8081 \
    --realm Demo \
    --admin-user admin \
    --admin-pass admin \
    --client-id ExampleTool \
    --agent-namespace agent \
    --agent-sa default

If APP_DOMAIN is not provided, the script exits with a helpful error.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional
from keycloak_wrapper import KeycloakWrapper 

import requests



def log(msg: str) -> None:
    print(f"\n==> {msg}")


# --- Minimal REST helpers (fallbacks when wrapper lacks a helper) ---

def _kc_auth_token(kc_url: str, realm: str, username: str, password: str) -> str:
    url = f"{kc_url}/realms/{realm}/protocol/openid-connect/token"
    data = {
        "client_id": "admin-cli",
        "username": username,
        "password": password,
        "grant_type": "password",
    }
    r = requests.post(url, data=data, timeout=20)
    r.raise_for_status()
    token = r.json().get("access_token")
    if not token:
        raise RuntimeError("No access_token in admin token response")
    return token


def _kc_get(kc_url: str, token: str, path: str) -> requests.Response:
    return requests.get(f"{kc_url}{path}", headers={"Authorization": f"Bearer {token}"}, timeout=20)


def _kc_put_json(kc_url: str, token: str, path: str, payload: Dict[str, Any]) -> requests.Response:
    return requests.put(
        f"{kc_url}{path}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        data=json.dumps(payload),
        timeout=20,
    )


def _kc_post_json(kc_url: str, token: str, path: str, payload: Dict[str, Any]) -> requests.Response:
    return requests.post(
        f"{kc_url}{path}",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        data=json.dumps(payload),
        timeout=20,
    )


def ensure_client_authz_enabled(
    kc_url: str, realm: str, token: str, client_uuid: str
) -> None:
    # Enable both service accounts and Authorization Services (Permissions tab)
    payload = {
        "serviceAccountsEnabled": True,
        "authorizationServicesEnabled": True,
    }
    r = _kc_put_json(kc_url, token, f"/admin/realms/{realm}/clients/{client_uuid}", payload)
    if not r.ok:
        raise RuntimeError(f"Failed enabling authz/services: {r.status_code} {r.text}")


def ensure_client_policy_present(
    kc_url: str,
    realm: str,
    token: str,
    client_uuid: str,
    policy_name: str,
    client_id_to_allow: str,
) -> None:
    # list policies
    r = _kc_get(kc_url, token, f"/admin/realms/{realm}/clients/{client_uuid}/authz/resource-server/policy")
    if not r.ok:
        raise RuntimeError(f"Failed listing policies: {r.status_code} {r.text}")
    policies: List[Dict[str, Any]] = r.json()
    for p in policies:
        if p.get("name") == policy_name:
            clients = set(p.get("clients") or [])
            if client_id_to_allow not in clients:
                clients.add(client_id_to_allow)
                p["clients"] = list(clients)
                u = _kc_put_json(
                    kc_url,
                    token,
                    f"/admin/realms/{realm}/clients/{client_uuid}/authz/resource-server/policy/{p['id']}",
                    p,
                )
                if not u.ok:
                    raise RuntimeError(f"Failed updating policy '{policy_name}': {u.status_code} {u.text}")
            return

    payload = {
        "name": policy_name,
        "type": "client",
        "logic": "POSITIVE",
        "decisionStrategy": "UNANIMOUS",
        "clients": [client_id_to_allow],
    }
    c = _kc_post_json(
        kc_url,
        token,
        f"/admin/realms/{realm}/clients/{client_uuid}/authz/resource-server/policy/client",
        payload,
    )
    if not (c.ok or c.status_code in (201, 204)):
        raise RuntimeError(f"Failed creating policy '{policy_name}': {c.status_code} {c.text}")


def attach_policy_to_token_exchange(
    kc_url: str, realm: str, token: str, client_uuid: str, policy_name: str
) -> None:
    r = _kc_get(
        kc_url, token, f"/admin/realms/{realm}/clients/{client_uuid}/authz/resource-server/permission/scope"
    )
    if not r.ok:
        raise RuntimeError(f"Failed listing scope permissions: {r.status_code} {r.text}")
    perms: List[Dict[str, Any]] = r.json()
    token_ex = next((p for p in perms if p.get("name") == "token-exchange"), None)
    if not token_ex:
        raise RuntimeError("token-exchange permission not found on client")

    policies = list(set((token_ex.get("policies") or []) + [policy_name]))
    patch = {"policies": policies}
    u = _kc_put_json(
        kc_url,
        token,
        f"/admin/realms/{realm}/clients/{client_uuid}/authz/resource-server/permission/scope/{token_ex['id']}",
        patch,
    )
    if not u.ok:
        raise RuntimeError(f"Failed attaching policy to token-exchange: {u.status_code} {u.text}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Setup Keycloak demo with Token Exchange using the wrapper.")
    ap.add_argument("--kc-url", default=os.getenv("KC_URL", "http://127.0.0.1:8081"))
    ap.add_argument("--realm", default=os.getenv("KC_REALM", "Demo"))
    ap.add_argument("--admin-user", default=os.getenv("KC_ADMIN", "admin"))
    ap.add_argument("--admin-pass", default=os.getenv("KC_PASSWORD", "admin"))

    # These should match the example demo content
    ap.add_argument("--client-id", default=os.getenv("KC_CLIENT_ID", "ExampleTool"))
    ap.add_argument("--policy-name", default=os.getenv("KC_POLICY_NAME", "tool-exchange"))

    # SPIFFE inputs
    ap.add_argument("--app-domain", default=os.getenv("APP_DOMAIN"))
    ap.add_argument("--agent-namespace", default=os.getenv("AGENT_NAMESPACE", "agent"))
    ap.add_argument("--agent-sa", default=os.getenv("AGENT_SA", "default"))

    args = ap.parse_args()

    if not args.app_domain:
        print("❌ APP_DOMAIN is required (set env APP_DOMAIN or use --app-domain)", file=sys.stderr)
        sys.exit(1)

    agent_spiffe = f"spiffe://{args.app_domain}/ns/{args.agent_namespace}/sa/{args.agent_sa}"

    # --- Connect via wrapper (auth etc.) ---
    log("Initializing Keycloak wrapper and logging in...")
    kc = KeycloakWrapper(
        base_url=args.kc_url,
        realm=args.realm,
        username=args.admin_user,
        password=args.admin_pass,
    )

    # If the demo file creates clients/realm/users, do that here via the wrapper.
    # (We call common names, and guard them to be idempotent.)
    # The exact method names can vary; we check presence and fallback to REST where needed.

    # Ensure realm exists (if wrapper provides it)
    if hasattr(kc, "ensure_realm"):
        log(f"Ensuring realm '{args.realm}' exists (wrapper)…")
        kc.ensure_realm(args.realm)

    # Ensure ExampleTool client exists via wrapper; fall back to REST if needed
    log(f"Ensuring client '{args.client_id}' exists…")
    client_uuid: Optional[str] = None
    if hasattr(kc, "ensure_client"):
        client_uuid = kc.ensure_client(args.client_id)  # expected to return UUID or truthy
        # Some wrappers may return dict or bool; resolve UUID if needed
        if isinstance(client_uuid, dict):
            client_uuid = client_uuid.get("id")
    else:
        # Fallback via REST: lookup only (creation is typically handled by demo script)
        admin_token = _kc_auth_token(args.kc_url, args.realm, args.admin_user, args.admin_pass)
        resp = _kc_get(args.kc_url, admin_token, f"/admin/realms/{args.realm}/clients?clientId={args.client_id}")
        if not resp.ok or not resp.json():
            raise RuntimeError(
                f"Client '{args.client_id}' not found and wrapper has no ensure_client(). "
                f"Run the original demo to create it first."
            )
        client_uuid = resp.json()[0]["id"]

    if not client_uuid:
        raise RuntimeError(f"Could not resolve UUID for client '{args.client_id}'")

    # Now enable Authorization Services + Service Accounts and wire Token Exchange
    admin_token = _kc_auth_token(args.kc_url, args.realm, args.admin_user, args.admin_pass)

    log("Enabling service accounts & authorization services on the client…")
    try:
        if hasattr(kc, "enable_client_authz"):
            kc.enable_client_authz(client_uuid)  # wrapper path if present
        else:
            ensure_client_authz_enabled(args.kc_url, args.realm, admin_token, client_uuid)
    except Exception as e:
        raise RuntimeError(f"Failed enabling client authorization/services: {e}") from e

    log(f"Creating/Updating client policy '{args.policy_name}' to include: {agent_spiffe}")
    try:
        if hasattr(kc, "ensure_client_policy"):
            kc.ensure_client_policy(client_uuid, args.policy_name, [agent_spiffe])  # wrapper path
        else:
            ensure_client_policy_present(
                args.kc_url,
                args.realm,
                admin_token,
                client_uuid,
                args.policy_name,
                agent_spiffe,
            )
    except Exception as e:
        raise RuntimeError(f"Failed ensuring client policy: {e}") from e

    log("Attaching policy to 'token-exchange' permission (idempotent)…")
    try:
        if hasattr(kc, "attach_policy_to_token_exchange"):
            kc.attach_policy_to_token_exchange(client_uuid, args.policy_name)  # wrapper path
        else:
            attach_policy_to_token_exchange(args.kc_url, args.realm, admin_token, client_uuid, args.policy_name)
    except Exception as e:
        raise RuntimeError(f"Failed attaching policy to token-exchange: {e}") from e

    log("✅ Done. Token Exchange is wired up for ExampleTool.")
    print(f"   Policy   : {args.policy_name}")
    print(f"   SPIFFE   : {agent_spiffe}")
    print(f"   Client   : {args.client_id}")
    print(f"   Realm    : {args.realm}")
    print("   Verify in UI: Clients → ExampleTool → Authorization → Policies / Permissions")


if __name__ == "__main__":
    # Quiet SSL warnings if self-signed (common in demos)
    try:
        requests.packages.urllib3.disable_warnings()  # type: ignore
    except Exception:
        pass
    main()
