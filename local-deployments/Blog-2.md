## Setup kind cluster
```
# kind-cluster.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      # Keycloak UI (later will run in cluster on 8080)
      - containerPort: 30080
        hostPort: 30080
        protocol: TCP
      # SPIRE OIDC Discovery Provider (later will run in cluster on 8443)
      - containerPort: 30443
        hostPort: 30443
        protocol: TCP

kind create cluster --name agent-platform --config kind-cluster.yaml

```
## 2) Install SPIRE via the hardened Helm charts
```
helm repo add spire https://spiffe.github.io/helm-charts-hardened/
helm repo update

helm upgrade --install \
  --create-namespace \
  -n spire \
  spire-crds spire/spire-crds

kubectl get pods -n spire
NAME                                                    READY   STATUS    RESTARTS   AGE
spire-agent-wlvnl                                       1/1     Running   0          28m
spire-server-0                                          2/2     Running   0          28m
spire-spiffe-csi-driver-lc2tj                           2/2     Running   0          28m
spire-spiffe-oidc-discovery-provider-5d89598d7b-ljjlt   2/2     Running   0          28m



```

## 3) Enable software‑statement claims in SPIRE (Credential Composer)

SPIRE “credential composer” plugin to inject `client_auth` and `jwks_url` claims into the JWT SVID. You’ll load a small Go plugin and reference it in server.conf under CredentialComposer `software_statements` (with plugin_cmd, plugin_checksum, and plugin_data including `jwks_url + client_auth`)

### 3A.  Prove SPIRE can mint JWT‑SVIDs to a workload in your KinD cluster and that the OIDC Discovery Provider publishes JWKS.

- 1) Register a demo workload entry (SPIFFE ID + k8s selectors)

```
kubectl -n spire exec -ti spire-server-0 -c \
spire-server --   /opt/spire/bin/spire-server entry create   \
-parentID spiffe://example.org/spire/agent/k8s_psat/example-cluster/65edb46f-c75e-4ea1-a9e8-d00d2dfd489e  \
-spiffeID spiffe://example.org/ns/spire-demo/sa/jwt-demo-sa   -selector k8s:ns:spire-demo \
-selector k8s:sa:jwt-demo-sa  \
-jwtSVIDTTL 600

# Check Trust Domain

kubectl -n spire get configmap spire-server -o yaml | grep trust_domain
"trust_domain": "example.org"

```

- 2) Run a tiny pod that can fetch a JWT‑SVID

```
kubectl apply -f jwt-svid-demo.yaml

# grab the token from the above pod in the logs
# You should see a JWT header+payload+signature (compact JWS).
```

- 3) Verify OIDC Discovery & JWKS are served

```
kubectl -n spire get svc | grep oidc
spire-spiffe-oidc-discovery-provider   ClusterIP   10.96.111.15    <none>        443/TCP   10h

# Port-forward 443 (TLS) to your host

# Sanity check: decode the JWT‑SVID’s header and ensure the kid matches one of the JWKS keys’ kid values:

python3 test.py
```

### 3B.  Add a SPIRE Credential Composer that injects client_auth + jwks_url into every JWT‑SVID.

## 4) Register a sample workload in SPIRE
Use kubectl exec to run spire-server entry create and mint an entry for “MCP client” workload (simple selector to start).

Then fetch a JWT SVID for that workload via the SPIFFE Workload API; it should include
- sub (SPIFFE ID), 
- aud (Keycloak realm URL),
- injected client_auth
- jwks_url. 


## 5) Build & run Keycloak with the SPIFFE DCR SPI

## 6) Dynamic Client Registration (the proof)
From your workload pod (or a debug pod with access to the SPIRE agent socket), get a JWT SVID.

Call Keycloak’s custom DCR endpoint:
POST /realms/<realm>/clients-registrations/spiffe-dcr/register with body:
{ "software_statement": "<your JWT SVID>", "client_name": "...", "grant_types": ["client_credentials"] }

You should see the new client in the Keycloak Admin UI.