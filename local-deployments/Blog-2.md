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

# Installing SPIRE with Helm

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

# Check Trust Domain

kubectl -n spire get configmap spire-server -o yaml | grep trust_domain
"trust_domain": "example.org"


```

