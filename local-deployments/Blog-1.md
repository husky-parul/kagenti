## Installation

`kagenti-kind-config.yaml`
```
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraPortMappings:
      - containerPort: 30080
        hostPort: 8080
      - containerPort: 30443
        hostPort: 8443

```

kind create cluster --name kagenti-cluster --config kagenti-kind-config.yaml
