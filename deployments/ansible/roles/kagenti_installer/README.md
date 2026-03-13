Role: kagenti_installer
----------------------

This role installs components defined in the top-level `values.yaml` using
`kubernetes.core.helm` for Helm releases and `kubernetes.core.k8s` for
Kubernetes objects (namespaces).

Behavior
- Loads `secret_values_file` when provided (via -e or values.yaml `secrets.file`).
- Ensures the namespace for each enabled component exists.
- Deploys each component with the combined values:
  component.values merged with secret values (deep merge).

Variables
- `components` (dict): taken from the playbook `values.yaml`.
- `secret_values_file` (string): optional path to a secrets YAML file.
- `helm_wait_timeout` (int): timeout in seconds for helm wait.
