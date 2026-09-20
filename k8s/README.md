# Kubernetes deployment

This directory deploys four internal wrapper services: Detect, Signature, BDBA, and Image. The wrapper images must implement the contract in `../references/service-contract.md` and create scan Jobs using the submitted `podResources`.

## Before deployment

1. Replace all `your-registry/...:latest` images in `workloads.yaml`.
2. Set the Black Duck URL, project group, proxy URLs, timeouts, and concurrency in `configmap.yaml`.
3. Create `blackduck-credentials` using your approved secret workflow. `secret.example.yaml` is not included by `kustomization.yaml`.

## Deploy

```bash
kubectl apply -f k8s/namespace.yaml
kubectl -n blackduck create secret generic blackduck-credentials \
  --from-literal=BLACKDUCK_API_TOKEN='REPLACE_ME'
kubectl apply -k k8s
kubectl -n blackduck rollout status deployment/blackduck-detect
kubectl -n blackduck rollout status deployment/blackduck-signature
kubectl -n blackduck rollout status deployment/blackduck-bdba
kubectl -n blackduck rollout status deployment/blackduck-image
kubectl -n blackduck get service,pod
```

Use a secret manager instead of a literal command in production so the token is not retained in shell history.

## Internal endpoints

- `http://blackduck-detect.blackduck.svc.cluster.local/scan`
- `http://blackduck-signature.blackduck.svc.cluster.local/scan`
- `http://blackduck-bdba.blackduck.svc.cluster.local/scan`
- `http://blackduck-image.blackduck.svc.cluster.local/scan`

Each wrapper must also expose `/health` and the returned status URL.
