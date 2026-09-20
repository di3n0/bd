# Kubernetes service contract

Each configured URL is an exact HTTP endpoint that accepts `POST application/json`. The client sends the Black Duck API token in the header named by `BLACKDUCK_TOKEN_HEADER` (default `X-BlackDuck-Api-Token`). Do not log this header in ingress, mesh, or application logs.

When proxy authentication is embedded in `HTTP_PROXY` or `HTTPS_PROXY`, the client sends credentials using the matching protocol-specific username/password headers. Do not log these headers. Proxy credentials are deliberately excluded from JSON.

## Request

```json
{
  "schemaVersion": 1,
  "requestId": "uuid",
  "profile": "source",
  "operation": "detector",
  "target": ".",
  "project": {
    "name": "demo",
    "version": "1.0.0",
    "group": "default-group"
  },
  "blackduck": {
    "url": "https://blackduck.example.com",
    "trustCert": false,
    "apiTimeoutSeconds": 300
  },
  "proxy": {
    "enabled": true,
    "http": {"scheme": "http", "host": "proxy.example.com", "port": 8080, "authenticated": false},
    "https": {"scheme": "http", "host": "proxy.example.com", "port": 8443, "authenticated": true},
    "noProxy": ["localhost", ".svc", ".cluster.local"],
    "authenticated": true
  },
  "scan": {
    "tools": ["DETECTOR"],
    "depth": 5,
    "componentScope": "source",
    "scanMode": "INTELLIGENT",
    "waitForResults": true,
    "cleanup": true,
    "logLevel": "INFO",
    "snippet": false,
    "properties": {}
  },
  "timeoutSeconds": 1800,
  "podResources": {
    "requests": {"cpu": "500m", "memory": "1Gi"},
    "limits": {"cpu": "2", "memory": "4Gi"}
  },
  "metadata": {}
}
```

`operation` is one of `detector`, `signature`, `binary`, or `image`. The service translates `scan` values to the Black Duck Detect/BDBA/container scanner version deployed in that service. This keeps tool-version-specific flags out of the skill.

## Response

Return a 2xx response with JSON. Include `requestId`, a non-terminal `status`, and `statusUrl`. Recommended additional fields are `scanId`, `project`, `version`, `codeLocation`, and `reportUrl`.

```json
{
  "requestId": "uuid",
  "status": "QUEUED",
  "statusUrl": "http://service/status/uuid/detector"
}
```

`GET statusUrl` should return `status`, `state`, or `phase`. The client polls until the value matches its configured success/failure sets or the maximum wait expires.

Return a non-2xx status for rejected or failed submissions and a concise JSON error. The client does not automatically retry, because a timeout can occur after the server accepted the scan and an automatic retry could create duplicate jobs.

## Operational requirements

- Enforce TLS or restrict access to the cluster network; never expose the token header through public ingress without TLS.
- Translate the proxy object to the deployed Black Duck tool's proxy parameters. Read credentials from headers and never persist them in Job metadata or logs.
- Apply server-side concurrency and timeout controls too. Client-side limits prevent accidental bursts but are not an admission controller.
- Apply `podResources.requests` and `podResources.limits` to the new scan Job, after enforcing server-side minimums and maximums.
- Make `requestId` idempotent when possible so operators can safely investigate uncertain submissions.
- Mount long-lived credentials from Kubernetes Secrets when feasible. If the service owns credentials, it may ignore the token header after the client and contract are updated together.
