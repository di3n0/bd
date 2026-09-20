# Configuration reference

The client uses this precedence: command-line or per-job override, `.env`, process environment, then the built-in profile default. The file wins over host-level `HTTP_PROXY` / `HTTPS_PROXY` settings. Keep `.env` out of version control.

## Required values

| Variable | Purpose |
| --- | --- |
| `BLACKDUCK_URL` | Black Duck server URL |
| `BLACKDUCK_API_TOKEN` | API token; sent only in the configured header |
| `BLACKDUCK_PROJECT_GROUP` | Default project group |
| `DETECT_SERVICE_URL` | Detector K8s HTTP endpoint |
| `SIGNATURE_SERVICE_URL` | Signature K8s HTTP endpoint; `SIGMA_SERVICE_URL` is an accepted alias |
| `BDBA_SERVICE_URL` | Binary/BDBA K8s HTTP endpoint |
| `IMAGE_SERVICE_URL` | Container image K8s HTTP endpoint |

`source` requires both Detect and Signature URLs. `binary` requires BDBA. `image` and `image-deep` require Image.

## Black Duck outbound proxy

Leave both proxy variables empty to disable outbound proxying. Expected values look like `http://xxx.xx.xx:xx`.

| Variable | Purpose |
| --- | --- |
| `HTTP_PROXY` | Proxy URL for HTTP destinations |
| `HTTPS_PROXY` | Proxy URL for HTTPS destinations |
| `NO_PROXY` | Comma-separated bypass list |
| `HTTP_PROXY_USERNAME_HEADER` | Wrapper header carrying the HTTP proxy username |
| `HTTP_PROXY_PASSWORD_HEADER` | Wrapper header carrying the HTTP proxy password |
| `HTTPS_PROXY_USERNAME_HEADER` | Wrapper header carrying the HTTPS proxy username |
| `HTTPS_PROXY_PASSWORD_HEADER` | Wrapper header carrying the HTTPS proxy password |

Optional credentials can be embedded as `http://user:password@host:port`. They are URL-decoded, excluded from the JSON payload and output, and sent to the wrapper only in protocol-specific headers. These proxies are for the wrapper's outbound connection to Black Duck, not for the client's connection to the Kubernetes Service.

## Timeouts and concurrency

| Scan type | Timeout | Max simultaneous jobs | Default |
| --- | --- | --- | --- |
| Source | `SOURCE_TIMEOUT_SECONDS` | `SOURCE_MAX_CONCURRENCY` | 1800 s / 5 |
| Binary | `BINARY_TIMEOUT_SECONDS` | `BINARY_MAX_CONCURRENCY` | 1800 s / 5 |
| Image | `IMAGE_TIMEOUT_SECONDS` | `IMAGE_MAX_CONCURRENCY` | 3600 s / 8 |

The timeout is passed to the service and is also used as the HTTP client timeout. The concurrency values apply to batch files; a source job occupies one source slot while its Detector and Signature requests run together.

## Status polling

| Variable | Default | Purpose |
| --- | ---: | --- |
| `STATUS_POLL_ENABLED` | `true` | Poll after a successful submission |
| `STATUS_POLL_INTERVAL_SECONDS` | `15` | Delay between status requests |
| `STATUS_HTTP_TIMEOUT_SECONDS` | `30` | Timeout of each status request |
| `STATUS_MAX_WAIT_SECONDS` | `0` | Maximum polling duration; `0` uses the scan timeout |
| `STATUS_SUCCESS_VALUES` | `COMPLETED,SUCCESS,SUCCEEDED,DONE` | Terminal success states |
| `STATUS_FAILURE_VALUES` | `FAILED,ERROR,CANCELLED,CANCELED,TIMED_OUT` | Terminal failure states |
| `ALLOW_CROSS_HOST_STATUS_URL` | `false` | Permit sending credentials to a different status origin |

The POST response should include `statusUrl`. Per-operation `*_STATUS_URL_TEMPLATE` values are fallbacks and accept `{requestId}` and `{operation}`. Keep cross-origin status URLs disabled unless the destination is trusted.

## Kubernetes Job resources

Each scan type has four settings: `*_POD_CPU_REQUEST`, `*_POD_CPU_LIMIT`, `*_POD_MEMORY_REQUEST`, and `*_POD_MEMORY_LIMIT`, where `*` is `SOURCE`, `BINARY`, or `IMAGE`. The client sends them as `podResources`; the wrapper service is responsible for applying them to the Kubernetes Job it creates.

Use `--cpu-request`, `--cpu-limit`, `--memory-request`, and `--memory-limit` for one scan. These values do not change the resources of an existing wrapper Deployment Pod.

## Profile defaults

| Variable | Default |
| --- | --- |
| `SOURCE_SCAN_DEPTH` | `5` |
| `BINARY_SCAN_DEPTH` | `1` |
| `IMAGE_SCAN_DEPTH` | `5` |
| `IMAGE_COMPONENT_SCOPE` | `source` |
| `IMAGE_DEEP_SCAN_DEPTH` | `100` |
| `IMAGE_DEEP_COMPONENT_SCOPE` | `all` |
| `SIGNATURE_SNIPPET_MODE` | `false` |

Use `--depth`, `--components source|all`, and `--snippet` for one-off overrides.

## Common Detect properties

The client maps the common settings into the service payload:

| Environment variable | Detect concept |
| --- | --- |
| `BLACKDUCK_SCAN_MODE` | `detect.blackduck.scan.mode` |
| `DETECT_WAIT_FOR_RESULTS` | `detect.wait.for.results` |
| `DETECT_CLEANUP` | `detect.cleanup` |
| `DETECT_LOG_LEVEL` | `logging.level.detect` |
| `BLACKDUCK_API_TIMEOUT_SECONDS` | `blackduck.timeout` |
| `BLACKDUCK_TRUST_CERT` | `blackduck.trust.cert` |

Put additional properties in `BLACKDUCK_EXTRA_PROPERTIES_JSON` or repeat `--property key=value`. CLI properties take precedence. Do not put passwords or tokens in extra properties.

## Batch job fields

Each object in `jobs.json` accepts `mode`, `target`, `project`, `version`, and optional `group`, `depth`, `components`, `snippet`, `timeout`, `properties`, `metadata`, `resources`, `wait_for_status`, `poll_interval`, and `status_max_wait`. The file may be a JSON array or an object with a `jobs` array.
