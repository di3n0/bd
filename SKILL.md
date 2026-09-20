---
name: black-duck-sca-service
description: Route Black Duck SCA, Synopsys Detect, signature, BDBA, and container-image scan requests to configured Kubernetes services. Use when a user mentions Black Duck and wants to configure, preview, submit, or batch source, binary, or image scans; do not submit a live scan for a merely informational question.
---

# Black Duck SCA Service

Use `scripts/blackduck_scan.py` as the deterministic client. It reads credentials, service URLs, defaults, timeouts, and concurrency limits from a `.env` file and emits JSON results.

## Two-question entry flow

When the user intends to configure or run Black Duck, ask only these routing questions before collecting target details:

1. **Mode or help:** ask whether they want `source`, `binary`, `image`, `image-deep`, or usage instructions. If they choose instructions, explain the profiles and do not submit anything.
2. **Defaults or adjustments:** after a mode is chosen, ask whether to use the `.env` defaults or adjust parameters. With defaults, summarize the selected endpoint, depth, components, timeout, Pod CPU/memory, polling interval, and whether an outbound Black Duck proxy is enabled. With adjustments, collect only the values they want to override and show the effective settings.

Do not repeat a question when the user already supplied its answer. After these questions, collect any missing target, project, and version. Preview by default unless the user explicitly asks to submit.

## Choose a profile

| User intent | `--mode` | Effective scan |
| --- | --- | --- |
| Source / 原始碼 | `source` | Detector and Signature in parallel |
| Binary / 二進位 | `binary` | BDBA |
| Image / 映像檔 | `image` | Container scan, depth 5, component scope `source` |
| Deep image / 深度映像檔掃描 | `image-deep` | Container scan, depth 100, component scope `all` |

Explicit `--depth` and `--components` values override profile defaults.

## Operate safely

1. Resolve the configuration file in this order: an explicitly named `--env-file`, then `.env` in the current working directory. If none exists, help the user copy `assets/.env.example`; never invent credentials.
2. Never display, log, commit, or copy `BLACKDUCK_API_TOKEN` or credentials embedded in `HTTP_PROXY` / `HTTPS_PROXY` into a command line. The client sends credentials only in configured HTTP headers and redacts them from output.
3. Treat a mention of “Black Duck” as a reason to load this skill, not as authorization to start a scan. For configuration, explanation, or an ambiguous request, use `--dry-run`. Submit live HTTP requests only when the user asks to run, start, submit, or execute the scan.
4. Before a live request, ensure the target, project, version, profile, and exact service endpoints are known. A scan can consume cluster and Black Duck capacity; do not retry a failed submission automatically unless the user asks.
5. Prefer `.env` defaults for operational settings. Use command-line overrides only for the current scan. Pod resources describe the Kubernetes Job that the wrapper should create; they do not resize an already-running Deployment Pod.
6. When polling is enabled, follow the returned `statusUrl` or trusted `.env` template at `STATUS_POLL_INTERVAL_SECONDS` until success, failure, or `STATUS_MAX_WAIT_SECONDS`. Do not send the token to a cross-origin status URL unless `.env` explicitly allows it.

Single scan:

```text
python scripts/blackduck_scan.py --env-file .env --mode source --target . --project demo --version 1.0 --dry-run
```

Batch scan:

```text
python scripts/blackduck_scan.py --env-file .env --batch jobs.json --output scan-results.json
```

For every execution, report the selected profile, target, endpoints, timeout, Pod resources, polling interval, and final status without exposing the token. If a source scan partially fails, report Detector and Signature independently.

## Supporting details

- Read [references/configuration.md](references/configuration.md) when creating or changing `.env`, defaults, timeouts, concurrency, or Detect properties.
- Read [references/service-contract.md](references/service-contract.md) when implementing or troubleshooting the Kubernetes services or their HTTP payloads.
- Use [README.md](README.md) as the user-facing setup and usage guide.
- Use [deploy_step.html](deploy_step.html) for the visual, step-by-step Kubernetes deployment guide.
