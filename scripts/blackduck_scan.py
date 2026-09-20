#!/usr/bin/env python3
"""Dependency-free client for Black Duck scan wrapper services."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


MODES = ("source", "binary", "image", "image-deep")
PLACEHOLDER_TOKENS = {"", "replace-me", "changeme", "token"}


class ScanError(RuntimeError):
    pass


def parse_env(path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not path.exists():
        raise ScanError(f"Environment file not found: {path}")
    for line_no, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise ScanError(f"Invalid .env line {line_no}: expected KEY=VALUE")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            raise ScanError(f"Invalid .env line {line_no}: empty key")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
            value = value[1:-1]
        values[key] = value
    return values


def env_config(path: Path) -> Dict[str, str]:
    values = {key: value for key, value in os.environ.items()}
    values.update(parse_env(path))
    return values


def as_bool(value: Any, name: str) -> bool:
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ScanError(f"{name} must be true or false, got {value!r}")


def as_int(value: Any, name: str, minimum: int = 1) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ScanError(f"{name} must be an integer, got {value!r}") from exc
    if parsed < minimum:
        raise ScanError(f"{name} must be at least {minimum}, got {parsed}")
    return parsed


def as_float(value: Any, name: str, minimum: float = 0.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ScanError(f"{name} must be a number, got {value!r}") from exc
    if parsed < minimum:
        raise ScanError(f"{name} must be at least {minimum}, got {parsed}")
    return parsed


def json_object(value: str, name: str) -> Dict[str, Any]:
    try:
        parsed = json.loads(value or "{}")
    except json.JSONDecodeError as exc:
        raise ScanError(f"{name} is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise ScanError(f"{name} must be a JSON object")
    return parsed


def cli_properties(items: Iterable[str]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise ScanError(f"Invalid --property {item!r}; expected key=value")
        key, value = item.split("=", 1)
        key = key.strip().lstrip("-")
        if not key:
            raise ScanError("--property key cannot be empty")
        lowered = key.lower()
        if any(secret in lowered for secret in ("token", "password", "secret")):
            raise ScanError(f"Sensitive property {key!r} must be configured outside extra properties")
        result[key] = value
    return result


def reject_sensitive_properties(properties: Mapping[str, Any]) -> None:
    for key in properties:
        lowered = str(key).lower()
        if any(secret in lowered for secret in ("token", "password", "secret")):
            raise ScanError(f"Sensitive property {key!r} must be configured outside extra properties")


def parse_proxy_url(proxy_url: str, name: str) -> Tuple[Optional[Dict[str, Any]], str, str]:
    proxy_url = proxy_url.strip()
    if not proxy_url:
        return None, "", ""
    parsed = urllib.parse.urlparse(proxy_url)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ScanError(f"{name} must use http:// or https://")
    if not parsed.hostname:
        raise ScanError(f"{name} must include a hostname")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ScanError(f"{name} contains an invalid port") from exc
    if port is None:
        raise ScanError(f"{name} must include a port")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ScanError(f"{name} must not include a path, query, or fragment")
    username = urllib.parse.unquote(parsed.username or "")
    password = urllib.parse.unquote(parsed.password or "")
    if bool(username) != bool(password):
        raise ScanError(f"{name} must include both username and password, or neither")
    return {
        "scheme": scheme,
        "host": parsed.hostname,
        "port": port,
        "authenticated": bool(username),
    }, username, password


def proxy_settings(cfg: Mapping[str, str]) -> Tuple[Dict[str, Any], Dict[str, Tuple[str, str]]]:
    http, http_user, http_password = parse_proxy_url(cfg.get("HTTP_PROXY", ""), "HTTP_PROXY")
    https, https_user, https_password = parse_proxy_url(cfg.get("HTTPS_PROXY", ""), "HTTPS_PROXY")
    no_proxy = [value.strip() for value in cfg.get("NO_PROXY", "").split(",") if value.strip()]
    credentials = {
        "http": (http_user, http_password),
        "https": (https_user, https_password),
    }
    return {
        "enabled": bool(http or https),
        "http": http,
        "https": https,
        "noProxy": no_proxy,
        "authenticated": bool(http_user or https_user),
    }, credentials


def validated_header_name(value: str, name: str) -> str:
    if not value or any(char in value for char in "\r\n:"):
        raise ScanError(f"{name} is invalid")
    return value


def profile_type(mode: str) -> str:
    return "image" if mode in {"image", "image-deep"} else mode


def default_depth(mode: str, cfg: Mapping[str, str]) -> int:
    key = {
        "source": "SOURCE_SCAN_DEPTH",
        "binary": "BINARY_SCAN_DEPTH",
        "image": "IMAGE_SCAN_DEPTH",
        "image-deep": "IMAGE_DEEP_SCAN_DEPTH",
    }[mode]
    fallback = {"source": 5, "binary": 1, "image": 5, "image-deep": 100}[mode]
    return as_int(cfg.get(key, fallback), key, 0)


def default_components(mode: str, cfg: Mapping[str, str]) -> str:
    if mode == "image-deep":
        value = cfg.get("IMAGE_DEEP_COMPONENT_SCOPE", "all")
    elif mode == "image":
        value = cfg.get("IMAGE_COMPONENT_SCOPE", "source")
    elif mode == "binary":
        value = "all"
    else:
        value = "source"
    if value not in {"source", "all"}:
        raise ScanError(f"Component scope must be source or all, got {value!r}")
    return value


def timeout_for(mode: str, cfg: Mapping[str, str]) -> int:
    scan_type = profile_type(mode)
    key = f"{scan_type.upper()}_TIMEOUT_SECONDS"
    fallback = 3600 if scan_type == "image" else 1800
    return as_int(cfg.get(key, fallback), key)


def concurrency_for(scan_type: str, cfg: Mapping[str, str]) -> int:
    key = f"{scan_type.upper()}_MAX_CONCURRENCY"
    fallback = 8 if scan_type == "image" else 5
    return as_int(cfg.get(key, fallback), key)


def pod_resources_for(mode: str, cfg: Mapping[str, str]) -> Dict[str, Dict[str, str]]:
    scan_type = profile_type(mode)
    defaults = {
        "source": ("500m", "2", "1Gi", "4Gi"),
        "binary": ("1", "4", "2Gi", "8Gi"),
        "image": ("2", "8", "4Gi", "16Gi"),
    }[scan_type]
    prefix = scan_type.upper()
    values = {
        "cpu_request": cfg.get(f"{prefix}_POD_CPU_REQUEST", defaults[0]),
        "cpu_limit": cfg.get(f"{prefix}_POD_CPU_LIMIT", defaults[1]),
        "memory_request": cfg.get(f"{prefix}_POD_MEMORY_REQUEST", defaults[2]),
        "memory_limit": cfg.get(f"{prefix}_POD_MEMORY_LIMIT", defaults[3]),
    }
    for name, value in values.items():
        if not value or not re.fullmatch(r"[A-Za-z0-9.+-]+", str(value)):
            raise ScanError(f"Invalid Kubernetes resource quantity for {name}: {value!r}")
    return {
        "requests": {"cpu": str(values["cpu_request"]), "memory": str(values["memory_request"])},
        "limits": {"cpu": str(values["cpu_limit"]), "memory": str(values["memory_limit"])},
    }


def apply_resource_overrides(
    resources: Dict[str, Dict[str, str]], raw: Mapping[str, Any], cli: argparse.Namespace
) -> Dict[str, Dict[str, str]]:
    raw_requests = raw.get("requests", {})
    raw_limits = raw.get("limits", {})
    if not isinstance(raw_requests, dict) or not isinstance(raw_limits, dict):
        raise ScanError("resources.requests and resources.limits must be JSON objects")
    overrides = {
        ("requests", "cpu"): raw_requests.get("cpu") or cli.cpu_request,
        ("limits", "cpu"): raw_limits.get("cpu") or cli.cpu_limit,
        ("requests", "memory"): raw_requests.get("memory") or cli.memory_request,
        ("limits", "memory"): raw_limits.get("memory") or cli.memory_limit,
    }
    for (section, key), value in overrides.items():
        if value is not None:
            if not re.fullmatch(r"[A-Za-z0-9.+-]+", str(value)):
                raise ScanError(f"Invalid Kubernetes resource quantity for {section}.{key}: {value!r}")
            resources[section][key] = str(value)
    return resources


def endpoint_operations(mode: str, cfg: Mapping[str, str]) -> List[Tuple[str, str]]:
    if mode == "source":
        return [
            ("detector", cfg.get("DETECT_SERVICE_URL", "")),
            ("signature", cfg.get("SIGNATURE_SERVICE_URL") or cfg.get("SIGMA_SERVICE_URL", "")),
        ]
    if mode == "binary":
        return [("binary", cfg.get("BDBA_SERVICE_URL", ""))]
    return [("image", cfg.get("IMAGE_SERVICE_URL", ""))]


def tools_for(operation: str) -> List[str]:
    return {
        "detector": ["DETECTOR"],
        "signature": ["SIGNATURE_SCAN"],
        "binary": ["BINARY_SCAN"],
        "image": ["CONTAINER_SCAN"],
    }[operation]


def normalize_job(raw: Mapping[str, Any], cfg: Mapping[str, str], cli: argparse.Namespace) -> Dict[str, Any]:
    mode = raw.get("mode") or cli.mode
    if mode not in MODES:
        raise ScanError(f"mode must be one of {', '.join(MODES)}, got {mode!r}")

    target = raw.get("target") or cli.target
    project = raw.get("project") or cli.project or cfg.get("BLACKDUCK_PROJECT_NAME")
    version = raw.get("version") or cli.version or cfg.get("BLACKDUCK_PROJECT_VERSION")
    if not target or not project or not version:
        raise ScanError("Every job requires target, project, and version")

    depth_value = raw.get("depth", cli.depth)
    depth = default_depth(mode, cfg) if depth_value is None else as_int(depth_value, "depth", 0)
    components = raw.get("components") or cli.components or default_components(mode, cfg)
    if components not in {"source", "all"}:
        raise ScanError("components must be source or all")

    snippet_value = raw.get("snippet")
    if snippet_value is None:
        snippet_value = cli.snippet
    if snippet_value is None:
        snippet_value = cfg.get("SIGNATURE_SNIPPET_MODE", "false")
    snippet = as_bool(snippet_value, "snippet")

    timeout_value = raw.get("timeout", cli.timeout)
    timeout = timeout_for(mode, cfg) if timeout_value is None else as_int(timeout_value, "timeout")

    properties = json_object(cfg.get("BLACKDUCK_EXTRA_PROPERTIES_JSON", "{}"), "BLACKDUCK_EXTRA_PROPERTIES_JSON")
    raw_properties = raw.get("properties", {})
    if not isinstance(raw_properties, dict):
        raise ScanError("job properties must be a JSON object")
    properties.update(raw_properties)
    properties.update(cli_properties(cli.properties))
    reject_sensitive_properties(properties)

    metadata = raw.get("metadata", {})
    if not isinstance(metadata, dict):
        raise ScanError("job metadata must be a JSON object")

    raw_resources = raw.get("resources", {})
    if not isinstance(raw_resources, dict):
        raise ScanError("job resources must be a JSON object")
    resources = apply_resource_overrides(pod_resources_for(mode, cfg), raw_resources, cli)

    wait_value = raw.get("wait_for_status")
    if wait_value is None:
        wait_value = cli.wait_for_status
    if wait_value is None:
        wait_value = cfg.get("STATUS_POLL_ENABLED", "true")
    wait_for_status = as_bool(wait_value, "wait_for_status")

    poll_interval_value = raw.get("poll_interval", cli.poll_interval)
    if poll_interval_value is None:
        poll_interval_value = cfg.get("STATUS_POLL_INTERVAL_SECONDS", 15)
    poll_interval = as_float(poll_interval_value, "poll_interval", 0.1)

    max_wait_value = raw.get("status_max_wait", cli.status_max_wait)
    if max_wait_value is None:
        max_wait_value = cfg.get("STATUS_MAX_WAIT_SECONDS", 0)
    status_max_wait = as_float(max_wait_value, "status_max_wait", 0)
    if status_max_wait == 0:
        status_max_wait = float(timeout)

    return {
        "mode": mode,
        "target": str(target),
        "project": str(project),
        "version": str(version),
        "group": str(raw.get("group") or cli.group or cfg.get("BLACKDUCK_PROJECT_GROUP", "")),
        "depth": depth,
        "components": components,
        "snippet": snippet,
        "timeout": timeout,
        "properties": properties,
        "metadata": metadata,
        "resources": resources,
        "poll": {
            "enabled": wait_for_status,
            "intervalSeconds": poll_interval,
            "maxWaitSeconds": status_max_wait,
        },
    }


def validate_config(job: Mapping[str, Any], cfg: Mapping[str, str], dry_run: bool) -> None:
    if not cfg.get("BLACKDUCK_URL"):
        raise ScanError("BLACKDUCK_URL is required")
    token = cfg.get("BLACKDUCK_API_TOKEN", "")
    if not dry_run and token.strip().lower() in PLACEHOLDER_TOKENS:
        raise ScanError("A real BLACKDUCK_API_TOKEN is required for a live scan")
    if not job.get("group"):
        raise ScanError("BLACKDUCK_PROJECT_GROUP or job group is required")
    for operation, endpoint in endpoint_operations(str(job["mode"]), cfg):
        if not endpoint:
            raise ScanError(f"Missing service URL for {operation}")
        if not endpoint.startswith(("http://", "https://")):
            raise ScanError(f"Service URL for {operation} must start with http:// or https://")


def make_payload(job: Mapping[str, Any], cfg: Mapping[str, str], operation: str, request_id: str) -> Dict[str, Any]:
    return {
        "schemaVersion": 1,
        "requestId": request_id,
        "profile": job["mode"],
        "operation": operation,
        "target": job["target"],
        "project": {
            "name": job["project"],
            "version": job["version"],
            "group": job["group"],
        },
        "blackduck": {
            "url": cfg["BLACKDUCK_URL"],
            "trustCert": as_bool(cfg.get("BLACKDUCK_TRUST_CERT", "false"), "BLACKDUCK_TRUST_CERT"),
            "apiTimeoutSeconds": as_int(cfg.get("BLACKDUCK_API_TIMEOUT_SECONDS", 300), "BLACKDUCK_API_TIMEOUT_SECONDS"),
        },
        "proxy": proxy_settings(cfg)[0],
        "scan": {
            "tools": tools_for(operation),
            "depth": job["depth"],
            "componentScope": job["components"],
            "scanMode": cfg.get("BLACKDUCK_SCAN_MODE", "INTELLIGENT"),
            "waitForResults": as_bool(cfg.get("DETECT_WAIT_FOR_RESULTS", "true"), "DETECT_WAIT_FOR_RESULTS"),
            "cleanup": as_bool(cfg.get("DETECT_CLEANUP", "true"), "DETECT_CLEANUP"),
            "logLevel": cfg.get("DETECT_LOG_LEVEL", "INFO"),
            "snippet": bool(job["snippet"]) if operation == "signature" else False,
            "properties": job["properties"],
        },
        "timeoutSeconds": job["timeout"],
        "podResources": job["resources"],
        "metadata": job["metadata"],
    }


def service_headers(cfg: Mapping[str, str]) -> Dict[str, str]:
    token_header = validated_header_name(
        cfg.get("BLACKDUCK_TOKEN_HEADER", "X-BlackDuck-Api-Token"), "BLACKDUCK_TOKEN_HEADER"
    )
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": "black-duck-sca-service-skill/1",
        token_header: cfg.get("BLACKDUCK_API_TOKEN", ""),
    }
    _proxy, credentials = proxy_settings(cfg)
    for protocol, (username, password) in credentials.items():
        if not username:
            continue
        prefix = protocol.upper()
        username_header = validated_header_name(
            cfg.get(f"{prefix}_PROXY_USERNAME_HEADER", f"X-BlackDuck-{protocol.title()}-Proxy-Username"),
            f"{prefix}_PROXY_USERNAME_HEADER",
        )
        password_header = validated_header_name(
            cfg.get(f"{prefix}_PROXY_PASSWORD_HEADER", f"X-BlackDuck-{protocol.title()}-Proxy-Password"),
            f"{prefix}_PROXY_PASSWORD_HEADER",
        )
        headers[username_header] = username
        headers[password_header] = password
    return headers


def request_json(
    method: str,
    endpoint: str,
    cfg: Mapping[str, str],
    timeout: float,
    payload: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(endpoint, data=body, headers=service_headers(cfg), method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read().decode("utf-8", errors="replace")
            try:
                parsed: Any = json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                parsed = {"text": raw[:4096]}
            return {"httpStatus": response.status, "response": parsed}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")[:4096]
        raise ScanError(f"HTTP {exc.code} from {endpoint}: {raw}") from exc
    except urllib.error.URLError as exc:
        raise ScanError(f"Request failed for {endpoint}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise ScanError(f"Request timed out after {timeout}s for {endpoint}") from exc


def post_json(endpoint: str, payload: Mapping[str, Any], cfg: Mapping[str, str], timeout: float) -> Dict[str, Any]:
    return request_json("POST", endpoint, cfg, timeout, payload)


def get_json(endpoint: str, cfg: Mapping[str, str], timeout: float) -> Dict[str, Any]:
    return request_json("GET", endpoint, cfg, timeout)


def status_template_for(operation: str, cfg: Mapping[str, str]) -> str:
    key = {
        "detector": "DETECT_STATUS_URL_TEMPLATE",
        "signature": "SIGNATURE_STATUS_URL_TEMPLATE",
        "binary": "BDBA_STATUS_URL_TEMPLATE",
        "image": "IMAGE_STATUS_URL_TEMPLATE",
    }[operation]
    return cfg.get(key, "")


def origin(url: str) -> Tuple[str, str, Optional[int]]:
    parsed = urllib.parse.urlparse(url)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port


def status_url_for(
    endpoint: str,
    operation: str,
    request_id: str,
    response: Mapping[str, Any],
    cfg: Mapping[str, str],
) -> str:
    response_body = response.get("response", {})
    candidate = response_body.get("statusUrl", "") if isinstance(response_body, dict) else ""
    if not candidate:
        candidate = status_template_for(operation, cfg)
    if not candidate:
        return ""
    candidate = str(candidate).replace("{requestId}", request_id).replace("{operation}", operation)
    status_url = urllib.parse.urljoin(endpoint, candidate)
    if not status_url.startswith(("http://", "https://")):
        raise ScanError(f"Status URL for {operation} must start with http:// or https://")
    allow_cross_host = as_bool(cfg.get("ALLOW_CROSS_HOST_STATUS_URL", "false"), "ALLOW_CROSS_HOST_STATUS_URL")
    if not allow_cross_host and origin(status_url) != origin(endpoint):
        raise ScanError(f"Refusing to send credentials to cross-origin status URL for {operation}")
    return status_url


def status_value(response: Mapping[str, Any]) -> str:
    body = response.get("response", {})
    if not isinstance(body, dict):
        return "UNKNOWN"
    for key in ("status", "state", "phase"):
        if body.get(key) is not None:
            return str(body[key]).strip().upper()
    return "UNKNOWN"


def configured_states(cfg: Mapping[str, str], key: str, fallback: str) -> set[str]:
    return {value.strip().upper() for value in cfg.get(key, fallback).split(",") if value.strip()}


def poll_status(
    endpoint: str,
    operation: str,
    request_id: str,
    submission: Mapping[str, Any],
    job: Mapping[str, Any],
    cfg: Mapping[str, str],
) -> Dict[str, Any]:
    success_values = configured_states(cfg, "STATUS_SUCCESS_VALUES", "COMPLETED,SUCCESS,SUCCEEDED,DONE")
    failure_values = configured_states(cfg, "STATUS_FAILURE_VALUES", "FAILED,ERROR,CANCELLED,CANCELED,TIMED_OUT")
    initial_state = status_value(submission)
    if initial_state in success_values:
        return {"pollStatus": "succeeded", "finalStatus": initial_state, "pollCount": 0}
    if initial_state in failure_values:
        return {"pollStatus": "failed", "finalStatus": initial_state, "pollCount": 0}

    status_url = status_url_for(endpoint, operation, request_id, submission, cfg)
    if not status_url:
        return {"pollStatus": "not-available", "finalStatus": initial_state, "pollCount": 0}

    interval = float(job["poll"]["intervalSeconds"])
    max_wait = float(job["poll"]["maxWaitSeconds"])
    http_timeout = as_float(cfg.get("STATUS_HTTP_TIMEOUT_SECONDS", 30), "STATUS_HTTP_TIMEOUT_SECONDS", 0.1)
    deadline = time.monotonic() + max_wait
    polls = 0
    last: Dict[str, Any] = {}
    last_state = initial_state
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return {
                "pollStatus": "timeout",
                "finalStatus": last_state,
                "pollCount": polls,
                "statusUrl": status_url,
                "statusResponse": last,
            }
        last = get_json(status_url, cfg, min(http_timeout, remaining))
        polls += 1
        last_state = status_value(last)
        if last_state in success_values:
            outcome = "succeeded"
        elif last_state in failure_values:
            outcome = "failed"
        else:
            outcome = ""
        if outcome:
            return {
                "pollStatus": outcome,
                "finalStatus": last_state,
                "pollCount": polls,
                "statusUrl": status_url,
                "statusResponse": last.get("response", {}),
            }
        time.sleep(min(interval, max(0.0, deadline - time.monotonic())))


def run_operation(
    operation: str,
    endpoint: str,
    job: Mapping[str, Any],
    cfg: Mapping[str, str],
    dry_run: bool,
    request_id: str,
) -> Dict[str, Any]:
    payload = make_payload(job, cfg, operation, request_id)
    if dry_run:
        return {
            "operation": operation,
            "endpoint": endpoint,
            "status": "dry-run",
            "polling": job["poll"],
            "request": payload,
        }
    response = post_json(endpoint, payload, cfg, int(job["timeout"]))
    result = {"operation": operation, "endpoint": endpoint, "status": "submitted", **response}
    if job["poll"]["enabled"]:
        polling = poll_status(endpoint, operation, request_id, response, job, cfg)
        result.update(polling)
        if polling["pollStatus"] in {"succeeded", "failed", "timeout"}:
            result["status"] = polling["pollStatus"]
    return result


def run_job(job: Mapping[str, Any], cfg: Mapping[str, str], dry_run: bool) -> Dict[str, Any]:
    validate_config(job, cfg, dry_run)
    request_id = str(uuid.uuid4())
    operations = endpoint_operations(str(job["mode"]), cfg)
    results: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(operations)) as executor:
        future_map = {
            executor.submit(run_operation, operation, endpoint, job, cfg, dry_run, request_id): operation
            for operation, endpoint in operations
        }
        for future in concurrent.futures.as_completed(future_map):
            operation = future_map[future]
            try:
                results.append(future.result())
            except Exception as exc:
                errors.append({"operation": operation, "error": str(exc)})

    results.sort(key=lambda item: item["operation"])
    errors.sort(key=lambda item: item["operation"])
    bad_results = [item for item in results if item["status"] in {"failed", "timeout"}]
    good_results = [item for item in results if item["status"] == "succeeded"]
    if errors:
        status = "failed" if not results else "partial"
    elif bad_results:
        status = "partial" if good_results else "failed"
    elif dry_run:
        status = "dry-run"
    elif results and len(good_results) == len(results):
        status = "succeeded"
    else:
        status = "submitted"
    return {
        "requestId": request_id,
        "mode": job["mode"],
        "target": job["target"],
        "project": job["project"],
        "version": job["version"],
        "timeoutSeconds": job["timeout"],
        "podResources": job["resources"],
        "polling": job["poll"],
        "status": status,
        "operations": results,
        "errors": errors,
    }


def load_batch(path: Path) -> List[Mapping[str, Any]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise ScanError(f"Batch file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ScanError(f"Invalid batch JSON: {exc}") from exc
    jobs = data.get("jobs") if isinstance(data, dict) else data
    if not isinstance(jobs, list) or not jobs:
        raise ScanError("Batch file must contain a non-empty jobs array")
    if not all(isinstance(job, dict) for job in jobs):
        raise ScanError("Every batch job must be a JSON object")
    return jobs


def run_group(
    indexed_jobs: List[Tuple[int, Dict[str, Any]]],
    scan_type: str,
    cfg: Mapping[str, str],
    dry_run: bool,
) -> List[Tuple[int, Dict[str, Any]]]:
    completed: List[Tuple[int, Dict[str, Any]]] = []
    workers = min(concurrency_for(scan_type, cfg), len(indexed_jobs))
    job_by_index = dict(indexed_jobs)
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {executor.submit(run_job, job, cfg, dry_run): index for index, job in indexed_jobs}
        for future in concurrent.futures.as_completed(future_map):
            index = future_map[future]
            try:
                result = future.result()
            except Exception as exc:
                job = job_by_index[index]
                result = {
                    "mode": job.get("mode"),
                    "target": job.get("target"),
                    "project": job.get("project"),
                    "version": job.get("version"),
                    "status": "failed",
                    "operations": [],
                    "errors": [{"error": str(exc)}],
                }
            completed.append((index, result))
    return completed


def run_all(jobs: List[Dict[str, Any]], cfg: Mapping[str, str], dry_run: bool) -> List[Dict[str, Any]]:
    groups: Dict[str, List[Tuple[int, Dict[str, Any]]]] = {"source": [], "binary": [], "image": []}
    for index, job in enumerate(jobs):
        groups[profile_type(job["mode"])].append((index, job))

    completed: List[Tuple[int, Dict[str, Any]]] = []
    active = [(scan_type, items) for scan_type, items in groups.items() if items]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(active)) as executor:
        futures = [executor.submit(run_group, items, scan_type, cfg, dry_run) for scan_type, items in active]
        for future in concurrent.futures.as_completed(futures):
            completed.extend(future.result())
    return [result for _, result in sorted(completed, key=lambda item: item[0])]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Submit Black Duck scans to Kubernetes wrapper services.")
    parser.add_argument("--env-file", default=".env", help="Path to .env (default: .env)")
    parser.add_argument("--mode", choices=MODES, help="Scan profile for a single job")
    parser.add_argument("--target", help="Source path, binary path, image reference, or tar path")
    parser.add_argument("--project", help="Black Duck project name")
    parser.add_argument("--version", help="Black Duck project version")
    parser.add_argument("--group", help="Override the default Black Duck project group")
    parser.add_argument("--depth", type=int, help="Override profile search depth")
    parser.add_argument("--components", choices=("source", "all"), help="Override component scope")
    snippet = parser.add_mutually_exclusive_group()
    snippet.add_argument("--snippet", action="store_true", dest="snippet", help="Enable source snippet scan")
    snippet.add_argument("--no-snippet", action="store_false", dest="snippet", help="Disable source snippet scan")
    parser.set_defaults(snippet=None)
    parser.add_argument("--timeout", type=int, help="Override job timeout in seconds")
    parser.add_argument("--cpu-request", help="Override Kubernetes Job CPU request, for example 500m")
    parser.add_argument("--cpu-limit", help="Override Kubernetes Job CPU limit, for example 2")
    parser.add_argument("--memory-request", help="Override Kubernetes Job memory request, for example 1Gi")
    parser.add_argument("--memory-limit", help="Override Kubernetes Job memory limit, for example 4Gi")
    wait_group = parser.add_mutually_exclusive_group()
    wait_group.add_argument("--wait-for-status", action="store_true", dest="wait_for_status")
    wait_group.add_argument("--no-wait-for-status", action="store_false", dest="wait_for_status")
    parser.set_defaults(wait_for_status=None)
    parser.add_argument("--poll-interval", type=float, help="Status poll interval in seconds")
    parser.add_argument("--status-max-wait", type=float, help="Maximum status wait in seconds; 0 uses scan timeout")
    parser.add_argument("--property", dest="properties", action="append", default=[], help="Extra Detect key=value")
    parser.add_argument("--batch", help="JSON batch file; per-job fields override single-job arguments")
    parser.add_argument("--dry-run", action="store_true", help="Print redacted requests without HTTP calls")
    parser.add_argument("--output", help="Write the result JSON to this file")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        cfg = env_config(Path(args.env_file))
        raw_jobs = load_batch(Path(args.batch)) if args.batch else [{}]
        if not args.batch and not args.mode:
            raise ScanError("--mode is required for a single scan")
        jobs = [normalize_job(raw, cfg, args) for raw in raw_jobs]
        results = run_all(jobs, cfg, args.dry_run)
        document = {
            "dryRun": args.dry_run,
            "summary": {
                "total": len(results),
                "succeeded": sum(result["status"] == "succeeded" for result in results),
                "submitted": sum(result["status"] == "submitted" for result in results),
                "partial": sum(result["status"] == "partial" for result in results),
                "failed": sum(result["status"] == "failed" for result in results),
            },
            "results": results,
        }
        rendered = json.dumps(document, ensure_ascii=False, indent=2)
        print(rendered)
        if args.output:
            Path(args.output).write_text(rendered + "\n", encoding="utf-8")
        return 1 if document["summary"]["failed"] or document["summary"]["partial"] else 0
    except ScanError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
