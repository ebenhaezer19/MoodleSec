from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple
from urllib.parse import urlsplit, urlunsplit

from proxy.ml.pipeline_orchestrator import PipelineOrchestrator


PROXY_ROOT = Path(__file__).resolve().parents[1]
PIPELINE_RESULTS_LOG_PATH = PROXY_ROOT / "logs" / "pipeline_results.json"


pipeline: PipelineOrchestrator | None
_pipeline_init_error: str | None = None

try:
    # Singleton-style initialization for reuse across all incoming requests.
    pipeline = PipelineOrchestrator(enable_logging=False)
except Exception as error:
    pipeline = None
    _pipeline_init_error = str(error)


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if hasattr(value, "item"):
            value = value.item()
        return float(value)
    except Exception:
        return float(default)


def _json_default(value: Any) -> Any:
    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            pass

    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")

    return _safe_text(value)


def _iter_header_pairs(headers: Any) -> Iterable[Tuple[str, str]]:
    if headers is None:
        return []

    if isinstance(headers, dict):
        return [(_safe_text(k), _safe_text(v)) for k, v in headers.items()]

    if isinstance(headers, (list, tuple, set)):
        pairs = []
        for item in headers:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                pairs.append((_safe_text(item[0]), _safe_text(item[1])))
            else:
                text = _safe_text(item)
                if ":" in text:
                    key, value = text.split(":", 1)
                    pairs.append((key.strip(), value.strip()))
        return pairs

    text = _safe_text(headers).strip()
    if not text:
        return []

    pairs = []
    for line in text.replace("\n", ";").split(";"):
        segment = line.strip()
        if not segment:
            continue
        if ":" in segment:
            key, value = segment.split(":", 1)
            pairs.append((key.strip(), value.strip()))
    return pairs


def _headers_to_string(headers: Any) -> str:
    pairs = _iter_header_pairs(headers)
    return "; ".join(f"{key}: {value}" for key, value in pairs if key)


def _resolve_uri(raw_request: Dict[str, Any]) -> str:
    uri = _safe_text(raw_request.get("uri"))
    if uri:
        return uri

    uri = _safe_text(raw_request.get("url"))
    if uri:
        return uri

    path = _safe_text(raw_request.get("path"))
    query = _safe_text(raw_request.get("query_params"))

    if query.startswith("?"):
        query = query[1:]

    if path:
        if not path.startswith("/") and not path.startswith("http"):
            path = "/" + path
        return urlunsplit(("", "", path or "/", query, ""))

    return "/"


def _normalize_request(raw_request: Dict[str, Any]) -> Dict[str, str]:
    uri = _resolve_uri(raw_request)
    parsed = urlsplit(uri)

    path = parsed.path or "/"
    query_params = parsed.query

    if not query_params:
        explicit_query = _safe_text(raw_request.get("query_params"))
        if explicit_query.startswith("?"):
            explicit_query = explicit_query[1:]
        query_params = explicit_query
    if query_params.startswith("?"):
        query_params = query_params[1:]

    method = _safe_text(raw_request.get("method")).upper() or "GET"
    body = _safe_text(raw_request.get("body"))
    headers = _headers_to_string(raw_request.get("headers"))

    request_raw = _safe_text(raw_request.get("request_raw"))
    if not request_raw:
        query_suffix = f"?{query_params}" if query_params else ""
        body_suffix = f" BODY:{body}" if body else ""
        request_raw = f"{method} {path}{query_suffix}{body_suffix}".strip()

    return {
        "method": method,
        "path": path,
        "query_params": query_params,
        "body": body,
        "headers": headers,
        "request_raw": request_raw,
    }


def _fallback_result() -> Dict[str, Any]:
    return {
        "decision": "IGNORE",
        "severity": "LOW",
        "attack_type": "unknown",
        "confidence": 0.0,
        "anomaly_score": 0.0,
        "reason": "ML failure fallback",
    }


def _ensure_result_schema(result: Dict[str, Any]) -> Dict[str, Any]:
    payload = result if isinstance(result, dict) else {}

    decision = _safe_text(payload.get("decision")).upper() or "IGNORE"
    if decision not in {"BLOCK", "ALERT", "IGNORE"}:
        decision = "IGNORE"

    severity = _safe_text(payload.get("severity")).upper() or "LOW"
    if severity not in {"HIGH", "MEDIUM", "LOW"}:
        severity = "LOW"

    attack_type = _safe_text(payload.get("attack_type")) or "unknown"
    confidence = _safe_float(payload.get("confidence"), 0.0)
    anomaly_score = _safe_float(payload.get("anomaly_score"), 0.0)
    reason = _safe_text(payload.get("reason")) or "ML failure fallback"

    return {
        "decision": decision,
        "severity": severity,
        "attack_type": attack_type,
        "confidence": float(confidence),
        "anomaly_score": float(anomaly_score),
        "reason": reason,
    }


def _append_json_array_entry(file_path: Path, entry: Dict[str, Any]) -> None:
    encoded_entry = json.dumps(entry, ensure_ascii=False, default=_json_default).encode("utf-8")

    file_path.parent.mkdir(parents=True, exist_ok=True)

    with file_path.open("a+b") as handle:
        handle.seek(0, os.SEEK_END)
        file_size = handle.tell()

        if file_size == 0:
            handle.write(b"[\n" + encoded_entry + b"\n]\n")
            return

        pos = file_size - 1
        last_char = b""
        while pos >= 0:
            handle.seek(pos)
            char = handle.read(1)
            if char not in b" \t\r\n":
                last_char = char
                break
            pos -= 1

        if pos < 0:
            handle.seek(0)
            handle.truncate()
            handle.write(b"[\n" + encoded_entry + b"\n]\n")
            return

        if last_char != b"]":
            # Recovery path for malformed log file.
            handle.seek(0)
            raw_content = handle.read().decode("utf-8", errors="replace").strip()
            parsed_entries = []
            if raw_content:
                try:
                    loaded = json.loads(raw_content)
                    if isinstance(loaded, list):
                        parsed_entries = loaded
                except Exception:
                    parsed_entries = []

            parsed_entries.append(entry)
            handle.seek(0)
            handle.truncate()
            handle.write(
                (json.dumps(parsed_entries, ensure_ascii=False, default=_json_default, indent=2) + "\n").encode(
                    "utf-8"
                )
            )
            return

        prev_non_ws = b"["
        prev_pos = pos - 1
        while prev_pos >= 0:
            handle.seek(prev_pos)
            prev_char = handle.read(1)
            if prev_char not in b" \t\r\n":
                prev_non_ws = prev_char
                break
            prev_pos -= 1

        handle.seek(pos)
        handle.truncate()

        prefix = b"\n" if prev_non_ws == b"[" else b",\n"
        handle.write(prefix + encoded_entry + b"\n]\n")


def log_pipeline_result(request: Dict[str, Any], result: Dict[str, Any]) -> None:
    try:
        normalized_request = _normalize_request(request if isinstance(request, dict) else {})
        normalized_result = _ensure_result_schema(result if isinstance(result, dict) else {})

        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "method": _safe_text(normalized_request.get("method")).upper() or "GET",
            "path": _safe_text(normalized_request.get("path")) or "/",
            "query": _safe_text(normalized_request.get("query_params")),
            "decision": normalized_result["decision"],
            "severity": normalized_result["severity"],
            "attack_type": normalized_result["attack_type"],
            "confidence": float(normalized_result["confidence"]),
            "anomaly_score": float(normalized_result["anomaly_score"]),
            "reason": normalized_result["reason"],
        }

        _append_json_array_entry(PIPELINE_RESULTS_LOG_PATH, log_entry)
    except Exception:
        # Logging must never break traffic processing.
        return


def process_http_request(raw_request: Dict[str, Any]) -> Dict[str, Any]:
    normalized_request = _normalize_request(raw_request if isinstance(raw_request, dict) else {})
    request = normalized_request

    if request.get("path", "").endswith("favicon.ico"):
        return {
            "decision": "IGNORE",
            "severity": "LOW",
            "attack_type": "normal",
            "confidence": 0.0,
            "anomaly_score": 0.0,
            "reason": "Static resource ignored"
        }

    method = normalized_request.get("method", "GET")
    path = normalized_request.get("path", "")

    try:
        if pipeline is None:
            raise RuntimeError(_pipeline_init_error or "Pipeline is not initialized")

        result = pipeline.process_request(normalized_request)
        output = _ensure_result_schema(result if isinstance(result, dict) else {})
    except Exception:
        output = _fallback_result()

    output = _ensure_result_schema(output)
    log_pipeline_result(normalized_request, output)

    print(
        f"[ML] {method} {path} | {output['decision']} | {output['attack_type']} | {output['severity']} "
        f"| conf={float(output['confidence']):.2f} | anomaly={float(output['anomaly_score']):.2f}"
    )

    return output


def should_block(result: Dict[str, Any]) -> bool:
    return result.get("decision") == "BLOCK"


def generate_manual_test_requests() -> list[Dict[str, Any]]:
    return [
        {
            "name": "normal",
            "uri": "http://localhost/course/view.php?id=2",
            "method": "GET",
            "headers": {"User-Agent": "Mozilla/5.0", "Accept": "text/html"},
            "body": "",
        },
        {
            "name": "xss",
            "uri": "http://localhost/login/index.php?q=%3Cscript%3Ealert(1)%3C/script%3E",
            "method": "GET",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
        },
        {
            "name": "sqli",
            "uri": "http://localhost/user/profile.php?id=1%20OR%201%3D1--",
            "method": "GET",
            "headers": {"User-Agent": "sqlmap/1.8"},
            "body": "",
        },
        {
            "name": "path_traversal",
            "uri": "http://localhost/pluginfile.php?file=../../../../etc/passwd",
            "method": "GET",
            "headers": {"User-Agent": "Mozilla/5.0"},
            "body": "",
        },
        {
            "name": "command_injection",
            "uri": "http://localhost/admin/tool/task/schedule_task.php?cmd=ping%20127.0.0.1;cat%20/etc/passwd",
            "method": "POST",
            "headers": {"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"},
            "body": "cmd=ping+127.0.0.1%3Bcat+%2Fetc%2Fpasswd",
        },
    ]
