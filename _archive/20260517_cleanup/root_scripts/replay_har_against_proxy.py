#!/usr/bin/env python3
"""
Replay OWASP ZAP HAR traffic against a running ML proxy.

v2 – Preserves attack payload integrity during replay.

Default target proxy:
    http://127.0.0.1:8000

Default HAR input directory:
    proxy/ml/data

Default output file:
    har_replay_results_v2.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlsplit, urlunsplit

import requests
from requests import RequestException
from requests.exceptions import ConnectionError, Timeout


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ATTACK_FILENAME_TOKENS = (
    "xss",
    "sql",
    "injection",
    "traversal",
    "attack",
    "tampering",
    "tempering",      # covers "Parameter-Tempering.har"
)

# Encoded tokens whose presence indicates an attack payload in the URL.
ENCODED_PAYLOAD_MARKERS = (
    "%27",   # single-quote  (SQL injection)
    "%3c",   # <             (XSS)
    "%3e",   # >             (XSS)
    "%22",   # "             (XSS)
    "%3cscript",
    "union",
    "select",
    "or+1%3d1",
    "or%201%3d1",
    "1=1",
)

DEFAULT_DATA_DIR = Path("proxy/ml/data")
DEFAULT_TARGET_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_OUTPUT_FILE = Path("har_replay_results_v2.json")
DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MIN_DELAY = 0.2
DEFAULT_MAX_DELAY = 1.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(level: str, message: str) -> None:
    """Print consistent terminal logs."""
    print(f"[{level}] {message}")


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def infer_label_from_filename(filename: str) -> str:
    """Infer label based on filename tokens."""
    lowered = filename.lower()
    if any(token in lowered for token in ATTACK_FILENAME_TOKENS):
        return "attack"
    return "normal"


# ---------------------------------------------------------------------------
# HAR loading
# ---------------------------------------------------------------------------

def load_har_file(file_path: Path) -> Optional[Dict[str, Any]]:
    """Safely load HAR JSON payload without crashing on bad files."""
    try:
        if not file_path.exists() or not file_path.is_file():
            log("WARN", f"Missing HAR file: {file_path}")
            return None

        raw_text = file_path.read_text(encoding="utf-8", errors="replace")
        if not raw_text.strip():
            log("WARN", f"Empty HAR file: {file_path.name}")
            return None

        payload = json.loads(raw_text)
        if not isinstance(payload, dict):
            log("WARN", f"Skipping non-object HAR JSON: {file_path.name}")
            return None

        return payload
    except json.JSONDecodeError as error:
        log("WARN", f"Invalid JSON in {file_path.name}: {error}")
        return None
    except OSError as error:
        log("WARN", f"Failed to read {file_path.name}: {error}")
        return None
    except Exception as error:  # Defensive catch to avoid stopping replay batch.
        log("WARN", f"Unexpected load error in {file_path.name}: {error}")
        return None


# ---------------------------------------------------------------------------
# Header extraction
# ---------------------------------------------------------------------------

def _extract_headers(headers_value: Any) -> Dict[str, str]:
    """Extract request headers from HAR format."""
    headers: Dict[str, str] = {}

    if isinstance(headers_value, list):
        for item in headers_value:
            if not isinstance(item, dict):
                continue
            name = _safe_str(item.get("name", "")).strip()
            if not name:
                continue
            value = _safe_str(item.get("value", ""))
            if name in headers and value:
                headers[name] = f"{headers[name]}, {value}" if headers[name] else value
            else:
                headers[name] = value
        return headers

    if isinstance(headers_value, dict):
        for key, value in headers_value.items():
            name = _safe_str(key).strip()
            if not name:
                continue
            headers[name] = _safe_str(value)
        return headers

    return headers


def _filter_forward_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Remove hop-by-hop and risky forwarding headers before replay."""
    blocked = {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "proxy-connection",
    }

    filtered: Dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in blocked:
            continue
        filtered[key] = value
    return filtered


# ---------------------------------------------------------------------------
# Body extraction  (B – POST BODY PRESERVATION)
# ---------------------------------------------------------------------------

def _extract_body(request_obj: Dict[str, Any]) -> str:
    """Extract body text from HAR postData, preserving raw content exactly.

    Priority:
      1. postData.text  — raw captured body (best fidelity)
      2. postData.params — reconstruct as url-encoded pairs with proper encoding
      3. request.body    — fallback field
    """
    post_data = request_obj.get("postData")
    if isinstance(post_data, dict):
        # Priority 1: raw text
        text = _safe_str(post_data.get("text", ""))
        if text:
            return text

        # Priority 2: params list → reconstruct faithfully
        params = post_data.get("params")
        if isinstance(params, list):
            pairs: List[str] = []
            for item in params:
                if not isinstance(item, dict):
                    continue
                name = _safe_str(item.get("name", ""))
                value = _safe_str(item.get("value", ""))
                if name or value:
                    # Use raw name=value to preserve any existing encoding
                    pairs.append(f"{name}={value}")
            if pairs:
                return "&".join(pairs)

    # Priority 3: top-level body field
    body = request_obj.get("body")
    if body is not None:
        return _safe_str(body)

    return ""


def _extract_content_type(request_obj: Dict[str, Any]) -> str:
    """Extract Content-Type from postData.mimeType or headers."""
    post_data = request_obj.get("postData")
    if isinstance(post_data, dict):
        mime = _safe_str(post_data.get("mimeType", "")).strip()
        if mime:
            return mime

    headers = request_obj.get("headers", [])
    if isinstance(headers, list):
        for item in headers:
            if not isinstance(item, dict):
                continue
            if _safe_str(item.get("name", "")).lower().strip() == "content-type":
                return _safe_str(item.get("value", "")).strip()

    return ""


# ---------------------------------------------------------------------------
# URL rewriting  (A – URL + QUERY PRESERVATION)
# ---------------------------------------------------------------------------

def _rewrite_url_to_target(
    original_url: str, target_base_url: str
) -> Optional[str]:
    """Rewrite original URL host/scheme to target proxy.

    The raw query string from the original URL is preserved **byte-for-byte**
    so that encoded attack payloads (e.g. ``%27%20OR%201=1%20--``) reach the
    proxy exactly as captured in the HAR file.
    """
    try:
        parsed_original = urlsplit(original_url)
        parsed_target = urlsplit(target_base_url)

        if not parsed_target.scheme or not parsed_target.netloc:
            return None

        path = parsed_original.path or "/"
        # Preserve the raw query string verbatim – do NOT parse/rebuild.
        rewritten = urlunsplit(
            (
                parsed_target.scheme,
                parsed_target.netloc,
                path,
                parsed_original.query,   # raw query, unchanged
                "",                       # fragment dropped
            )
        )
        return rewritten
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Replay-ID generation  (E – MATCHING SUPPORT)
# ---------------------------------------------------------------------------

def _make_replay_id(method: str, original_url: str, body: str, index: int) -> str:
    """Create a stable, deterministic replay_id for matching."""
    blob = f"{method}|{original_url}|{body[:200]}|{index}"
    return hashlib.sha256(blob.encode("utf-8", errors="replace")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Validation  (D – VALIDATION CHECKS)
# ---------------------------------------------------------------------------

def _validate_replay(
    *,
    true_label: str,
    original_url: str,
    rewritten_url: str,
    original_query: str,
    replay_query: str,
    body: str,
    content_type: str,
    method: str,
) -> List[str]:
    """Detect and warn about replay integrity issues."""
    warnings: List[str] = []

    is_attack = true_label == "attack"

    # 1. Attack request with empty query after rewrite
    if is_attack and original_query and not replay_query:
        warnings.append("attack query lost after rewrite")

    # 2. Payload length shrinks significantly (>50%)
    if original_query and replay_query:
        if len(replay_query) < len(original_query) * 0.5:
            warnings.append(
                f"query length shrunk: {len(original_query)} → {len(replay_query)}"
            )

    # 3. Encoded payload markers disappear
    orig_lower = original_url.lower()
    rewr_lower = rewritten_url.lower()
    for marker in ENCODED_PAYLOAD_MARKERS:
        if marker in orig_lower and marker not in rewr_lower:
            warnings.append(f"encoded payload marker '{marker}' disappeared")
            break  # one warning is enough

    # 4. Body becomes empty unexpectedly
    if method in ("POST", "PUT", "PATCH") and content_type and not body:
        warnings.append("POST body is empty but Content-Type present")

    return warnings


# ---------------------------------------------------------------------------
# Entry extraction
# ---------------------------------------------------------------------------

def extract_entries(
    har_payload: Dict[str, Any],
    source_file: str,
    true_label: str,
    target_base_url: str,
) -> Tuple[List[Dict[str, Any]], int]:
    """Extract replay-ready requests from one HAR payload."""
    extracted: List[Dict[str, Any]] = []
    skipped_entries = 0

    log_obj = har_payload.get("log")
    if not isinstance(log_obj, dict):
        log("WARN", f"{source_file}: missing 'log' object")
        return extracted, skipped_entries

    entries = log_obj.get("entries")
    if not isinstance(entries, list):
        log("WARN", f"{source_file}: missing or invalid 'entries' list")
        return extracted, skipped_entries

    for index, entry in enumerate(entries):
        try:
            if not isinstance(entry, dict):
                skipped_entries += 1
                log("WARN", f"{source_file}: malformed entry at index {index}")
                continue

            request_obj = entry.get("request")
            if not isinstance(request_obj, dict):
                skipped_entries += 1
                log("WARN", f"{source_file}: missing request object at index {index}")
                continue

            method = _safe_str(request_obj.get("method", "")).strip().upper()
            original_url = _safe_str(request_obj.get("url", "")).strip()
            if not method or not original_url:
                skipped_entries += 1
                log("WARN", f"{source_file}: missing method/url at index {index}")
                continue

            rewritten_url = _rewrite_url_to_target(original_url, target_base_url)
            if not rewritten_url:
                skipped_entries += 1
                log("WARN", f"{source_file}: invalid URL rewrite at index {index}")
                continue

            headers = _extract_headers(request_obj.get("headers", []))
            body = _extract_body(request_obj)
            content_type = _extract_content_type(request_obj)

            # Query string comparison (A – debug fields)
            original_query = urlsplit(original_url).query or ""
            replay_query = urlsplit(rewritten_url).query or ""

            # Stable replay ID (E)
            replay_id = _make_replay_id(method, original_url, body, index)

            # Validation (D)
            replay_warnings = _validate_replay(
                true_label=true_label,
                original_url=original_url,
                rewritten_url=rewritten_url,
                original_query=original_query,
                replay_query=replay_query,
                body=body,
                content_type=content_type,
                method=method,
            )
            for w in replay_warnings:
                log("WARN", f"{source_file}[{index}]: {w}")

            extracted.append(
                {
                    "replay_id": replay_id,
                    "source_file": source_file,
                    "true_label": true_label,
                    "method": method,
                    "original_url": original_url,
                    "rewritten_url": rewritten_url,
                    "original_query": original_query,
                    "replay_query": replay_query,
                    "headers": headers,
                    "body": body,
                    "content_type": content_type,
                    "replay_warnings": replay_warnings,
                }
            )
        except Exception as error:
            skipped_entries += 1
            log("WARN", f"{source_file}: unexpected error at index {index}: {error}")
            continue

    return extracted, skipped_entries


# ---------------------------------------------------------------------------
# Replay engine
# ---------------------------------------------------------------------------

def replay_requests(
    requests_to_replay: List[Dict[str, Any]],
    timeout_seconds: float,
    min_delay_seconds: float,
    max_delay_seconds: float,
) -> List[Dict[str, Any]]:
    """Replay requests against target proxy using requests.Session()."""
    results: List[Dict[str, Any]] = []
    total = len(requests_to_replay)

    with requests.Session() as session:
        for index, item in enumerate(requests_to_replay, start=1):
            method = _safe_str(item.get("method", "GET")).upper() or "GET"
            rewritten_url = _safe_str(item.get("rewritten_url", "")).strip()
            original_url = _safe_str(item.get("original_url", "")).strip()
            source_file = _safe_str(item.get("source_file", ""))
            true_label = _safe_str(item.get("true_label", "normal"))
            replay_id = _safe_str(item.get("replay_id", ""))
            original_query = _safe_str(item.get("original_query", ""))
            replay_query = _safe_str(item.get("replay_query", ""))
            body = _safe_str(item.get("body", ""))
            content_type = _safe_str(item.get("content_type", ""))
            replay_warnings = item.get("replay_warnings", [])

            headers = _filter_forward_headers(item.get("headers", {}))

            # Ensure Content-Type is forwarded if present
            if content_type and "Content-Type" not in headers and "content-type" not in headers:
                headers["Content-Type"] = content_type

            status_code: Optional[int] = None
            replay_error: Optional[str] = None
            timestamp = datetime.now(timezone.utc).isoformat()

            try:
                response = session.request(
                    method=method,
                    url=rewritten_url,
                    headers=headers,
                    data=body.encode("utf-8") if body else None,
                    timeout=timeout_seconds,
                    allow_redirects=False,
                )
                status_code = int(response.status_code)
                log("INFO", f"[{index}/{total}] {method} {rewritten_url} -> HTTP {status_code}")
            except Timeout:
                replay_error = "TIMEOUT"
                log("WARN", f"[{index}/{total}] {method} {rewritten_url} -> TIMEOUT")
            except ConnectionError:
                replay_error = "CONNECTION_ERROR"
                log("WARN", f"[{index}/{total}] {method} {rewritten_url} -> CONNECTION_ERROR")
            except RequestException as error:
                replay_error = f"REQUEST_ERROR: {error}"
                log("WARN", f"[{index}/{total}] {method} {rewritten_url} -> REQUEST_ERROR ({error})")
            except Exception as error:  # Defensive catch to keep replay running.
                replay_error = f"UNEXPECTED_ERROR: {error}"
                log("WARN", f"[{index}/{total}] {method} {rewritten_url} -> UNEXPECTED_ERROR ({error})")

            # (C) Full debug record
            results.append(
                {
                    "replay_id": replay_id,
                    "source_file": source_file,
                    "true_label": true_label,
                    "method": method,
                    "original_url": original_url,
                    "rewritten_url": rewritten_url,
                    "url": rewritten_url,  # backward-compat key
                    "original_query": original_query,
                    "replay_query": replay_query,
                    "request_body_preview": body[:200] if body else "",
                    "status_code": status_code,
                    "replay_error": replay_error,
                    "replay_warnings": replay_warnings,
                    "timestamp": timestamp,
                }
            )

            if index < total and max_delay_seconds > 0:
                delay = random.uniform(min_delay_seconds, max_delay_seconds)
                log("INFO", f"Delay {delay:.2f}s")
                time.sleep(delay)

    return results


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def save_results(results: List[Dict[str, Any]], output_path: Path) -> None:
    """Save replay result objects to JSON."""
    output_path.write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
    )


# ---------------------------------------------------------------------------
# Terminal summary  (G)
# ---------------------------------------------------------------------------

def print_summary(results: List[Dict[str, Any]], skipped_entries: int) -> None:
    """Print enhanced replay summary counters."""
    total_replayed = len(results)
    attack_requests = sum(1 for r in results if r.get("true_label") == "attack")
    normal_requests = total_replayed - attack_requests

    preserved_query = sum(
        1
        for r in results
        if r.get("original_query") and r.get("replay_query") == r.get("original_query")
    )
    lost_query = sum(
        1
        for r in results
        if r.get("original_query") and not r.get("replay_query")
    )
    preserved_body = sum(
        1
        for r in results
        if r.get("request_body_preview")
    )

    suspicious = sum(
        1
        for r in results
        if r.get("replay_warnings")
    )

    http_403_count = sum(1 for r in results if r.get("status_code") == 403)
    http_200_count = sum(1 for r in results if r.get("status_code") == 200)
    failed_requests = sum(1 for r in results if r.get("status_code") is None)

    print()
    log("SUMMARY", "=" * 55)
    log("SUMMARY", f"total requests replayed:       {total_replayed}")
    log("SUMMARY", f"  attack requests:             {attack_requests}")
    log("SUMMARY", f"  normal requests:             {normal_requests}")
    log("SUMMARY", f"requests with preserved query:  {preserved_query}")
    log("SUMMARY", f"requests with lost query:       {lost_query}")
    log("SUMMARY", f"requests with preserved body:   {preserved_body}")
    log("SUMMARY", f"suspicious replay mismatches:   {suspicious}")
    log("SUMMARY", "-" * 55)
    log("SUMMARY", f"HTTP 403 (blocked):            {http_403_count}")
    log("SUMMARY", f"HTTP 200 (allowed):            {http_200_count}")
    log("SUMMARY", f"failed requests:               {failed_requests}")
    log("SUMMARY", f"skipped HAR entries:           {skipped_entries}")
    log("SUMMARY", "=" * 55)
    print()


# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------

def _collect_har_files(data_dir: Path) -> List[Path]:
    if not data_dir.exists() or not data_dir.is_dir():
        return []
    return sorted(
        path
        for path in data_dir.rglob("*")
        if path.is_file() and path.suffix.lower() == ".har"
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Replay HAR requests against ML proxy (v2 – payload-preserving)."
    )
    parser.add_argument(
        "--data-dir",
        default=str(DEFAULT_DATA_DIR),
        help="Directory containing .har files",
    )
    parser.add_argument(
        "--target-base-url",
        default=DEFAULT_TARGET_BASE_URL,
        help="Target proxy base URL",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT_FILE),
        help="Output results JSON path",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="Per-request timeout in seconds",
    )
    parser.add_argument(
        "--min-delay",
        type=float,
        default=DEFAULT_MIN_DELAY,
        help="Minimum delay between requests",
    )
    parser.add_argument(
        "--max-delay",
        type=float,
        default=DEFAULT_MAX_DELAY,
        help="Maximum delay between requests",
    )
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    output_path = Path(args.output)
    target_base_url = _safe_str(args.target_base_url).strip()

    min_delay = max(0.0, float(args.min_delay))
    max_delay = max(0.0, float(args.max_delay))
    if max_delay < min_delay:
        min_delay, max_delay = max_delay, min_delay

    log("INFO", f"HAR data directory: {data_dir}")
    log("INFO", f"Target proxy URL:   {target_base_url}")
    log("INFO", f"Output file:        {output_path}")

    har_files = _collect_har_files(data_dir)
    if not har_files:
        log("WARN", f"No HAR files found under {data_dir}")
        save_results([], output_path)
        print_summary([], skipped_entries=0)
        return 0

    all_requests: List[Dict[str, Any]] = []
    skipped_entries = 0

    for har_file in har_files:
        source_file = har_file.name
        true_label = infer_label_from_filename(source_file)
        log("INFO", f"Loading {source_file} (label={true_label})")

        payload = load_har_file(har_file)
        if payload is None:
            continue

        extracted, skipped = extract_entries(
            har_payload=payload,
            source_file=source_file,
            true_label=true_label,
            target_base_url=target_base_url,
        )
        all_requests.extend(extracted)
        skipped_entries += skipped
        log("INFO", f"{source_file}: extracted={len(extracted)}, skipped={skipped}")

    if not all_requests:
        log("WARN", "No valid HAR requests extracted for replay")
        save_results([], output_path)
        print_summary([], skipped_entries=skipped_entries)
        return 0

    random.seed()
    results = replay_requests(
        requests_to_replay=all_requests,
        timeout_seconds=float(args.timeout),
        min_delay_seconds=min_delay,
        max_delay_seconds=max_delay,
    )

    save_results(results, output_path)
    print_summary(results, skipped_entries=skipped_entries)
    log("INFO", f"Saved replay results to {output_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
