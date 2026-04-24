#!/usr/bin/env python3
"""
Replay OWASP ZAP HAR traffic against a running ML proxy.

Default target proxy:
    http://127.0.0.1:8000

Default HAR input directory:
    data/

Default output file:
    har_replay_results.json
"""

from __future__ import annotations

import argparse
import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import requests
from requests import RequestException
from requests.exceptions import ConnectionError, Timeout


ATTACK_FILENAME_TOKENS = (
    "xss",
    "sql",
    "injection",
    "traversal",
    "attack",
    "tampering",
)

DEFAULT_DATA_DIR = Path("data")
DEFAULT_TARGET_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_OUTPUT_FILE = Path("har_replay_results.json")
DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_MIN_DELAY = 0.2
DEFAULT_MAX_DELAY = 1.0


def log(level: str, message: str) -> None:
    """Print consistent terminal logs."""
    print(f"[{level}] {message}")


def infer_label_from_filename(filename: str) -> str:
    """Infer label based on filename tokens."""
    lowered = filename.lower()
    if any(token in lowered for token in ATTACK_FILENAME_TOKENS):
        return "attack"
    return "normal"


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


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


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


def _extract_query_params(request_obj: Dict[str, Any]) -> Dict[str, str]:
    """Extract query params from HAR queryString and/or URL."""
    query_params: Dict[str, str] = {}

    query_items = request_obj.get("queryString")
    if isinstance(query_items, list):
        for item in query_items:
            if not isinstance(item, dict):
                continue
            name = _safe_str(item.get("name", ""))
            value = _safe_str(item.get("value", ""))
            if not name and not value:
                continue
            query_params[name] = value

    if query_params:
        return query_params

    full_url = _safe_str(request_obj.get("url", "")).strip()
    if not full_url:
        return query_params

    parsed = urlsplit(full_url)
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        query_params[_safe_str(key)] = _safe_str(value)
    return query_params


def _extract_body(request_obj: Dict[str, Any]) -> str:
    """Extract body text from HAR postData if available."""
    post_data = request_obj.get("postData")
    if isinstance(post_data, dict):
        text = _safe_str(post_data.get("text", ""))
        if text:
            return text

        params = post_data.get("params")
        if isinstance(params, list):
            pairs: List[str] = []
            for item in params:
                if not isinstance(item, dict):
                    continue
                name = _safe_str(item.get("name", ""))
                value = _safe_str(item.get("value", ""))
                if name or value:
                    pairs.append(f"{name}={value}")
            if pairs:
                return "&".join(pairs)

    body = request_obj.get("body")
    if body is not None:
        return _safe_str(body)

    return ""


def _rewrite_url_to_target(original_url: str, target_base_url: str) -> Optional[str]:
    """Rewrite original URL host/scheme to target proxy while preserving path/query."""
    try:
        parsed_original = urlsplit(original_url)
        parsed_target = urlsplit(target_base_url)

        if not parsed_target.scheme or not parsed_target.netloc:
            return None

        path = parsed_original.path or "/"
        rewritten = urlunsplit(
            (
                parsed_target.scheme,
                parsed_target.netloc,
                path,
                parsed_original.query,
                "",
            )
        )
        return rewritten
    except Exception:
        return None


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
        query_params = _extract_query_params(request_obj)
        body = _extract_body(request_obj)

        extracted.append(
            {
                "source_file": source_file,
                "true_label": true_label,
                "method": method,
                "url": rewritten_url,
                "headers": headers,
                "query_params": query_params,
                "body": body,
            }
        )

    return extracted, skipped_entries


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
            url = _safe_str(item.get("url", "")).strip()
            source_file = _safe_str(item.get("source_file", ""))
            true_label = _safe_str(item.get("true_label", "normal"))
            headers = _filter_forward_headers(item.get("headers", {}))
            body = _safe_str(item.get("body", ""))

            status_code: Optional[int] = None
            timestamp = datetime.now(timezone.utc).isoformat()

            try:
                response = session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=body if body else None,
                    timeout=timeout_seconds,
                    allow_redirects=False,
                )
                status_code = int(response.status_code)
                log("INFO", f"[{index}/{total}] {method} {url} -> HTTP {status_code}")
            except Timeout:
                log("WARN", f"[{index}/{total}] {method} {url} -> TIMEOUT")
            except ConnectionError:
                log("WARN", f"[{index}/{total}] {method} {url} -> CONNECTION_ERROR")
            except RequestException as error:
                log("WARN", f"[{index}/{total}] {method} {url} -> REQUEST_ERROR ({error})")
            except Exception as error:  # Defensive catch to keep replay running.
                log("WARN", f"[{index}/{total}] {method} {url} -> UNEXPECTED_ERROR ({error})")

            results.append(
                {
                    "source_file": source_file,
                    "true_label": true_label,
                    "method": method,
                    "url": url,
                    "status_code": status_code,
                    "timestamp": timestamp,
                }
            )

            if index < total and max_delay_seconds > 0:
                delay = random.uniform(min_delay_seconds, max_delay_seconds)
                log("INFO", f"Delay {delay:.2f}s")
                time.sleep(delay)

    return results


def save_results(results: List[Dict[str, Any]], output_path: Path) -> None:
    """Save replay result objects to JSON."""
    output_path.write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")


def print_summary(results: List[Dict[str, Any]], skipped_entries: int) -> None:
    """Print replay summary counters."""
    total_replayed = len(results)
    attack_requests = sum(1 for row in results if row.get("true_label") == "attack")
    http_403_count = sum(1 for row in results if row.get("status_code") == 403)
    http_200_count = sum(1 for row in results if row.get("status_code") == 200)
    failed_requests = sum(1 for row in results if row.get("status_code") is None)

    log("SUMMARY", f"total requests replayed: {total_replayed}")
    log("SUMMARY", f"attack requests: {attack_requests}")
    log("SUMMARY", f"HTTP 403 count: {http_403_count}")
    log("SUMMARY", f"HTTP 200 count: {http_200_count}")
    log("SUMMARY", f"failed requests: {failed_requests}")
    log("SUMMARY", f"skipped entries: {skipped_entries}")


def _collect_har_files(data_dir: Path) -> List[Path]:
    if not data_dir.exists() or not data_dir.is_dir():
        return []
    return sorted(path for path in data_dir.rglob("*") if path.is_file() and path.suffix.lower() == ".har")


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay HAR requests against ML proxy.")
    parser.add_argument("--data-dir", default=str(DEFAULT_DATA_DIR), help="Directory containing .har files")
    parser.add_argument("--target-base-url", default=DEFAULT_TARGET_BASE_URL, help="Target proxy base URL")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_FILE), help="Output results JSON path")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS, help="Per-request timeout in seconds")
    parser.add_argument("--min-delay", type=float, default=DEFAULT_MIN_DELAY, help="Minimum delay between requests")
    parser.add_argument("--max-delay", type=float, default=DEFAULT_MAX_DELAY, help="Maximum delay between requests")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    output_path = Path(args.output)
    target_base_url = _safe_str(args.target_base_url).strip()

    min_delay = max(0.0, float(args.min_delay))
    max_delay = max(0.0, float(args.max_delay))
    if max_delay < min_delay:
        min_delay, max_delay = max_delay, min_delay

    log("INFO", f"HAR data directory: {data_dir}")
    log("INFO", f"Target proxy URL: {target_base_url}")
    log("INFO", f"Output file: {output_path}")

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
