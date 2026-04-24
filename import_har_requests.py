#!/usr/bin/env python3
"""
Import HTTP requests from HAR files and convert them into labeled evaluation samples.

Default input directory:
    data/

Default output file:
    har_extracted_requests.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit


ATTACK_FILENAME_TOKENS = (
    "xss",
    "sql",
    "injection",
    "traversal",
    "command",
    "attack",
)

REQUIRED_OUTPUT_KEYS = (
    "source_file",
    "true_label",
    "method",
    "url",
    "path",
    "query",
    "headers",
    "body",
    "timestamp",
)

DEFAULT_INPUT_DIR = Path("data")
DEFAULT_OUTPUT_FILE = Path("har_extracted_requests.json")


def log(level: str, message: str) -> None:
    """Print consistent terminal log messages."""
    print(f"[{level}] {message}")


def infer_label_from_filename(filename: str) -> str:
    """Infer true_label from HAR filename."""
    lowered = filename.lower()
    if any(token in lowered for token in ATTACK_FILENAME_TOKENS):
        return "attack"
    return "normal"


def load_har_file(file_path: Path) -> Optional[Dict[str, Any]]:
    """Safely load a HAR JSON file without crashing on malformed files."""
    try:
        if not file_path.exists() or not file_path.is_file():
            log("WARN", f"Skipping missing file: {file_path}")
            return None

        raw_text = file_path.read_text(encoding="utf-8", errors="replace")
        if not raw_text.strip():
            log("WARN", f"Skipping empty HAR file: {file_path.name}")
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
    except Exception as error:  # Defensive catch to prevent pipeline interruption.
        log("WARN", f"Unexpected load error for {file_path.name}: {error}")
        return None


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _extract_headers(headers_value: Any) -> Dict[str, str]:
    """Convert HAR header list to a simple dictionary."""
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


def _extract_query_from_querystring_array(query_string_value: Any) -> str:
    """Build query string from HAR queryString array when URL query is missing."""
    if not isinstance(query_string_value, list):
        return ""

    pairs: List[str] = []
    for item in query_string_value:
        if not isinstance(item, dict):
            continue
        name = _safe_str(item.get("name", ""))
        value = _safe_str(item.get("value", ""))
        if not name and not value:
            continue
        pairs.append(f"{name}={value}")

    return "&".join(pairs)


def _extract_body(request_obj: Dict[str, Any]) -> str:
    """Extract request body text from HAR request object."""
    post_data = request_obj.get("postData")
    if isinstance(post_data, dict):
        text = _safe_str(post_data.get("text", ""))
        if text:
            return text

        params = post_data.get("params")
        if isinstance(params, list):
            parts: List[str] = []
            for item in params:
                if not isinstance(item, dict):
                    continue
                name = _safe_str(item.get("name", ""))
                value = _safe_str(item.get("value", ""))
                if name or value:
                    parts.append(f"{name}={value}")
            if parts:
                return "&".join(parts)

    raw_body = request_obj.get("body")
    if raw_body is not None:
        return _safe_str(raw_body)

    return ""


def normalize_entry(entry: Dict[str, Any], source_file: str, true_label: str) -> Optional[Dict[str, Any]]:
    """Normalize one HAR entry into pipeline evaluation format."""
    if not isinstance(entry, dict):
        return None

    request_obj = entry.get("request")
    if not isinstance(request_obj, dict):
        return None

    method = _safe_str(request_obj.get("method", "")).strip().upper()
    full_url = _safe_str(request_obj.get("url", "")).strip()
    if not method or not full_url:
        return None

    try:
        parsed = urlsplit(full_url)
        path = parsed.path or "/"
        query = parsed.query or _extract_query_from_querystring_array(request_obj.get("queryString"))
    except Exception:
        return None

    headers = _extract_headers(request_obj.get("headers", []))
    body = _extract_body(request_obj)
    timestamp = _safe_str(entry.get("startedDateTime", "")).strip()

    normalized = {
        "source_file": source_file,
        "true_label": true_label,
        "method": method,
        "url": full_url,
        "path": path,
        "query": query,
        "headers": headers,
        "body": body,
        "timestamp": timestamp,
    }
    return normalized


def extract_entries(har_payload: Dict[str, Any], source_file: str, true_label: str) -> Tuple[List[Dict[str, Any]], int]:
    """Extract and normalize all valid entries from one HAR payload."""
    extracted: List[Dict[str, Any]] = []
    skipped_entries = 0

    log_obj = har_payload.get("log")
    if not isinstance(log_obj, dict):
        log("WARN", f"{source_file}: missing 'log' object")
        return extracted, skipped_entries

    entries = log_obj.get("entries")
    if not isinstance(entries, list):
        log("WARN", f"{source_file}: missing or invalid 'entries' array")
        return extracted, skipped_entries

    if not entries:
        log("WARN", f"{source_file}: empty HAR entries")
        return extracted, skipped_entries

    for index, entry in enumerate(entries):
        try:
            normalized = normalize_entry(entry, source_file=source_file, true_label=true_label)
            if normalized is None:
                skipped_entries += 1
                log("WARN", f"{source_file}: skipped malformed entry at index {index}")
                continue
            extracted.append(normalized)
        except Exception as error:
            skipped_entries += 1
            log("WARN", f"{source_file}: failed to normalize entry {index}: {error}")

    return extracted, skipped_entries


def _is_valid_output_object(item: Dict[str, Any]) -> bool:
    if not isinstance(item, dict):
        return False

    for key in REQUIRED_OUTPUT_KEYS:
        if key not in item:
            return False

    if item.get("true_label") not in {"attack", "normal"}:
        return False

    if not isinstance(item.get("method"), str) or not item.get("method"):
        return False
    if not isinstance(item.get("url"), str) or not item.get("url"):
        return False
    if not isinstance(item.get("path"), str) or not item.get("path"):
        return False
    if not isinstance(item.get("query"), str):
        return False
    if not isinstance(item.get("headers"), dict):
        return False
    if not isinstance(item.get("body"), str):
        return False
    if not isinstance(item.get("timestamp"), str):
        return False

    return True


def save_results(results: List[Dict[str, Any]], output_path: Path) -> Tuple[int, int]:
    """Validate and save normalized results as JSON."""
    valid_results: List[Dict[str, Any]] = []
    invalid_count = 0

    for item in results:
        if _is_valid_output_object(item):
            valid_results.append(item)
        else:
            invalid_count += 1

    output_path.write_text(json.dumps(valid_results, ensure_ascii=False, indent=2), encoding="utf-8")
    return len(valid_results), invalid_count


def _collect_har_files(data_dir: Path) -> List[Path]:
    if not data_dir.exists() or not data_dir.is_dir():
        return []

    return sorted(path for path in data_dir.rglob("*") if path.is_file() and path.suffix.lower() == ".har")


def main() -> int:
    parser = argparse.ArgumentParser(description="Import HAR requests into normalized evaluation JSON.")
    parser.add_argument("--data-dir", default=str(DEFAULT_INPUT_DIR), help="Directory containing HAR files")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_FILE), help="Output JSON file path")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    output_path = Path(args.output)

    log("INFO", f"HAR input directory: {data_dir.resolve() if data_dir.exists() else data_dir}")
    log("INFO", f"Output file: {output_path.resolve() if output_path.parent.exists() else output_path}")

    har_files = _collect_har_files(data_dir)
    if not har_files:
        log("WARN", f"No .har files found in {data_dir}")
        saved_count, invalid_count = save_results([], output_path)
        log("SUMMARY", f"total files: 0")
        log("SUMMARY", f"total extracted requests: {saved_count}")
        log("SUMMARY", f"attack count: 0")
        log("SUMMARY", f"normal count: 0")
        log("SUMMARY", f"skipped entries: 0")
        if invalid_count:
            log("SUMMARY", f"invalid output objects dropped: {invalid_count}")
        return 0

    all_results: List[Dict[str, Any]] = []
    skipped_entries = 0

    for har_file in har_files:
        source_file = har_file.name
        true_label = infer_label_from_filename(source_file)
        log("INFO", f"Processing {source_file} (label={true_label})")

        payload = load_har_file(har_file)
        if payload is None:
            continue

        extracted, skipped = extract_entries(payload, source_file=source_file, true_label=true_label)
        all_results.extend(extracted)
        skipped_entries += skipped
        log("INFO", f"{source_file}: extracted={len(extracted)}, skipped={skipped}")

    saved_count, invalid_count = save_results(all_results, output_path)

    attack_count = sum(1 for item in all_results if item.get("true_label") == "attack")
    normal_count = sum(1 for item in all_results if item.get("true_label") == "normal")

    log("SUMMARY", f"total files: {len(har_files)}")
    log("SUMMARY", f"total extracted requests: {saved_count}")
    log("SUMMARY", f"attack count: {attack_count}")
    log("SUMMARY", f"normal count: {normal_count}")
    log("SUMMARY", f"skipped entries: {skipped_entries}")
    if invalid_count:
        log("SUMMARY", f"invalid output objects dropped: {invalid_count}")

    log("INFO", f"Saved extracted requests to {output_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())