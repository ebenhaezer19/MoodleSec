#!/usr/bin/env python3
"""
Build per-request ground truth labels from HAR replay results.

Instead of labeling an entire HAR file as "attack" or "normal", this script
inspects each individual request's URL, query string, and POST body to
determine whether it actually contains an attack payload.

Input:
    har_replay_results_v2.json

Output:
    request_ground_truth.json
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import unquote_plus


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_REPLAY_PATH = Path("har_replay_results_v2.json")
DEFAULT_OUTPUT_PATH = Path("request_ground_truth.json")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def log(level: str, message: str) -> None:
    print(f"[{level}] {message}")


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _load_json_list(path: Path, label: str) -> List[Dict[str, Any]]:
    """Load JSON file and normalize to list[dict]."""
    if not path.exists() or not path.is_file():
        log("WARN", f"Missing {label} file: {path}")
        return []
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
        if not raw.strip():
            log("WARN", f"Empty {label} file: {path}")
            return []
        payload = json.loads(raw)
    except (json.JSONDecodeError, OSError) as err:
        log("WARN", f"Failed to load {label} file {path}: {err}")
        return []
    except Exception as err:
        log("WARN", f"Unexpected error loading {label}: {err}")
        return []

    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("results", "data", "entries", "items"):
            nested = payload.get(key)
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]
    log("WARN", f"Unsupported JSON structure in {label}: {path}")
    return []


# ---------------------------------------------------------------------------
# Attack indicator definitions
# ---------------------------------------------------------------------------

# Each category is a list of (indicator_name, pattern_or_func).
# Patterns are matched against the *decoded* combined blob of URL + query + body.

SQLI_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("union_select",       re.compile(r"union\s+(all\s+)?select", re.I)),
    ("or_1=1",             re.compile(r"(?:^|[\s'\"%;])or\s+1\s*=\s*1", re.I)),
    ("and_1=1",            re.compile(r"(?:^|[\s'\"%;])and\s+1\s*=\s*1", re.I)),
    ("sleep_func",         re.compile(r"sleep\s*\(", re.I)),
    ("benchmark_func",     re.compile(r"benchmark\s*\(", re.I)),
    ("waitfor_delay",      re.compile(r"waitfor\s+delay", re.I)),
    ("information_schema", re.compile(r"information_schema", re.I)),
    ("select_from",        re.compile(r"select\s+.{1,80}\s+from\s+", re.I)),
    ("sql_comment_dash",   re.compile(r"(?:--|#)\s*$", re.M)),
    ("single_quote_inject", re.compile(r"['\u0027]\s*;\s*(?:select|drop|insert|update|delete|exec)", re.I)),
    ("hex_sqli_quote",     re.compile(r"%27\s*;?\s*(?:select|union|or\b)", re.I)),
    ("sql_drop_table",     re.compile(r"drop\s+table", re.I)),
    ("sql_exec",           re.compile(r"(?:exec|execute)\s*\(", re.I)),
    ("java_sleep_sqli",    re.compile(r"java\.lang\.Thread\.sleep", re.I)),
]

XSS_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("script_tag",        re.compile(r"<\s*script", re.I)),
    ("script_tag_enc",    re.compile(r"%3c\s*script", re.I)),
    ("onerror_handler",   re.compile(r"onerror\s*=", re.I)),
    ("onload_handler",    re.compile(r"onload\s*=", re.I)),
    ("onmouseover",       re.compile(r"onmouseover\s*=", re.I)),
    ("onfocus",           re.compile(r"onfocus\s*=", re.I)),
    ("javascript_proto",  re.compile(r"javascript\s*:", re.I)),
    ("img_tag_event",     re.compile(r"<\s*img[^>]+on\w+\s*=", re.I)),
    ("svg_tag",           re.compile(r"<\s*svg[^>]+on\w+\s*=", re.I)),
    ("alert_func",        re.compile(r"alert\s*\(", re.I)),
    ("document_cookie",   re.compile(r"document\.cookie", re.I)),
    ("eval_func",         re.compile(r"\beval\s*\(", re.I)),
]

PATH_TRAVERSAL_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("dot_dot_slash",     re.compile(r"\.\./", re.I)),
    ("dot_dot_backslash", re.compile(r"\.\\.\\", re.I)),
    ("encoded_traversal", re.compile(r"\.\.%2[fF]", re.I)),
    ("etc_passwd",        re.compile(r"/etc/passwd", re.I)),
    ("win_ini",           re.compile(r"win\.ini", re.I)),
    ("boot_ini",          re.compile(r"boot\.ini", re.I)),
    ("proc_self",         re.compile(r"/proc/self", re.I)),
]

CMDI_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("semicolon_cmd",     re.compile(r";\s*(?:ls|cat|id|whoami|uname|pwd|dir|ping|wget|curl)\b", re.I)),
    ("pipe_cmd",          re.compile(r"\|\s*(?:bash|sh|cmd|powershell|whoami)\b", re.I)),
    ("ampersand_cmd",     re.compile(r"&&\s*(?:ls|cat|id|whoami|uname|pwd|dir|ping|wget|curl)\b", re.I)),
    ("backtick_cmd",      re.compile(r"`[^`]+`", re.I)),
    ("dollar_paren_cmd",  re.compile(r"\$\([^)]+\)", re.I)),
    ("cmd_param",         re.compile(r"[?&]cmd\s*=", re.I)),
    ("whoami_raw",        re.compile(r"\bwhoami\b", re.I)),
]

CATEGORY_PATTERNS = [
    ("SQLi",             SQLI_PATTERNS),
    ("XSS",              XSS_PATTERNS),
    ("Path Traversal",   PATH_TRAVERSAL_PATTERNS),
    ("Command Injection", CMDI_PATTERNS),
]


# ---------------------------------------------------------------------------
# Labeling logic
# ---------------------------------------------------------------------------

def _build_search_blob(request: Dict[str, Any]) -> str:
    """Build a combined text blob from all request fields for pattern matching.

    We search against both the raw (encoded) text and decoded text to catch
    payloads in either form.
    """
    parts: List[str] = []

    for field in ("original_url", "rewritten_url", "url"):
        parts.append(_safe_str(request.get(field, "")))

    parts.append(_safe_str(request.get("original_query", "")))
    parts.append(_safe_str(request.get("replay_query", "")))
    parts.append(_safe_str(request.get("request_body_preview", "")))

    # Also get the full body if stored under other keys
    parts.append(_safe_str(request.get("body", "")))

    raw_blob = " ".join(parts)

    # Build decoded version
    try:
        decoded_blob = unquote_plus(raw_blob)
    except Exception:
        decoded_blob = raw_blob

    return f"{raw_blob} {decoded_blob}"


def label_request(request: Dict[str, Any], index: int) -> Dict[str, Any]:
    """Analyze a single request and assign ground truth label."""
    blob = _build_search_blob(request)

    detected_indicators: List[str] = []
    detected_categories: List[str] = []

    for category_name, patterns in CATEGORY_PATTERNS:
        category_hits: List[str] = []
        for indicator_name, pattern in patterns:
            if pattern.search(blob):
                category_hits.append(indicator_name)

        if category_hits:
            detected_categories.append(category_name)
            for hit in category_hits:
                detected_indicators.append(f"{category_name}:{hit}")

    # Determine label
    if detected_categories:
        true_label = "attack"
        # Primary category = first matched
        attack_category = detected_categories[0]
        if len(detected_categories) > 1:
            attack_category = " + ".join(detected_categories)
        labeling_reason = (
            f"Detected {len(detected_indicators)} indicator(s): "
            + ", ".join(detected_indicators[:5])
        )
        if len(detected_indicators) > 5:
            labeling_reason += f" (+{len(detected_indicators) - 5} more)"
    else:
        true_label = "normal"
        attack_category = "none"
        labeling_reason = "No attack indicators found in URL, query, or body"

    # Extract path from URL
    url = _safe_str(request.get("rewritten_url", request.get("url", "")))
    path = ""
    query = ""
    try:
        from urllib.parse import urlsplit
        parsed = urlsplit(url)
        path = parsed.path or "/"
        query = parsed.query or ""
    except Exception:
        path = url
        query = ""

    return {
        "replay_id": _safe_str(request.get("replay_id", f"idx-{index}")),
        "source_file": _safe_str(request.get("source_file", "")),
        "file_level_label": _safe_str(request.get("true_label", "unknown")),
        "method": _safe_str(request.get("method", "GET")),
        "path": path,
        "query": query,
        "body_preview": _safe_str(request.get("request_body_preview", ""))[:200],
        "detected_indicators": detected_indicators,
        "true_label": true_label,
        "attack_category": attack_category,
        "labeling_reason": labeling_reason,
    }


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(ground_truth: List[Dict[str, Any]]) -> None:
    """Print validation summary."""
    total = len(ground_truth)
    attacks = [r for r in ground_truth if r["true_label"] == "attack"]
    normals = [r for r in ground_truth if r["true_label"] == "normal"]

    # Category breakdown
    category_counts: Dict[str, int] = {}
    for r in attacks:
        cat = r.get("attack_category", "unknown")
        category_counts[cat] = category_counts.get(cat, 0) + 1

    # Multi-indicator requests
    multi_indicator = sum(
        1 for r in attacks if len(r.get("detected_indicators", [])) > 1
    )

    # File-level vs request-level comparison
    file_level_attack = sum(
        1 for r in ground_truth if r.get("file_level_label") == "attack"
    )
    request_level_attack = len(attacks)

    print()
    log("SUMMARY", "=" * 60)
    log("SUMMARY", f"total requests:                    {total}")
    log("SUMMARY", f"  attack (request-level):          {len(attacks)}")
    log("SUMMARY", f"  normal (request-level):          {len(normals)}")
    log("SUMMARY", "-" * 60)
    log("SUMMARY", "Attack breakdown by category:")
    for cat, count in sorted(category_counts.items(), key=lambda x: -x[1]):
        log("SUMMARY", f"  {cat:30s}  {count}")
    log("SUMMARY", "-" * 60)
    log("SUMMARY", f"requests with multiple indicators:  {multi_indicator}")
    log("SUMMARY", "-" * 60)
    log("SUMMARY", "File-level vs request-level comparison:")
    log("SUMMARY", f"  file-level 'attack' labels:      {file_level_attack}")
    log("SUMMARY", f"  request-level 'attack' labels:   {request_level_attack}")
    log("SUMMARY", f"  over-labeled (now normal):       {file_level_attack - request_level_attack}")
    log("SUMMARY", "=" * 60)
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build per-request ground truth labels from HAR replay results."
    )
    parser.add_argument(
        "--replay",
        default=str(DEFAULT_REPLAY_PATH),
        help="Path to har_replay_results_v2.json",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT_PATH),
        help="Output ground truth JSON path",
    )
    args = parser.parse_args()

    replay_path = Path(args.replay)
    output_path = Path(args.output)

    log("INFO", f"Replay input:  {replay_path}")
    log("INFO", f"Output:        {output_path}")

    replay_entries = _load_json_list(replay_path, "replay")
    if not replay_entries:
        log("WARN", "No replay entries found. Writing empty output.")
        output_path.write_text("[]", encoding="utf-8")
        return 0

    log("INFO", f"Loaded {len(replay_entries)} replay entries")

    ground_truth: List[Dict[str, Any]] = []
    for idx, entry in enumerate(replay_entries):
        try:
            labeled = label_request(entry, idx)
            ground_truth.append(labeled)
        except Exception as err:
            log("WARN", f"Failed to label entry {idx}: {err}")
            ground_truth.append({
                "replay_id": _safe_str(entry.get("replay_id", f"idx-{idx}")),
                "source_file": _safe_str(entry.get("source_file", "")),
                "file_level_label": _safe_str(entry.get("true_label", "unknown")),
                "method": _safe_str(entry.get("method", "GET")),
                "path": "",
                "query": "",
                "body_preview": "",
                "detected_indicators": [],
                "true_label": "unknown",
                "attack_category": "error",
                "labeling_reason": f"Labeling error: {err}",
            })

    output_path.write_text(
        json.dumps(ground_truth, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    print_summary(ground_truth)
    log("INFO", f"Saved request ground truth to {output_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
