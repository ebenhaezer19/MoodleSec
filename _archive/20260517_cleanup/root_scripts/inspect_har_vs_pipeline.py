#!/usr/bin/env python3
"""
Inspect HAR replay results versus pipeline logs for replay integrity issues.

Inputs:
  - har_replay_results.json
  - proxy/logs/pipeline_results.json

Output:
  - har_pipeline_forensics.json
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, unquote_plus, urlsplit


DEFAULT_REPLAY_PATH = Path("har_replay_results.json")
DEFAULT_PIPELINE_PATH = Path("proxy/logs/pipeline_results.json")
DEFAULT_OUTPUT_PATH = Path("har_pipeline_forensics.json")

ATTACK_TOKENS = (
    "xss",
    "sql",
    "injection",
    "traversal",
    "attack",
    "tampering",
    "script",
    "union",
    "select",
    "onerror",
    "onload",
    "../",
    "..\\",
    "or 1=1",
    "%3c",
    "%27",
)


def log(level: str, message: str) -> None:
    """Print clean terminal output."""
    print(f"[{level}] {message}")


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def parse_timestamp(value: Any) -> Optional[datetime]:
    """Parse various ISO-like timestamp strings safely."""
    text = _safe_str(value).strip()
    if not text:
        return None

    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def load_json_list(path: Path, label: str) -> List[Dict[str, Any]]:
    """Safely load JSON and normalize to list[dict] without crashing."""
    if not path.exists() or not path.is_file():
        log("WARN", f"Missing {label} file: {path}")
        return []

    try:
        raw_text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as error:
        log("WARN", f"Failed reading {label} file {path}: {error}")
        return []

    if not raw_text.strip():
        log("WARN", f"Empty {label} file: {path}")
        return []

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as error:
        log("WARN", f"Invalid JSON in {label} file {path}: {error}")
        return []
    except Exception as error:
        log("WARN", f"Unexpected JSON parse error in {label} file {path}: {error}")
        return []

    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if isinstance(payload, dict):
        for key in ("results", "data", "entries", "items"):
            nested = payload.get(key)
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]

    log("WARN", f"Unsupported JSON structure in {label} file: {path}")
    return []


def normalize_url(url: str) -> str:
    """Normalize URL into canonical comparison form."""
    text = _safe_str(url).strip()
    if not text:
        return ""

    try:
        parsed = urlsplit(text)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        query = parsed.query
        if scheme and netloc:
            return f"{scheme}://{netloc}{path}" + (f"?{query}" if query else "")
        return f"{path}" + (f"?{query}" if query else "")
    except Exception:
        return text


def extract_query(url: str) -> str:
    """Extract query string from URL safely."""
    text = _safe_str(url).strip()
    if not text:
        return ""
    try:
        return urlsplit(text).query or ""
    except Exception:
        return ""


def canonical_query(query: str) -> str:
    """Canonicalize query by sorting decoded key-value pairs for safe comparison."""
    text = _safe_str(query).strip()
    if text.startswith("?"):
        text = text[1:]
    if not text:
        return ""

    pairs = parse_qsl(text, keep_blank_values=True)
    normalized_pairs = sorted((unquote_plus(k), unquote_plus(v)) for k, v in pairs)
    return "&".join(f"{k}={v}" for k, v in normalized_pairs)


def safe_compare(a: str, b: str) -> bool:
    """Safely compare possibly-encoded strings with canonical fallback."""
    a_text = _safe_str(a).strip()
    b_text = _safe_str(b).strip()
    if a_text == b_text:
        return True

    if canonical_query(a_text) and canonical_query(b_text):
        return canonical_query(a_text) == canonical_query(b_text)

    return unquote_plus(a_text) == unquote_plus(b_text)


def _decision_to_label(decision: str) -> str:
    value = _safe_str(decision).upper()
    if value in {"BLOCK", "ALERT"}:
        return "attack"
    return "normal"


def _looks_attack_payload(path: str, query: str, original_url: str, rewritten_url: str) -> bool:
    blob = " ".join(
        [
            _safe_str(path).lower(),
            _safe_str(query).lower(),
            unquote_plus(_safe_str(query)).lower(),
            _safe_str(original_url).lower(),
            _safe_str(rewritten_url).lower(),
        ]
    )
    return any(token in blob for token in ATTACK_TOKENS)


def _seconds_delta(a: Optional[datetime], b: Optional[datetime]) -> Optional[float]:
    if a is None or b is None:
        return None
    return abs((a - b).total_seconds())


def normalize_replay_entries(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize replay entries with robust field fallbacks."""
    normalized: List[Dict[str, Any]] = []

    for idx, row in enumerate(entries):
        if not isinstance(row, dict):
            continue

        rewritten_url = _safe_str(row.get("url", "")).strip()
        original_url = _safe_str(row.get("original_url", row.get("source_url", ""))).strip()
        if not original_url:
            original_url = rewritten_url

        if not rewritten_url:
            continue

        try:
            parsed = urlsplit(rewritten_url)
            path = parsed.path or "/"
            query = parsed.query or ""
        except Exception:
            path = ""
            query = ""

        normalized.append(
            {
                "id": idx,
                "source_file": _safe_str(row.get("source_file", "")),
                "true_label": _safe_str(row.get("true_label", "normal")).lower() or "normal",
                "method": _safe_str(row.get("method", "GET")).upper() or "GET",
                "original_url": normalize_url(original_url),
                "rewritten_url": normalize_url(rewritten_url),
                "path": path,
                "query": query,
                "canonical_query": canonical_query(query),
                "timestamp_raw": _safe_str(row.get("timestamp", "")),
                "timestamp": parse_timestamp(row.get("timestamp")),
                "status_code": row.get("status_code"),
            }
        )

    return normalized


def normalize_pipeline_entries(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize pipeline log entries for matching and analysis."""
    normalized: List[Dict[str, Any]] = []

    for idx, row in enumerate(entries):
        if not isinstance(row, dict):
            continue

        path = _safe_str(row.get("path", "")).strip() or "/"
        query = _safe_str(row.get("query", "")).strip()

        normalized.append(
            {
                "id": idx,
                "path": path,
                "query": query,
                "canonical_query": canonical_query(query),
                "timestamp_raw": _safe_str(row.get("timestamp", "")),
                "timestamp": parse_timestamp(row.get("timestamp")),
                "decision": _safe_str(row.get("decision", "IGNORE")).upper() or "IGNORE",
                "attack_type": _safe_str(row.get("attack_type", "unknown")) or "unknown",
                "confidence": float(row.get("confidence", 0.0) or 0.0),
                "anomaly_score": float(row.get("anomaly_score", 0.0) or 0.0),
                "reason": _safe_str(row.get("reason", "")),
            }
        )

    return normalized


def find_best_match(
    replay_entry: Dict[str, Any],
    pipeline_entries: List[Dict[str, Any]],
    used_pipeline_ids: set[int],
) -> Optional[Dict[str, Any]]:
    """Find best pipeline match using path, query, and timestamp proximity."""
    replay_path = _safe_str(replay_entry.get("path", ""))
    replay_query = _safe_str(replay_entry.get("query", ""))
    replay_canonical_query = _safe_str(replay_entry.get("canonical_query", ""))
    replay_ts = replay_entry.get("timestamp")

    exact_candidates = [
        item
        for item in pipeline_entries
        if item.get("id") not in used_pipeline_ids
        and _safe_str(item.get("path", "")) == replay_path
        and (
            safe_compare(_safe_str(item.get("query", "")), replay_query)
            or _safe_str(item.get("canonical_query", "")) == replay_canonical_query
        )
    ]

    path_only_candidates = [
        item
        for item in pipeline_entries
        if item.get("id") not in used_pipeline_ids and _safe_str(item.get("path", "")) == replay_path
    ]

    candidates = exact_candidates if exact_candidates else path_only_candidates
    if not candidates:
        return None

    def candidate_score(item: Dict[str, Any]) -> Tuple[float, int, int]:
        ts_delta = _seconds_delta(replay_ts, item.get("timestamp"))
        if ts_delta is None:
            ts_delta = 10_000_000.0
        query_mismatch = 0 if safe_compare(_safe_str(item.get("query", "")), replay_query) else 1
        pipeline_id = int(item.get("id", 0))
        return (ts_delta, query_mismatch, pipeline_id)

    return min(candidates, key=candidate_score)


def analyze_integrity(
    replay_entry: Dict[str, Any],
    pipeline_entry: Optional[Dict[str, Any]],
) -> List[str]:
    """Detect likely replay integrity problems."""
    reasons: List[str] = []

    true_label = _safe_str(replay_entry.get("true_label", "normal")).lower()
    replay_path = _safe_str(replay_entry.get("path", ""))
    replay_query = _safe_str(replay_entry.get("query", ""))
    replay_original_url = _safe_str(replay_entry.get("original_url", ""))
    replay_rewritten_url = _safe_str(replay_entry.get("rewritten_url", ""))

    if true_label == "attack" and not replay_query:
        reasons.append("empty query on attack request")

    if pipeline_entry is None:
        reasons.append("unmatched replay request")
        return reasons

    pipeline_path = _safe_str(pipeline_entry.get("path", ""))
    pipeline_query = _safe_str(pipeline_entry.get("query", ""))
    decision = _safe_str(pipeline_entry.get("decision", "IGNORE")).upper()
    attack_type = _safe_str(pipeline_entry.get("attack_type", "unknown")).lower()
    anomaly_score = float(pipeline_entry.get("anomaly_score", 0.0) or 0.0)

    replay_payload_like_attack = _looks_attack_payload(
        path=replay_path,
        query=replay_query,
        original_url=replay_original_url,
        rewritten_url=replay_rewritten_url,
    )

    if replay_query and not pipeline_query:
        reasons.append("query string disappeared")

    if replay_query and pipeline_query and not safe_compare(replay_query, pipeline_query):
        reasons.append("encoded payload mismatch")

    if replay_path and pipeline_path and replay_path != pipeline_path:
        reasons.append("path mismatch between replay and pipeline")

    if replay_payload_like_attack and not pipeline_query:
        reasons.append("payload missing after replay")

    if (
        true_label == "attack"
        and _decision_to_label(decision) == "normal"
        and (attack_type in {"normal", "benign", "unknown"} or anomaly_score < 0.4)
    ):
        reasons.append("attack request became normal-looking")

    return reasons


def build_forensics(
    replay_entries: List[Dict[str, Any]],
    pipeline_entries: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build full forensic analysis and summary."""
    used_pipeline_ids: set[int] = set()
    matched_records: List[Dict[str, Any]] = []
    suspicious_cases: List[Dict[str, Any]] = []
    unmatched_records: List[Dict[str, Any]] = []

    total_replay_requests = len(replay_entries)
    attack_requests_with_empty_query = 0
    attack_requests_classified_as_normal = 0
    attack_requests_low_anomaly = 0

    for replay in replay_entries:
        is_attack = _safe_str(replay.get("true_label", "normal")).lower() == "attack"
        if is_attack and not _safe_str(replay.get("query", "")):
            attack_requests_with_empty_query += 1

        match = find_best_match(replay, pipeline_entries, used_pipeline_ids)
        if match is not None:
            used_pipeline_ids.add(int(match.get("id", -1)))

        reasons = analyze_integrity(replay, match)

        record = {
            "replay": {
                "source_file": _safe_str(replay.get("source_file", "")),
                "original_url": _safe_str(replay.get("original_url", "")),
                "rewritten_url": _safe_str(replay.get("rewritten_url", "")),
                "true_label": _safe_str(replay.get("true_label", "normal")),
                "method": _safe_str(replay.get("method", "GET")),
                "path": _safe_str(replay.get("path", "")),
                "query": _safe_str(replay.get("query", "")),
                "timestamp": _safe_str(replay.get("timestamp_raw", "")),
            },
            "pipeline": None,
            "integrity_flags": reasons,
        }

        if match is not None:
            record["pipeline"] = {
                "path": _safe_str(match.get("path", "")),
                "query": _safe_str(match.get("query", "")),
                "decision": _safe_str(match.get("decision", "")),
                "attack_type": _safe_str(match.get("attack_type", "")),
                "confidence": float(match.get("confidence", 0.0) or 0.0),
                "anomaly_score": float(match.get("anomaly_score", 0.0) or 0.0),
                "reason": _safe_str(match.get("reason", "")),
                "timestamp": _safe_str(match.get("timestamp_raw", "")),
            }

            if is_attack and _decision_to_label(_safe_str(match.get("decision", "IGNORE"))) == "normal":
                attack_requests_classified_as_normal += 1

            if is_attack and float(match.get("anomaly_score", 0.0) or 0.0) < 0.4:
                attack_requests_low_anomaly += 1
        else:
            unmatched_records.append(record)

        matched_records.append(record)
        if reasons:
            suspicious_cases.append(record)

    matched_requests = total_replay_requests - len(unmatched_records)
    summary = {
        "total_replay_requests": total_replay_requests,
        "matched_requests": matched_requests,
        "unmatched_requests": len(unmatched_records),
        "attack_requests_with_empty_query": attack_requests_with_empty_query,
        "attack_requests_classified_as_normal": attack_requests_classified_as_normal,
        "attack_requests_with_very_low_anomaly_score": attack_requests_low_anomaly,
    }

    return {
        "summary": summary,
        "suspicious_cases": suspicious_cases,
        "matched_records": matched_records,
        "unmatched_records": unmatched_records,
    }


def print_suspicious_cases(suspicious_cases: List[Dict[str, Any]], limit: int = 20) -> None:
    """Print suspicious cases clearly in terminal output."""
    if not suspicious_cases:
        log("INFO", "No suspicious replay integrity cases detected.")
        return

    log("INFO", f"Suspicious cases detected: {len(suspicious_cases)}")
    for idx, case in enumerate(suspicious_cases[:limit], start=1):
        replay = case.get("replay", {})
        pipeline = case.get("pipeline", {}) or {}
        flags = case.get("integrity_flags", [])

        log("CASE", f"#{idx} source={_safe_str(replay.get('source_file', ''))}")
        log("CASE", f"  true_label={_safe_str(replay.get('true_label', ''))} method={_safe_str(replay.get('method', ''))}")
        log("CASE", f"  replay_url={_safe_str(replay.get('rewritten_url', ''))}")
        log("CASE", f"  replay_query={_safe_str(replay.get('query', ''))}")
        if pipeline:
            log(
                "CASE",
                "  pipeline="
                f"path={_safe_str(pipeline.get('path', ''))} "
                f"query={_safe_str(pipeline.get('query', ''))} "
                f"decision={_safe_str(pipeline.get('decision', ''))} "
                f"attack_type={_safe_str(pipeline.get('attack_type', ''))} "
                f"confidence={float(pipeline.get('confidence', 0.0) or 0.0):.3f} "
                f"anomaly={float(pipeline.get('anomaly_score', 0.0) or 0.0):.3f}",
            )
            log("CASE", f"  reason={_safe_str(pipeline.get('reason', ''))}")
        else:
            log("CASE", "  pipeline=NO MATCH")
        log("CASE", f"  flags={'; '.join(_safe_str(x) for x in flags)}")

    if len(suspicious_cases) > limit:
        log("INFO", f"... plus {len(suspicious_cases) - limit} more suspicious cases in JSON output")


def save_results(output_path: Path, findings: Dict[str, Any]) -> None:
    output_path.write_text(json.dumps(findings, ensure_ascii=False, indent=2), encoding="utf-8")


def print_summary(summary: Dict[str, Any]) -> None:
    log("SUMMARY", f"total replay requests: {int(summary.get('total_replay_requests', 0))}")
    log("SUMMARY", f"matched requests: {int(summary.get('matched_requests', 0))}")
    log("SUMMARY", f"unmatched requests: {int(summary.get('unmatched_requests', 0))}")
    log("SUMMARY", f"attack requests with empty query: {int(summary.get('attack_requests_with_empty_query', 0))}")
    log("SUMMARY", f"attack requests classified as normal: {int(summary.get('attack_requests_classified_as_normal', 0))}")
    log(
        "SUMMARY",
        "attack requests with very low anomaly score (< 0.4): "
        f"{int(summary.get('attack_requests_with_very_low_anomaly_score', 0))}",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Forensic inspection of HAR replay versus pipeline logs.")
    parser.add_argument("--replay", default=str(DEFAULT_REPLAY_PATH), help="Path to har_replay_results.json")
    parser.add_argument("--pipeline", default=str(DEFAULT_PIPELINE_PATH), help="Path to proxy/logs/pipeline_results.json")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_PATH), help="Output forensic JSON file")
    args = parser.parse_args()

    replay_path = Path(args.replay)
    pipeline_path = Path(args.pipeline)
    output_path = Path(args.output)

    log("INFO", f"Replay input: {replay_path}")
    log("INFO", f"Pipeline input: {pipeline_path}")
    log("INFO", f"Output report: {output_path}")

    replay_raw = load_json_list(replay_path, "replay")
    pipeline_raw = load_json_list(pipeline_path, "pipeline")

    replay_entries = normalize_replay_entries(replay_raw)
    pipeline_entries = normalize_pipeline_entries(pipeline_raw)

    if not replay_entries:
        log("WARN", "No valid replay entries found. Creating empty forensic report.")
        findings = {
            "summary": {
                "total_replay_requests": 0,
                "matched_requests": 0,
                "unmatched_requests": 0,
                "attack_requests_with_empty_query": 0,
                "attack_requests_classified_as_normal": 0,
                "attack_requests_with_very_low_anomaly_score": 0,
            },
            "suspicious_cases": [],
            "matched_records": [],
            "unmatched_records": [],
        }
        save_results(output_path, findings)
        print_summary(findings["summary"])
        return 0

    findings = build_forensics(replay_entries=replay_entries, pipeline_entries=pipeline_entries)
    save_results(output_path, findings)

    print_suspicious_cases(findings.get("suspicious_cases", []), limit=20)
    print_summary(findings.get("summary", {}))
    log("INFO", f"Detailed findings saved to {output_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
