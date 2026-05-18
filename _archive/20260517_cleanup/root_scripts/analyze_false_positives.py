#!/usr/bin/env python3
"""
Analyze false positives from MoodleSec evaluation artifacts.

Loads:
- labeled_requests.json
- proxy/logs/pipeline_results.json
- merged_evaluation.json (if available)

Outputs:
- Console analysis with detailed false-positive breakdown
- false_positive_report.json
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import quote, unquote, urlsplit, urlunsplit


DEFAULT_LABELED_PATH = Path("labeled_requests.json")
DEFAULT_PIPELINE_PATH = Path("proxy/logs/pipeline_results.json")
DEFAULT_MERGED_PATH = Path("merged_evaluation.json")
DEFAULT_OUTPUT_PATH = Path("false_positive_report.json")
DEFAULT_BASE_URL = "http://127.0.0.1:8000"

TRIGGER_KEYWORDS = ("select", "script", "union", "drop")
EDUCATIONAL_TERMS = (
    "how to",
    "course",
    "materials",
    "python",
    "math",
    "overview",
    "assignment",
    "comment",
)


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


def _safe_divide(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return float(numerator / denominator)


def _compact_spaces(text: Any) -> str:
    return " ".join(_safe_text(text).strip().split())


def _normalize_true_label(raw_label: Any) -> Optional[str]:
    label = _safe_text(raw_label).strip().lower()
    if label in {"attack", "anomaly", "malicious", "1", "true", "yes"}:
        return "attack"
    if label in {"normal", "benign", "legitimate", "0", "false", "no"}:
        return "normal"
    return None


def _normalize_decision(raw_decision: Any) -> str:
    decision = _safe_text(raw_decision).strip().upper()
    if decision in {"BLOCK", "ALERT", "IGNORE"}:
        return decision
    return "IGNORE"


def _decision_to_label(decision: Any) -> str:
    normalized = _normalize_decision(decision)
    if normalized in {"BLOCK", "ALERT"}:
        return "attack"
    return "normal"


def _load_json_entries(path: Path, *, optional: bool = False) -> List[Dict[str, Any]]:
    if not path.exists():
        if not optional:
            print(f"[WARN] File not found: {path}")
        else:
            print(f"[INFO] Optional file not found: {path}")
        return []

    try:
        raw_text = path.read_text(encoding="utf-8", errors="replace").strip()
    except Exception as error:
        print(f"[WARN] Failed reading {path}: {error}")
        return []

    if not raw_text:
        print(f"[WARN] File is empty: {path}")
        return []

    try:
        payload = json.loads(raw_text)
    except Exception as error:
        print(f"[WARN] Invalid JSON in {path}: {error}")
        return []

    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if isinstance(payload, dict):
        for key in ("results", "data", "items", "requests", "dataset", "entries"):
            nested = payload.get(key)
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]

    print(f"[WARN] Unexpected JSON structure in {path}")
    return []


def _canonicalize_url(url: str, default_base: str = DEFAULT_BASE_URL) -> str:
    text = _compact_spaces(url)
    if not text:
        return ""

    base_parts = urlsplit(default_base)

    if "://" not in text:
        if not text.startswith("/"):
            text = "/" + text
        text = f"{base_parts.scheme}://{base_parts.netloc}{text}"

    try:
        parsed = urlsplit(text)
    except Exception:
        return text

    scheme = (parsed.scheme or base_parts.scheme or "http").lower()
    netloc = (parsed.netloc or base_parts.netloc).lower()
    path = parsed.path or "/"
    query = parsed.query.lstrip("?")

    safe_path = quote(unquote(path), safe="/%:@-._~!$&'()*+,;=")
    safe_query = quote(unquote(query), safe="=&%:@-._~!$'()*+,;/?")

    return urlunsplit((scheme, netloc, safe_path, safe_query, ""))


def _path_query_keys(path: str, query: str) -> List[str]:
    raw_path = _compact_spaces(path) or "/"
    raw_query = _compact_spaces(query).lstrip("?")

    if raw_path.startswith("http://") or raw_path.startswith("https://"):
        parsed = urlsplit(raw_path)
        raw_path = parsed.path or "/"
        if not raw_query:
            raw_query = parsed.query

    if not raw_path.startswith("/"):
        raw_path = "/" + raw_path

    encoded_path = quote(unquote(raw_path), safe="/%:@-._~!$&'()*+,;=")
    encoded_query = quote(unquote(raw_query), safe="=&%:@-._~!$'()*+,;/?")

    raw_full = f"{raw_path}?{raw_query}" if raw_query else raw_path
    encoded_full = f"{encoded_path}?{encoded_query}" if encoded_query else encoded_path
    decoded_full = unquote(encoded_full)

    ordered: List[str] = []
    for item in (raw_full, encoded_full, decoded_full):
        if item and item not in ordered:
            ordered.append(item)
    return ordered


def _url_keys(url: str, default_base: str = DEFAULT_BASE_URL) -> List[str]:
    raw = _compact_spaces(url)
    if not raw:
        return []

    canonical = _canonicalize_url(raw, default_base=default_base)
    decoded = unquote(canonical) if canonical else ""

    ordered: List[str] = []
    for item in (raw, canonical, decoded):
        if item and item not in ordered:
            ordered.append(item)
    return ordered


def _extract_path_and_query_from_url(url: str) -> Tuple[str, str]:
    canonical = _canonicalize_url(url)
    if not canonical:
        return "/", ""

    parsed = urlsplit(canonical)
    path = parsed.path or "/"
    query = parsed.query
    return path, query


def _normalize_labeled_entries(items: Iterable[Dict[str, Any]]) -> List[Dict[str, str]]:
    normalized: List[Dict[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            continue

        url = _compact_spaces(item.get("url", ""))
        true_label = _normalize_true_label(item.get("true_label"))

        if not url or true_label is None:
            continue

        normalized.append({"url": url, "true_label": true_label})
    return normalized


def _normalize_pipeline_entries(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []

    for item in items:
        if not isinstance(item, dict):
            continue

        raw_url = ""
        for key in ("url", "uri", "request_url", "target_url", "full_url"):
            candidate = _compact_spaces(item.get(key, ""))
            if candidate:
                raw_url = candidate
                break

        path = _compact_spaces(item.get("path", ""))
        query = _compact_spaces(item.get("query", ""))
        if not query:
            query = _compact_spaces(item.get("query_params", ""))
        query = query.lstrip("?")

        if raw_url and not path:
            parsed = urlsplit(_canonicalize_url(raw_url))
            path = parsed.path
            if not query:
                query = parsed.query

        if not raw_url and path:
            path_value = path
            if not path_value.startswith("/") and "://" not in path_value:
                path_value = "/" + path_value

            if "://" in path_value:
                raw_url = path_value
            else:
                raw_url = f"{DEFAULT_BASE_URL.rstrip('/')}{path_value}"
                if query:
                    raw_url = f"{raw_url}?{query}"

        canonical_url = _canonicalize_url(raw_url) if raw_url else ""
        if not path and canonical_url:
            parsed = urlsplit(canonical_url)
            path = parsed.path
            if not query:
                query = parsed.query

        if not path:
            continue

        normalized.append(
            {
                "timestamp": _compact_spaces(item.get("timestamp", "")),
                "url": canonical_url or raw_url,
                "decision": _normalize_decision(item.get("decision", "IGNORE")),
                "attack_type": _compact_spaces(item.get("attack_type", "unknown")) or "unknown",
                "confidence": float(_safe_float(item.get("confidence"), 0.0)),
                "anomaly_score": float(_safe_float(item.get("anomaly_score"), 0.0)),
                "reason": _compact_spaces(item.get("reason", "")),
                "url_keys": _url_keys(canonical_url or raw_url),
                "path_query_keys": _path_query_keys(path, query),
            }
        )

    return normalized


def _normalize_merged_entries(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []

    for item in items:
        if not isinstance(item, dict):
            continue

        url = _compact_spaces(item.get("url", ""))
        true_label = _normalize_true_label(item.get("true_label"))
        decision = _normalize_decision(item.get("decision", item.get("pipeline_decision", "IGNORE")))
        predicted_label = _normalize_true_label(item.get("predicted_label"))

        if not url or true_label is None:
            continue

        normalized.append(
            {
                "url": url,
                "true_label": true_label,
                "decision": decision,
                "predicted_label": predicted_label if predicted_label is not None else _decision_to_label(decision),
                "confidence": float(_safe_float(item.get("confidence"), 0.0)),
                "anomaly_score": float(_safe_float(item.get("anomaly_score"), 0.0)),
            }
        )

    return normalized


def _build_indexes(
    pipeline_entries: List[Dict[str, Any]],
    *,
    newest_first: bool = True,
) -> Tuple[Dict[str, Deque[int]], Dict[str, Deque[int]]]:
    url_index: Dict[str, Deque[int]] = defaultdict(deque)
    path_query_index: Dict[str, Deque[int]] = defaultdict(deque)

    indices = range(len(pipeline_entries) - 1, -1, -1) if newest_first else range(len(pipeline_entries))

    for idx in indices:
        entry = pipeline_entries[idx]
        for key in entry.get("url_keys", []):
            url_index[key].append(idx)
        for key in entry.get("path_query_keys", []):
            path_query_index[key].append(idx)

    return url_index, path_query_index


def _find_match(
    keys: Iterable[str],
    index_map: Dict[str, Deque[int]],
    used_ids: Set[int],
) -> Optional[int]:
    for key in keys:
        queue = index_map.get(key)
        if not queue:
            continue

        while queue and queue[0] in used_ids:
            queue.popleft()

        if queue:
            return queue.popleft()

    return None


def _match_pipeline_for_url(
    url: str,
    url_index: Dict[str, Deque[int]],
    path_query_index: Dict[str, Deque[int]],
    used_pipeline_ids: Set[int],
) -> Optional[int]:
    match_id = _find_match(_url_keys(url), url_index, used_pipeline_ids)
    if match_id is not None:
        return match_id

    path, query = _extract_path_and_query_from_url(url)
    return _find_match(_path_query_keys(path, query), path_query_index, used_pipeline_ids)


def _compute_evaluation_snapshot(merged_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    tp = fp = tn = fn = 0

    for item in merged_entries:
        true_label = _normalize_true_label(item.get("true_label"))
        predicted_label = _normalize_true_label(item.get("predicted_label"))
        if true_label is None or predicted_label is None:
            continue

        if true_label == "attack" and predicted_label == "attack":
            tp += 1
        elif true_label == "normal" and predicted_label == "attack":
            fp += 1
        elif true_label == "normal" and predicted_label == "normal":
            tn += 1
        else:
            fn += 1

    total = tp + fp + tn + fn
    precision = _safe_divide(tp, tp + fp)
    recall = _safe_divide(tp, tp + fn)
    f1_score = _safe_divide(2.0 * precision * recall, precision + recall)
    accuracy = _safe_divide(tp + tn, total)
    fp_rate = _safe_divide(fp, fp + tn)

    return {
        "total_samples": int(total),
        "TP": int(tp),
        "FP": int(fp),
        "TN": int(tn),
        "FN": int(fn),
        "precision": float(precision),
        "recall": float(recall),
        "f1_score": float(f1_score),
        "accuracy": float(accuracy),
        "false_positive_rate": float(fp_rate),
    }


def _build_false_positive_record(
    url: str,
    true_label: str,
    decision: str,
    confidence: float,
    anomaly_score: float,
    attack_type: str,
    reason: str,
    source: str,
    pipeline_timestamp: str,
) -> Dict[str, Any]:
    return {
        "url": url,
        "true_label": true_label,
        "predicted_label": _decision_to_label(decision),
        "decision": _normalize_decision(decision),
        "attack_type": attack_type or "unknown",
        "confidence": float(confidence),
        "anomaly_score": float(anomaly_score),
        "reason": reason,
        "source": source,
        "pipeline_timestamp": pipeline_timestamp,
    }


def identify_false_positives(
    labeled_entries: List[Dict[str, str]],
    pipeline_entries: List[Dict[str, Any]],
    merged_entries: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    false_positives: List[Dict[str, Any]] = []

    url_index, path_query_index = _build_indexes(pipeline_entries, newest_first=True)
    used_pipeline_ids: Set[int] = set()

    source_used = "labeled+pipeline"

    if merged_entries:
        source_used = "merged_evaluation"
        for item in merged_entries:
            true_label = _normalize_true_label(item.get("true_label"))
            decision = _normalize_decision(item.get("decision"))
            if true_label != "normal" or decision not in {"ALERT", "BLOCK"}:
                continue

            url = _compact_spaces(item.get("url", ""))
            if not url:
                continue

            match_id = _match_pipeline_for_url(url, url_index, path_query_index, used_pipeline_ids)
            pipeline_item = pipeline_entries[match_id] if match_id is not None else {}
            if match_id is not None:
                used_pipeline_ids.add(match_id)

            fp_record = _build_false_positive_record(
                url=url,
                true_label="normal",
                decision=decision,
                confidence=float(
                    _safe_float(
                        pipeline_item.get("confidence", item.get("confidence", 0.0)),
                        _safe_float(item.get("confidence", 0.0), 0.0),
                    )
                ),
                anomaly_score=float(
                    _safe_float(
                        pipeline_item.get("anomaly_score", item.get("anomaly_score", 0.0)),
                        _safe_float(item.get("anomaly_score", 0.0), 0.0),
                    )
                ),
                attack_type=_compact_spaces(
                    pipeline_item.get("attack_type", item.get("attack_type", "unknown"))
                )
                or "unknown",
                reason=_compact_spaces(pipeline_item.get("reason", item.get("reason", ""))),
                source="merged_evaluation",
                pipeline_timestamp=_compact_spaces(pipeline_item.get("timestamp", "")),
            )
            false_positives.append(fp_record)
    else:
        for item in labeled_entries:
            true_label = _normalize_true_label(item.get("true_label"))
            if true_label != "normal":
                continue

            url = _compact_spaces(item.get("url", ""))
            if not url:
                continue

            match_id = _match_pipeline_for_url(url, url_index, path_query_index, used_pipeline_ids)
            if match_id is None:
                continue

            used_pipeline_ids.add(match_id)
            pipeline_item = pipeline_entries[match_id]
            decision = _normalize_decision(pipeline_item.get("decision", "IGNORE"))
            if decision not in {"ALERT", "BLOCK"}:
                continue

            false_positives.append(
                _build_false_positive_record(
                    url=url,
                    true_label="normal",
                    decision=decision,
                    confidence=float(_safe_float(pipeline_item.get("confidence"), 0.0)),
                    anomaly_score=float(_safe_float(pipeline_item.get("anomaly_score"), 0.0)),
                    attack_type=_compact_spaces(pipeline_item.get("attack_type", "unknown")) or "unknown",
                    reason=_compact_spaces(pipeline_item.get("reason", "")),
                    source="labeled+pipeline",
                    pipeline_timestamp=_compact_spaces(pipeline_item.get("timestamp", "")),
                )
            )

    stats = {
        "source_used": source_used,
        "pipeline_entries": len(pipeline_entries),
        "pipeline_entries_matched": len(used_pipeline_ids),
        "pipeline_entries_unmatched": max(len(pipeline_entries) - len(used_pipeline_ids), 0),
    }

    return false_positives, stats


def _trigger_group_for_url(url: str) -> str:
    decoded = unquote(_safe_text(url)).lower()

    # Keep order explicit; UNION+SELECT payloads are grouped as UNION.
    if "union" in decoded:
        return "contains union"
    if "select" in decoded:
        return "contains select"
    if "script" in decoded:
        return "contains script"
    if "drop" in decoded:
        return "contains drop"
    return "other"


def analyze_trigger_patterns(false_positives: List[Dict[str, Any]]) -> Tuple[Dict[str, int], Dict[str, int], Dict[str, int]]:
    trigger_group_counts: Counter[str] = Counter()
    keyword_counts: Counter[str] = Counter()
    token_counts: Counter[str] = Counter()

    for item in false_positives:
        url = _safe_text(item.get("url", ""))
        decoded = unquote(url).lower()

        group = _trigger_group_for_url(url)
        trigger_group_counts[group] += 1

        for keyword in TRIGGER_KEYWORDS:
            if keyword in decoded:
                keyword_counts[keyword] += 1

        for token in re.findall(r"[a-zA-Z]{3,}", decoded):
            if token in {"http", "https", "php", "com", "www", "index", "view"}:
                continue
            token_counts[token] += 1

    return dict(trigger_group_counts), dict(keyword_counts), dict(token_counts)


def generate_recommendations(
    false_positives: List[Dict[str, Any]],
    keyword_counts: Dict[str, int],
    avg_confidence: float,
    avg_anomaly_score: float,
) -> List[str]:
    recommendations: List[str] = []

    select_count = int(keyword_counts.get("select", 0))
    union_count = int(keyword_counts.get("union", 0))
    drop_count = int(keyword_counts.get("drop", 0))
    script_count = int(keyword_counts.get("script", 0))

    if (select_count + union_count + drop_count) > 0:
        recommendations.append("Keyword-only detection causing SQLi false positives")

    if script_count > 0:
        recommendations.append("XSS keyword matching too aggressive")

    decoded_urls = [unquote(_safe_text(item.get("url", ""))).lower() for item in false_positives]
    if any(term in url for url in decoded_urls for term in EDUCATIONAL_TERMS):
        recommendations.append("Need stronger distinction between educational terms and attack payloads")

    if false_positives and avg_anomaly_score >= 0.70 and avg_confidence <= 0.45:
        recommendations.append(
            "Decision threshold appears anomaly-heavy; consider calibrating confidence gating for benign traffic"
        )

    if not recommendations:
        recommendations.append("No dominant keyword pattern detected; review feature weighting for benign request context")

    # Preserve order and remove duplicates.
    unique_recommendations: List[str] = []
    seen: Set[str] = set()
    for item in recommendations:
        if item not in seen:
            unique_recommendations.append(item)
            seen.add(item)

    return unique_recommendations


def _top_items(counts: Dict[str, int], limit: int = 10) -> List[Dict[str, Any]]:
    return [
        {"item": key, "count": value}
        for key, value in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
    ]


def print_false_positive_details(false_positives: List[Dict[str, Any]]) -> None:
    print("\n=== FALSE POSITIVE DETAILS ===")
    if not false_positives:
        print("No false positives detected with current inputs.")
        return

    for idx, item in enumerate(false_positives, start=1):
        print(f"\n[{idx}] URL: {_safe_text(item.get('url', ''))}")
        print(f"    decision: {_safe_text(item.get('decision', ''))}")
        print(f"    attack_type: {_safe_text(item.get('attack_type', 'unknown'))}")
        print(f"    confidence: {float(_safe_float(item.get('confidence', 0.0), 0.0)):.3f}")
        print(f"    anomaly_score: {float(_safe_float(item.get('anomaly_score', 0.0), 0.0)):.3f}")
        print(f"    reason: {_safe_text(item.get('reason', ''))}")


def print_summary(
    false_positives: List[Dict[str, Any]],
    trigger_group_counts: Dict[str, int],
    keyword_counts: Dict[str, int],
    avg_confidence: float,
    avg_anomaly_score: float,
    recommendations: List[str],
) -> None:
    print("\n=== FALSE POSITIVE SUMMARY ===")
    print(f"Total false positives: {len(false_positives)}")

    print("\nGrouped by trigger type:")
    for group_name in ("contains select", "contains script", "contains union", "contains drop", "other"):
        print(f"- {group_name}: {int(trigger_group_counts.get(group_name, 0))}")

    common_keywords = _top_items(keyword_counts, limit=10)
    if common_keywords:
        keywords_text = ", ".join(f"{entry['item']} ({entry['count']})" for entry in common_keywords)
    else:
        keywords_text = "none"

    print(f"\nMost common trigger words: {keywords_text}")
    print(f"Average confidence (FP): {avg_confidence:.3f}")
    print(f"Average anomaly score (FP): {avg_anomaly_score:.3f}")

    print("\nRecommendations:")
    for recommendation in recommendations:
        print(f"- {recommendation}")


def save_json(path: Path, payload: Any) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as error:
        print(f"[WARN] Failed to write report to {path}: {error}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze false positives from evaluation artifacts.")
    parser.add_argument("--labeled", default=str(DEFAULT_LABELED_PATH), help="Path to labeled_requests.json")
    parser.add_argument("--pipeline", default=str(DEFAULT_PIPELINE_PATH), help="Path to pipeline_results.json")
    parser.add_argument("--merged", default=str(DEFAULT_MERGED_PATH), help="Path to merged_evaluation.json")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_PATH), help="Path to output false-positive report JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    labeled_path = Path(args.labeled)
    pipeline_path = Path(args.pipeline)
    merged_path = Path(args.merged)
    output_path = Path(args.output)

    labeled_raw = _load_json_entries(labeled_path)
    pipeline_raw = _load_json_entries(pipeline_path)
    merged_raw = _load_json_entries(merged_path, optional=True)

    labeled_entries = _normalize_labeled_entries(labeled_raw)
    pipeline_entries = _normalize_pipeline_entries(pipeline_raw)
    merged_entries = _normalize_merged_entries(merged_raw)

    evaluation_snapshot = _compute_evaluation_snapshot(merged_entries) if merged_entries else {}

    false_positives, matching_stats = identify_false_positives(
        labeled_entries=labeled_entries,
        pipeline_entries=pipeline_entries,
        merged_entries=merged_entries,
    )

    trigger_group_counts, keyword_counts, token_counts = analyze_trigger_patterns(false_positives)

    avg_confidence = _safe_divide(
        sum(_safe_float(item.get("confidence", 0.0), 0.0) for item in false_positives),
        len(false_positives),
    )
    avg_anomaly_score = _safe_divide(
        sum(_safe_float(item.get("anomaly_score", 0.0), 0.0) for item in false_positives),
        len(false_positives),
    )

    recommendations = generate_recommendations(
        false_positives=false_positives,
        keyword_counts=keyword_counts,
        avg_confidence=avg_confidence,
        avg_anomaly_score=avg_anomaly_score,
    )

    print("=== CURRENT EVALUATION SNAPSHOT ===")
    if evaluation_snapshot:
        print(f"Total samples: {int(evaluation_snapshot.get('total_samples', 0))}")
        print(
            "Confusion matrix: "
            f"TP={int(evaluation_snapshot.get('TP', 0))}, "
            f"FP={int(evaluation_snapshot.get('FP', 0))}, "
            f"TN={int(evaluation_snapshot.get('TN', 0))}, "
            f"FN={int(evaluation_snapshot.get('FN', 0))}"
        )
        print(
            "Metrics: "
            f"precision={float(evaluation_snapshot.get('precision', 0.0)):.3f}, "
            f"recall={float(evaluation_snapshot.get('recall', 0.0)):.3f}, "
            f"f1={float(evaluation_snapshot.get('f1_score', 0.0)):.3f}, "
            f"accuracy={float(evaluation_snapshot.get('accuracy', 0.0)):.3f}, "
            f"fp_rate={float(evaluation_snapshot.get('false_positive_rate', 0.0)):.3f}"
        )
    else:
        print("merged_evaluation.json unavailable or invalid; evaluation snapshot skipped.")

    print_false_positive_details(false_positives)
    print_summary(
        false_positives=false_positives,
        trigger_group_counts=trigger_group_counts,
        keyword_counts=keyword_counts,
        avg_confidence=avg_confidence,
        avg_anomaly_score=avg_anomaly_score,
        recommendations=recommendations,
    )

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_files": {
            "labeled": str(labeled_path),
            "pipeline": str(pipeline_path),
            "merged": str(merged_path),
        },
        "input_counts": {
            "labeled_entries": len(labeled_entries),
            "pipeline_entries": len(pipeline_entries),
            "merged_entries": len(merged_entries),
        },
        "matching_stats": matching_stats,
        "evaluation_snapshot": evaluation_snapshot,
        "false_positive_summary": {
            "total_false_positives": len(false_positives),
            "average_confidence": float(avg_confidence),
            "average_anomaly_score": float(avg_anomaly_score),
        },
        "trigger_groups": trigger_group_counts,
        "trigger_word_counts": keyword_counts,
        "common_url_tokens": _top_items(token_counts, limit=20),
        "recommendations": recommendations,
        "false_positives": false_positives,
    }

    save_json(output_path, report)
    print(f"\nFull false-positive report saved to: {output_path.resolve()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
