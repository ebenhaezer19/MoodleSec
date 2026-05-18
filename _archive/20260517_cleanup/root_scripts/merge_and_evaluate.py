#!/usr/bin/env python3
"""
Merge labeled requests with pipeline decisions and compute evaluation metrics.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Deque, Dict, Iterable, List, Optional, Set
from urllib.parse import quote, unquote, urlsplit, urlunsplit


DEFAULT_LABELED_PATH = Path("labeled_requests.json")
DEFAULT_PIPELINE_PATH = Path("proxy/logs/pipeline_results.json")
DEFAULT_OUTPUT_PATH = Path("merged_evaluation.json")
DEFAULT_BASE_URL = "http://127.0.0.1:8000"


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


def _load_json_entries(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        print(f"[WARN] File not found: {path}")
        return []

    try:
        raw_text = path.read_text(encoding="utf-8", errors="replace").strip()
    except Exception as error:
        print(f"[WARN] Failed reading file {path}: {error}")
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

    print(f"[WARN] Unexpected JSON structure in {path}; expected list or known list-wrapper keys")
    return []


def _normalize_true_label(raw_label: Any) -> Optional[str]:
    label = _safe_text(raw_label).strip().lower()
    if label in {"attack", "anomaly", "malicious", "1", "true", "yes"}:
        return "attack"
    if label in {"normal", "benign", "legitimate", "0", "false", "no"}:
        return "normal"
    return None


def _decision_to_predicted_label(decision: Any) -> str:
    normalized = _safe_text(decision).strip().upper()
    if normalized in {"BLOCK", "ALERT"}:
        return "attack"
    return "normal"


def _normalize_decision(raw_decision: Any) -> str:
    decision = _safe_text(raw_decision).strip().upper()
    if decision in {"BLOCK", "ALERT", "IGNORE"}:
        return decision
    return "IGNORE"


def _compact_spaces(text: str) -> str:
    return " ".join(_safe_text(text).strip().split())


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

    ordered = []
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

    ordered = []
    for item in (raw, canonical, decoded):
        if item and item not in ordered:
            ordered.append(item)
    return ordered


def _extract_path_and_query_from_url(url: str) -> tuple[str, str]:
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

        normalized.append(
            {
                "url": url,
                "true_label": true_label,
            }
        )

    return normalized


def _normalize_pipeline_entry(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(item, dict):
        return None

    decision = _normalize_decision(item.get("decision", "IGNORE"))
    confidence = _safe_float(item.get("confidence"), 0.0)
    anomaly_score = _safe_float(item.get("anomaly_score"), 0.0)

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
        return None

    return {
        "url": canonical_url or raw_url,
        "decision": decision,
        "confidence": float(confidence),
        "anomaly_score": float(anomaly_score),
        "url_keys": _url_keys(canonical_url or raw_url),
        "path_query_keys": _path_query_keys(path, query),
    }


def _normalize_pipeline_entries(items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized: List[Dict[str, Any]] = []

    for item in items:
        normalized_item = _normalize_pipeline_entry(item)
        if normalized_item is not None:
            normalized.append(normalized_item)

    return normalized


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


def _build_indexes(pipeline_entries: List[Dict[str, Any]]) -> tuple[Dict[str, Deque[int]], Dict[str, Deque[int]]]:
    url_index: Dict[str, Deque[int]] = defaultdict(deque)
    path_query_index: Dict[str, Deque[int]] = defaultdict(deque)

    for idx, entry in enumerate(pipeline_entries):
        for key in entry.get("url_keys", []):
            url_index[key].append(idx)

        for key in entry.get("path_query_keys", []):
            path_query_index[key].append(idx)

    return url_index, path_query_index


def merge_datasets(
    labeled_entries: List[Dict[str, str]],
    pipeline_entries: List[Dict[str, Any]],
) -> tuple[List[Dict[str, Any]], Dict[str, int]]:
    merged: List[Dict[str, Any]] = []
    used_pipeline_ids: Set[int] = set()

    url_index, path_query_index = _build_indexes(pipeline_entries)

    unmatched_labeled = 0

    for labeled_item in labeled_entries:
        labeled_url = labeled_item["url"]
        true_label = labeled_item["true_label"]

        match_id = _find_match(_url_keys(labeled_url), url_index, used_pipeline_ids)

        if match_id is None:
            path, query = _extract_path_and_query_from_url(labeled_url)
            match_id = _find_match(_path_query_keys(path, query), path_query_index, used_pipeline_ids)

        if match_id is None:
            unmatched_labeled += 1
            continue

        used_pipeline_ids.add(match_id)
        pipeline_item = pipeline_entries[match_id]
        decision = pipeline_item.get("decision", "IGNORE")
        predicted_label = _decision_to_predicted_label(decision)

        merged.append(
            {
                "url": labeled_url,
                "true_label": true_label,
                "predicted_label": predicted_label,
                "decision": decision,
                "confidence": float(pipeline_item.get("confidence", 0.0)),
                "anomaly_score": float(pipeline_item.get("anomaly_score", 0.0)),
            }
        )

    unmatched_pipeline = len(pipeline_entries) - len(used_pipeline_ids)

    stats = {
        "matched": len(merged),
        "unmatched_labeled": unmatched_labeled,
        "unmatched_pipeline": max(unmatched_pipeline, 0),
    }

    return merged, stats


def compute_metrics(merged_items: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    tp = fp = tn = fn = 0
    total = 0

    for item in merged_items:
        true_label = _normalize_true_label(item.get("true_label"))
        predicted_label = _normalize_true_label(item.get("predicted_label"))

        if true_label is None or predicted_label is None:
            continue

        total += 1

        if true_label == "attack" and predicted_label == "attack":
            tp += 1
        elif true_label == "normal" and predicted_label == "attack":
            fp += 1
        elif true_label == "normal" and predicted_label == "normal":
            tn += 1
        else:
            fn += 1

    precision = _safe_divide(tp, tp + fp)
    recall = _safe_divide(tp, tp + fn)
    f1_score = _safe_divide(2.0 * precision * recall, precision + recall)
    accuracy = _safe_divide(tp + tn, total)
    false_positive_rate = _safe_divide(fp, fp + tn)

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
        "false_positive_rate": float(false_positive_rate),
    }


def save_json(path: Path, payload: Any) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as error:
        print(f"[WARN] Failed to write {path}: {error}")


def print_evaluation(metrics: Dict[str, Any]) -> None:
    print("=== EVALUATION RESULT ===")
    print(f"Total Samples: {int(metrics.get('total_samples', 0))}")
    print("")
    print("Confusion Matrix:")
    print(f"TP: {int(metrics.get('TP', 0))}")
    print(f"FP: {int(metrics.get('FP', 0))}")
    print(f"TN: {int(metrics.get('TN', 0))}")
    print(f"FN: {int(metrics.get('FN', 0))}")
    print("")
    print(f"Precision: {float(metrics.get('precision', 0.0)):.3f}")
    print(f"Recall: {float(metrics.get('recall', 0.0)):.3f}")
    print(f"F1 Score: {float(metrics.get('f1_score', 0.0)):.3f}")
    print(f"Accuracy: {float(metrics.get('accuracy', 0.0)):.3f}")
    print(f"FP Rate: {float(metrics.get('false_positive_rate', 0.0)):.3f}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Merge labeled requests with pipeline logs and evaluate metrics.")
    parser.add_argument("--labeled", default=str(DEFAULT_LABELED_PATH), help="Path to labeled_requests.json")
    parser.add_argument(
        "--pipeline",
        default=str(DEFAULT_PIPELINE_PATH),
        help="Path to proxy/logs/pipeline_results.json",
    )
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT_PATH), help="Path to merged output JSON")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    labeled_path = Path(args.labeled)
    pipeline_path = Path(args.pipeline)
    output_path = Path(args.output)

    labeled_raw = _load_json_entries(labeled_path)
    pipeline_raw = _load_json_entries(pipeline_path)

    labeled_entries = _normalize_labeled_entries(labeled_raw)
    pipeline_entries = _normalize_pipeline_entries(pipeline_raw)

    merged_items, merge_stats = merge_datasets(labeled_entries, pipeline_entries)
    metrics = compute_metrics(merged_items)

    save_json(output_path, merged_items)

    print_evaluation(metrics)
    print("")
    print(f"Matched: {merge_stats['matched']}")
    print(f"Unmatched labeled entries (skipped): {merge_stats['unmatched_labeled']}")
    print(f"Unmatched pipeline entries: {merge_stats['unmatched_pipeline']}")
    print(f"Merged dataset saved to: {output_path.resolve()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
