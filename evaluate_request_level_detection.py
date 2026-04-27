#!/usr/bin/env python3
"""
Evaluate ML pipeline detection accuracy using per-request ground truth labels.

Inputs:
    request_ground_truth.json   — per-request labels from build_request_ground_truth.py
    har_replay_results_v2.json  — replay results with replay_id + timestamps
    proxy/logs/pipeline_results.json — pipeline decisions

Outputs:
    request_level_evaluation.json       — full matched evaluation records
    request_level_metrics.json          — precision / recall / F1 / accuracy
    request_level_false_positives.json  — FP detail
    request_level_false_negatives.json  — FN detail
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, unquote_plus, urlsplit


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_GROUND_TRUTH_PATH = Path("request_ground_truth.json")
DEFAULT_REPLAY_PATH = Path("har_replay_results_v2.json")
DEFAULT_PIPELINE_PATH = Path("proxy/logs/pipeline_results.json")

DEFAULT_EVAL_OUTPUT = Path("request_level_evaluation.json")
DEFAULT_METRICS_OUTPUT = Path("request_level_metrics.json")
DEFAULT_FP_OUTPUT = Path("request_level_false_positives.json")
DEFAULT_FN_OUTPUT = Path("request_level_false_negatives.json")


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


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value) if value is not None else default
    except (ValueError, TypeError):
        return default


def _load_json_list(path: Path, label: str) -> List[Dict[str, Any]]:
    if not path.exists() or not path.is_file():
        log("WARN", f"Missing {label} file: {path}")
        return []
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
        if not raw.strip():
            return []
        payload = json.loads(raw)
    except (json.JSONDecodeError, OSError) as err:
        log("WARN", f"Failed to load {label}: {err}")
        return []
    except Exception as err:
        log("WARN", f"Unexpected load error for {label}: {err}")
        return []

    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in ("results", "data", "entries", "items"):
            nested = payload.get(key)
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]
    return []


def _save_json(data: Any, path: Path) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _parse_timestamp(value: Any) -> Optional[datetime]:
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


# ---------------------------------------------------------------------------
# Matching replay → pipeline
# ---------------------------------------------------------------------------

def _extract_path_query(url: str) -> Tuple[str, str]:
    try:
        parsed = urlsplit(url)
        return (parsed.path or "/", parsed.query or "")
    except Exception:
        return ("/", "")


def _canonical_query(query: str) -> str:
    text = _safe_str(query).strip().lstrip("?")
    if not text:
        return ""
    try:
        pairs = parse_qsl(text, keep_blank_values=True)
        normalized = sorted((unquote_plus(k), unquote_plus(v)) for k, v in pairs)
        return "&".join(f"{k}={v}" for k, v in normalized)
    except Exception:
        return text


def build_replay_index(replay_entries: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Index replay entries by replay_id for fast lookup."""
    index: Dict[str, Dict[str, Any]] = {}
    for entry in replay_entries:
        rid = _safe_str(entry.get("replay_id", ""))
        if rid:
            url = _safe_str(entry.get("rewritten_url", entry.get("url", "")))
            path, query = _extract_path_query(url)
            index[rid] = {
                "replay_id": rid,
                "method": _safe_str(entry.get("method", "GET")).upper(),
                "path": path,
                "query": query,
                "canonical_query": _canonical_query(query),
                "timestamp": _parse_timestamp(entry.get("timestamp")),
                "timestamp_raw": _safe_str(entry.get("timestamp", "")),
                "status_code": entry.get("status_code"),
                "source_file": _safe_str(entry.get("source_file", "")),
            }
    return index


def normalize_pipeline_entries(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize pipeline entries for matching."""
    normalized: List[Dict[str, Any]] = []
    for idx, row in enumerate(entries):
        if not isinstance(row, dict):
            continue
        path = _safe_str(row.get("path", "")).strip() or "/"
        query = _safe_str(row.get("query", "")).strip()
        normalized.append({
            "id": idx,
            "path": path,
            "query": query,
            "canonical_query": _canonical_query(query),
            "timestamp": _parse_timestamp(row.get("timestamp")),
            "decision": _safe_str(row.get("decision", "IGNORE")).upper(),
            "attack_type": _safe_str(row.get("attack_type", "unknown")),
            "confidence": _safe_float(row.get("confidence")),
            "anomaly_score": _safe_float(row.get("anomaly_score")),
            "reason": _safe_str(row.get("reason", "")),
        })
    return normalized


def find_pipeline_match(
    replay_info: Dict[str, Any],
    pipeline_entries: List[Dict[str, Any]],
    used_ids: set,
) -> Optional[Dict[str, Any]]:
    """Find best pipeline entry matching a replay entry."""
    r_path = replay_info.get("path", "")
    r_query = replay_info.get("query", "")
    r_cquery = replay_info.get("canonical_query", "")
    r_ts = replay_info.get("timestamp")

    # Exact path + query candidates
    exact = [
        p for p in pipeline_entries
        if p["id"] not in used_ids
        and p["path"] == r_path
        and (p["query"] == r_query or p["canonical_query"] == r_cquery)
    ]

    # Path-only fallback
    path_only = [
        p for p in pipeline_entries
        if p["id"] not in used_ids and p["path"] == r_path
    ]

    candidates = exact if exact else path_only
    if not candidates:
        return None

    def score(p: Dict[str, Any]) -> Tuple[float, int, int]:
        if r_ts and p.get("timestamp"):
            delta = abs((r_ts - p["timestamp"]).total_seconds())
        else:
            delta = 10_000_000.0
        q_mismatch = 0 if (p["query"] == r_query or p["canonical_query"] == r_cquery) else 1
        return (delta, q_mismatch, p["id"])

    return min(candidates, key=score)


# ---------------------------------------------------------------------------
# Classification logic
# ---------------------------------------------------------------------------

def _pipeline_detected_attack(decision: str) -> bool:
    """BLOCK and ALERT count as detected_attack."""
    return decision in ("BLOCK", "ALERT")


# ---------------------------------------------------------------------------
# Metrics computation
# ---------------------------------------------------------------------------

def compute_metrics(
    eval_records: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute TP/FP/TN/FN and derived metrics."""
    tp = fp = tn = fn = 0

    for rec in eval_records:
        gt = rec.get("ground_truth_label", "normal")
        detected = rec.get("pipeline_detected_attack", False)

        if gt == "attack" and detected:
            tp += 1
        elif gt == "normal" and detected:
            fp += 1
        elif gt == "normal" and not detected:
            tn += 1
        elif gt == "attack" and not detected:
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / (tp + fp + tn + fn) if (tp + fp + tn + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

    return {
        "total_evaluated": len(eval_records),
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "false_positive_rate": round(fpr, 4),
    }


def compute_per_category_metrics(
    eval_records: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """Compute detection rate per attack category."""
    categories: Dict[str, Dict[str, int]] = {}

    for rec in eval_records:
        gt = rec.get("ground_truth_label", "normal")
        if gt != "attack":
            continue
        cat = rec.get("attack_category", "unknown")
        if cat not in categories:
            categories[cat] = {"total": 0, "detected": 0}
        categories[cat]["total"] += 1
        if rec.get("pipeline_detected_attack", False):
            categories[cat]["detected"] += 1

    result: Dict[str, Dict[str, Any]] = {}
    for cat, counts in sorted(categories.items()):
        total = counts["total"]
        detected = counts["detected"]
        rate = detected / total if total > 0 else 0.0
        result[cat] = {
            "total_attacks": total,
            "detected": detected,
            "missed": total - detected,
            "detection_rate": round(rate, 4),
        }
    return result


# ---------------------------------------------------------------------------
# False positive / negative extraction
# ---------------------------------------------------------------------------

def extract_false_positives(eval_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    fps: List[Dict[str, Any]] = []
    for rec in eval_records:
        if rec.get("ground_truth_label") == "normal" and rec.get("pipeline_detected_attack"):
            fps.append({
                "replay_id": rec.get("replay_id", ""),
                "source_file": rec.get("source_file", ""),
                "method": rec.get("method", ""),
                "path": rec.get("path", ""),
                "query": rec.get("query", ""),
                "body_preview": rec.get("body_preview", ""),
                "pipeline_decision": rec.get("pipeline_decision", ""),
                "predicted_attack_type": rec.get("pipeline_attack_type", ""),
                "confidence": rec.get("pipeline_confidence", 0.0),
                "anomaly_score": rec.get("pipeline_anomaly_score", 0.0),
                "reason": rec.get("pipeline_reason", ""),
            })
    return fps


def extract_false_negatives(eval_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    fns: List[Dict[str, Any]] = []
    for rec in eval_records:
        if rec.get("ground_truth_label") == "attack" and not rec.get("pipeline_detected_attack"):
            fns.append({
                "replay_id": rec.get("replay_id", ""),
                "source_file": rec.get("source_file", ""),
                "method": rec.get("method", ""),
                "path": rec.get("path", ""),
                "query": rec.get("query", ""),
                "body_preview": rec.get("body_preview", ""),
                "attack_category": rec.get("attack_category", ""),
                "detected_indicators": rec.get("detected_indicators", []),
                "pipeline_decision": rec.get("pipeline_decision", "UNMATCHED"),
                "pipeline_attack_type": rec.get("pipeline_attack_type", ""),
                "anomaly_score": rec.get("pipeline_anomaly_score", 0.0),
                "confidence": rec.get("pipeline_confidence", 0.0),
                "reason": rec.get("pipeline_reason", ""),
            })
    return fns


# ---------------------------------------------------------------------------
# Summary printing
# ---------------------------------------------------------------------------

def print_metrics(metrics: Dict[str, Any], category_metrics: Dict[str, Dict[str, Any]]) -> None:
    print()
    log("METRICS", "=" * 60)
    log("METRICS", f"Total evaluated:      {metrics['total_evaluated']}")
    log("METRICS", "-" * 60)
    log("METRICS", f"  TP (true positive):  {metrics['TP']}")
    log("METRICS", f"  FP (false positive): {metrics['FP']}")
    log("METRICS", f"  TN (true negative):  {metrics['TN']}")
    log("METRICS", f"  FN (false negative): {metrics['FN']}")
    log("METRICS", "-" * 60)
    log("METRICS", f"  Precision:           {metrics['precision']:.4f}")
    log("METRICS", f"  Recall:              {metrics['recall']:.4f}")
    log("METRICS", f"  F1 Score:            {metrics['f1_score']:.4f}")
    log("METRICS", f"  Accuracy:            {metrics['accuracy']:.4f}")
    log("METRICS", f"  False Positive Rate: {metrics['false_positive_rate']:.4f}")
    log("METRICS", "-" * 60)

    if category_metrics:
        log("METRICS", "Per-category detection rates:")
        for cat, info in category_metrics.items():
            log("METRICS",
                f"  {cat:25s} {info['detected']}/{info['total_attacks']} "
                f"= {info['detection_rate']:.1%}  "
                f"(missed: {info['missed']})")

    log("METRICS", "=" * 60)
    print()


def print_false_positives(fps: List[Dict[str, Any]], limit: int = 10) -> None:
    if not fps:
        log("FP", "No false positives detected.")
        return
    log("FP", f"False positives: {len(fps)}")
    for i, fp in enumerate(fps[:limit], 1):
        log("FP", f"  #{i} {fp['method']} {fp['path']}")
        if fp.get("query"):
            log("FP", f"     query: {fp['query'][:120]}")
        if fp.get("body_preview"):
            log("FP", f"     body:  {fp['body_preview'][:120]}")
        log("FP",
            f"     pred={fp['predicted_attack_type']} "
            f"conf={fp['confidence']:.3f} "
            f"anom={fp['anomaly_score']:.3f}")
        log("FP", f"     reason: {fp['reason'][:150]}")
    if len(fps) > limit:
        log("FP", f"  ... +{len(fps) - limit} more in JSON output")


def print_false_negatives(fns: List[Dict[str, Any]], limit: int = 10) -> None:
    if not fns:
        log("FN", "No false negatives detected.")
        return
    log("FN", f"False negatives: {len(fns)}")
    for i, fn in enumerate(fns[:limit], 1):
        log("FN", f"  #{i} {fn['method']} {fn['path']}")
        log("FN", f"     category: {fn['attack_category']}")
        indicators = fn.get("detected_indicators", [])
        log("FN", f"     indicators: {', '.join(indicators[:4])}")
        if fn.get("body_preview"):
            log("FN", f"     body: {fn['body_preview'][:120]}")
        log("FN",
            f"     pipeline: decision={fn.get('pipeline_decision','?')} "
            f"anom={fn.get('anomaly_score',0):.3f} "
            f"conf={fn.get('confidence',0):.3f}")
    if len(fns) > limit:
        log("FN", f"  ... +{len(fns) - limit} more in JSON output")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate ML pipeline using per-request ground truth labels."
    )
    parser.add_argument("--ground-truth", default=str(DEFAULT_GROUND_TRUTH_PATH))
    parser.add_argument("--replay", default=str(DEFAULT_REPLAY_PATH))
    parser.add_argument("--pipeline", default=str(DEFAULT_PIPELINE_PATH))
    parser.add_argument("--eval-output", default=str(DEFAULT_EVAL_OUTPUT))
    parser.add_argument("--metrics-output", default=str(DEFAULT_METRICS_OUTPUT))
    parser.add_argument("--fp-output", default=str(DEFAULT_FP_OUTPUT))
    parser.add_argument("--fn-output", default=str(DEFAULT_FN_OUTPUT))
    args = parser.parse_args()

    gt_path = Path(args.ground_truth)
    replay_path = Path(args.replay)
    pipeline_path = Path(args.pipeline)

    log("INFO", f"Ground truth: {gt_path}")
    log("INFO", f"Replay:       {replay_path}")
    log("INFO", f"Pipeline:     {pipeline_path}")

    # Load inputs
    gt_entries = _load_json_list(gt_path, "ground_truth")
    replay_entries = _load_json_list(replay_path, "replay")
    pipeline_raw = _load_json_list(pipeline_path, "pipeline")

    if not gt_entries:
        log("WARN", "No ground truth entries. Cannot evaluate.")
        return 1

    log("INFO", f"Ground truth entries: {len(gt_entries)}")
    log("INFO", f"Replay entries:       {len(replay_entries)}")
    log("INFO", f"Pipeline entries:     {len(pipeline_raw)}")

    # Build indexes
    replay_index = build_replay_index(replay_entries)
    pipeline_entries = normalize_pipeline_entries(pipeline_raw)

    # Match each ground truth entry to pipeline
    used_pipeline_ids: set = set()
    eval_records: List[Dict[str, Any]] = []
    unmatched_count = 0

    for gt in gt_entries:
        replay_id = _safe_str(gt.get("replay_id", ""))
        replay_info = replay_index.get(replay_id)

        if not replay_info:
            # Try to build replay info from ground truth fields
            replay_info = {
                "replay_id": replay_id,
                "method": _safe_str(gt.get("method", "GET")),
                "path": _safe_str(gt.get("path", "/")),
                "query": _safe_str(gt.get("query", "")),
                "canonical_query": _canonical_query(_safe_str(gt.get("query", ""))),
                "timestamp": None,
            }

        pipeline_match = find_pipeline_match(replay_info, pipeline_entries, used_pipeline_ids)
        if pipeline_match:
            used_pipeline_ids.add(pipeline_match["id"])

        gt_label = _safe_str(gt.get("true_label", "normal"))
        pipeline_decision = _safe_str(pipeline_match.get("decision", "IGNORE")) if pipeline_match else "UNMATCHED"
        detected = _pipeline_detected_attack(pipeline_decision) if pipeline_match else False

        record = {
            "replay_id": replay_id,
            "source_file": _safe_str(gt.get("source_file", "")),
            "method": _safe_str(gt.get("method", "")),
            "path": _safe_str(gt.get("path", "")),
            "query": _safe_str(gt.get("query", "")),
            "body_preview": _safe_str(gt.get("body_preview", "")),
            "ground_truth_label": gt_label,
            "attack_category": _safe_str(gt.get("attack_category", "none")),
            "detected_indicators": gt.get("detected_indicators", []),
            "file_level_label": _safe_str(gt.get("file_level_label", "")),
            "pipeline_detected_attack": detected,
            "pipeline_decision": pipeline_decision,
            "pipeline_attack_type": _safe_str(pipeline_match.get("attack_type", "")) if pipeline_match else "",
            "pipeline_confidence": _safe_float(pipeline_match.get("confidence")) if pipeline_match else 0.0,
            "pipeline_anomaly_score": _safe_float(pipeline_match.get("anomaly_score")) if pipeline_match else 0.0,
            "pipeline_reason": _safe_str(pipeline_match.get("reason", "")) if pipeline_match else "",
            "matched": pipeline_match is not None,
        }
        eval_records.append(record)

        if not pipeline_match:
            unmatched_count += 1

    log("INFO", f"Evaluated: {len(eval_records)}, Unmatched: {unmatched_count}")

    # Compute metrics
    metrics = compute_metrics(eval_records)
    category_metrics = compute_per_category_metrics(eval_records)
    fps = extract_false_positives(eval_records)
    fns = extract_false_negatives(eval_records)

    # Combine all metrics
    full_metrics = {
        "overall": metrics,
        "per_category": category_metrics,
        "false_positive_count": len(fps),
        "false_negative_count": len(fns),
        "unmatched_count": unmatched_count,
    }

    # Save outputs
    _save_json(eval_records, Path(args.eval_output))
    _save_json(full_metrics, Path(args.metrics_output))
    _save_json(fps, Path(args.fp_output))
    _save_json(fns, Path(args.fn_output))

    # Print summary
    print_metrics(metrics, category_metrics)
    print_false_positives(fps)
    print_false_negatives(fns)

    log("INFO", f"Saved evaluation:       {Path(args.eval_output).resolve()}")
    log("INFO", f"Saved metrics:          {Path(args.metrics_output).resolve()}")
    log("INFO", f"Saved false positives:  {Path(args.fp_output).resolve()}")
    log("INFO", f"Saved false negatives:  {Path(args.fn_output).resolve()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
