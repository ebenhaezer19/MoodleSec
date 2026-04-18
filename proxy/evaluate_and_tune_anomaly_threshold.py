#!/usr/bin/env python3
"""
Evaluate anomaly detector on real proxy logs and tune meta threshold.

This script does two things:
1. Step-1: Evaluate detector behavior on available real logs.
2. Step-2: Sweep meta threshold using labeled Moodle holdout and recommend
   an operating point with good F1 and low real-log alert rate.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ML_DIR = os.path.join(CURRENT_DIR, "ml")
if ML_DIR not in sys.path:
    sys.path.insert(0, ML_DIR)
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from anomaly_detector import AnomalyDetector
from retrain_anomaly_detector_moodle import load_moodle_samples, _sample_for_eval


def _compute_metrics(tp: int, fp: int, tn: int, fn: int) -> Dict[str, float]:
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0
    fp_rate = fp / (fp + tn) if (fp + tn) else 0.0
    fn_rate = fn / (fn + tp) if (fn + tp) else 0.0
    return {
        "accuracy": float(accuracy),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "fp_rate": float(fp_rate),
        "fn_rate": float(fn_rate),
    }


def _entry_to_payload(entry: Dict[str, Any], include_error_events: bool) -> Tuple[Dict[str, Any], str] | Tuple[None, None]:
    event_type = str(entry.get("type", "")).strip()

    if event_type == "proxy_transaction":
        status_code = int(entry.get("status_code", 200))
        response_size = int(entry.get("response_size", 0))
        response_time_ms = int(entry.get("response_time_ms", 120))
        request_count = int(entry.get("window_request_count", 1))
        unique_ips = int(entry.get("window_unique_ips", 1))
        error_rate = float(entry.get("window_error_rate", 1.0 if status_code >= 400 else 0.0))

        payload = {
            "request": {
                "url": str(entry.get("target_url", "http://localhost/")),
                "method": str(entry.get("method", "GET")),
                "headers": entry.get("headers", {}) if isinstance(entry.get("headers"), dict) else {},
                "body": "",
            },
            "response": {
                "status_code": status_code,
                "size": response_size,
                "time": response_time_ms,
                "headers": {},
            },
            "request_count_last_minute": request_count,
            "unique_ips_last_minute": max(unique_ips, 1),
            "error_rate_last_minute": error_rate,
        }
        return payload, "transaction"

    if include_error_events and event_type == "proxy_error":
        payload = {
            "request": {
                "url": str(entry.get("target_url", "http://localhost/")),
                "method": str(entry.get("method", "GET")),
                "headers": entry.get("headers", {}) if isinstance(entry.get("headers"), dict) else {},
                "body": "",
            },
            "response": {
                "status_code": 503,
                "size": 0,
                "time": 2000,
                "headers": {},
            },
            "request_count_last_minute": 1,
            "unique_ips_last_minute": 1,
            "error_rate_last_minute": 1.0,
        }
        return payload, "error"

    return None, None


def load_real_log_payloads(log_dir: str, include_error_events: bool = False) -> Dict[str, List[Dict[str, Any]]]:
    transactions: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    skipped = 0

    log_files = sorted(Path(log_dir).glob("*.jsonl"))
    for log_file in log_files:
        with log_file.open("r", encoding="utf-8", errors="replace") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    skipped += 1
                    continue

                payload, bucket = _entry_to_payload(entry, include_error_events)
                if payload is None:
                    continue

                if bucket == "transaction":
                    transactions.append(payload)
                elif bucket == "error":
                    errors.append(payload)

    return {
        "transactions": transactions,
        "errors": errors,
        "skipped_lines": skipped,
        "files": [str(p) for p in log_files],
    }


def prepare_moodle_holdout(
    dataset_path: str,
    train_ratio: float,
    meta_anomaly_ratio: float,
    max_eval: int,
    seed: int,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    normal_samples, anomalous_samples, skipped_rows, _ = load_moodle_samples(dataset_path, max_rows=0)

    rng = random.Random(seed)
    rng.shuffle(normal_samples)
    rng.shuffle(anomalous_samples)

    split_idx = int(len(normal_samples) * train_ratio)
    split_idx = min(max(split_idx, 20), len(normal_samples) - 1)

    train_normals = normal_samples[:split_idx]
    holdout_normals = normal_samples[split_idx:]

    meta_anomaly_count = int(len(anomalous_samples) * meta_anomaly_ratio)
    meta_anomaly_count = max(30, meta_anomaly_count)
    meta_anomaly_count = min(meta_anomaly_count, len(anomalous_samples))
    eval_anomaly_pool = anomalous_samples[meta_anomaly_count:] if meta_anomaly_count < len(anomalous_samples) else anomalous_samples

    eval_normals, eval_anomalous = _sample_for_eval(
        holdout_normals=holdout_normals,
        all_anomalous=eval_anomaly_pool,
        max_eval=max_eval,
        seed=seed,
    )

    meta = {
        "normal_total": len(normal_samples),
        "anomalous_total": len(anomalous_samples),
        "skipped_rows": skipped_rows,
        "train_normals": len(train_normals),
        "holdout_normals": len(holdout_normals),
        "eval_normals": len(eval_normals),
        "eval_anomalous": len(eval_anomalous),
        "meta_anomaly_count": int(meta_anomaly_count),
    }

    return eval_normals, eval_anomalous, meta


def evaluate_labeled(detector: AnomalyDetector, normals: List[Dict[str, Any]], anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
    tp = fp = tn = fn = 0

    for sample in normals:
        is_anomaly, _, _ = detector.detect(sample, use_meta=True)
        if is_anomaly:
            fp += 1
        else:
            tn += 1

    for sample in anomalies:
        is_anomaly, _, _ = detector.detect(sample, use_meta=True)
        if is_anomaly:
            tp += 1
        else:
            fn += 1

    metrics = _compute_metrics(tp=tp, fp=fp, tn=tn, fn=fn)
    return {
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "metrics": metrics,
    }


def evaluate_real(detector: AnomalyDetector, samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not samples:
        return {
            "samples": 0,
            "anomalies": 0,
            "anomaly_rate": 0.0,
            "mean_score": 0.0,
            "median_score": 0.0,
        }

    anomalies = 0
    scores: List[float] = []
    for sample in samples:
        is_anomaly, score, _ = detector.detect(sample, use_meta=True)
        if is_anomaly:
            anomalies += 1
        scores.append(float(score))

    return {
        "samples": len(samples),
        "anomalies": anomalies,
        "anomaly_rate": float(anomalies / len(samples)),
        "mean_score": float(np.mean(scores)),
        "median_score": float(np.median(scores)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate and tune anomaly threshold")
    parser.add_argument("--dataset", default="ml/training_data/moodle_attack_dataset.csv")
    parser.add_argument("--model-path", default="ml/models/anomaly_detector.pkl")
    parser.add_argument("--logs-dir", default="logs")
    parser.add_argument("--output", default="ml/training_data/anomaly_threshold_tuning_report.json")
    parser.add_argument("--train-ratio", type=float, default=0.8)
    parser.add_argument("--meta-anomaly-ratio", type=float, default=0.6)
    parser.add_argument("--max-eval", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--threshold-min", type=float, default=0.30)
    parser.add_argument("--threshold-max", type=float, default=0.90)
    parser.add_argument("--threshold-step", type=float, default=0.01)
    parser.add_argument("--include-error-events", action="store_true")
    args = parser.parse_args()

    if not os.path.exists(args.model_path):
        print(f"Model not found: {args.model_path}")
        return 1
    if not os.path.exists(args.dataset):
        print(f"Dataset not found: {args.dataset}")
        return 1
    if not os.path.exists(args.logs_dir):
        print(f"Logs dir not found: {args.logs_dir}")
        return 1

    detector = AnomalyDetector(model_path=args.model_path)
    if not detector.is_trained:
        print("Anomaly detector model is not trained")
        return 1
    if detector.meta_classifier is None:
        print("Meta classifier not found in model; threshold tuning for calibrated mode is unavailable")
        return 1

    eval_normals, eval_anomalous, split_meta = prepare_moodle_holdout(
        dataset_path=args.dataset,
        train_ratio=args.train_ratio,
        meta_anomaly_ratio=args.meta_anomaly_ratio,
        max_eval=args.max_eval,
        seed=args.seed,
    )

    real_payloads = load_real_log_payloads(log_dir=args.logs_dir, include_error_events=args.include_error_events)
    tx_samples = real_payloads["transactions"]
    err_samples = real_payloads["errors"]

    original_threshold = float(detector.meta_threshold)

    thresholds = np.arange(args.threshold_min, args.threshold_max + 1e-9, args.threshold_step)
    rows: List[Dict[str, Any]] = []
    for threshold in thresholds:
        detector.meta_threshold = float(round(float(threshold), 6))

        labeled = evaluate_labeled(detector, eval_normals, eval_anomalous)
        real_tx = evaluate_real(detector, tx_samples)
        real_err = evaluate_real(detector, err_samples)

        row = {
            "threshold": float(detector.meta_threshold),
            "labeled": labeled,
            "real_transactions": real_tx,
            "real_errors": real_err,
        }
        rows.append(row)

    # restore model threshold in memory
    detector.meta_threshold = original_threshold

    max_f1 = max((r["labeled"]["metrics"]["f1"] for r in rows), default=0.0)
    near_best = [r for r in rows if r["labeled"]["metrics"]["f1"] >= max_f1 - 0.01]

    if tx_samples:
        near_best.sort(
            key=lambda r: (
                r["real_transactions"]["anomaly_rate"],
                r["labeled"]["metrics"]["fp_rate"],
                -r["labeled"]["metrics"]["f1"],
            )
        )
    else:
        near_best.sort(
            key=lambda r: (
                r["labeled"]["metrics"]["fp_rate"],
                r["labeled"]["metrics"]["fn_rate"],
                -r["labeled"]["metrics"]["f1"],
            )
        )

    recommended = near_best[0] if near_best else rows[0]

    report = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "inputs": {
            "dataset": args.dataset,
            "model_path": args.model_path,
            "logs_dir": args.logs_dir,
            "original_meta_threshold": original_threshold,
            "threshold_min": args.threshold_min,
            "threshold_max": args.threshold_max,
            "threshold_step": args.threshold_step,
            "include_error_events": bool(args.include_error_events),
        },
        "data_overview": {
            "labeled_split": split_meta,
            "real_logs": {
                "files": real_payloads["files"],
                "transaction_samples": len(tx_samples),
                "error_samples": len(err_samples),
                "skipped_lines": real_payloads["skipped_lines"],
            },
        },
        "recommended": recommended,
        "top5_by_f1": sorted(rows, key=lambda r: r["labeled"]["metrics"]["f1"], reverse=True)[:5],
        "all_thresholds": rows,
        "notes": [
            "Real-log transaction sample count is used as sanity check, not ground-truth FP/FN label set.",
            "Recommended threshold favors near-best labeled F1, then lower real-log anomaly rate.",
        ],
    }

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)

    rec_t = recommended["threshold"]
    rec_m = recommended["labeled"]["metrics"]
    rec_tx = recommended["real_transactions"]
    print("=" * 80)
    print("ANOMALY THRESHOLD TUNING SUMMARY")
    print("=" * 80)
    print(f"Real transaction samples: {len(tx_samples)}")
    print(f"Recommended threshold: {rec_t:.3f}")
    print(
        "Labeled metrics: "
        f"acc={rec_m['accuracy']:.4f}, prec={rec_m['precision']:.4f}, "
        f"recall={rec_m['recall']:.4f}, f1={rec_m['f1']:.4f}, "
        f"fp_rate={rec_m['fp_rate']:.4f}, fn_rate={rec_m['fn_rate']:.4f}"
    )
    print(
        "Real-log transactions: "
        f"anomalies={rec_tx['anomalies']}/{rec_tx['samples']} "
        f"(rate={rec_tx['anomaly_rate']:.4f}), mean_score={rec_tx['mean_score']:.4f}"
    )
    print(f"Report saved: {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
