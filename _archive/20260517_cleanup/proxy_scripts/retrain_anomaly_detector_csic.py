#!/usr/bin/env python3
"""
Retrain anomaly detector with CSIC 2010 dataset and run quick evaluation.

This script maps CSIC rows into the request/response structure expected by
ml.anomaly_detector.AnomalyDetector, trains using only normal traffic, then
evaluates against holdout normal + anomalous samples.
"""

import argparse
import csv
import hashlib
import json
import os
import random
import re
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ML_DIR = os.path.join(CURRENT_DIR, "ml")
if ML_DIR not in sys.path:
    sys.path.insert(0, ML_DIR)

from anomaly_detector import AnomalyDetector


def _clean_text(value: Any) -> str:
    """Return a normalized string value."""
    if value is None:
        return ""
    return str(value).strip()


def _normalize_url(raw_url: str) -> str:
    """Strip protocol suffix like 'HTTP/1.1' from CSIC URL column."""
    url = _clean_text(raw_url)
    if not url:
        return "http://localhost/"

    return re.sub(r"\s+HTTP/\d\.\d$", "", url, flags=re.IGNORECASE)


def _extract_label(row: Dict[str, str]) -> Optional[str]:
    """Extract normalized label from CSIC row."""
    raw_label = (
        _clean_text(row.get("H1"))
        or _clean_text(row.get(""))
        or _clean_text(row.get("label"))
        or _clean_text(row.get("Label"))
    )

    if raw_label:
        label = raw_label.lower()
        if label.startswith("normal"):
            return "Normal"
        if label.startswith("anomal"):
            return "Anomalous"

    classification = _clean_text(row.get("classification"))
    if classification == "0":
        return "Normal"
    if classification == "1":
        return "Anomalous"

    return None


def _build_headers(row: Dict[str, str]) -> Dict[str, str]:
    """Map CSIC columns into request headers."""
    header_map = {
        "User-Agent": "User-Agent",
        "Pragma": "Pragma",
        "Cache-Control": "Cache-Control",
        "Accept": "Accept",
        "Accept-encoding": "Accept-Encoding",
        "Accept-charset": "Accept-Charset",
        "language": "Accept-Language",
        "host": "Host",
        "cookie": "Cookie",
        "content-type": "Content-Type",
        "connection": "Connection",
    }

    headers: Dict[str, str] = {}
    for source_col, header_name in header_map.items():
        value = _clean_text(row.get(source_col))
        if value:
            headers[header_name] = value

    return headers


def _estimate_response(url: str, body: str, method: str, headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Create deterministic synthetic response fields.

    CSIC request records do not provide response values, but the current
    anomaly detector expects response_time/status/size features.
    """
    digest_input = f"{method}|{url}|{len(body)}|{len(headers)}"
    digest = hashlib.md5(digest_input.encode("utf-8")).hexdigest()
    selector = int(digest[:2], 16)

    if selector % 20 == 0:
        status_code = 304
    elif selector % 10 == 0:
        status_code = 302
    else:
        status_code = 200

    response_time = min(5000, 80 + len(url) * 2 + len(body) // 2 + (30 if method == "POST" else 0))
    response_size = max(300, min(120000, 1200 + len(url) * 8 + len(body) * 5))

    return {
        "status_code": int(status_code),
        "size": int(response_size),
        "time": int(response_time),
        "headers": {},
    }


def _row_to_sample(row: Dict[str, str]) -> Optional[Tuple[Dict[str, Any], str]]:
    """Convert one CSIC row into detector sample + label."""
    label = _extract_label(row)
    if not label:
        return None

    method = _clean_text(row.get("Method")).upper() or "GET"
    url = _normalize_url(row.get("URL", ""))

    body = _clean_text(row.get("content"))
    declared_length = _clean_text(row.get("lenght"))
    if not body and declared_length.isdigit() and int(declared_length) > 0:
        body = "x" * min(int(declared_length), 4096)

    headers = _build_headers(row)
    response = _estimate_response(url=url, body=body, method=method, headers=headers)

    query_weight = url.count("?") + url.count("&") + url.count("=")
    request_rate = min(180, 2 + query_weight * 3 + len(body) // 120 + (2 if method == "POST" else 0))

    sample = {
        "request": {
            "url": url,
            "method": method,
            "headers": headers,
            "body": body,
        },
        "response": response,
        "request_count_last_minute": int(request_rate),
        "unique_ips_last_minute": 1,
        "error_rate_last_minute": 0.0,
    }

    return sample, label


def load_csic_samples(csv_path: str, max_rows: int = 0) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], int]:
    """Load and convert CSIC samples into normal and anomalous lists."""
    normal_samples: List[Dict[str, Any]] = []
    anomalous_samples: List[Dict[str, Any]] = []
    skipped_rows = 0

    with open(csv_path, "r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for idx, row in enumerate(reader, start=1):
            if max_rows and idx > max_rows:
                break

            converted = _row_to_sample(row)
            if not converted:
                skipped_rows += 1
                continue

            sample, label = converted
            if label == "Normal":
                normal_samples.append(sample)
            elif label == "Anomalous":
                anomalous_samples.append(sample)
            else:
                skipped_rows += 1

    return normal_samples, anomalous_samples, skipped_rows


def _compute_metrics(tp: int, fp: int, tn: int, fn: int) -> Dict[str, float]:
    """Compute binary classification metrics safely."""
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def evaluate_detector(
    detector: AnomalyDetector,
    normal_eval: List[Dict[str, Any]],
    anomalous_eval: List[Dict[str, Any]],
    use_meta: bool = True,
) -> Dict[str, Any]:
    """Evaluate detector predictions against provided labels."""
    tp = fp = tn = fn = 0
    normal_scores: List[float] = []
    anomalous_scores: List[float] = []

    for sample in normal_eval:
        is_anomaly, score, _ = detector.detect(sample, use_meta=use_meta)
        normal_scores.append(score)
        if is_anomaly:
            fp += 1
        else:
            tn += 1

    for sample in anomalous_eval:
        is_anomaly, score, _ = detector.detect(sample, use_meta=use_meta)
        anomalous_scores.append(score)
        if is_anomaly:
            tp += 1
        else:
            fn += 1

    metrics = _compute_metrics(tp=tp, fp=fp, tn=tn, fn=fn)

    return {
        "samples": {
            "normal_eval": len(normal_eval),
            "anomalous_eval": len(anomalous_eval),
            "total_eval": len(normal_eval) + len(anomalous_eval),
        },
        "confusion_matrix": {
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
        },
        "metrics": metrics,
        "score_summary": {
            "normal_mean": (sum(normal_scores) / len(normal_scores)) if normal_scores else 0.0,
            "anomalous_mean": (sum(anomalous_scores) / len(anomalous_scores)) if anomalous_scores else 0.0,
        },
    }


def _sample_for_eval(
    holdout_normals: List[Dict[str, Any]],
    all_anomalous: List[Dict[str, Any]],
    max_eval: int,
    seed: int,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Downsample evaluation set while preserving class ratio."""
    rng = random.Random(seed)
    normal_eval = list(holdout_normals)
    anomalous_eval = list(all_anomalous)

    if max_eval > 0:
        total = len(normal_eval) + len(anomalous_eval)
        if total > max_eval:
            normal_target = max(1, round(max_eval * len(normal_eval) / total))
            anomalous_target = max(1, max_eval - normal_target)

            if len(normal_eval) > normal_target:
                normal_eval = rng.sample(normal_eval, int(normal_target))
            if len(anomalous_eval) > anomalous_target:
                anomalous_eval = rng.sample(anomalous_eval, int(anomalous_target))

    return normal_eval, anomalous_eval


def main() -> int:
    parser = argparse.ArgumentParser(description="Retrain anomaly detector with CSIC dataset")
    parser.add_argument(
        "--dataset",
        default="ml/training_data/archive/csic_database.csv",
        help="Path to CSIC CSV dataset",
    )
    parser.add_argument(
        "--model-path",
        default="ml/models/anomaly_detector.pkl",
        help="Path for anomaly detector model output",
    )
    parser.add_argument(
        "--output",
        default="",
        help="Optional JSON report path (default: timestamped in ml/training_data)",
    )
    parser.add_argument("--train-ratio", type=float, default=0.8, help="Normal-data train ratio")
    parser.add_argument("--contamination", type=float, default=0.08, help="IsolationForest contamination")
    parser.add_argument("--max-rows", type=int, default=0, help="Limit rows loaded from CSV (0 = all)")
    parser.add_argument("--max-eval", type=int, default=15000, help="Max eval samples (0 = all)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for split/sampling")
    parser.add_argument("--disable-meta", action="store_true", help="Disable calibrated second-stage training")
    parser.add_argument("--meta-model-type", default="random_forest", help="Meta model type: random_forest or logistic")
    parser.add_argument("--meta-normal-ratio", type=float, default=0.2, help="Fraction of train normal data used for meta training")
    parser.add_argument("--meta-anomaly-ratio", type=float, default=0.6, help="Fraction of anomaly data used for meta training")
    parser.add_argument("--meta-validation-ratio", type=float, default=0.2, help="Validation split ratio inside meta training")
    parser.add_argument("--keep-existing-model", action="store_true", help="Do not remove previous model first")
    args = parser.parse_args()

    if not os.path.exists(args.dataset):
        print(f"Dataset not found: {args.dataset}")
        return 1

    print("=" * 80)
    print("CSIC RETRAINING FOR ANOMALY DETECTOR")
    print("=" * 80)
    print(f"Dataset: {args.dataset}")

    normal_samples, anomalous_samples, skipped_rows = load_csic_samples(
        csv_path=args.dataset,
        max_rows=args.max_rows,
    )

    print(f"Loaded Normal samples: {len(normal_samples)}")
    print(f"Loaded Anomalous samples: {len(anomalous_samples)}")
    print(f"Skipped rows: {skipped_rows}")

    if len(normal_samples) < 20:
        print("Insufficient normal samples for training (need at least 20)")
        return 1

    rng = random.Random(args.seed)
    rng.shuffle(normal_samples)
    rng.shuffle(anomalous_samples)

    split_idx = int(len(normal_samples) * args.train_ratio)
    split_idx = min(max(split_idx, 20), len(normal_samples) - 1)

    train_normals = normal_samples[:split_idx]
    holdout_normals = normal_samples[split_idx:]

    print(f"Train normal samples: {len(train_normals)}")
    print(f"Holdout normal samples: {len(holdout_normals)}")

    if not args.keep_existing_model and os.path.exists(args.model_path):
        os.remove(args.model_path)
        print(f"Removed previous model: {args.model_path}")

    detector = AnomalyDetector(model_path=args.model_path)
    train_results = detector.train(train_normals, contamination=args.contamination)

    if "error" in train_results:
        print(f"Training failed: {train_results['error']}")
        return 1

    # Reserve labeled slices for meta-classifier training from CSIC labels.
    meta_train_normals = []
    meta_train_anomalies = []

    if not args.disable_meta:
        meta_normal_count = int(len(train_normals) * args.meta_normal_ratio)
        meta_normal_count = max(30, meta_normal_count)
        meta_normal_count = min(meta_normal_count, len(train_normals))
        meta_train_normals = train_normals[:meta_normal_count]

        meta_anomaly_count = int(len(anomalous_samples) * args.meta_anomaly_ratio)
        meta_anomaly_count = max(30, meta_anomaly_count)
        meta_anomaly_count = min(meta_anomaly_count, len(anomalous_samples))
        meta_train_anomalies = anomalous_samples[:meta_anomaly_count]
        eval_anomaly_pool = anomalous_samples[meta_anomaly_count:] if meta_anomaly_count < len(anomalous_samples) else anomalous_samples
    else:
        eval_anomaly_pool = anomalous_samples

    eval_normals, eval_anomalous = _sample_for_eval(
        holdout_normals=holdout_normals,
        all_anomalous=eval_anomaly_pool,
        max_eval=args.max_eval,
        seed=args.seed,
    )

    baseline_eval_results = evaluate_detector(
        detector=detector,
        normal_eval=eval_normals,
        anomalous_eval=eval_anomalous,
        use_meta=False,
    )

    meta_results = {
        'enabled': False,
        'message': 'Meta classifier disabled',
    }

    if not args.disable_meta:
        meta_results = detector.train_meta_classifier(
            normal_data=meta_train_normals,
            anomaly_data=meta_train_anomalies,
            validation_ratio=args.meta_validation_ratio,
            random_state=args.seed,
            model_type=args.meta_model_type,
        )

    calibrated_eval_results = evaluate_detector(
        detector=detector,
        normal_eval=eval_normals,
        anomalous_eval=eval_anomalous,
        use_meta=True,
    )

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_path = args.output or f"ml/training_data/csic_anomaly_eval_{timestamp}.json"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    report = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "dataset": {
            "path": args.dataset,
            "normal_samples": len(normal_samples),
            "anomalous_samples": len(anomalous_samples),
            "skipped_rows": skipped_rows,
        },
        "training": {
            "train_ratio": args.train_ratio,
            "contamination": args.contamination,
            "train_normals": len(train_normals),
            "holdout_normals": len(holdout_normals),
            "meta_training_normals": len(meta_train_normals),
            "meta_training_anomalies": len(meta_train_anomalies),
            "model_path": args.model_path,
            "train_result": train_results,
            "meta_result": meta_results,
        },
        "evaluation": calibrated_eval_results,
        "baseline_evaluation": baseline_eval_results,
        "calibrated_evaluation": calibrated_eval_results,
    }

    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)

    baseline_metrics = baseline_eval_results["metrics"]
    baseline_cm = baseline_eval_results["confusion_matrix"]
    calibrated_metrics = calibrated_eval_results["metrics"]
    calibrated_cm = calibrated_eval_results["confusion_matrix"]

    print("\n" + "=" * 80)
    print("EVALUATION SUMMARY (BASELINE VS CALIBRATED)")
    print("=" * 80)

    print("\nBaseline (Isolation Forest + heuristic):")
    print(
        f"Eval samples: {baseline_eval_results['samples']['total_eval']} "
        f"(normal={baseline_eval_results['samples']['normal_eval']}, "
        f"anomalous={baseline_eval_results['samples']['anomalous_eval']})"
    )
    print(f"Confusion Matrix: TP={baseline_cm['tp']} FP={baseline_cm['fp']} TN={baseline_cm['tn']} FN={baseline_cm['fn']}")
    print(
        "Metrics: "
        f"accuracy={baseline_metrics['accuracy']:.4f}, "
        f"precision={baseline_metrics['precision']:.4f}, "
        f"recall={baseline_metrics['recall']:.4f}, "
        f"f1={baseline_metrics['f1']:.4f}"
    )

    print("\nCalibrated (second-stage classifier):")
    print(f"Confusion Matrix: TP={calibrated_cm['tp']} FP={calibrated_cm['fp']} TN={calibrated_cm['tn']} FN={calibrated_cm['fn']}")
    print(
        "Metrics: "
        f"accuracy={calibrated_metrics['accuracy']:.4f}, "
        f"precision={calibrated_metrics['precision']:.4f}, "
        f"recall={calibrated_metrics['recall']:.4f}, "
        f"f1={calibrated_metrics['f1']:.4f}"
    )

    if meta_results.get('success'):
        print(f"Calibrated threshold: {meta_results.get('meta_threshold', 0.5):.3f}")

    print(f"Saved report: {output_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
