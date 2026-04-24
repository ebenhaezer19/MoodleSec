from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


try:
    from proxy.ml.pipeline_orchestrator import PipelineOrchestrator
except Exception:
    import sys

    ROOT_DIR = Path(__file__).resolve().parent
    sys.path.insert(0, str(ROOT_DIR / "proxy" / "ml"))
    from pipeline_orchestrator import PipelineOrchestrator


def _safe_divide(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return float(numerator / denominator)


def _normalize_true_label(raw_label: Any) -> str:
    label = str(raw_label).strip().lower()
    if label in {"attack", "anomaly", "malicious", "1", "true", "yes"}:
        return "attack"
    if label in {"normal", "benign", "legitimate", "0", "false", "no"}:
        return "normal"
    raise ValueError(f"Invalid true_label value: {raw_label}")


def _decision_to_label(decision: Any) -> str:
    normalized = str(decision).strip().upper()
    if normalized in {"BLOCK", "ALERT"}:
        return "attack"
    return "normal"


def _fallback_result(reason: str) -> Dict[str, Any]:
    return {
        "decision": "IGNORE",
        "severity": "LOW",
        "attack_type": "unknown",
        "confidence": 0.0,
        "anomaly_score": 0.0,
        "reason": reason,
    }


def _load_dataset_from_json(dataset_path: Union[str, Path]) -> List[Dict[str, Any]]:
    path = Path(dataset_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found: {path}")

    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if isinstance(payload, list):
        return payload

    if isinstance(payload, dict):
        for key in ("dataset", "data", "items", "requests"):
            value = payload.get(key)
            if isinstance(value, list):
                return value

    raise ValueError("Dataset JSON must be a list or a dict containing a list in dataset/data/items/requests")


def load_dataset(dataset_source: Union[str, Path, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    if isinstance(dataset_source, list):
        return dataset_source
    return _load_dataset_from_json(dataset_source)


def _get_pipeline_normalize_fn(pipeline: PipelineOrchestrator):
    normalize_fn = getattr(pipeline, "normalize_request", None)
    if callable(normalize_fn):
        return normalize_fn

    normalize_fn = getattr(pipeline, "_normalize_request", None)
    if callable(normalize_fn):
        return normalize_fn

    return None


def _build_anomaly_input_fallback(normalized_request: Dict[str, Any]) -> Dict[str, Any]:
    method = str(normalized_request.get("method", "GET")).upper() or "GET"
    path = str(normalized_request.get("path", "/")) or "/"
    query = str(normalized_request.get("query_params", "")).strip()
    if query.startswith("?"):
        query = query[1:]

    url = f"{path}?{query}" if query else path

    return {
        "request": {
            "url": url,
            "method": method,
            "headers": normalized_request.get("headers", {}),
            "body": normalized_request.get("body", ""),
        },
        "response": {
            "status_code": int(normalized_request.get("response_status_code", 200) or 200),
            "size": int(normalized_request.get("response_size", 0) or 0),
            "time": float(normalized_request.get("response_time", 0.0) or 0.0),
            "headers": normalized_request.get("response_headers", {}) or {},
        },
        "finding": normalized_request.get("finding", {}) or {},
        "request_count_last_minute": int(normalized_request.get("request_count_last_minute", 1) or 1),
        "unique_ips_last_minute": int(normalized_request.get("unique_ips_last_minute", 1) or 1),
        "error_rate_last_minute": float(normalized_request.get("error_rate_last_minute", 0.0) or 0.0),
    }


def _build_anomaly_input(pipeline: PipelineOrchestrator, normalized_request: Dict[str, Any]) -> Dict[str, Any]:
    to_anomaly_input = getattr(pipeline, "_to_anomaly_input", None)
    if callable(to_anomaly_input):
        return to_anomaly_input(normalized_request)
    return _build_anomaly_input_fallback(normalized_request)


def _predict_anomaly_baseline(
    pipeline: PipelineOrchestrator,
    normalized_request: Dict[str, Any],
) -> Dict[str, Any]:
    anomaly_input = _build_anomaly_input(pipeline, normalized_request)

    try:
        is_anomaly, anomaly_score, reason = pipeline.anomaly_detector.detect(anomaly_input)
        return {
            "predicted_label": "attack" if bool(is_anomaly) else "normal",
            "is_anomaly": bool(is_anomaly),
            "anomaly_score": float(anomaly_score),
            "reason": str(reason),
        }
    except Exception as detect_error:
        try:
            is_anomaly, anomaly_score, reason = pipeline.anomaly_detector._heuristic_detection(anomaly_input)
            return {
                "predicted_label": "attack" if bool(is_anomaly) else "normal",
                "is_anomaly": bool(is_anomaly),
                "anomaly_score": float(anomaly_score),
                "reason": f"heuristic fallback: {reason}",
                "error": f"detect failed: {detect_error}",
            }
        except Exception as fallback_error:
            return {
                "predicted_label": "normal",
                "is_anomaly": False,
                "anomaly_score": 0.0,
                "reason": "anomaly baseline failed",
                "error": f"detect failed: {detect_error}; heuristic failed: {fallback_error}",
            }


def run_pipeline_on_dataset(
    dataset: List[Dict[str, Any]],
    pipeline: Optional[PipelineOrchestrator] = None,
) -> List[Dict[str, Any]]:
    local_pipeline = pipeline or PipelineOrchestrator(enable_logging=False)

    # Keep evaluation output readable.
    local_pipeline.enable_logging = False
    if hasattr(local_pipeline.decision_engine, "debug_logging"):
        local_pipeline.decision_engine.debug_logging = False
    if hasattr(local_pipeline.anomaly_detector, "debug_feature_logging"):
        local_pipeline.anomaly_detector.debug_feature_logging = False

    normalize_fn = _get_pipeline_normalize_fn(local_pipeline)

    processed_results: List[Dict[str, Any]] = []

    for index, item in enumerate(dataset):
        record: Dict[str, Any] = {"index": int(index)}

        if not isinstance(item, dict):
            record.update(
                {
                    "request": {},
                    "true_label": "normal",
                    "result": _fallback_result("Invalid dataset item format"),
                    "anomaly_prediction": {
                        "predicted_label": "normal",
                        "is_anomaly": False,
                        "anomaly_score": 0.0,
                        "reason": "invalid dataset item",
                    },
                    "error": "Item is not a dict",
                }
            )
            record["predicted_label"] = _decision_to_label(record["result"]["decision"])
            processed_results.append(record)
            continue

        raw_request = item.get("request", {})
        if not isinstance(raw_request, dict):
            raw_request = {}

        try:
            true_label = _normalize_true_label(item.get("true_label", "normal"))
            label_error = ""
        except Exception as error:
            true_label = "normal"
            label_error = str(error)

        try:
            if callable(normalize_fn):
                normalized_request = normalize_fn(raw_request)
            else:
                normalized_request = raw_request
            if not isinstance(normalized_request, dict):
                normalized_request = {}
        except Exception as error:
            normalized_request = raw_request
            label_error = f"{label_error}; normalize_request failed: {error}".strip("; ")

        anomaly_prediction = _predict_anomaly_baseline(local_pipeline, normalized_request)

        try:
            pipeline_result = local_pipeline.process_request(normalized_request)
        except Exception as error:
            pipeline_result = _fallback_result(f"Pipeline error: {error}")
            label_error = f"{label_error}; process_request failed: {error}".strip("; ")

        predicted_label = _decision_to_label(pipeline_result.get("decision", "IGNORE"))

        record.update(
            {
                "request": normalized_request,
                "true_label": true_label,
                "result": pipeline_result,
                "predicted_label": predicted_label,
                "anomaly_prediction": anomaly_prediction,
            }
        )

        if label_error:
            record["error"] = label_error

        processed_results.append(record)

    return processed_results


def _update_confusion_matrix(confusion: Dict[str, int], true_label: str, predicted_label: str) -> None:
    if true_label == "attack" and predicted_label == "attack":
        confusion["TP"] += 1
    elif true_label == "normal" and predicted_label == "attack":
        confusion["FP"] += 1
    elif true_label == "normal" and predicted_label == "normal":
        confusion["TN"] += 1
    else:
        confusion["FN"] += 1


def _compute_metrics(confusion: Dict[str, int], total: int) -> Dict[str, Any]:
    tp = int(confusion["TP"])
    fp = int(confusion["FP"])
    tn = int(confusion["TN"])
    fn = int(confusion["FN"])

    precision = _safe_divide(tp, tp + fp)
    recall = _safe_divide(tp, tp + fn)
    f1 = _safe_divide(2.0 * precision * recall, precision + recall)
    accuracy = _safe_divide(tp + tn, total)
    fp_rate = _safe_divide(fp, fp + tn)

    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "accuracy": float(accuracy),
        "fp_rate": float(fp_rate),
        "confusion_matrix": {
            "TP": tp,
            "FP": fp,
            "TN": tn,
            "FN": fn,
        },
    }


def evaluate_pipeline(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    pipeline_confusion = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    anomaly_confusion = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    decision_counts = {"BLOCK": 0, "ALERT": 0, "IGNORE": 0}

    for item in results:
        if not isinstance(item, dict):
            continue

        try:
            true_label = _normalize_true_label(item.get("true_label", "normal"))
        except Exception:
            true_label = "normal"

        result_payload = item.get("result", {})
        if not isinstance(result_payload, dict):
            result_payload = {}

        decision = str(result_payload.get("decision", "IGNORE")).strip().upper()
        if decision not in decision_counts:
            decision = "IGNORE"

        decision_counts[decision] += 1

        pipeline_predicted_label = _decision_to_label(decision)
        _update_confusion_matrix(pipeline_confusion, true_label, pipeline_predicted_label)

        anomaly_payload = item.get("anomaly_prediction", {})
        if isinstance(anomaly_payload, dict):
            anomaly_predicted_label = str(anomaly_payload.get("predicted_label", "normal")).strip().lower()
            if anomaly_predicted_label not in {"attack", "normal"}:
                anomaly_predicted_label = "normal"
        else:
            anomaly_predicted_label = "normal"

        _update_confusion_matrix(anomaly_confusion, true_label, anomaly_predicted_label)

    total = len(results)
    if total == 0:
        return {
            "pipeline_metrics": {
                "precision": 0.0,
                "recall": 0.0,
                "f1": 0.0,
                "accuracy": 0.0,
                "fp_rate": 0.0,
                "confusion_matrix": {"TP": 0, "FP": 0, "TN": 0, "FN": 0},
            },
            "decision_distribution": {
                "BLOCK": 0.0,
                "ALERT": 0.0,
                "IGNORE": 0.0,
            },
            "comparison": {
                "fp_reduction": 0.0,
                "recall_drop": 0.0,
                "anomaly_recall": 0.0,
                "pipeline_recall": 0.0,
                "anomaly_fp_rate": 0.0,
                "pipeline_fp_rate": 0.0,
            },
        }

    pipeline_metrics = _compute_metrics(pipeline_confusion, total)
    anomaly_metrics = _compute_metrics(anomaly_confusion, total)

    return {
        "pipeline_metrics": {
            "precision": float(pipeline_metrics["precision"]),
            "recall": float(pipeline_metrics["recall"]),
            "f1": float(pipeline_metrics["f1"]),
            "accuracy": float(pipeline_metrics["accuracy"]),
            "fp_rate": float(pipeline_metrics["fp_rate"]),
            "confusion_matrix": dict(pipeline_metrics["confusion_matrix"]),
        },
        "decision_distribution": {
            "BLOCK": float(_safe_divide(decision_counts["BLOCK"], total) * 100.0),
            "ALERT": float(_safe_divide(decision_counts["ALERT"], total) * 100.0),
            "IGNORE": float(_safe_divide(decision_counts["IGNORE"], total) * 100.0),
        },
        "comparison": {
            "fp_reduction": float(anomaly_metrics["fp_rate"] - pipeline_metrics["fp_rate"]),
            "recall_drop": float(anomaly_metrics["recall"] - pipeline_metrics["recall"]),
            "anomaly_recall": float(anomaly_metrics["recall"]),
            "pipeline_recall": float(pipeline_metrics["recall"]),
            "anomaly_fp_rate": float(anomaly_metrics["fp_rate"]),
            "pipeline_fp_rate": float(pipeline_metrics["fp_rate"]),
        },
    }


def save_json_file(path: Union[str, Path], payload: Any) -> None:
    target = Path(path)
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)

    with target.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, default=str)


def run_full_pipeline_evaluation(
    dataset_source: Union[str, Path, List[Dict[str, Any]]],
    results_output_path: Union[str, Path] = "evaluation_results.json",
    metrics_output_path: Union[str, Path] = "evaluation_metrics.json",
) -> Dict[str, Any]:
    dataset = load_dataset(dataset_source)
    results = run_pipeline_on_dataset(dataset)
    metrics = evaluate_pipeline(results)

    save_json_file(results_output_path, results)
    save_json_file(metrics_output_path, metrics)

    return metrics


def print_summary(metrics: Dict[str, Any]) -> None:
    pipeline_metrics = metrics.get("pipeline_metrics", {}) if isinstance(metrics, dict) else {}
    comparison = metrics.get("comparison", {}) if isinstance(metrics, dict) else {}
    decision_distribution = metrics.get("decision_distribution", {}) if isinstance(metrics, dict) else {}

    print("\n=== Full Pipeline Evaluation Summary ===")
    print(f"Precision      : {float(pipeline_metrics.get('precision', 0.0)):.4f}")
    print(f"Recall         : {float(pipeline_metrics.get('recall', 0.0)):.4f}")
    print(f"F1             : {float(pipeline_metrics.get('f1', 0.0)):.4f}")
    print(f"FP Rate        : {float(pipeline_metrics.get('fp_rate', 0.0)):.4f}")
    print(f"Recall Drop    : {float(comparison.get('recall_drop', 0.0)):.4f}")
    print(f"FP Reduction   : {float(comparison.get('fp_reduction', 0.0)):.4f}")
    print(
        "Decision Dist. : "
        f"BLOCK={float(decision_distribution.get('BLOCK', 0.0)):.2f}% "
        f"ALERT={float(decision_distribution.get('ALERT', 0.0)):.2f}% "
        f"IGNORE={float(decision_distribution.get('IGNORE', 0.0)):.2f}%"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run full end-to-end pipeline evaluation.")
    parser.add_argument(
        "--input",
        required=True,
        help="Path to dataset JSON file with items: {'request': {...}, 'true_label': 'attack|normal'}",
    )
    parser.add_argument(
        "--results-output",
        default="evaluation_results.json",
        help="Output path for raw per-request evaluation results JSON.",
    )
    parser.add_argument(
        "--metrics-output",
        default="evaluation_metrics.json",
        help="Output path for aggregate evaluation metrics JSON.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    try:
        metrics = run_full_pipeline_evaluation(
            dataset_source=args.input,
            results_output_path=args.results_output,
            metrics_output_path=args.metrics_output,
        )

        print_summary(metrics)
        print(f"Raw results saved to: {Path(args.results_output).resolve()}")
        print(f"Metrics saved to    : {Path(args.metrics_output).resolve()}")
        return 0
    except Exception as error:
        print(f"Evaluation failed: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
