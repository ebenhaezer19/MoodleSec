#!/usr/bin/env python3
"""
Evaluate FP reduction on normal, tricky normal, and attack requests.

Outputs a results JSON file with per-request decisions and metrics.
Optionally compares against a baseline results file to print before/after metrics
and list downgrades (ALERT/BLOCK -> IGNORE).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


try:
    from proxy.ml.pipeline_orchestrator import PipelineOrchestrator
except Exception:
    import sys

    ROOT_DIR = Path(__file__).resolve().parent
    sys.path.insert(0, str(ROOT_DIR / "proxy" / "ml"))
    from pipeline_orchestrator import PipelineOrchestrator


DEFAULT_OUTPUT = Path("fp_reduction_results.json")


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _decision_to_label(decision: str) -> str:
    return "attack" if _safe_text(decision).upper() in {"BLOCK", "ALERT"} else "normal"


def build_request(method: str, path: str, query: str) -> Dict[str, Any]:
    query = query.lstrip("?")
    query_suffix = f"?{query}" if query else ""
    request_raw = f"{method} {path}{query_suffix}".strip()

    return {
        "method": method,
        "path": path,
        "query_params": query,
        "body": "",
        "headers": "User-Agent: MoodleSec-FP-Eval/1.0",
        "request_raw": request_raw,
    }


def build_dataset() -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []

    def add_case(case_id: str, true_label: str, path: str, query: str = "") -> None:
        cases.append(
            {
                "case_id": case_id,
                "true_label": true_label,
                "request": build_request("GET", path, query),
            }
        )

    # Normal navigation
    add_case("normal_login", "normal", "/login/index.php")
    add_case("normal_course_overview", "normal", "/course/view.php", "id=2&section=overview")
    add_case("normal_assignment", "normal", "/mod/assign/view.php", "id=10")

    # Tricky normal (natural language with keywords)
    add_case("tricky_select_materials", "normal", "/search/index.php", "q=select course materials")
    add_case("tricky_union_math", "normal", "/course/view.php", "comment=union of sets in math")
    add_case("tricky_script_python", "normal", "/search/index.php", "q=how to use script in python")
    add_case("tricky_drop_by", "normal", "/course/view.php", "note=drop by later")

    # Strong attacks
    add_case("attack_sqli_or", "attack", "/login/index.php", "q=%27%20OR%201=1%20--")
    add_case("attack_sqli_union", "attack", "/course/view.php", "id=1%20UNION%20SELECT%201,2%20--")
    add_case("attack_xss_script", "attack", "/login/index.php", "q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    add_case("attack_xss_img", "attack", "/search/index.php", "q=%3Cimg%20src=x%20onerror=alert(1)%3E")
    add_case("attack_path_traversal", "attack", "/pluginfile.php", "file=../../../../etc/passwd")
    add_case("attack_path_traversal_encoded", "attack", "/pluginfile.php", "file=..%2F..%2F..%2Fetc%2Fpasswd")

    return cases


def run_pipeline(cases: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    pipeline = PipelineOrchestrator(enable_logging=False)
    if hasattr(pipeline.decision_engine, "debug_logging"):
        pipeline.decision_engine.debug_logging = False
    if hasattr(pipeline.anomaly_detector, "debug_feature_logging"):
        pipeline.anomaly_detector.debug_feature_logging = False

    results: List[Dict[str, Any]] = []
    for case in cases:
        request = case["request"]
        true_label = case["true_label"]
        result = pipeline.process_request(request)
        decision = _safe_text(result.get("decision", "IGNORE")).upper() or "IGNORE"
        predicted_label = _decision_to_label(decision)

        results.append(
            {
                "case_id": case["case_id"],
                "true_label": true_label,
                "predicted_label": predicted_label,
                "decision": decision,
                "attack_type": _safe_text(result.get("attack_type", "unknown")),
                "confidence": float(result.get("confidence", 0.0) or 0.0),
                "anomaly_score": float(result.get("anomaly_score", 0.0) or 0.0),
                "reason": _safe_text(result.get("reason", "")),
                "request": request,
            }
        )

    return results


def compute_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    tp = fp = tn = fn = 0

    for row in results:
        true_label = _safe_text(row.get("true_label")).lower()
        predicted_label = _safe_text(row.get("predicted_label")).lower()
        if true_label == "attack" and predicted_label == "attack":
            tp += 1
        elif true_label == "normal" and predicted_label == "attack":
            fp += 1
        elif true_label == "normal" and predicted_label == "normal":
            tn += 1
        else:
            fn += 1

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    fp_rate = fp / (fp + tn) if (fp + tn) else 0.0

    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "false_positive_rate": fp_rate,
    }


def print_metrics(label: str, metrics: Dict[str, Any]) -> None:
    print(f"\n=== {label} METRICS ===")
    print(
        "Confusion: "
        f"TP={metrics['TP']} "
        f"FP={metrics['FP']} "
        f"TN={metrics['TN']} "
        f"FN={metrics['FN']}"
    )
    print(
        "Metrics: "
        f"precision={metrics['precision']:.3f} "
        f"recall={metrics['recall']:.3f} "
        f"f1={metrics['f1']:.3f} "
        f"fp_rate={metrics['false_positive_rate']:.3f}"
    )


def load_results(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("results"), list):
        return payload["results"]
    return []


def compare_results(baseline: List[Dict[str, Any]], current: List[Dict[str, Any]]) -> None:
    baseline_map = {row.get("case_id"): row for row in baseline}
    downgrades: List[Dict[str, Any]] = []
    remaining_fp: List[Dict[str, Any]] = []

    for row in current:
        case_id = row.get("case_id")
        baseline_row = baseline_map.get(case_id)
        if baseline_row:
            baseline_decision = _safe_text(baseline_row.get("decision", "IGNORE")).upper()
            current_decision = _safe_text(row.get("decision", "IGNORE")).upper()
            if baseline_decision in {"ALERT", "BLOCK"} and current_decision == "IGNORE":
                downgrades.append(
                    {
                        "case_id": case_id,
                        "request_raw": _safe_text(row.get("request", {}).get("request_raw", "")),
                        "baseline_decision": baseline_decision,
                        "current_decision": current_decision,
                        "reason": _safe_text(row.get("reason", "")),
                    }
                )

        if _safe_text(row.get("true_label", "normal")).lower() == "normal" and row.get("predicted_label") == "attack":
            remaining_fp.append(row)

    if downgrades:
        print("\n=== DOWNGRADED TO IGNORE ===")
        for item in downgrades:
            print(
                f"- {item['case_id']}: {item['request_raw']} | "
                f"{item['baseline_decision']} -> {item['current_decision']} | "
                f"reason: {item['reason']}"
            )
    else:
        print("\n=== DOWNGRADED TO IGNORE ===")
        print("None")

    if remaining_fp:
        print("\n=== REMAINING FALSE POSITIVES ===")
        for row in remaining_fp:
            print(
                f"- {row['case_id']}: {row['request']['request_raw']} | "
                f"decision={row['decision']} reason={row['reason']}"
            )
    else:
        print("\n=== REMAINING FALSE POSITIVES ===")
        print("None")


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate FP reduction on keyword-heavy requests.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Output JSON file for results")
    parser.add_argument("--baseline", default="", help="Optional baseline results JSON for comparison")
    args = parser.parse_args()

    cases = build_dataset()
    results = run_pipeline(cases)
    metrics = compute_metrics(results)

    output_path = Path(args.output)
    output_path.write_text(json.dumps({"results": results, "metrics": metrics}, indent=2), encoding="utf-8")

    print_metrics("CURRENT", metrics)

    if args.baseline:
        baseline_results = load_results(Path(args.baseline))
        if baseline_results:
            baseline_metrics = compute_metrics(baseline_results)
            print_metrics("BEFORE", baseline_metrics)
            print_metrics("AFTER", metrics)
            compare_results(baseline_results, results)
        else:
            print("\n[WARN] Baseline results not found or invalid; skipping comparison.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
