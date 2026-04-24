from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


LOG_PATH = Path("proxy/logs/pipeline_results.json")


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


def _normalize_attack_type(raw_attack_type: Any) -> str:
    text = str(raw_attack_type or "").strip().lower()

    mapping = {
        "xss": "XSS",
        "cross-site scripting": "XSS",
        "cross site scripting": "XSS",
        "sqli": "SQLi",
        "sql injection": "SQLi",
        "path traversal": "Path Traversal",
        "directory traversal": "Path Traversal",
        "command injection": "Command Injection",
        "cmd injection": "Command Injection",
        "os command injection": "Command Injection",
        "normal": "normal",
        "benign": "normal",
        "legitimate": "normal",
        "none": "normal",
    }

    return mapping.get(text, text)


def load_pipeline_results(log_path: Path = LOG_PATH) -> List[Dict[str, Any]]:
    if not log_path.exists():
        print(f"Log file not found: {log_path}")
        return []

    try:
        raw_text = log_path.read_text(encoding="utf-8", errors="replace").strip()
        if not raw_text:
            print(f"Log file is empty: {log_path}")
            return []

        payload = json.loads(raw_text)
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]

        if isinstance(payload, dict):
            nested = payload.get("results")
            if isinstance(nested, list):
                return [item for item in nested if isinstance(item, dict)]

        print(f"Unexpected JSON format in log file: {log_path}")
        return []
    except Exception as error:
        print(f"Failed to read log file: {error}")
        return []


def analyze_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    decision_counts = {
        "BLOCK": 0,
        "ALERT": 0,
        "IGNORE": 0,
    }
    attack_counts = {
        "XSS": 0,
        "SQLi": 0,
        "Path Traversal": 0,
        "Command Injection": 0,
        "normal": 0,
    }

    confidence_sum = 0.0
    anomaly_score_sum = 0.0

    for item in results:
        decision = str(item.get("decision", "")).strip().upper()
        if decision in decision_counts:
            decision_counts[decision] += 1

        attack_type = _normalize_attack_type(item.get("attack_type", ""))
        if attack_type in attack_counts:
            attack_counts[attack_type] += 1

        confidence_sum += _safe_float(item.get("confidence", 0.0), 0.0)
        anomaly_score_sum += _safe_float(item.get("anomaly_score", 0.0), 0.0)

    total = len(results)

    block_percentage = _safe_divide(decision_counts["BLOCK"] * 100.0, total)
    alert_percentage = _safe_divide(decision_counts["ALERT"] * 100.0, total)
    ignore_percentage = _safe_divide(decision_counts["IGNORE"] * 100.0, total)

    avg_confidence = _safe_divide(confidence_sum, total)
    avg_anomaly_score = _safe_divide(anomaly_score_sum, total)

    return {
        "total_requests": int(total),
        "decision_counts": decision_counts,
        "decision_percentages": {
            "BLOCK": float(block_percentage),
            "ALERT": float(alert_percentage),
            "IGNORE": float(ignore_percentage),
        },
        "attack_counts": attack_counts,
        "avg_confidence": float(avg_confidence),
        "avg_anomaly_score": float(avg_anomaly_score),
    }


def print_summary(summary: Dict[str, Any]) -> None:
    total = summary.get("total_requests", 0)
    decision_counts = summary.get("decision_counts", {})
    decision_percentages = summary.get("decision_percentages", {})
    attack_counts = summary.get("attack_counts", {})

    print("=== PIPELINE ANALYSIS ===")
    print(f"Total Requests: {int(total)}")
    print(
        f"BLOCK: {int(decision_counts.get('BLOCK', 0))} "
        f"({float(decision_percentages.get('BLOCK', 0.0)):.2f}%)"
    )
    print(
        f"ALERT: {int(decision_counts.get('ALERT', 0))} "
        f"({float(decision_percentages.get('ALERT', 0.0)):.2f}%)"
    )
    print(
        f"IGNORE: {int(decision_counts.get('IGNORE', 0))} "
        f"({float(decision_percentages.get('IGNORE', 0.0)):.2f}%)"
    )
    print("")

    print("Attack Distribution:")
    print(f"XSS: {int(attack_counts.get('XSS', 0))}")
    print(f"SQLi: {int(attack_counts.get('SQLi', 0))}")
    print(f"Path Traversal: {int(attack_counts.get('Path Traversal', 0))}")
    print(f"Command Injection: {int(attack_counts.get('Command Injection', 0))}")
    print(f"normal: {int(attack_counts.get('normal', 0))}")
    print("")

    print(f"Avg Confidence: {float(summary.get('avg_confidence', 0.0)):.2f}")
    print(f"Avg Anomaly Score: {float(summary.get('avg_anomaly_score', 0.0)):.2f}")


def main() -> int:
    results = load_pipeline_results(LOG_PATH)
    summary = analyze_results(results)
    print_summary(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
