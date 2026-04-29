#!/usr/bin/env python3
"""
Compare hard evaluation results BEFORE and AFTER pipeline improvements.

Usage:
    1. Ensure baseline results exist:  hard_eval_results.json  (BEFORE)
    2. Run evaluation with improved code:
       python generate_hard_eval_dataset.py \
           --results-out hard_eval_results_after.json \
           --dataset-out hard_eval_dataset_after.json
    3. Run this script:
       python run_hard_eval_comparison.py
"""

from __future__ import annotations

import json
import sys
import io
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Fix Windows encoding
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

BEFORE_PATH = Path("hard_eval_results.json")
AFTER_PATH = Path("hard_eval_results_after.json")


def load_results(path: Path) -> Dict[str, Any]:
    if not path.exists():
        print(f"[ERROR] Results file not found: {path}")
        sys.exit(1)
    return json.loads(path.read_text(encoding="utf-8"))


def extract_metrics(results: Dict[str, Any]) -> Dict[str, Any]:
    m = results.get("metrics", {})
    return {
        "TP": m.get("TP", 0),
        "FP": m.get("FP", 0),
        "TN": m.get("TN", 0),
        "FN": m.get("FN", 0),
        "precision": m.get("precision", 0.0),
        "recall": m.get("recall", 0.0),
        "f1": m.get("f1", 0.0),
        "accuracy": m.get("accuracy", 0.0),
        "fpr": m.get("false_positive_rate", 0.0),
        "fnr": m.get("false_negative_rate", 0.0),
    }


def build_case_id_set(cases: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    index = {}
    for c in cases:
        eval_id = c.get("eval_id", "")
        if eval_id:
            index[eval_id] = c
    return index


def main() -> int:
    before = load_results(BEFORE_PATH)
    after = load_results(AFTER_PATH)

    bm = extract_metrics(before)
    am = extract_metrics(after)

    print()
    print("=" * 72)
    print("   HARD EVALUATION: BEFORE vs AFTER COMPARISON")
    print("=" * 72)
    print()

    header = f"  {'Metric':<30} {'BEFORE':>10}  {'AFTER':>10}  {'DELTA':>10}"
    sep = "  " + "-" * 65
    print(header)
    print(sep)

    int_metrics = ["TP", "FP", "TN", "FN"]
    float_metrics = [
        ("precision", "Precision"),
        ("recall", "Recall"),
        ("f1", "F1 Score"),
        ("accuracy", "Accuracy"),
        ("fpr", "False Positive Rate"),
        ("fnr", "False Negative Rate"),
    ]

    for key in int_metrics:
        delta = am[key] - bm[key]
        sign = "+" if delta > 0 else ""
        print(f"  {key:<30} {bm[key]:>10}  {am[key]:>10}  {sign}{delta:>9}")

    print(sep)

    for key, label in float_metrics:
        delta = am[key] - bm[key]
        sign = "+" if delta > 0 else ""
        print(f"  {label:<30} {bm[key]:>10.4f}  {am[key]:>10.4f}  {sign}{delta:>9.4f}")

    print(sep)
    print()

    # Summary deltas
    fp_reduction = bm["FP"] - am["FP"]
    fn_reduction = bm["FN"] - am["FN"]
    precision_delta = am["precision"] - bm["precision"]
    recall_delta = am["recall"] - bm["recall"]

    print("  KEY IMPROVEMENTS:")
    print(f"    FP reduction:    {fp_reduction:>+d} (from {bm['FP']} to {am['FP']})")
    print(f"    FN reduction:    {fn_reduction:>+d} (from {bm['FN']} to {am['FN']})")
    print(f"    Precision delta: {precision_delta:>+.4f}")
    print(f"    Recall delta:    {recall_delta:>+.4f}")
    print()

    # Cases that changed classification
    before_fps = before.get("false_positives", [])
    after_fps = after.get("false_positives", [])
    before_fns = before.get("false_negatives", [])
    after_fns = after.get("false_negatives", [])

    before_fp_ids = {c.get("eval_id", "") for c in before_fps}
    after_fp_ids = {c.get("eval_id", "") for c in after_fps}
    before_fn_ids = {c.get("eval_id", "") for c in before_fns}
    after_fn_ids = {c.get("eval_id", "") for c in after_fns}

    fixed_fps = before_fp_ids - after_fp_ids
    new_fps = after_fp_ids - before_fp_ids
    fixed_fns = before_fn_ids - after_fn_ids
    new_fns = after_fn_ids - before_fn_ids

    before_fp_index = {c.get("eval_id"): c for c in before_fps}
    after_fp_index = {c.get("eval_id"): c for c in after_fps}
    before_fn_index = {c.get("eval_id"): c for c in before_fns}
    after_fn_index = {c.get("eval_id"): c for c in after_fns}

    print("  CLASSIFICATION CHANGES:")
    print()

    if fixed_fps:
        print(f"  Fixed False Positives ({len(fixed_fps)}):")
        for eid in sorted(fixed_fps):
            info = before_fp_index.get(eid, {})
            payload = info.get("payload_text", "")
            path = info.get("path", "")
            old_dec = info.get("decision", "?")
            print(f"    {eid}: {path} payload=\"{payload}\"")
            print(f"           BEFORE: {old_dec} -> AFTER: IGNORED (correct)")
        print()

    if new_fps:
        print(f"  NEW False Positives ({len(new_fps)}) [REGRESSION]:")
        for eid in sorted(new_fps):
            info = after_fp_index.get(eid, {})
            payload = info.get("payload_text", "")
            path = info.get("path", "")
            dec = info.get("decision", "?")
            print(f"    {eid}: {path} payload=\"{payload}\" -> {dec}")
        print()

    if fixed_fns:
        print(f"  Fixed False Negatives ({len(fixed_fns)}):")
        for eid in sorted(fixed_fns):
            info = before_fn_index.get(eid, {})
            payload = info.get("payload_text", "")
            path = info.get("path", "")
            old_dec = info.get("decision", "?")
            print(f"    {eid}: {path} payload=\"{payload}\"")
            print(f"           BEFORE: {old_dec} -> AFTER: BLOCKED/ALERTED (correct)")
        print()

    if new_fns:
        print(f"  NEW False Negatives ({len(new_fns)}) [REGRESSION]:")
        for eid in sorted(new_fns):
            info = after_fn_index.get(eid, {})
            payload = info.get("payload_text", "")
            path = info.get("path", "")
            dec = info.get("decision", "?")
            print(f"    {eid}: {path} payload=\"{payload}\" -> {dec}")
        print()

    if not fixed_fps and not new_fps and not fixed_fns and not new_fns:
        print("    No classification changes detected.")
        print()

    # Final verdict
    print("=" * 72)
    if new_fps or new_fns:
        print("  VERDICT: REGRESSION DETECTED - review new FP/FN cases above")
    elif fp_reduction > 0 or fn_reduction > 0:
        print(f"  VERDICT: IMPROVEMENT - {fp_reduction} FP fixed, {fn_reduction} FN fixed")
    else:
        print("  VERDICT: NO CHANGE")
    print("=" * 72)
    print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
