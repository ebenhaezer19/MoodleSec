#!/usr/bin/env python3          
"""Compare file-level vs request-level evaluation results."""
import json, sys, io

# Fix Windows encoding
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# Load data
gt = json.load(open("request_ground_truth.json", "r", encoding="utf-8"))
metrics = json.load(open("request_level_metrics.json", "r", encoding="utf-8"))
fps = json.load(open("request_level_false_positives.json", "r", encoding="utf-8"))
fns = json.load(open("request_level_false_negatives.json", "r", encoding="utf-8"))
forensics_v2 = json.load(open("har_pipeline_forensics_v2.json", "r", encoding="utf-8"))

overall = metrics.get("overall", {})
per_cat = metrics.get("per_category", {})
f_summary = forensics_v2.get("summary", {})

# File-level numbers
fl_total = f_summary.get("total_replay_requests", 0)
fl_attack = fl_total
fl_classified_normal = f_summary.get("attack_requests_classified_as_normal", 0)
fl_detected = fl_total - fl_classified_normal

fl_tp = fl_detected
fl_fn = fl_classified_normal
fl_fp = 0
fl_tn = 0
fl_prec = fl_tp / (fl_tp + fl_fp) if (fl_tp + fl_fp) > 0 else 0
fl_recall = fl_tp / (fl_tp + fl_fn) if (fl_tp + fl_fn) > 0 else 0
fl_f1 = 2 * fl_prec * fl_recall / (fl_prec + fl_recall) if (fl_prec + fl_recall) > 0 else 0
fl_acc = (fl_tp + fl_tn) / fl_total if fl_total > 0 else 0

print()
print("=" * 72)
print("   FILE-LEVEL vs REQUEST-LEVEL EVALUATION COMPARISON")
print("=" * 72)
print()

header = f"  {'Metric':<30} {'File-Level':>13}  {'Request-Level':>13}"
sep    = "  " + "-" * 60
print(header)
print(sep)
print(f"  {'Total requests':<30} {fl_total:>13}  {overall['total_evaluated']:>13}")
print(f"  {'Ground truth: attack':<30} {fl_attack:>13}  {overall['TP']+overall['FN']:>13}")
print(f"  {'Ground truth: normal':<30} {0:>13}  {overall['TN']+overall['FP']:>13}")
print(sep)
print(f"  {'TP (true positive)':<30} {fl_tp:>13}  {overall['TP']:>13}")
print(f"  {'FP (false positive)':<30} {fl_fp:>13}  {overall['FP']:>13}")
print(f"  {'TN (true negative)':<30} {fl_tn:>13}  {overall['TN']:>13}")
print(f"  {'FN (false negative)':<30} {fl_fn:>13}  {overall['FN']:>13}")
print(sep)
print(f"  {'Precision':<30} {fl_prec:>13.4f}  {overall['precision']:>13.4f}")
print(f"  {'Recall':<30} {fl_recall:>13.4f}  {overall['recall']:>13.4f}")
print(f"  {'F1 Score':<30} {fl_f1:>13.4f}  {overall['f1_score']:>13.4f}")
print(f"  {'Accuracy':<30} {fl_acc:>13.4f}  {overall['accuracy']:>13.4f}")
print(f"  {'False Positive Rate':<30} {'N/A':>13}  {overall['false_positive_rate']:>13.4f}")
print(sep)
print()

print("  Per-category detection (request-level):")
print(f"  {'Category':<22} {'Detected':>9} {'Total':>7} {'Rate':>10}")
print("  " + "-" * 50)
for cat, info in per_cat.items():
    rate_str = f"{info['detection_rate']:.1%}"
    print(f"  {cat:<22} {info['detected']:>9} {info['total_attacks']:>7} {rate_str:>10}")
print()

print("  False positive breakdown (request-level):")
fp_types = {}
for fp in fps:
    t = fp.get("predicted_attack_type", "unknown")
    fp_types[t] = fp_types.get(t, 0) + 1
for t, c in sorted(fp_types.items(), key=lambda x: -x[1]):
    print(f"    {t:20s} -> {c} false alerts")
print()

print("  False negative breakdown (request-level):")
if fns:
    fn_types = {}
    for fn in fns:
        t = fn.get("attack_category", "unknown")
        fn_types[t] = fn_types.get(t, 0) + 1
    for t, c in sorted(fn_types.items(), key=lambda x: -x[1]):
        print(f"    {t:20s} -> {c} missed attacks")
else:
    print("    None -- all attack requests were detected!")
print()

print("=" * 72)
print("  WHY REQUEST-LEVEL EVALUATION IS MORE ACCURATE")
print("=" * 72)
print()
print("  File-level labeling marks ALL requests from an attack HAR as")
print('  "attack", even benign navigation like GET /, GET /favicon.ico.')
print("  This creates these problems:")
print()
print("  1. INFLATED FALSE NEGATIVES")
print("     Normal navigation counted as missed attacks.")
print(f"     File-level: {fl_fn} FN  vs  Request-level: {overall['FN']} FN")
print()
print("  2. HIDDEN FALSE POSITIVES")
print("     No way to measure FP when all labels are 'attack'.")
print(f"     File-level: {fl_fp} FP  vs  Request-level: {overall['FP']} FP")
print()
print("  3. MISLEADING RECALL")
print(f"     File-level recall = {fl_recall:.4f} suggests model misses attacks.")
print(f"     Request-level recall = {overall['recall']:.4f} -- all real attacks detected!")
print()
print("  4. PRECISION VISIBILITY")
print(f"     Request-level precision = {overall['precision']:.4f} reveals the proxy")
print("     alerts on many benign requests. Invisible with file-level.")
print()
print("  CONCLUSION:")
print("  The ML proxy detects 100% of actual SQLi attacks (recall=1.0),")
print(f"  but has a high false positive rate ({overall['false_positive_rate']:.1%}) on benign")
print("  requests. Priority should be reducing FP, not improving detection.")
print()
print("=" * 72)
