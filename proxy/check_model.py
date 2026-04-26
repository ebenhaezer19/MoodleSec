"""
Diagnostic script: inspect fp_reducer.pkl and test its accuracy.
Run from /proxy directory: python check_model.py
"""
import pickle
import os
import sys
import numpy as np

MODEL_PATH = "ml/models/fp_reducer.pkl"

print("=" * 60)
print("FP REDUCER MODEL DIAGNOSTIC")
print("=" * 60)

# ── 1. Check file metadata ──────────────────────────────────────
if not os.path.exists(MODEL_PATH):
    print(f"[ERROR] Model file not found: {MODEL_PATH}")
    sys.exit(1)

size_kb = os.path.getsize(MODEL_PATH) / 1024
mtime   = os.path.getmtime(MODEL_PATH)
import datetime
mtime_str = datetime.datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")

print(f"\n[FILE]")
print(f"  Path      : {MODEL_PATH}")
print(f"  Size      : {size_kb:.1f} KB")
print(f"  Modified  : {mtime_str}")

# ── 2. Load and inspect pkl contents ───────────────────────────
try:
    with open(MODEL_PATH, "rb") as f:
        model_data = pickle.load(f)
except Exception as e:
    print(f"\n[ERROR] Cannot load pkl: {e}")
    sys.exit(1)

print(f"\n[PKL CONTENTS] Keys: {list(model_data.keys())}")
print(f"  is_trained : {model_data.get('is_trained')}")
print(f"  timestamp  : {model_data.get('timestamp', 'NOT FOUND — old model!')}")

model  = model_data.get("model")
scaler = model_data.get("scaler")

# ── 3. Identify model type ──────────────────────────────────────
print(f"\n[MODEL TYPE]")
print(f"  Class: {type(model).__name__}")

if hasattr(model, "calibrated_classifiers_"):
    ccs = model.calibrated_classifiers_
    print(f"  CalibratedClassifierCV with {len(ccs)} folds")
    base = ccs[0].estimator if hasattr(ccs[0], "estimator") else ccs[0].base_estimator
    print(f"  Base estimator: {type(base).__name__}")
    if hasattr(base, "estimators_"):
        for name, est in zip(base.estimators, base.estimators_):
            print(f"    - {name[0]}: {type(est).__name__}")
elif hasattr(model, "estimators_"):
    print(f"  Voting/Ensemble with {len(model.estimators_)} members")
else:
    print(f"  Single estimator")

if hasattr(scaler, "mean_"):
    print(f"\n[SCALER] Fitted on {len(scaler.mean_)} features")
    print(f"  Feature means (first 5): {scaler.mean_[:5].round(4).tolist()}")
else:
    print("\n[SCALER] Not fitted (old model?)")

# ── 4. Accuracy test on representative findings ─────────────────
print(f"\n[ACCURACY TEST]")
print("  Testing with 20 known-label security findings...\n")

# Simulate findings like the scanner generates
# Each finding maps to features extracted by FalsePositiveReducer.extract_features()
# Feature order: severity, category, evidence_len, desc_len, url_complexity,
#   has_params, cvss_score, risk_score, fp_kw_count, tp_kw_count,
#   keyword_ratio, is_informational, status_code, response_time, occurrence, days

# TP findings (label=0): Real injections, should NOT be filtered
tp_samples = [
    # [sev, cat, evid_len, desc_len, url_cx, has_p, cvss, risk, fp_kw, tp_kw, kw_ratio, is_info, sc, rt, occ, days]
    [5, 1, 8.0, 5.0, 3, 1, 9.0, 90, 0, 3, 0.0, 0, 200, 15200, 1, 0],  # SQLi time-based (CWE-89)
    [5, 1, 5.0, 5.0, 3, 1, 9.0, 85, 0, 2, 0.0, 0, 500, 100,   1, 0],  # SQLi HTTP 500
    [4, 2, 4.0, 4.0, 2, 1, 7.0, 75, 0, 2, 0.0, 0, 200, 200,   1, 0],  # XSS reflected
    [4, 4, 3.0, 4.0, 2, 0, 6.5, 70, 0, 2, 0.0, 0, 200, 100,   1, 0],  # CSRF bypass
    [5, 1, 6.0, 6.0, 4, 1, 9.8, 95, 0, 3, 0.0, 0, 200, 300,   1, 0],  # SQLi error-based
    [4, 2, 5.0, 4.0, 3, 1, 7.5, 80, 0, 2, 0.0, 0, 200, 150,   1, 0],  # XSS via payload
    [4, 4, 4.0, 4.0, 2, 0, 6.0, 65, 0, 1, 0.0, 0, 200, 120,   1, 0],  # CSRF missing token
    [5, 1, 7.0, 5.0, 3, 1, 9.0, 88, 0, 3, 0.0, 0, 200, 16000, 1, 0],  # SQLi pg_sleep
    [4, 2, 3.0, 4.0, 2, 1, 7.0, 72, 0, 2, 0.0, 0, 200, 180,   1, 0],  # XSS SVG
    [4, 4, 3.5, 4.0, 2, 0, 6.5, 68, 0, 2, 0.0, 0, 200, 110,   1, 0],  # CSRF token bypass
]

# FP findings (label=1): Should be filtered (Moodle FPs)
fp_samples = [
    [1, 2, 2.0, 3.0, 2, 0, 0, 0, 2, 0, 1.0, 1, 200, 100, 1, 0],  # XSS: "input fields detected"
    [1, 8, 1.5, 2.5, 1, 0, 0, 0, 3, 0, 1.0, 1, 200, 80,  1, 0],  # Missing header
    [1, 2, 2.0, 3.0, 1, 0, 0, 0, 2, 0, 1.0, 1, 200, 90,  1, 0],  # XSS: "dangerous html tag"
    [1, 2, 1.5, 2.5, 1, 0, 0, 0, 2, 0, 1.0, 1, 200, 95,  1, 0],  # XSS: "verify xss protection"
    [1, 8, 1.0, 2.0, 1, 0, 0, 0, 3, 0, 1.0, 1, 200, 70,  1, 0],  # Missing CSP header
    [1, 8, 1.0, 2.0, 1, 0, 0, 0, 3, 0, 1.0, 1, 200, 75,  1, 0],  # Missing HSTS
    [1, 2, 2.5, 3.0, 2, 0, 0, 0, 2, 0, 1.0, 1, 200, 88,  1, 0],  # XSS: "form field detected"
    [2, 8, 1.5, 2.5, 1, 0, 0, 0, 2, 0, 1.0, 1, 200, 60,  1, 0],  # Low header missing
    [1, 9, 1.0, 2.0, 1, 0, 0, 0, 3, 0, 1.0, 1, 200, 65,  1, 0],  # CSP info
    [1, 2, 2.0, 3.0, 1, 0, 0, 0, 2, 0, 1.0, 1, 200, 82,  1, 0],  # XSS generic info
]

X_test = np.array(tp_samples + fp_samples)
y_true = [0]*10 + [1]*10  # 0=TP, 1=FP

try:
    X_scaled = scaler.transform(X_test)
    y_pred   = model.predict(X_scaled)
    y_proba  = model.predict_proba(X_scaled)

    correct = sum(p == t for p, t in zip(y_pred, y_true))
    accuracy = correct / len(y_true) * 100

    print(f"  Samples tested : {len(y_true)} (10 TP + 10 FP)")
    print(f"  Accuracy       : {accuracy:.1f}%")
    print()
    print(f"  {'#':<4} {'True':<8} {'Pred':<8} {'Conf':>8}  {'Result'}")
    print(f"  {'-'*50}")
    for i, (true, pred, prob) in enumerate(zip(y_true, y_pred, y_proba)):
        label_true = "TP" if true == 0 else "FP"
        label_pred = "TP" if pred == 0 else "FP"
        conf = prob[pred]
        result = "✓" if pred == true else "✗ WRONG"
        print(f"  {i+1:<4} {label_true:<8} {label_pred:<8} {conf:>7.1%}  {result}")

    # Summary
    tp_correct = sum(p == 0 for p, t in zip(y_pred[:10], y_true[:10]) if t == 0)
    fp_correct = sum(p == 1 for p, t in zip(y_pred[10:], y_true[10:]) if t == 1)
    print(f"\n  TP correctly identified (not filtered): {tp_correct}/10")
    print(f"  FP correctly identified (filtered):     {fp_correct}/10")

    if accuracy >= 80:
        verdict = "✅ GOOD — model is effective"
    elif accuracy >= 60:
        verdict = "⚠️  MARGINAL — rule-based backup is necessary"
    else:
        verdict = "❌ POOR — model predicts all same class (needs retraining)"
    print(f"\n  Verdict: {verdict}")

except Exception as e:
    print(f"  [ERROR] Prediction failed: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "=" * 60)
print("Check if this is v2.0 (Calibrated RF+GB Ensemble):")
print("  - Should have CalibratedClassifierCV wrapping VotingClassifier")
print("  - Should have timestamp in pkl")
print("  - Should have 16 features in scaler")
print("=" * 60)
