"""
evaluate_model.py — Evaluasi lengkap FP Reducer v3.0-clean14
Jalankan: cd proxy && python evaluate_model.py
"""
import sys, os, csv, random, json, datetime
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sklearn.model_selection import cross_val_score, StratifiedKFold, train_test_split
from sklearn.metrics import (
    classification_report, confusion_matrix,
    precision_score, recall_score, f1_score,
    roc_auc_score, brier_score_loss, accuracy_score
)
import joblib

random.seed(42)
np.random.seed(42)

print("=" * 65)
print("  FP REDUCER v3.0-clean14 — FULL EVALUATION")
print("=" * 65)

# ── 1. Load model langsung (pkl = RandomForestClassifier) ───────
MODEL_PATH = "ml/models/fp_reducer.pkl"
model = joblib.load(MODEL_PATH)
print(f"\n[OK] Model loaded: {type(model).__name__}")

# ── 2. Load FalsePositiveReducer untuk extract_features ─────────
from ml.false_positive_reducer import FalsePositiveReducer
fp = FalsePositiveReducer()

# ── 3. Rebuild dataset dari CSV (same as deploy_clean14.py) ─────
proxy_dir = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.join(proxy_dir, 'ml', 'training_data',
                        'phase3_balanced_dataset_FINAL.csv')
if not os.path.exists(csv_path):
    print(f"[ERROR] CSV tidak ditemukan: {csv_path}")
    sys.exit(1)

rows = []
with open(csv_path) as f:
    for row in csv.DictReader(f):
        rows.append(row)

attacks = [r for r in rows if float(r['label']) == 1.0]
normals = [r for r in rows if float(r['label']) == 0.0]
print(f"[DATA] CSV: {len(attacks)} attacks (TP), {len(normals)} normals (FP)")

TP_TEMPLATES = [
    {'severity':'Critical','category':'SQL Injection',
     'description':'SQL Injection detected in parameter via payload injection',
     'evidence':'SQL error pattern found after injecting payload. Error writing to database.',
     'url':'http://localhost:8998/login/index.php'},
    {'severity':'Critical','category':'SQL Injection',
     'description':'Time-based blind SQL Injection detected',
     'evidence':'Payload with sleep/delay caused timeout.',
     'url':'http://localhost:8998/course/view.php?id=1'},
    {'severity':'High','category':'SQL Injection',
     'description':'Potential SQL Injection - HTTP 500 after payload',
     'evidence':'HTTP 500 returned after injecting SQL payload.',
     'url':'http://localhost:8998/mod/quiz/attempt.php?attempt=1'},
    {'severity':'High','category':'Cross-Site Scripting (XSS)',
     'description':'Reflected XSS via Payload detected in parameter',
     'evidence':'JavaScript code reflected in response.',
     'url':'http://localhost:8998/search/index.php?q=test'},
    {'severity':'High','category':'Cross-Site Request Forgery (CSRF)',
     'description':'CSRF protection bypass - missing sesskey validation',
     'evidence':'Request without valid CSRF token was accepted.',
     'url':'http://localhost:8998/user/editadvanced.php?id=2'},
    {'severity':'Medium','category':'SQL Injection',
     'description':'Possible SQL Injection in parameter',
     'evidence':'Unusual database response after payload injection.',
     'url':'http://localhost:8998/course/search.php?search=test'},
    {'severity':'Medium','category':'Cross-Site Scripting (XSS)',
     'description':'Possible XSS detected - payload partially reflected',
     'evidence':'Part of injected payload found in response body.',
     'url':'http://localhost:8998/message/index.php'},
    {'severity':'Low','category':'Cross-Site Request Forgery (CSRF)',
     'description':'Weak CSRF protection on form endpoint',
     'evidence':'Form accepts requests with expired session token.',
     'url':'http://localhost:8998/user/preferences.php'},
]
FP_TEMPLATES = [
    {'severity':'Info','category':'Cross-Site Scripting (XSS)',
     'description':'Found input field(s) - verify XSS protection on each field',
     'evidence':'Input fields detected. Ensure proper output encoding.',
     'url':'http://localhost:8998/login/index.php'},
    {'severity':'Info','category':'Cross-Site Scripting (XSS)',
     'description':'Potentially dangerous HTML tag detected in response',
     'evidence':'Page contains script tag from legitimate Moodle JS.',
     'url':'http://localhost:8998/my/'},
    {'severity':'Info','category':'Security Header',
     'description':'Missing security header - not set, best practice recommendation',
     'evidence':'Response header missing. Informational finding.',
     'url':'http://localhost:8998/'},
    {'severity':'Low','category':'Security Header',
     'description':'Content-Security-Policy header not implemented',
     'evidence':'Missing CSP header. Best practice recommendation.',
     'url':'http://localhost:8998/'},
    {'severity':'Info','category':'Information Disclosure',
     'description':'Version disclosure in response - banner information detected',
     'evidence':'Server version information disclosed in header.',
     'url':'http://localhost:8998/lib/ajax/service.php'},
    {'severity':'High','category':'Cross-Site Scripting (XSS)',
     'description':'Potential XSS detected in Moodle form parameter',
     'evidence':'Form parameter value appears unescaped in response HTML.',
     'url':'http://localhost:8998/course/edit.php?id=1'},
    {'severity':'Medium','category':'Cross-Site Scripting (XSS)',
     'description':'Suspicious script tag found in page response',
     'evidence':'Script element found in response. Moodle uses inline JS.',
     'url':'http://localhost:8998/mod/forum/view.php?id=1'},
    {'severity':'Medium','category':'Security Misconfiguration',
     'description':'Server configuration may expose sensitive information',
     'evidence':'Debug information visible in response.',
     'url':'http://localhost:8998/admin/index.php'},
]

def make_sample(row, is_attack):
    """Buat sample features + label dari CSV row + template."""
    status  = int(float(row['response_status']))
    time_ms = float(row['request_time_ms'])
    ctx = {'status_code': status, 'response_time': time_ms,
           'occurrence_count': 1, 'days_since_first_seen': 0}
    tmpl = random.choice(TP_TEMPLATES if is_attack else FP_TEMPLATES)
    finding = dict(tmpl)
    finding['cvss_score'] = 0.0
    finding['risk_score']  = 0.0
    features = fp.extract_features(finding, ctx)
    label = 0 if is_attack else 1  # 0=TP, 1=FP
    return features, label

# Build dataset (same as deploy_clean14.py)
n_real = min(len(attacks), len(normals), 38)
sel_attacks = random.sample(attacks, n_real)
sel_normals = random.sample(normals, n_real)

all_X, all_y = [], []
for r in sel_attacks:
    x, y = make_sample(r, True);  all_X.append(x); all_y.append(y)
for r in sel_normals:
    x, y = make_sample(r, False); all_X.append(x); all_y.append(y)

# +40 synthetic TP augmentation
for _ in range(40):
    x, y = make_sample(random.choice(attacks), True)
    all_X.append(x); all_y.append(y)

# +8 synthetic FP
for _ in range(8):
    x, y = make_sample(random.choice(normals), False)
    all_X.append(x); all_y.append(y)

X = np.array(all_X, dtype=float)
y = np.array(all_y)

# Trim to model's n_features if needed
n_feat = model.n_features_in_ if hasattr(model, 'n_features_in_') else X.shape[1]
X = X[:, :n_feat]
print(f"[DATA] Total: {len(y)} | TP(0)={sum(y==0)} | FP(1)={sum(y==1)} | Features={n_feat}")

# ── 4. Train/test split ─────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=22, random_state=42, stratify=y)
print(f"[SPLIT] Train={len(y_train)} | Holdout test={len(y_test)}")

# ── 5. 5-Fold CV ────────────────────────────────────────────────
print("\n" + "─"*65)
print("  5-FOLD CROSS-VALIDATION")
print("─"*65)
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_results = {}
for metric in ['accuracy', 'precision', 'recall', 'f1']:
    scores = cross_val_score(model, X_train, y_train, cv=cv, scoring=metric)
    cv_results[metric] = {'mean': round(scores.mean(),4), 'std': round(scores.std(),4),
                          'min': round(scores.min(),4), 'max': round(scores.max(),4)}
    print(f"  {metric.upper():12s}: {scores.mean():.4f} ± {scores.std():.4f}"
          f"  [min={scores.min():.4f}, max={scores.max():.4f}]")

# ── 6. Holdout test ─────────────────────────────────────────────
print("\n" + "─"*65)
print("  HOLDOUT TEST SET (22 samples)")
print("─"*65)
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, zero_division=0)
rec  = recall_score(y_test, y_pred, zero_division=0)
f1   = f1_score(y_test, y_pred, zero_division=0)
try:    auc = roc_auc_score(y_test, y_prob)
except: auc = float('nan')

print(f"\n  Accuracy  : {acc:.4f}  ({acc*100:.1f}%)")
print(f"  Precision : {prec:.4f}  ({prec*100:.1f}%)")
print(f"  Recall    : {rec:.4f}  ({rec*100:.1f}%)")
print(f"  F1-Score  : {f1:.4f}  ({f1*100:.1f}%)")
print(f"  ROC-AUC   : {auc:.4f}")

cm = confusion_matrix(y_test, y_pred)
print(f"\n  Confusion Matrix:")
print(f"               Pred:TP   Pred:FP")
print(f"  Actual:TP  [{cm[0][0]:5d}   ] [{cm[0][1]:5d}   ]")
print(f"  Actual:FP  [{cm[1][0]:5d}   ] [{cm[1][1]:5d}   ]")
print(f"\n{classification_report(y_test, y_pred, target_names=['True Positive','False Positive'])}")

# ── 7. Calibration ──────────────────────────────────────────────
print("─"*65)
print("  CALIBRATION (Brier Score)")
print("─"*65)
brier = brier_score_loss(y_test, y_prob)
cal_score = round(1.0 - (brier / 0.25), 4)  # normalized 0-1
print(f"\n  Brier Score       : {brier:.4f}  (0=perfect, 0.25=random)")
print(f"  Calibration Score : {cal_score:.4f}  (1=perfect)")
print(f"  Target ≥ 0.85     : {'✅ PASS' if cal_score >= 0.85 else '❌ FAIL'}")

# ── 8. Acceptance Criteria ──────────────────────────────────────
print("\n" + "="*65)
print("  ACCEPTANCE CRITERIA — HASIL AKTUAL")
print("="*65)
checks = [
    ("CV Accuracy ≥ 90%",       cv_results['accuracy']['mean'] >= 0.90,  f"{cv_results['accuracy']['mean']*100:.1f}% ± {cv_results['accuracy']['std']*100:.1f}%"),
    ("CV Precision ≥ 90%",      cv_results['precision']['mean'] >= 0.90, f"{cv_results['precision']['mean']*100:.1f}% ± {cv_results['precision']['std']*100:.1f}%"),
    ("CV Recall ≥ 85%",         cv_results['recall']['mean'] >= 0.85,    f"{cv_results['recall']['mean']*100:.1f}% ± {cv_results['recall']['std']*100:.1f}%"),
    ("Holdout Accuracy ≥ 80%",  acc  >= 0.80,  f"{acc*100:.1f}%"),
    ("Holdout Precision ≥ 90%", prec >= 0.90,  f"{prec*100:.1f}%"),
    ("Holdout Recall ≥ 85%",    rec  >= 0.85,  f"{rec*100:.1f}%"),
    ("Holdout F1 ≥ 85%",        f1   >= 0.85,  f"{f1*100:.1f}%"),
    ("Calibration Score ≥ 0.85",cal_score>=0.85, f"{cal_score:.4f}"),
]
for name, passed, val in checks:
    icon = "✅" if passed else "❌"
    print(f"  {icon} {name:35s} → {val}")

# ── 9. Save JSON ────────────────────────────────────────────────
results = {
    "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    "model_type": type(model).__name__,
    "n_features": int(n_feat),
    "dataset": {"n_total": len(y), "n_train": len(y_train),
                 "n_holdout": len(y_test),
                 "n_tp": int(sum(y==0)), "n_fp": int(sum(y==1))},
    "cv_5fold": cv_results,
    "holdout": {
        "accuracy": round(acc,4), "precision": round(prec,4),
        "recall": round(rec,4), "f1": round(f1,4),
        "roc_auc": round(auc,4) if not np.isnan(auc) else None,
        "brier_score": round(brier,4),
        "calibration_score": cal_score,
    },
    "confusion_matrix": cm.tolist(),
    "acceptance_criteria": {c[0]: bool(c[1]) for c in checks},
}
out = "fp_reducer_evaluation_results.json"
with open(out, 'w') as f:
    json.dump(results, f, indent=2)
print(f"\n[OK] Results saved → proxy/{out}")
print("=" * 65)
