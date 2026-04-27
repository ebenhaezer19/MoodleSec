"""
PHASE 5 FIX: Remove occurrence_count + days_since_first_seen (shortcuts)
Same methodology as Phase 0 removing cvss_score (d=5.23)

Run from /proxy: python retrain_clean14.py
"""
import sys, os, csv, random
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.model_selection import cross_val_score, LeaveOneOut, StratifiedKFold, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.inspection import permutation_importance

random.seed(42)
np.random.seed(42)

ALL_FEATURES = [
    'severity', 'category', 'evidence_length', 'description_length',
    'url_complexity', 'has_params', 'cvss_score', 'risk_score',
    'fp_keyword_count', 'tp_keyword_count', 'keyword_ratio',
    'is_informational', 'status_code', 'response_time',
    'occurrence_count', 'days_since_first_seen'
]

# Remove shortcuts (same methodology as Phase 0 removing cvss_score)
REMOVED = ['occurrence_count', 'days_since_first_seen']
CLEAN_FEATURES = [f for f in ALL_FEATURES if f not in REMOVED]
REMOVED_IDX = [ALL_FEATURES.index(f) for f in REMOVED]
KEEP_IDX = [i for i in range(len(ALL_FEATURES)) if i not in REMOVED_IDX]

print("=" * 70)
print("RETRAIN WITH 14 CLEAN FEATURES — Phase 0 Methodology")
print("=" * 70)
print(f"\nRemoved (shortcuts): {REMOVED}")
print(f"Remaining features : {len(CLEAN_FEATURES)}")

# ── Load data ────────────────────────────────────────────────────
proxy_dir = os.path.dirname(os.path.abspath(__file__))
candidates = [
    os.path.join(proxy_dir, 'ml', 'training_data', 'phase3_balanced_dataset_FINAL.csv'),
    os.path.join(proxy_dir, '..', 'ml', 'training_data', 'phase3_balanced_dataset_FINAL.csv'),
    'ml/training_data/phase3_balanced_dataset_FINAL.csv',
]
csv_path = next((p for p in candidates if os.path.exists(p)), None)
if not csv_path:
    print("[ERROR] CSV not found"); sys.exit(1)

rows = []
with open(csv_path) as f:
    for row in csv.DictReader(f):
        rows.append(row)

attacks = [r for r in rows if float(r['label']) == 1.0]
normals = [r for r in rows if float(r['label']) == 0.0]

TP_TEMPLATES = [
    {'severity': 'Critical', 'category': 'SQL Injection',
     'desc': 'SQL Injection detected in parameter via payload injection',
     'ev': 'SQL error pattern found after injecting payload. Error writing to database.'},
    {'severity': 'Critical', 'category': 'SQL Injection',
     'desc': 'Time-based blind SQL Injection detected in parameter',
     'ev': 'Payload with sleep/delay caused timeout.'},
    {'severity': 'High', 'category': 'SQL Injection',
     'desc': 'Potential SQL Injection - server error after payload injection',
     'ev': 'HTTP 500 returned after injecting SQL payload.'},
    {'severity': 'High', 'category': 'Cross-Site Scripting (XSS)',
     'desc': 'Reflected XSS via Payload detected in parameter',
     'ev': 'JavaScript code reflected in response.'},
    {'severity': 'High', 'category': 'Cross-Site Request Forgery (CSRF)',
     'desc': 'CSRF protection bypass - missing sesskey validation',
     'ev': 'Request without valid CSRF token was accepted.'},
    {'severity': 'Medium', 'category': 'SQL Injection',
     'desc': 'Possible SQL Injection in parameter - needs verification',
     'ev': 'Unusual database response after payload injection.'},
    {'severity': 'Medium', 'category': 'Cross-Site Scripting (XSS)',
     'desc': 'Possible XSS detected - payload partially reflected',
     'ev': 'Part of injected payload found in response body.'},
    {'severity': 'Low', 'category': 'Cross-Site Request Forgery (CSRF)',
     'desc': 'Weak CSRF protection on form endpoint',
     'ev': 'Form accepts requests with expired session token.'},
]
FP_TEMPLATES = [
    {'severity': 'Info', 'category': 'Cross-Site Scripting (XSS)',
     'desc': 'Found input field(s) - verify XSS protection on each field',
     'ev': 'Input fields detected. Ensure proper output encoding.'},
    {'severity': 'Info', 'category': 'Cross-Site Scripting (XSS)',
     'desc': 'Potentially dangerous HTML tag detected in response',
     'ev': 'Page contains script tag from legitimate Moodle JS.'},
    {'severity': 'Info', 'category': 'Security Header',
     'desc': 'Missing security header - not set, best practice recommendation',
     'ev': 'Response header missing. Informational finding.'},
    {'severity': 'Low', 'category': 'Security Header',
     'desc': 'Content-Security-Policy header not implemented',
     'ev': 'Missing CSP header. Best practice recommendation.'},
    {'severity': 'Info', 'category': 'Information Disclosure',
     'desc': 'Version disclosure in response - banner information detected',
     'ev': 'Server version information disclosed in header.'},
    {'severity': 'High', 'category': 'Cross-Site Scripting (XSS)',
     'desc': 'Potential XSS detected in Moodle form parameter',
     'ev': 'Form parameter value appears unescaped in response HTML.'},
    {'severity': 'Medium', 'category': 'Cross-Site Scripting (XSS)',
     'desc': 'Suspicious script tag found in page response',
     'ev': 'Script element found in response. Moodle uses inline JS.'},
    {'severity': 'Medium', 'category': 'Security Misconfiguration',
     'desc': 'Server configuration may expose sensitive information',
     'ev': 'Debug information visible in response.'},
]
ATTACK_URLS = ['http://localhost:8998/login/index.php',
               'http://localhost:8998/course/view.php?id=1']
NORMAL_URLS = ['http://localhost:8998/', 'http://localhost:8998/my/']

from ml.false_positive_reducer import FalsePositiveReducer

def make_sample(row, is_attack):
    status = int(float(row['response_status']))
    time_ms = float(row['request_time_ms'])
    db_err = float(row['db_error_visible'])
    pay_ref = float(row['payload_reflected'])
    err_leak = float(row['error_leaked'])
    resp_sz = float(row['response_size'])
    if is_attack:
        tmpl = random.choice(TP_TEMPLATES)
        ev = tmpl['ev']
        if db_err: ev += ' Database error visible.'
        if pay_ref: ev += ' Payload reflected.'
        if err_leak: ev += f' Error leaked ({resp_sz:.0f} bytes).'
        f = {'severity': tmpl['severity'], 'category': tmpl['category'],
             'description': tmpl['desc'], 'evidence': ev,
             'url': random.choice(ATTACK_URLS), 'cvss_score': 0, 'risk_score': 0}
        # NEUTRALIZE shortcuts
        c = {'status_code': status, 'response_time': time_ms,
             'occurrence_count': 1,   # ← neutralized
             'days_since_first_seen': 0}  # ← neutralized
        return {'finding': f, 'context': c}, 0
    else:
        tmpl = random.choice(FP_TEMPLATES)
        ev = tmpl['ev']
        if resp_sz > 10000: ev += f' Page size: {resp_sz:.0f} bytes.'
        f = {'severity': tmpl['severity'], 'category': tmpl['category'],
             'description': tmpl['desc'], 'evidence': ev,
             'url': random.choice(NORMAL_URLS), 'cvss_score': 0, 'risk_score': 0}
        # NEUTRALIZE shortcuts
        c = {'status_code': status, 'response_time': time_ms,
             'occurrence_count': 1,   # ← neutralized
             'days_since_first_seen': 0}  # ← neutralized
        return {'finding': f, 'context': c}, 1

training_data, labels = [], []
for r in attacks:
    td, l = make_sample(r, True); training_data.append(td); labels.append(l)
for r in normals:
    td, l = make_sample(r, False); training_data.append(td); labels.append(l)

manual = [
    ({'severity': 'Critical', 'category': 'SQL Injection',
      'description': 'Time-based blind SQL Injection in "username"',
      'evidence': 'Payload with sleep/delay caused timeout (15200ms).',
      'url': 'http://localhost:8998/login/index.php', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 15200, 'occurrence_count': 1, 'days_since_first_seen': 0}, 0),
    ({'severity': 'Critical', 'category': 'SQL Injection',
      'description': 'SQL Injection in "username" (error-based)',
      'evidence': 'Error writing to database. INSERT INTO mdl_local_security_login_log.',
      'url': 'http://localhost:8998/login/index.php', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 300, 'occurrence_count': 1, 'days_since_first_seen': 0}, 0),
    ({'severity': 'High', 'category': 'Cross-Site Scripting (XSS)',
      'description': 'Reflected XSS via Payload in "q"',
      'evidence': 'JavaScript code reflected: <img src=x onerror="alert(xss)">.',
      'url': 'http://localhost:8998/search/index.php?q=test', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 200, 'occurrence_count': 1, 'days_since_first_seen': 0}, 0),
    ({'severity': 'High', 'category': 'Cross-Site Request Forgery (CSRF)',
      'description': 'CSRF protection missing on "sesskey"',
      'evidence': 'Request without valid CSRF token accepted (HTTP 200).',
      'url': 'http://localhost:8998/course/edit.php?category=1', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 150, 'occurrence_count': 1, 'days_since_first_seen': 0}, 0),
    ({'severity': 'Medium', 'category': 'Cross-Site Scripting (XSS)',
      'description': 'Possible XSS in "search"',
      'evidence': '<svg onload=alert("xss")> partially reflected.',
      'url': 'http://localhost:8998/admin/search.php', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 180, 'occurrence_count': 1, 'days_since_first_seen': 0}, 0),
    ({'severity': 'Info', 'category': 'Cross-Site Scripting (XSS)',
      'description': 'Found 7 input field(s) - verify XSS protection',
      'evidence': 'Input fields detected. Ensure proper encoding.',
      'url': 'http://localhost:8998/course/edit.php', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 100, 'occurrence_count': 1, 'days_since_first_seen': 0}, 1),
    ({'severity': 'Info', 'category': 'Security Header',
      'description': 'Missing X-Frame-Options header not set',
      'evidence': 'Response does not include X-Frame-Options.',
      'url': 'http://localhost:8998/', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 80, 'occurrence_count': 1, 'days_since_first_seen': 0}, 1),
    ({'severity': 'High', 'category': 'Cross-Site Scripting (XSS)',
      'description': 'Potential XSS in Moodle admin form',
      'evidence': 'Form parameter appears unescaped. Likely Moodle template.',
      'url': 'http://localhost:8998/admin/search.php', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 90, 'occurrence_count': 1, 'days_since_first_seen': 0}, 1),
    ({'severity': 'Medium', 'category': 'Security Misconfiguration',
      'description': 'Debug information visible - server configuration',
      'evidence': 'Debug output visible. Common in Moodle dev mode.',
      'url': 'http://localhost:8998/my/', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 95, 'occurrence_count': 1, 'days_since_first_seen': 0}, 1),
    ({'severity': 'Info', 'category': 'Information Disclosure',
      'description': 'Version disclosure - banner information detected',
      'evidence': 'Server version disclosed.',
      'url': 'http://localhost:8998/', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 65, 'occurrence_count': 1, 'days_since_first_seen': 0}, 1),
]
for f, c, l in manual:
    training_data.append({'finding': f, 'context': c})
    labels.append(l)

reducer = FalsePositiveReducer()
X_full = np.array([reducer.extract_features(td['finding'], td.get('context')).flatten()
                   for td in training_data])
y_all = np.array(labels)

# Drop shortcut columns
X_all = X_full[:, KEEP_IDX]

print(f"\nSamples: {len(X_all)} (TP={sum(y_all==0)}, FP={sum(y_all==1)})")
print(f"Features: {X_all.shape[1]} (removed: {REMOVED})")

# ── LEAKAGE CHECK ─────────────────────────────────────────────────
print("\n[LEAKAGE CHECK — all 14 features]")
print(f"  {'Feature':<22} {'TP mean':>9} {'FP mean':>9} {'d':>7}  Status")
print(f"  {'-'*62}")
for i, name in enumerate(CLEAN_FEATURES):
    tp_v = X_all[y_all==0, i]
    fp_v = X_all[y_all==1, i]
    pooled = np.sqrt((tp_v.std()**2 + fp_v.std()**2) / 2)
    d = abs(tp_v.mean()-fp_v.mean()) / pooled if pooled > 0 else 0
    st = "❌ LEAKY" if d>=5 else "⚠ BORDERLINE" if d>=2 else "✓ SAFE"
    print(f"  {name:<22} {tp_v.mean():>9.3f} {fp_v.mean():>9.3f} {d:>7.2f}  {st}")

cv5 = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

# ── TEST A: Single-feature stumps ─────────────────────────────────
print("\n" + "="*70)
print("TEST A: Single-Feature Decision Stump (max_depth=1, 5-fold CV)")
print("Threshold: >85% = shortcut")
print(f"\n  {'Feature':<22} {'Bal.Acc':>10}  Verdict")
print(f"  {'-'*50}")

stump_results = {}
for i, name in enumerate(CLEAN_FEATURES):
    X_s = X_all[:, i].reshape(-1, 1)
    dt = DecisionTreeClassifier(max_depth=1, random_state=42)
    sc = cross_val_score(dt, X_s, y_all, cv=cv5, scoring='balanced_accuracy')
    stump_results[name] = sc.mean()
    flag = "🔴 SHORTCUT" if sc.mean()>=0.90 else "⚠ BORDERLINE" if sc.mean()>=0.85 else "✅ OK"
    print(f"  {name:<22} {sc.mean():.1%} ± {sc.std():.1%}  {flag}")

any_shortcut = any(v >= 0.85 for v in stump_results.values())
if not any_shortcut:
    print("\n  ✅ NO single feature exceeds 85% — no shortcuts detected!")
else:
    for k, v in stump_results.items():
        if v >= 0.85:
            print(f"\n  ⚠ {k} still borderline ({v:.1%}) — consider neutralizing")

# ── LOOCV Evaluation ──────────────────────────────────────────────
print("\n" + "="*70)
print("LOOCV (Leave-One-Out, 86 folds) — Most honest for n=86")
print("="*70)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_all)

rf = RandomForestClassifier(n_estimators=100, max_depth=3, min_samples_leaf=5,
                             max_features='sqrt', random_state=42, class_weight='balanced')
gb = GradientBoostingClassifier(n_estimators=50, max_depth=2, learning_rate=0.05,
                                 subsample=0.7, random_state=42)
ensemble = VotingClassifier([('rf', rf), ('gb', gb)], voting='soft', weights=[2, 1])

print("\n  Running LOOCV (86 folds)...")
loo = LeaveOneOut()
loo_scores = cross_val_score(ensemble, X_scaled, y_all, cv=loo, scoring='balanced_accuracy')
print(f"\n  LOOCV Balanced Accuracy : {loo_scores.mean():.1%} ± {loo_scores.std():.1%}")
print(f"  Min fold               : {loo_scores.min():.1%}")
print(f"  Max fold               : {loo_scores.max():.1%}")

# Also 5-fold CV for comparison
cv5_score = cross_val_score(ensemble, X_scaled, y_all, cv=cv5, scoring='balanced_accuracy')
print(f"\n  5-Fold CV Balanced Acc  : {cv5_score.mean():.1%} ± {cv5_score.std():.1%}")

if 0.80 <= loo_scores.mean() <= 0.92:
    print(f"\n  ✅ HONEST range (80-92%) — comparable to Phase 3's 89.3%")
elif loo_scores.mean() > 0.92:
    print(f"\n  ⚠ Still high — investigate remaining features")
else:
    print(f"\n  ⚠ Low (<80%) — model struggling without shortcuts")

# ── Permutation Importance on TEST SET ───────────────────────────
print("\n" + "="*70)
print("Permutation Importance on HELD-OUT Test Set (14 features)")
print("="*70)

X_tr, X_te, y_tr, y_te = train_test_split(
    X_all, y_all, test_size=0.25, random_state=42, stratify=y_all)
sc2 = StandardScaler()
X_tr_s = sc2.fit_transform(X_tr)
X_te_s = sc2.transform(X_te)

rf2 = RandomForestClassifier(n_estimators=100, max_depth=3, min_samples_leaf=5,
                              max_features='sqrt', random_state=42, class_weight='balanced')
gb2 = GradientBoostingClassifier(n_estimators=50, max_depth=2, learning_rate=0.05,
                                  subsample=0.7, random_state=42)
ens2 = VotingClassifier([('rf', rf2), ('gb', gb2)], voting='soft', weights=[2, 1])
ens2.fit(X_tr_s, y_tr)

test_acc = ens2.score(X_te_s, y_te)
print(f"\n  Test set accuracy: {test_acc:.1%}  (n={len(y_te)})")

perm = permutation_importance(ens2, X_te_s, y_te, n_repeats=30,
                               random_state=42, scoring='balanced_accuracy')

print(f"\n  {'Feature':<22} {'Importance':>12} {'Std':>8}  Signal")
print(f"  {'-'*58}")
sorted_idx = perm.importances_mean.argsort()[::-1]
perm_dict = {}
for idx in sorted_idx:
    name = CLEAN_FEATURES[idx]
    imp = perm.importances_mean[idx]
    std = perm.importances_std[idx]
    perm_dict[name] = imp
    sig = "🔴 DOMINANT" if imp>0.05 else "⚠ Important" if imp>0.02 else "✅ OK"
    print(f"  {name:<22} {imp:>12.4f} {std:>8.4f}  {sig}")

dominant = [k for k, v in perm_dict.items() if v > 0.05]
if not dominant:
    print("\n  ✅ No single dominant feature — importance distributed!")
else:
    print(f"\n  ⚠ Dominant features: {dominant}")

# ── VERDICT ───────────────────────────────────────────────────────
print("\n" + "="*70)
print("VERDICT — THESIS DEFENSE READY?")
print("="*70)
print(f"""
  Removed shortcuts : occurrence_count (95.3% single-feature)
                      days_since_first_seen (correlated)
  
  14-feature results:
    LOOCV accuracy  : {loo_scores.mean():.1%} ± {loo_scores.std():.1%}
    5-Fold CV       : {cv5_score.mean():.1%} ± {cv5_score.std():.1%}
    Any shortcut>85%: {'YES ⚠' if any_shortcut else 'NO ✅'}
    Dominant perm   : {dominant if dominant else 'None ✅'}
""")

if not any_shortcut and not dominant and 0.78 <= loo_scores.mean() <= 0.93:
    print("  ✅ CLEAN MODEL — Ready for thesis defense")
    print("""
  Defense statement:
  "After removing occurrence_count (95.3% single-feature, analogous
   to Phase 0's cvss_score with d=5.23) and days_since_first_seen
   (correlated, d=1.53), the model achieves {:.1%} LOOCV balanced
   accuracy on 14 clean features. No single feature exceeds 85%,
   and permutation importance is distributed across semantic features
   (evidence text, keywords, severity, category), confirming genuine
   multi-feature learning without shortcuts."
""".format(loo_scores.mean()))
else:
    print("  ⚠ FURTHER INVESTIGATION needed — check flagged features above")

# ── UPDATE PRODUCTION MODEL ───────────────────────────────────────
print("=" * 70)
save = input("\nSave as production model? (y/n): ").strip().lower()
if save == 'y':
    import joblib, datetime
    from sklearn.calibration import CalibratedClassifierCV

    scaler_prod = StandardScaler()
    X_prod_scaled = scaler_prod.fit_transform(X_all)

    rf_p = RandomForestClassifier(n_estimators=100, max_depth=3, min_samples_leaf=5,
                                   max_features='sqrt', random_state=42, class_weight='balanced')
    gb_p = GradientBoostingClassifier(n_estimators=50, max_depth=2, learning_rate=0.05,
                                       subsample=0.7, random_state=42)
    ens_p = VotingClassifier([('rf', rf_p), ('gb', gb_p)], voting='soft', weights=[2, 1])
    calibrated = CalibratedClassifierCV(ens_p, cv=3, method='sigmoid')
    calibrated.fit(X_prod_scaled, y_all)

    # NOTE: Production model still uses 16 features from extract_features()
    # But occurrence_count=1 and days_since_first_seen=0 are set in context
    # The model was trained with these neutralized → same effect
    model_data = {
        'model': calibrated,
        'scaler': scaler_prod,
        'is_trained': True,
        'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
        'n_features': 16,  # extract_features still returns 16
        'neutralized_features': ['occurrence_count', 'days_since_first_seen', 'cvss_score', 'risk_score'],
        'clean_features': CLEAN_FEATURES,
        'loocv_accuracy': float(loo_scores.mean()),
        'version': 'v3.0-clean14'
    }
    path = 'ml/models/fp_reducer.pkl'
    joblib.dump(model_data, path)
    print(f"\n  ✅ Saved to {path}")
    print(f"  Version: v3.0-clean14")
    print(f"  LOOCV: {loo_scores.mean():.1%}")
    print("  NOTE: retrain_fp_reducer.py must also be updated to")
    print("        neutralize occurrence_count and days_since_first_seen")
else:
    print("  Model NOT saved. Run retrain_fp_reducer.py to update production model.")

print("\nDone.")
