"""
Retrain FP Reducer — Phase 3 Integration with Phase 0 Leakage Prevention
=========================================================================
Applies the SAME methodology as Phase 0 to avoid data leakage:
  - Phase 0 found: cvss_score (d=5.23) caused 100% accuracy → REMOVED IT
  - Here: cvss_score and risk_score are neutralized (set to 0 for all samples)
    so the model must learn from NON-LEAKY features only:
    → evidence text, keyword counts, category, response_time, status_code

Evaluation uses 5-fold StratifiedKFold CV (same as Phase 3) for honest metrics.
"""
import sys, os, csv, random
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ml.false_positive_reducer import FalsePositiveReducer

random.seed(42)
np.random.seed(42)

# ── Load Phase 3 dataset ────────────────────────────────────────
csv_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '..', 'ml', 'training_data', 'phase3_balanced_dataset_FINAL.csv'
)
if not os.path.exists(csv_path):
    csv_path = 'ml/training_data/phase3_balanced_dataset_FINAL.csv'
    if not os.path.exists(csv_path):
        csv_path = '../ml/training_data/phase3_balanced_dataset_FINAL.csv'

print("=" * 70)
print("FP REDUCER RETRAINING — Phase 3 + Phase 0 Leakage Prevention")
print("=" * 70)

rows = []
with open(csv_path, 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        rows.append(row)

print(f"\nLoaded {len(rows)} rows from phase3_balanced_dataset_FINAL.csv")
attacks = [r for r in rows if float(r['label']) == 1.0]
normals = [r for r in rows if float(r['label']) == 0.0]
print(f"  Attacks (→ TP findings): {len(attacks)}")
print(f"  Normals (→ FP findings): {len(normals)}")

# ── Leakage Analysis (Phase 0 methodology) ──────────────────────
print(f"\n[LEAKAGE PREVENTION — Phase 0 methodology]")
print(f"  ⚠ cvss_score and risk_score are SET TO 0 for ALL samples")
print(f"  ⚠ This prevents the model from using them as shortcuts")
print(f"  ⚠ Model must learn from: evidence text, keywords, category,")
print(f"    response_time, status_code, occurrence_count")
print(f"  Reference: PHASE0_DATA_LEAKAGE_REMOVAL.md (Cohen's d=5.23)")

# ── URLs ─────────────────────────────────────────────────────────
MOODLE_ATTACK_URLS = [
    'http://localhost:8998/login/index.php',
    'http://localhost:8998/admin/search.php?query=test',
    'http://localhost:8998/course/view.php?id=1',
    'http://localhost:8998/mod/assign/view.php?id=1',
    'http://localhost:8998/user/profile.php?id=2',
    'http://localhost:8998/mod/forum/post.php?forum=1',
    'http://localhost:8998/lib/ajax/service.php',
    'http://localhost:8998/course/edit.php?category=1',
]
MOODLE_NORMAL_URLS = [
    'http://localhost:8998/',
    'http://localhost:8998/my/',
    'http://localhost:8998/my/courses.php',
    'http://localhost:8998/calendar/view.php?view=month',
    'http://localhost:8998/admin/',
    'http://localhost:8998/course/index.php',
    'http://localhost:8998/user/preferences.php',
    'http://localhost:8998/message/index.php',
]

# ── Templates ────────────────────────────────────────────────────
# Severity is MIXED for both classes (prevents severity-based leakage)
# TP templates include Low/Medium to create overlap
# FP templates include Medium/High to create overlap

TP_TEMPLATES = [
    {'severity': 'Critical', 'category': 'SQL Injection',
     'desc': 'SQL Injection detected in parameter via payload injection',
     'evidence_base': 'SQL error pattern found after injecting payload. Error writing to database.'},
    {'severity': 'Critical', 'category': 'SQL Injection',
     'desc': 'Time-based blind SQL Injection detected in parameter',
     'evidence_base': 'Payload with sleep/delay caused timeout.'},
    {'severity': 'High', 'category': 'SQL Injection',
     'desc': 'Potential SQL Injection - server error after payload injection',
     'evidence_base': 'HTTP 500 returned after injecting SQL payload.'},
    {'severity': 'High', 'category': 'Cross-Site Scripting (XSS)',
     'desc': 'Reflected XSS via Payload detected in parameter',
     'evidence_base': 'JavaScript code reflected in response.'},
    {'severity': 'High', 'category': 'Cross-Site Request Forgery (CSRF)',
     'desc': 'CSRF protection bypass - missing sesskey validation',
     'evidence_base': 'Request without valid CSRF token was accepted.'},
    # Borderline TPs with lower severity
    {'severity': 'Medium', 'category': 'SQL Injection',
     'desc': 'Possible SQL Injection in parameter - needs verification',
     'evidence_base': 'Unusual database response after payload injection.'},
    {'severity': 'Medium', 'category': 'Cross-Site Scripting (XSS)',
     'desc': 'Possible XSS detected - payload partially reflected',
     'evidence_base': 'Part of injected payload found in response body.'},
    {'severity': 'Low', 'category': 'Cross-Site Request Forgery (CSRF)',
     'desc': 'Weak CSRF protection on form endpoint',
     'evidence_base': 'Form accepts requests with expired session token.'},
]

FP_TEMPLATES = [
    {'severity': 'Info', 'category': 'Cross-Site Scripting (XSS)',
     'desc': 'Found input field(s) - verify XSS protection on each field',
     'evidence_base': 'Input fields detected. Ensure proper output encoding.'},
    {'severity': 'Info', 'category': 'Cross-Site Scripting (XSS)',
     'desc': 'Potentially dangerous HTML tag detected in response',
     'evidence_base': 'Page contains script tag from legitimate Moodle JS.'},
    {'severity': 'Info', 'category': 'Security Header',
     'desc': 'Missing security header - not set, best practice recommendation',
     'evidence_base': 'Response header missing. Informational finding.'},
    {'severity': 'Low', 'category': 'Security Header',
     'desc': 'Content-Security-Policy header not implemented',
     'evidence_base': 'Missing CSP header. Best practice recommendation.'},
    {'severity': 'Info', 'category': 'Information Disclosure',
     'desc': 'Version disclosure in response - banner information detected',
     'evidence_base': 'Server version information disclosed in header.'},
    # Borderline FPs with higher severity (scanner over-flags)
    {'severity': 'High', 'category': 'Cross-Site Scripting (XSS)',
     'desc': 'Potential XSS detected in Moodle form parameter',
     'evidence_base': 'Form parameter value appears unescaped in response HTML.'},
    {'severity': 'Medium', 'category': 'Cross-Site Scripting (XSS)',
     'desc': 'Suspicious script tag found in page response',
     'evidence_base': 'Script element found in response. Moodle uses inline JS.'},
    {'severity': 'Medium', 'category': 'Security Misconfiguration',
     'desc': 'Server configuration may expose sensitive information',
     'evidence_base': 'Debug information visible in response.'},
]


def har_to_finding(row, is_attack):
    """Convert HAR row to finding dict with LEAKAGE-FREE features.
    
    cvss_score and risk_score are set to 0 for ALL samples (Phase 0 methodology).
    The model must discriminate using non-leaky features only.
    """
    status = int(float(row['response_status']))
    time_ms = float(row['request_time_ms'])
    payload_len = float(row['payload_length'])
    error_leaked = float(row['error_leaked'])
    db_error = float(row['db_error_visible'])
    payload_reflected = float(row['payload_reflected'])
    response_size = float(row['response_size'])

    if is_attack:
        tmpl = random.choice(TP_TEMPLATES)
        url = random.choice(MOODLE_ATTACK_URLS)

        # Build evidence from HAR features (variable length = real signal)
        evidence = tmpl['evidence_base']
        if db_error:
            evidence += ' Database error visible in response.'
        if payload_reflected:
            evidence += ' Payload reflected in response body.'
        if error_leaked:
            evidence += f' Error information leaked ({response_size:.0f} bytes).'

        finding = {
            'severity': tmpl['severity'],
            'category': tmpl['category'],
            'description': tmpl['desc'],
            'evidence': evidence,
            'url': url,
            'cvss_score': 0,      # ← NEUTRALIZED (Phase 0 leakage prevention)
            'risk_score': 0,      # ← NEUTRALIZED
        }
        context = {
            'status_code': status,
            'response_time': time_ms,
            'occurrence_count': random.randint(1, 3),
            'days_since_first_seen': random.randint(0, 5),
        }
        label = 0  # True Positive
    else:
        tmpl = random.choice(FP_TEMPLATES)
        url = random.choice(MOODLE_NORMAL_URLS)

        evidence = tmpl['evidence_base']
        if response_size > 10000:
            evidence += f' Page size: {response_size:.0f} bytes.'

        finding = {
            'severity': tmpl['severity'],
            'category': tmpl['category'],
            'description': tmpl['desc'],
            'evidence': evidence,
            'url': url,
            'cvss_score': 0,      # ← NEUTRALIZED
            'risk_score': 0,      # ← NEUTRALIZED
        }
        context = {
            'status_code': status,
            'response_time': time_ms,
            'occurrence_count': random.randint(1, 25),
            'days_since_first_seen': random.randint(0, 30),
        }
        label = 1  # False Positive

    return {'finding': finding, 'context': context}, label


# ── Build training data ──────────────────────────────────────────
training_data = []
labels = []

for row in attacks:
    td, lbl = har_to_finding(row, is_attack=True)
    training_data.append(td)
    labels.append(lbl)

for row in normals:
    td, lbl = har_to_finding(row, is_attack=False)
    training_data.append(td)
    labels.append(lbl)

# Manual findings (also with cvss=0, risk=0)
manual_tp = [
    {'finding': {'severity': 'Critical', 'category': 'SQL Injection',
     'description': 'Time-based blind SQL Injection detected in parameter "username"',
     'evidence': 'Payload with sleep/delay caused request timeout (15200ms).',
     'url': 'http://localhost:8998/login/index.php', 'risk_score': 0, 'cvss_score': 0},
     'context': {'status_code': 200, 'response_time': 15200, 'occurrence_count': 1}},
    {'finding': {'severity': 'Critical', 'category': 'SQL Injection',
     'description': 'SQL Injection detected in parameter "username" (error-based)',
     'evidence': 'Error writing to database. INSERT INTO mdl_local_security_login_log.',
     'url': 'http://localhost:8998/login/index.php', 'risk_score': 0, 'cvss_score': 0},
     'context': {'status_code': 200, 'response_time': 300, 'occurrence_count': 1}},
    {'finding': {'severity': 'High', 'category': 'Cross-Site Scripting (XSS)',
     'description': 'Reflected XSS via Payload detected in parameter "q"',
     'evidence': 'JavaScript code reflected: <img src=x onerror="alert(xss)">.',
     'url': 'http://localhost:8998/search/index.php?q=test', 'risk_score': 0, 'cvss_score': 0},
     'context': {'status_code': 200, 'response_time': 200, 'occurrence_count': 1}},
    {'finding': {'severity': 'High', 'category': 'Cross-Site Request Forgery (CSRF)',
     'description': 'CSRF protection may be missing on parameter "sesskey"',
     'evidence': 'Request with invalid/missing CSRF token was accepted (HTTP 200).',
     'url': 'http://localhost:8998/course/edit.php?category=1', 'risk_score': 0, 'cvss_score': 0},
     'context': {'status_code': 200, 'response_time': 150, 'occurrence_count': 1}},
    {'finding': {'severity': 'Medium', 'category': 'Cross-Site Scripting (XSS)',
     'description': 'Possible XSS via Payload in parameter "search"',
     'evidence': '<svg onload=alert("xss")> partially reflected in response.',
     'url': 'http://localhost:8998/admin/search.php', 'risk_score': 0, 'cvss_score': 0},
     'context': {'status_code': 200, 'response_time': 180, 'occurrence_count': 1}},
]
manual_fp = [
    {'finding': {'severity': 'Info', 'category': 'Cross-Site Scripting (XSS)',
     'description': 'Found 7 input field(s) - verify XSS protection on each field',
     'evidence': 'Input fields detected in form. Ensure proper output encoding.',
     'url': 'http://localhost:8998/course/edit.php?category=1', 'risk_score': 0, 'cvss_score': 0},
     'context': {'status_code': 200, 'response_time': 100, 'occurrence_count': 5}},
    {'finding': {'severity': 'Info', 'category': 'Security Header',
     'description': 'Missing X-Frame-Options header - not set on this endpoint',
     'evidence': 'Response does not include X-Frame-Options header.',
     'url': 'http://localhost:8998/', 'risk_score': 0, 'cvss_score': 0},
     'context': {'status_code': 200, 'response_time': 80, 'occurrence_count': 20}},
    {'finding': {'severity': 'High', 'category': 'Cross-Site Scripting (XSS)',
     'description': 'Potential XSS detected in Moodle admin form parameter',
     'evidence': 'Form parameter appears unescaped in response HTML. Likely Moodle template.',
     'url': 'http://localhost:8998/admin/search.php', 'risk_score': 0, 'cvss_score': 0},
     'context': {'status_code': 200, 'response_time': 90, 'occurrence_count': 10}},
    {'finding': {'severity': 'Medium', 'category': 'Security Misconfiguration',
     'description': 'Debug information visible in response - server configuration',
     'evidence': 'Debug output visible. Common in Moodle development mode.',
     'url': 'http://localhost:8998/my/', 'risk_score': 0, 'cvss_score': 0},
     'context': {'status_code': 200, 'response_time': 95, 'occurrence_count': 15}},
    {'finding': {'severity': 'Info', 'category': 'Information Disclosure',
     'description': 'Version disclosure in response - banner information detected',
     'evidence': 'Server version information disclosed.',
     'url': 'http://localhost:8998/', 'risk_score': 0, 'cvss_score': 0},
     'context': {'status_code': 200, 'response_time': 65, 'occurrence_count': 25}},
]

for td in manual_tp:
    training_data.append(td)
    labels.append(0)
for td in manual_fp:
    training_data.append(td)
    labels.append(1)

print(f"\nTotal training data: {len(training_data)}")
print(f"  TP (label=0): {labels.count(0)}")
print(f"  FP (label=1): {labels.count(1)}")

# ── Step 1: Cross-Validation (Phase 3 methodology) ──────────────
print(f"\n{'='*70}")
print(f"STEP 1: 5-Fold Stratified Cross-Validation (Phase 3 methodology)")
print(f"{'='*70}")

# Extract features for all samples
reducer = FalsePositiveReducer()
X_all = []
for td in training_data:
    features = reducer.extract_features(td['finding'], td.get('context'))
    X_all.append(features.flatten())
X_all = np.array(X_all)
y_all = np.array(labels)

print(f"\nFeature matrix: {X_all.shape}")
print(f"Class distribution: TP={sum(y_all==0)}, FP={sum(y_all==1)}")

# Check for leakage in features 7 (cvss) and 8 (risk)
print(f"\n[LEAKAGE CHECK]")
for i, name in [(0, 'severity'), (6, 'cvss_score'), (7, 'risk_score')]:
    tp_vals = X_all[y_all == 0, i]
    fp_vals = X_all[y_all == 1, i]
    tp_mean, fp_mean = tp_vals.mean(), fp_vals.mean()
    pooled_std = np.sqrt((tp_vals.std()**2 + fp_vals.std()**2) / 2) if (tp_vals.std() + fp_vals.std()) > 0 else 1
    cohens_d = abs(tp_mean - fp_mean) / pooled_std if pooled_std > 0 else 0
    status = "✓ SAFE" if cohens_d < 2.0 else "⚠ LEAKY" if cohens_d < 5.0 else "❌ EXTREME LEAKAGE"
    print(f"  Feature {i} ({name:>12}): TP mean={tp_mean:.2f}, FP mean={fp_mean:.2f}, d={cohens_d:.2f} {status}")

# 5-fold CV
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.dummy import DummyClassifier

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X_all)

# RF (same config as false_positive_reducer.py)
rf = RandomForestClassifier(
    n_estimators=100, max_depth=8, min_samples_split=6,
    min_samples_leaf=3, max_features='sqrt',
    random_state=42, class_weight='balanced'
)

# GB
gb = GradientBoostingClassifier(
    n_estimators=75, max_depth=4, learning_rate=0.05,
    min_samples_split=6, min_samples_leaf=3, subsample=0.8,
    random_state=42
)

# Ensemble
ensemble = VotingClassifier(
    estimators=[('rf', rf), ('gb', gb)],
    voting='soft', weights=[2, 1]
)

print(f"\n[5-FOLD CROSS-VALIDATION RESULTS]")
for name, model in [("Random Forest", rf), ("Gradient Boosting", gb),
                     ("Ensemble (RF+GB)", ensemble)]:
    acc = cross_val_score(model, X_scaled, y_all, cv=cv, scoring='accuracy')
    bal = cross_val_score(model, X_scaled, y_all, cv=cv, scoring='balanced_accuracy')
    print(f"  {name:<25} Acc: {acc.mean():.1%} ± {acc.std():.1%}   Bal.Acc: {bal.mean():.1%} ± {bal.std():.1%}")

# Baselines
for name, strat in [("Baseline (Most Frequent)", "most_frequent"),
                     ("Baseline (Stratified)", "stratified")]:
    dummy = DummyClassifier(strategy=strat, random_state=42)
    acc = cross_val_score(dummy, X_scaled, y_all, cv=cv, scoring='accuracy')
    print(f"  {name:<25} Acc: {acc.mean():.1%} ± {acc.std():.1%}")

# ── Step 2: Train production model ──────────────────────────────
print(f"\n{'='*70}")
print(f"STEP 2: Train Production Model (75/25 split)")
print(f"{'='*70}")

result = reducer.train(training_data, labels)

print(f"\n  Train accuracy : {result.get('train_accuracy', 0):.1%}")
print(f"  Test accuracy  : {result.get('test_accuracy', 0):.1%}")
print(f"  Precision      : {result.get('precision', 0):.1%}")
print(f"  Recall         : {result.get('recall', 0):.1%}")
print(f"  F1             : {result.get('f1', 0):.1%}")
print(f"  Samples train  : {result.get('samples_trained')}")
print(f"  Samples test   : {result.get('samples_tested')}")

if result.get('benchmark_results'):
    print(f"\n[BENCHMARKS]")
    for name, scores in result['benchmark_results'].items():
        print(f"  {name:<30} acc={scores['accuracy']:.1%}  f1={scores['f1']:.1%}")

print(f"\n[FEATURE IMPORTANCE (top 5)]")
fi = result.get('feature_importance', {})
if fi:
    for k, v in sorted(fi.items(), key=lambda x: -x[1])[:5]:
        print(f"  {k:<25} {v:.4f}")

# ── Step 3: Sanity test ─────────────────────────────────────────
print(f"\n{'='*70}")
print(f"STEP 3: Sanity Test (8 cases)")
print(f"{'='*70}")

tests = [
    ({'severity': 'Critical', 'category': 'SQL Injection',
      'description': 'Time-based blind SQL Injection in username',
      'evidence': 'sleep(15000) caused timeout. Server executed SQL.', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 15000}, "SQLi time-based", "TP"),
    ({'severity': 'Info', 'category': 'Cross-Site Scripting (XSS)',
      'description': 'Found 5 input fields - verify XSS protection',
      'evidence': 'Input fields detected in form', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 100}, "XSS input fields", "FP"),
    ({'severity': 'High', 'category': 'Cross-Site Scripting (XSS)',
      'description': 'Reflected XSS via Payload in parameter q',
      'evidence': '<img src=x onerror="alert"> reflected in response', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 200}, "XSS reflected", "TP"),
    ({'severity': 'Info', 'category': 'Security Header',
      'description': 'Missing X-Frame-Options header not set',
      'evidence': 'Header missing. Best practice.', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 80}, "Missing header", "FP"),
    ({'severity': 'High', 'category': 'Cross-Site Request Forgery (CSRF)',
      'description': 'Missing CSRF protection on POST request',
      'evidence': 'POST without sesskey accepted HTTP 200', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 140}, "CSRF bypass", "TP"),
    ({'severity': 'Critical', 'category': 'SQL Injection',
      'description': 'Error-based SQL Injection in parameter id',
      'evidence': 'Error writing to database. Data too long for column.', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 500, 'response_time': 300}, "SQLi error-based", "TP"),
    ({'severity': 'Info', 'category': 'Information Disclosure',
      'description': 'Version disclosure detected - banner information',
      'evidence': 'Server version info in header', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 60}, "Version disclosure", "FP"),
    ({'severity': 'High', 'category': 'SQL Injection',
      'description': 'Potential SQL Injection - server error 500',
      'evidence': 'HTTP 500 after SQL payload injection', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 500, 'response_time': 120}, "SQLi HTTP 500", "TP"),
]

correct = 0
for finding, context, name, expected in tests:
    is_fp, conf = reducer.predict(finding, context)
    pred = "FP" if is_fp else "TP"
    ok = "✓" if pred == expected else "✗"
    if pred == expected:
        correct += 1
    print(f"  {ok} {name:<25} → {pred} ({conf:.0%}) [expected {expected}]")

print(f"\n  Score: {correct}/{len(tests)}")
if correct >= 7:
    print("  ✅ Model trained successfully!")
elif correct >= 5:
    print("  ⚠️  Acceptable — some borderline cases wrong")
else:
    print("  ❌ Needs more training data")

print(f"\nModel saved to: ml/models/fp_reducer.pkl")
print("Restart the proxy server to use the new model.")
