"""
Retrain FP Reducer by integrating Phase 3 real HAR data (89% accuracy)
with production finding-level features.

Bridge strategy:
  Phase 3 attack samples (label=1) → TP findings (fp_reducer label=0)
    "Real ZAP SQLi attacks that scanner SHOULD detect as vulnerabilities"
  Phase 3 normal samples (label=0) → FP findings (fp_reducer label=1)
    "Normal Moodle browsing that scanner SHOULD filter as false positives"

We convert each HAR row into a finding dict that extract_features() can process,
using the HAR features (response_status, request_time_ms, etc.) as context.
"""
import sys, os, csv, random
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ml.false_positive_reducer import FalsePositiveReducer

random.seed(42)

# ── Load Phase 3 dataset ────────────────────────────────────────
csv_path = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '..', 'ml', 'training_data', 'phase3_balanced_dataset_FINAL.csv'
)
if not os.path.exists(csv_path):
    csv_path = 'ml/training_data/phase3_balanced_dataset_FINAL.csv'
    if not os.path.exists(csv_path):
        # Try relative to MoodleSec root
        csv_path = '../ml/training_data/phase3_balanced_dataset_FINAL.csv'

print("=" * 60)
print("FP REDUCER RETRAINING — Phase 3 Integration")
print("=" * 60)

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

# ── Bridge: HAR row → finding dict ──────────────────────────────
#
# Phase 3 features: method, has_post_data, payload_length, has_session_cookie,
#   request_time_ms, response_status, response_size, has_xframe_options,
#   has_csp, has_content_type, error_leaked, db_error_visible,
#   payload_reflected, response_time_anomaly
#
# fp_reducer features (via extract_features):
#   1. severity (from finding dict)
#   2. category (from finding dict)
#   3. evidence_length (len(evidence)/100, capped 10)
#   4. description_length (len(description)/100, capped 10)
#   5. url_complexity (url.count('/'))
#   6. has_params (1 if '?' in url)
#   7. cvss_score
#   8. risk_score
#   9. fp_keyword_count (from description)
#  10. tp_keyword_count (from description)
#  11. keyword_ratio (fp / (fp+tp))
#  12. is_informational (severity info/low + tp_count==0)
#  13. status_code (from context)
#  14. response_time (from context)
#  15. occurrence_count (from context)
#  16. days_since_first_seen (from context)

# Moodle URLs for realistic url_complexity
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

# Attack finding templates (TP)
ATTACK_TEMPLATES = [
    {
        'severity': 'Critical', 'category': 'SQL Injection',
        'desc': 'SQL Injection detected in parameter via payload injection',
        'evidence_base': 'SQL error pattern found after injecting payload. Error writing to database.',
    },
    {
        'severity': 'Critical', 'category': 'SQL Injection',
        'desc': 'Time-based blind SQL Injection detected in parameter',
        'evidence_base': 'Payload with sleep/delay caused timeout. Server executed injected SQL.',
    },
    {
        'severity': 'High', 'category': 'SQL Injection',
        'desc': 'Potential SQL Injection - server error after payload injection',
        'evidence_base': 'HTTP 500 returned after injecting SQL payload.',
    },
    {
        'severity': 'High', 'category': 'Cross-Site Scripting (XSS)',
        'desc': 'Reflected XSS via Payload detected in parameter',
        'evidence_base': 'JavaScript code reflected in response: <script>alert(1)</script>',
    },
    {
        'severity': 'High', 'category': 'Cross-Site Request Forgery (CSRF)',
        'desc': 'CSRF protection bypass - missing sesskey validation',
        'evidence_base': 'Request without valid CSRF token was accepted (HTTP 200).',
    },
]

# Normal finding templates (FP) - things scanner would flag on normal pages
FP_TEMPLATES = [
    {
        'severity': 'Info', 'category': 'Cross-Site Scripting (XSS)',
        'desc': 'Found input field(s) - verify XSS protection on each field',
        'evidence_base': 'Input fields detected. Ensure proper output encoding.',
    },
    {
        'severity': 'Info', 'category': 'Cross-Site Scripting (XSS)',
        'desc': 'Potentially dangerous HTML tag detected in response',
        'evidence_base': 'Page contains <script> tag from legitimate Moodle JS bundle.',
    },
    {
        'severity': 'Info', 'category': 'Security Header',
        'desc': 'Missing security header - not set, best practice recommendation',
        'evidence_base': 'Response header missing. Informational finding.',
    },
    {
        'severity': 'Low', 'category': 'Security Header',
        'desc': 'Content-Security-Policy header not implemented',
        'evidence_base': 'Missing CSP header. Best practice recommendation.',
    },
    {
        'severity': 'Info', 'category': 'Information Disclosure',
        'desc': 'Version disclosure in response - banner information detected',
        'evidence_base': 'Server version information disclosed in header.',
    },
]


def har_to_finding(row, is_attack):
    """Convert a Phase 3 HAR row to a finding dict + context."""
    status = int(float(row['response_status']))
    time_ms = float(row['request_time_ms'])
    payload_len = float(row['payload_length'])
    error_leaked = float(row['error_leaked'])
    db_error = float(row['db_error_visible'])
    payload_reflected = float(row['payload_reflected'])
    response_size = float(row['response_size'])
    has_params = float(row['has_post_data'])

    if is_attack:
        tmpl = random.choice(ATTACK_TEMPLATES)
        url = random.choice(MOODLE_ATTACK_URLS)

        # Derive CVSS/risk from HAR features
        cvss = 9.0 if tmpl['severity'] == 'Critical' else 7.5
        risk = min(95, 60 + payload_len * 0.05 + (20 if db_error else 0) + (10 if error_leaked else 0))

        # Build evidence with variable length from HAR data
        evidence = tmpl['evidence_base']
        if db_error:
            evidence += ' Database error visible in response.'
        if payload_reflected:
            evidence += ' Payload reflected in response body.'
        if error_leaked:
            evidence += f' Error information leaked ({response_size:.0f} bytes response).'

        finding = {
            'severity': tmpl['severity'],
            'category': tmpl['category'],
            'description': tmpl['desc'],
            'evidence': evidence,
            'url': url,
            'cvss_score': cvss,
            'risk_score': risk,
        }
        context = {
            'status_code': status,
            'response_time': time_ms,
            'occurrence_count': 1,
            'days_since_first_seen': 0,
        }
        label = 0  # True Positive (keep this finding)
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
            'cvss_score': 0,
            'risk_score': random.randint(0, 10),
        }
        context = {
            'status_code': status,
            'response_time': time_ms,
            'occurrence_count': random.randint(3, 25),
            'days_since_first_seen': random.randint(0, 30),
        }
        label = 1  # False Positive (filter this finding)

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

# Add 20 manual findings from previous retrain (for extra diversity)
manual_tp = [
    {'finding': {'severity': 'Critical', 'category': 'SQL Injection',
     'description': 'Time-based blind SQL Injection detected in parameter "username"',
     'evidence': 'Payload with sleep/delay caused request timeout (15200ms).',
     'url': 'http://localhost:8998/login/index.php', 'risk_score': 90, 'cvss_score': 9.0},
     'context': {'status_code': 200, 'response_time': 15200, 'occurrence_count': 1}},
    {'finding': {'severity': 'Critical', 'category': 'SQL Injection',
     'description': 'SQL Injection detected in parameter "username" (error-based)',
     'evidence': 'Error writing to database. INSERT INTO mdl_local_security_login_log',
     'url': 'http://localhost:8998/login/index.php', 'risk_score': 85, 'cvss_score': 9.0},
     'context': {'status_code': 200, 'response_time': 300, 'occurrence_count': 1}},
    {'finding': {'severity': 'High', 'category': 'Cross-Site Scripting (XSS)',
     'description': 'Reflected XSS via Payload detected in parameter "q"',
     'evidence': 'JavaScript code reflected: <img src=x onerror="alert(xss)">',
     'url': 'http://localhost:8998/search/index.php?q=test', 'risk_score': 75, 'cvss_score': 7.5},
     'context': {'status_code': 200, 'response_time': 200, 'occurrence_count': 1}},
    {'finding': {'severity': 'High', 'category': 'Cross-Site Request Forgery (CSRF)',
     'description': 'CSRF protection may be missing on parameter "sesskey"',
     'evidence': 'Request with invalid/missing CSRF token was accepted (HTTP 200).',
     'url': 'http://localhost:8998/course/edit.php?category=1', 'risk_score': 70, 'cvss_score': 6.5},
     'context': {'status_code': 200, 'response_time': 150, 'occurrence_count': 1}},
    {'finding': {'severity': 'High', 'category': 'Cross-Site Scripting (XSS)',
     'description': 'Reflected XSS via Payload in parameter "search"',
     'evidence': '<svg onload=alert("xss")> reflected in response',
     'url': 'http://localhost:8998/admin/search.php', 'risk_score': 73, 'cvss_score': 7.2},
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
    {'finding': {'severity': 'Info', 'category': 'Security Header',
     'description': 'Content-Security-Policy header not implemented - best practice',
     'evidence': 'Missing CSP header. Informational finding.',
     'url': 'http://localhost:8998/', 'risk_score': 0, 'cvss_score': 0},
     'context': {'status_code': 200, 'response_time': 75, 'occurrence_count': 20}},
    {'finding': {'severity': 'Info', 'category': 'Cross-Site Scripting (XSS)',
     'description': 'Dangerous HTML tag detected - potentially dangerous html tag',
     'evidence': 'Moodle page contains <script> tag from legitimate JS.',
     'url': 'http://localhost:8998/my/', 'risk_score': 0, 'cvss_score': 0},
     'context': {'status_code': 200, 'response_time': 90, 'occurrence_count': 10}},
    {'finding': {'severity': 'Info', 'category': 'Information Disclosure',
     'description': 'Version disclosure in response - banner information detected',
     'evidence': 'Server version information disclosed.',
     'url': 'http://localhost:8998/', 'risk_score': 2, 'cvss_score': 0},
     'context': {'status_code': 200, 'response_time': 65, 'occurrence_count': 25}},
]

for td in manual_tp:
    training_data.append(td)
    labels.append(0)  # TP
for td in manual_fp:
    training_data.append(td)
    labels.append(1)  # FP

print(f"\nTotal training data: {len(training_data)}")
print(f"  TP (label=0): {labels.count(0)}  (Phase 3 attacks + manual)")
print(f"  FP (label=1): {labels.count(1)}  (Phase 3 normals + manual)")

# ── Train ────────────────────────────────────────────────────────
print("\nTraining fp_reducer with Phase 3 integrated data...")
reducer = FalsePositiveReducer()
result = reducer.train(training_data, labels)

print(f"\n{'='*60}")
print(f"RESULTS")
print(f"{'='*60}")
print(f"  Train accuracy : {result.get('train_accuracy', 0):.1%}")
print(f"  Test accuracy  : {result.get('test_accuracy', 0):.1%}")
print(f"  Precision      : {result.get('precision', 0):.1%}")
print(f"  Recall         : {result.get('recall', 0):.1%}")
print(f"  F1             : {result.get('f1', 0):.1%}")
print(f"  Samples train  : {result.get('samples_trained')}")
print(f"  Samples test   : {result.get('samples_tested')}")

if result.get('benchmark_results'):
    print(f"\n[BENCHMARKS]")
    for name, scores in result['benchmark_results'].items():
        print(f"  {name:<30} acc={scores['accuracy']:.1%}  prec={scores['precision']:.1%}  f1={scores['f1']:.1%}")

print(f"\n[FEATURE IMPORTANCE (top 5)]")
fi = result.get('feature_importance', {})
if fi:
    for k, v in sorted(fi.items(), key=lambda x: -x[1])[:5]:
        print(f"  {k:<25} {v:.4f}")

# ── Sanity test ──────────────────────────────────────────────────
print(f"\n[SANITY TEST]")
tests = [
    ({'severity': 'Critical', 'category': 'SQL Injection',
      'description': 'Time-based blind SQL Injection in username',
      'evidence': 'sleep(15000) caused timeout', 'risk_score': 90, 'cvss_score': 9.0},
     {'status_code': 200, 'response_time': 15000}, "SQLi time-based", "TP"),

    ({'severity': 'Info', 'category': 'Cross-Site Scripting (XSS)',
      'description': 'Found 5 input fields - verify XSS protection',
      'evidence': 'Input fields detected', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 100}, "XSS input fields", "FP"),

    ({'severity': 'High', 'category': 'Cross-Site Scripting (XSS)',
      'description': 'Reflected XSS via Payload in parameter q',
      'evidence': '<img src=x onerror="alert"> reflected', 'risk_score': 75, 'cvss_score': 7.5},
     {'status_code': 200, 'response_time': 200}, "XSS reflected", "TP"),

    ({'severity': 'Info', 'category': 'Security Header',
      'description': 'Missing X-Frame-Options header not set',
      'evidence': 'Header missing', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 80}, "Missing header", "FP"),

    ({'severity': 'High', 'category': 'Cross-Site Request Forgery (CSRF)',
      'description': 'Missing CSRF protection on POST request',
      'evidence': 'POST without sesskey accepted HTTP 200', 'risk_score': 68, 'cvss_score': 6.5},
     {'status_code': 200, 'response_time': 140}, "CSRF bypass", "TP"),

    ({'severity': 'Critical', 'category': 'SQL Injection',
      'description': 'Error-based SQL Injection in parameter id',
      'evidence': 'Error writing to database. Data too long for column.', 'risk_score': 85, 'cvss_score': 9.0},
     {'status_code': 500, 'response_time': 300}, "SQLi error-based", "TP"),

    ({'severity': 'Info', 'category': 'Information Disclosure',
      'description': 'Version disclosure detected - banner information',
      'evidence': 'Server version info in header', 'risk_score': 2, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 60}, "Version disclosure", "FP"),

    ({'severity': 'High', 'category': 'SQL Injection',
      'description': 'Potential SQL Injection - server error 500',
      'evidence': 'HTTP 500 after SQL payload injection', 'risk_score': 80, 'cvss_score': 8.5},
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
    print("  ✅ Model integrated successfully with Phase 3 data!")
else:
    print("  ⚠️  Some predictions wrong — may need more training data")

print(f"\nModel saved to: ml/models/fp_reducer.pkl")
print("Restart the proxy server to use the new model.")
