"""
Retrain FP Reducer with finding-level training data.
Run from /proxy directory: python retrain_fp_reducer.py

The current model (2026-03-31) predicts ALL findings as FP (class collapse).
This script trains it on realistic scanner-output findings labeled as TP/FP.
"""
import sys
import os

# Add proxy dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ml.false_positive_reducer import FalsePositiveReducer

# ── Training data: security findings as the scanner generates them ─────────────
# Label: 0 = True Positive (real vulnerability, keep it)
#        1 = False Positive (noise, filter it out)

training_data = [
    # ── TRUE POSITIVES (label=0) ─────────────────────────────────────────────
    # Time-based Blind SQL Injection
    {
        'finding': {
            'severity': 'Critical', 'category': 'SQL Injection',
            'description': 'Time-based blind SQL Injection detected in parameter "username"',
            'evidence': 'Payload with sleep/delay caused request timeout (15200ms). Server executed the injected SQL sleep command.',
            'url': 'http://localhost:8998/login/index.php', 'risk_score': 90, 'cvss_score': 9.0
        }, 'context': {'status_code': 200, 'response_time': 15200, 'occurrence_count': 1}
    },
    # Error-based SQL Injection (Moodle DML error)
    {
        'finding': {
            'severity': 'Critical', 'category': 'SQL Injection',
            'description': 'SQL Injection detected in parameter "username" (error-based)',
            'evidence': 'Error writing to database (Data too long for column). INSERT INTO mdl_local_security_login_log',
            'url': 'http://localhost:8998/login/index.php', 'risk_score': 85, 'cvss_score': 9.0
        }, 'context': {'status_code': 200, 'response_time': 300, 'occurrence_count': 1}
    },
    # HTTP 500 SQL Injection
    {
        'finding': {
            'severity': 'High', 'category': 'SQL Injection',
            'description': 'Potential SQL Injection in parameter "id" - server error 500',
            'evidence': 'HTTP 500 returned after injecting SQL payload. Server may have failed.',
            'url': 'http://localhost:8998/course/view.php?id=1', 'risk_score': 80, 'cvss_score': 8.5
        }, 'context': {'status_code': 500, 'response_time': 120, 'occurrence_count': 1}
    },
    # Reflected XSS via payload injection
    {
        'finding': {
            'severity': 'High', 'category': 'Cross-Site Scripting (XSS)',
            'description': 'Reflected XSS via Payload detected in parameter "q"',
            'evidence': 'JavaScript code reflected in response: <img src=x onerror="alert(\'xss\')">',
            'url': 'http://localhost:8998/search/index.php?q=test', 'risk_score': 75, 'cvss_score': 7.5
        }, 'context': {'status_code': 200, 'response_time': 200, 'occurrence_count': 1}
    },
    # XSS via SVG
    {
        'finding': {
            'severity': 'High', 'category': 'Cross-Site Scripting (XSS)',
            'description': 'Reflected XSS via Payload detected in parameter "search"',
            'evidence': 'JavaScript code reflected in response: <svg onload=alert("xss")>',
            'url': 'http://localhost:8998/admin/search.php?search=test', 'risk_score': 73, 'cvss_score': 7.2
        }, 'context': {'status_code': 200, 'response_time': 180, 'occurrence_count': 1}
    },
    # CSRF bypass (token accepted)
    {
        'finding': {
            'severity': 'High', 'category': 'Cross-Site Request Forgery (CSRF)',
            'description': 'CSRF protection may be missing on parameter "sesskey"',
            'evidence': 'Request with invalid/missing CSRF token was accepted (HTTP 200). Form may not validate CSRF tokens.',
            'url': 'http://localhost:8998/course/edit.php?category=1', 'risk_score': 70, 'cvss_score': 6.5
        }, 'context': {'status_code': 200, 'response_time': 150, 'occurrence_count': 1}
    },
    # CSRF missing on POST
    {
        'finding': {
            'severity': 'High', 'category': 'Cross-Site Request Forgery (CSRF)',
            'description': 'Missing CSRF protection on POST request',
            'evidence': 'POST request to /course/management.php does not include valid sesskey token',
            'url': 'http://localhost:8998/course/management.php?categoryid=1', 'risk_score': 68, 'cvss_score': 6.3
        }, 'context': {'status_code': 200, 'response_time': 140, 'occurrence_count': 1}
    },
    # Reflected XSS on setmode param
    {
        'finding': {
            'severity': 'High', 'category': 'Cross-Site Scripting (XSS)',
            'description': 'Potential reflected XSS in parameter "setmode"',
            'evidence': 'Parameter value "" appears unescaped in response at http://localhost:8998/blocks/...',
            'url': 'http://localhost:8998/blocks/recentlyaccessedcourses/ajax.php', 'risk_score': 72, 'cvss_score': 7.0
        }, 'context': {'status_code': 200, 'response_time': 190, 'occurrence_count': 1}
    },
    # SQLi via waitfor
    {
        'finding': {
            'severity': 'Critical', 'category': 'SQL Injection',
            'description': 'Time-based blind SQL Injection detected in parameter "password"',
            'evidence': 'Payload with waitfor delay caused timeout. Server executed injected SQL.',
            'url': 'http://localhost:8998/login/index.php', 'risk_score': 88, 'cvss_score': 9.0
        }, 'context': {'status_code': 200, 'response_time': 12000, 'occurrence_count': 1}
    },
    # XSS via script tag
    {
        'finding': {
            'severity': 'High', 'category': 'Cross-Site Scripting (XSS)',
            'description': 'Reflected XSS via Payload detected in parameter "context"',
            'evidence': 'JavaScript code reflected: "><script>alert("xss")</script>',
            'url': 'http://localhost:8998/search/index.php', 'risk_score': 74, 'cvss_score': 7.3
        }, 'context': {'status_code': 200, 'response_time': 210, 'occurrence_count': 1}
    },

    # ── FALSE POSITIVES (label=1) ────────────────────────────────────────────
    # XSS: generic input field detection (Moodle form scanner noise)
    {
        'finding': {
            'severity': 'Info', 'category': 'Cross-Site Scripting (XSS)',
            'description': 'Found 7 input field(s) - verify XSS protection on each field',
            'evidence': 'Input fields detected in http://localhost:8998/course/edit.php. Ensure proper output encoding.',
            'url': 'http://localhost:8998/course/edit.php?category=1', 'risk_score': 0, 'cvss_score': 0
        }, 'context': {'status_code': 200, 'response_time': 100, 'occurrence_count': 5}
    },
    # XSS: dangerous html tag (Moodle's own HTML)
    {
        'finding': {
            'severity': 'Info', 'category': 'Cross-Site Scripting (XSS)',
            'description': 'Dangerous HTML tag detected in response - potentially dangerous html tag',
            'evidence': 'Moodle page contains <script> tag from legitimate JS bundle.',
            'url': 'http://localhost:8998/my/', 'risk_score': 0, 'cvss_score': 0
        }, 'context': {'status_code': 200, 'response_time': 90, 'occurrence_count': 10}
    },
    # Missing X-Frame-Options header
    {
        'finding': {
            'severity': 'Info', 'category': 'Security Header',
            'description': 'Missing X-Frame-Options header - not set on this endpoint',
            'evidence': 'Response does not include X-Frame-Options header. Recommend adding.',
            'url': 'http://localhost:8998/', 'risk_score': 0, 'cvss_score': 0
        }, 'context': {'status_code': 200, 'response_time': 80, 'occurrence_count': 20}
    },
    # Missing CSP header
    {
        'finding': {
            'severity': 'Info', 'category': 'Security Header',
            'description': 'Content-Security-Policy header not implemented - best practice recommendation',
            'evidence': 'Missing Content-Security-Policy header. This is an informational finding.',
            'url': 'http://localhost:8998/', 'risk_score': 0, 'cvss_score': 0
        }, 'context': {'status_code': 200, 'response_time': 75, 'occurrence_count': 20}
    },
    # XSS: verify protection (informational)
    {
        'finding': {
            'severity': 'Info', 'category': 'Cross-Site Scripting (XSS)',
            'description': 'Found 3 input field(s) - verify XSS protection',
            'evidence': 'Input fields detected in http://localhost:8998/login/index.php. Ensure output encoding.',
            'url': 'http://localhost:8998/login/index.php', 'risk_score': 0, 'cvss_score': 0
        }, 'context': {'status_code': 200, 'response_time': 95, 'occurrence_count': 8}
    },
    # Missing HSTS
    {
        'finding': {
            'severity': 'Low', 'category': 'Security Header',
            'description': 'Strict-Transport-Security header not set - missing security header',
            'evidence': 'HSTS header missing. Best practice to add for HTTPS enforcement.',
            'url': 'http://localhost:8998/', 'risk_score': 5, 'cvss_score': 0
        }, 'context': {'status_code': 200, 'response_time': 70, 'occurrence_count': 15}
    },
    # XSS: input fields on admin page
    {
        'finding': {
            'severity': 'Info', 'category': 'Cross-Site Scripting (XSS)',
            'description': 'Found 12 input field(s) - verify XSS protection on each field',
            'evidence': 'Input fields detected in http://localhost:8998/admin/. Ensure proper output encoding.',
            'url': 'http://localhost:8998/admin/search.php', 'risk_score': 0, 'cvss_score': 0
        }, 'context': {'status_code': 200, 'response_time': 105, 'occurrence_count': 6}
    },
    # Version disclosure
    {
        'finding': {
            'severity': 'Info', 'category': 'Information Disclosure',
            'description': 'Version disclosure in response header - banner information detected',
            'evidence': 'Server header discloses version information. Recommend removing.',
            'url': 'http://localhost:8998/', 'risk_score': 2, 'cvss_score': 0
        }, 'context': {'status_code': 200, 'response_time': 65, 'occurrence_count': 25}
    },
    # Referrer policy missing
    {
        'finding': {
            'severity': 'Info', 'category': 'Security Header',
            'description': 'Referrer-Policy header not set - recommendation for best practice',
            'evidence': 'Referrer-Policy header missing. Informational finding only.',
            'url': 'http://localhost:8998/', 'risk_score': 0, 'cvss_score': 0
        }, 'context': {'status_code': 200, 'response_time': 72, 'occurrence_count': 18}
    },
    # XSS: form field on search
    {
        'finding': {
            'severity': 'Info', 'category': 'Cross-Site Scripting (XSS)',
            'description': 'Found 2 input field(s) - verify XSS protection',
            'evidence': 'Input fields detected in http://localhost:8998/search/. Ensure encoding.',
            'url': 'http://localhost:8998/search/index.php', 'risk_score': 0, 'cvss_score': 0
        }, 'context': {'status_code': 200, 'response_time': 88, 'occurrence_count': 4}
    },
]

labels = [
    # TP=0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    # FP=1
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
]

print("=" * 60)
print("FP REDUCER RETRAINING")
print("=" * 60)
print(f"\nTraining samples: {len(training_data)}")
print(f"  TP (label=0): {labels.count(0)}")
print(f"  FP (label=1): {labels.count(1)}")

# ── Retrain ────────────────────────────────────────────────────
reducer = FalsePositiveReducer()
print(f"\nOld model is_trained: {reducer.is_trained}")

print("\nTraining new model...")
result = reducer.train(training_data, labels)

print(f"\n[RESULTS]")
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
        print(f"  {name:<30} acc={scores['accuracy']:.1%}  f1={scores['f1']:.1%}")

print(f"\n[FEATURE IMPORTANCE (top 5)]")
fi = result.get('feature_importance', {})
if fi:
    for k, v in sorted(fi.items(), key=lambda x: -x[1])[:5]:
        print(f"  {k:<25} {v:.4f}")

# ── Quick sanity test ──────────────────────────────────────────
print(f"\n[SANITY TEST]")
test_cases = [
    ({'severity': 'Critical', 'category': 'SQL Injection',
      'description': 'Time-based blind SQL Injection in username',
      'evidence': 'sleep(15000) caused timeout', 'risk_score': 90, 'cvss_score': 9.0},
     {'status_code': 200, 'response_time': 15000}, "SQLi time-based", "TP"),

    ({'severity': 'Info', 'category': 'Cross-Site Scripting (XSS)',
      'description': 'Found 5 input fields - verify XSS protection',
      'evidence': 'Input fields detected', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 100}, "XSS input fields (FP)", "FP"),

    ({'severity': 'High', 'category': 'Cross-Site Scripting (XSS)',
      'description': 'Reflected XSS via Payload in parameter q',
      'evidence': '<img src=x onerror="alert"> reflected', 'risk_score': 75, 'cvss_score': 7.5},
     {'status_code': 200, 'response_time': 200}, "XSS reflected (TP)", "TP"),

    ({'severity': 'Info', 'category': 'Security Header',
      'description': 'Missing X-Frame-Options header not set',
      'evidence': 'Header missing', 'risk_score': 0, 'cvss_score': 0},
     {'status_code': 200, 'response_time': 80}, "Missing header (FP)", "FP"),

    ({'severity': 'High', 'category': 'Cross-Site Request Forgery (CSRF)',
      'description': 'Missing CSRF protection on POST request',
      'evidence': 'POST without sesskey accepted HTTP 200', 'risk_score': 68, 'cvss_score': 6.5},
     {'status_code': 200, 'response_time': 140}, "CSRF bypass (TP)", "TP"),
]

correct = 0
for finding, context, name, expected in test_cases:
    is_fp, conf = reducer.predict(finding, context)
    pred = "FP" if is_fp else "TP"
    ok = "✓" if pred == expected else "✗"
    if pred == expected:
        correct += 1
    print(f"  {ok} {name:<30} → {pred} ({conf:.0%}) [expected {expected}]")

print(f"\n  Score: {correct}/{len(test_cases)} correct")

verdict = "✅ Model retrained successfully!" if correct >= 4 else "⚠️  Some predictions wrong — check training data"
print(f"\n  {verdict}")
print(f"\nModel saved to: ml/models/fp_reducer.pkl")
print("Restart the proxy server to use the new model.")
