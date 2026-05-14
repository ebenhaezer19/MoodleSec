import sys
sys.path.insert(0, '.')

# ── Test 1: path normalization ──────────────────────────────────────────────
from integrations.ml_pipeline_integration import _normalize_request

cases = [
    {'uri': 'http://localhost:8999/search?q=test'},
    {'uri': 'http://localhost:8999/search/?q=test'},
    {'path': '/search/', 'query_params': 'q=test'},
    {'path': '/search',  'query_params': 'q=test'},
    {'path': '/', 'query_params': ''},
]
print("=== Path normalization (search/ and search must match) ===")
for c in cases:
    r = _normalize_request(c)
    key = c.get('uri', c.get('path', ''))
    print(f"  in={key!r:45s} -> path={r['path']!r}")

# ── Test 2: fallback is ALERT not IGNORE ────────────────────────────────────
from integrations.ml_pipeline_integration import _fallback_result
fb = _fallback_result()
print()
print("=== Fallback result ===")
print(f"  decision = {fb['decision']}  (expect: ALERT)")
print(f"  reason   = {fb['reason']}  (expect: pipeline_failure:risk_unknown)")

# ── Test 3: end-to-end ──────────────────────────────────────────────────────
from integrations.ml_pipeline_integration import process_http_request
print()
print("=== End-to-end pipeline (both /search and /search/ must give same result) ===")
payloads = [
    ({'path': '/search/', 'query_params': 'q=<img src=x onerror=alert(1)>', 'method': 'GET', 'body': '', 'headers': ''}, 'XSS /search/'),
    ({'path': '/search',  'query_params': 'q=<img src=x onerror=alert(1)>', 'method': 'GET', 'body': '', 'headers': ''}, 'XSS /search'),
    ({'path': '/login/',  'query_params': "q=' OR 1=1--", 'method': 'GET', 'body': '', 'headers': ''}, 'SQLi /login/'),
    ({'path': '/login',   'query_params': "q=' OR 1=1--", 'method': 'GET', 'body': '', 'headers': ''}, 'SQLi /login'),
]
for req, label in payloads:
    r = process_http_request(req)
    print(f"  [{label:22s}] decision={r['decision']:5s} attack={r['attack_type']:10s} conf={r['confidence']:.2f} reason={r['reason'][:50]}")
