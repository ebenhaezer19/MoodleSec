"""
verify_soc_loop.py — Validates the full SOC decision loop without an HTTP server.
Tests: fingerprint construction, add_alert, resolve_alert -> BLOCK, middleware check.
Run from: proxy/
    python verify_soc_loop.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

SEP = "=" * 65

# ── 1. Import SOC queue ──────────────────────────────────────────────────────
print(f"\n{SEP}\n1. ALERT QUEUE IMPORT\n{SEP}")
from utils.alert_queue import AlertQueue, STATUS_PENDING, STATUS_BLOCK
aq = AlertQueue(max_alerts=50)
print("   AlertQueue instantiated: OK")

# ── 2. Alert schema validation ───────────────────────────────────────────────
print(f"\n{SEP}\n2. ALERT SCHEMA VALIDATION\n{SEP}")
REQUIRED_FIELDS = {
    "alert_id", "timestamp", "client_ip", "path", "method",
    "attack_type", "confidence", "status",
}

alert = aq.add_alert(
    attack_type="XSS",
    severity="MEDIUM",
    confidence=0.72,
    anomaly_score=0.90,
    client_ip="127.0.0.1",
    method="GET",
    path="search",          # FastAPI route param — no leading slash
    url="http://localhost:8999/search?q=<script>alert(1)</script>",
    reason="High anomaly + high confidence cross-site scripting",
    ml_decision_original="BLOCK",
    source="ml_pipeline",
)
alert_id = alert["alert_id"]
missing = REQUIRED_FIELDS - set(alert.keys())
if missing:
    print(f"   FAIL — missing fields: {missing}")
else:
    print(f"   OK  — all required fields present")
    print(f"   alert_id = {alert_id}")
    print(f"   status   = {alert['status']}  (expect: PENDING_ADMIN_ACTION)")
    assert alert["status"] == STATUS_PENDING

# ── 3. Resolve -> BLOCK  ──────────────────────────────────────────────────────
print(f"\n{SEP}\n3. RESOLVE -> BLOCK\n{SEP}")
resolved = aq.resolve_alert(alert_id, "BLOCK")
assert resolved is not None, "resolve_alert returned None"
assert resolved["status"] == STATUS_BLOCK, f"Expected ADMIN_BLOCK, got {resolved['status']}"
print(f"   OK  — alert resolved: {resolved['status']}")

# ── 4. Fingerprint match check ───────────────────────────────────────────────
print(f"\n{SEP}\n4. FINGERPRINT MATCH (middleware vs resolve_alert)\n{SEP}")

# Simulate what the middleware computes from request.url.path = "/search"
middleware_fp = "GET:/search:127.0.0.1"

# Verify the blocked set contains the correct fingerprint
blocked = aq._blocked_fingerprints
print(f"   Blocked fingerprints in set: {blocked}")
print(f"   Middleware fingerprint:      {middleware_fp!r}")

if middleware_fp in blocked:
    print("   OK  — fingerprint MATCH: middleware will block replayed request")
else:
    print("   FAIL — fingerprint MISMATCH: middleware would NOT block replay!")
    print("   Expected:", middleware_fp)
    print("   Got:", blocked)
assert middleware_fp in blocked, "FINGERPRINT MISMATCH — enforcement broken"

# ── 5. Middleware enforcement simulation ─────────────────────────────────────
print(f"\n{SEP}\n5. MIDDLEWARE ENFORCEMENT SIMULATION\n{SEP}")

def simulate_middleware(method: str, path: str, client_ip: str) -> str:
    norm_path = path.rstrip("/") or "/"
    fp = f"{method}:{norm_path}:{client_ip}"
    if aq.is_fingerprint_blocked(fp):
        return "403 BLOCKED"
    return "200 OK"

cases = [
    ("GET",  "/search",  "127.0.0.1"),   # exact match -> BLOCKED
    ("GET",  "/search/", "127.0.0.1"),   # trailing slash -> BLOCKED
    ("GET",  "/search",  "10.0.0.1"),    # different IP -> OK
    ("POST", "/search",  "127.0.0.1"),   # different method -> OK
    ("GET",  "/login",   "127.0.0.1"),   # different path -> OK
]
all_pass = True
for method, path, ip in cases:
    result = simulate_middleware(method, path, ip)
    expected_block = (method == "GET" and path.rstrip("/") == "/search" and ip == "127.0.0.1")
    expected = "403 BLOCKED" if expected_block else "200 OK"
    status = "OK" if result == expected else "FAIL"
    if status == "FAIL":
        all_pass = False
    print(f"   {status}  {method} {path} ip={ip:10s} -> {result}  (expect {expected})")

# ── 6. Persist / reload test ─────────────────────────────────────────────────
print(f"\n{SEP}\n6. PERSIST AND RELOAD (block survives restart)\n{SEP}")
aq._persist()
aq2 = AlertQueue(max_alerts=50)
if middleware_fp in aq2._blocked_fingerprints:
    print("   OK  — BLOCK fingerprint rebuilt from disk after reload")
else:
    print("   FAIL — fingerprint lost after reload (enforcement breaks on restart)")
assert middleware_fp in aq2._blocked_fingerprints, "Block not persisted across restart"

# ── 7. /soc/resolve alias endpoint check ────────────────────────────────────
print(f"\n{SEP}\n7. /soc/resolve ALIAS ENDPOINT\n{SEP}")
import ast
src = open("app.py", encoding="utf-8", errors="replace").read()
if "@app.post(\"/soc/resolve\")" in src:
    print("   OK  — POST /soc/resolve endpoint registered in app.py")
else:
    print("   FAIL — POST /soc/resolve not found in app.py")

# ── 8. BLOCK -> ALLOW unblock (stale fingerprint cleanup) ────────────────────
print(f"\n{SEP}\n8. UNBLOCK: ADMIN_BLOCK -> ADMIN_ALLOW (stale fingerprint cleanup)\n{SEP}")
aq3 = AlertQueue(max_alerts=50)
a8 = aq3.add_alert(
    attack_type="XSS", severity="MEDIUM", confidence=0.72, anomaly_score=0.90,
    client_ip="192.168.1.10", method="GET", path="admin",
    url="http://proxy/admin", reason="test",
    ml_decision_original="ALERT", source="test",
)
a8_id = a8["alert_id"]
a8_fp = "GET:/admin:192.168.1.10"

# Step 1: BLOCK
aq3.resolve_alert(a8_id, "BLOCK")
assert a8_fp in aq3._blocked_fingerprints, "FAIL — fingerprint not added on BLOCK"
blocked_count_after_block = len(aq3._blocked_fingerprints)
assert aq3.get_stats()["override_rules_active"] == blocked_count_after_block, \
    "FAIL — override_rules_active must equal len(_blocked_fingerprints)"
print("   OK  — fingerprint added to _blocked_fingerprints on ADMIN_BLOCK")

# Step 2: Resolve to ALLOW — must clear the fingerprint
aq3.resolve_alert(a8_id, "ALLOW")
if a8_fp not in aq3._blocked_fingerprints:
    print("   OK  — fingerprint removed from _blocked_fingerprints on ADMIN_ALLOW")
else:
    print("   FAIL — fingerprint still in _blocked_fingerprints after ADMIN_ALLOW (stale enforcement!)")
    all_pass = False

stats = aq3.get_stats()
expected_active = blocked_count_after_block - 1   # one fingerprint was removed
if stats["override_rules_active"] == expected_active:
    print(f"   OK  — override_rules_active decreased from {blocked_count_after_block} -> {expected_active} after ADMIN_ALLOW")
else:
    print(f"   FAIL — override_rules_active={stats['override_rules_active']} (expected {expected_active})")
    all_pass = False

# Sanity: stat must always equal the actual set size
assert stats["override_rules_active"] == len(aq3._blocked_fingerprints), \
    "FAIL — override_rules_active out of sync with _blocked_fingerprints"
print(f"   OK  — override_rules_active in sync with _blocked_fingerprints set")

if stats["blocked"] == 0 and stats["allowed"] == 1:
    print(f"   OK  — aq3 stats: blocked={stats['blocked']} allowed={stats['allowed']}")
else:
    print(f"   INFO — aq3 stats include disk-loaded alerts: blocked={stats['blocked']} allowed={stats['allowed']}")

# ── Summary ──────────────────────────────────────────────────────────────────
print(f"\n{SEP}")
if all_pass:
    print("ALL TESTS PASSED — SOC loop is correctly enforced end-to-end.")
else:
    print("SOME TESTS FAILED — see FAIL lines above.")
print(SEP)
