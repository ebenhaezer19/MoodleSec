import sys
sys.path.insert(0, ".")
from ml.decision_engine import DecisionEngine

engine = DecisionEngine()

# (label, anomaly, attack_type, confidence, expected_after_patch)
cases = [
    ("anom=0.80 normal conf=0.00", 0.80, "normal", 0.00, "IGNORE"),  # stays quiet
    ("anom=0.81 normal conf=0.00", 0.81, "normal", 0.00, "IGNORE"),  # stays quiet
    ("anom=0.84 normal conf=0.00", 0.84, "normal", 0.00, "IGNORE"),  # boundary-1
    ("anom=0.85 normal conf=0.00", 0.85, "normal", 0.00, "ALERT"),   # NEW: escalate
    ("anom=0.87 normal conf=0.00", 0.87, "normal", 0.00, "ALERT"),   # from log — was IGNORE
    ("anom=0.88 normal conf=0.00", 0.88, "normal", 0.00, "ALERT"),   # from log — was IGNORE
    ("anom=0.90 normal conf=0.00", 0.90, "normal", 0.00, "ALERT"),   # already ALERT before patch
    ("anom=0.82 SQLi  conf=0.84",  0.82, "SQLi",  0.84, "BLOCK"),   # BLOCK unchanged
    ("anom=0.72 XSS   conf=0.72",  0.72, "XSS",   0.72, "BLOCK"),   # BLOCK unchanged
    ("anom=0.30 normal conf=0.00", 0.30, "normal", 0.00, "IGNORE"),  # low anom stays IGNORE
    ("anom=0.50 normal conf=0.00", 0.50, "normal", 0.00, "IGNORE"),  # medium anom + normal
    # conf=0.36 is ABOVE the 0.35 guard — was always ALERT before AND after patch
    ("anom=0.70 normal conf=0.36", 0.70, "normal", 0.36, "ALERT"),
    # conf=0.35 is AT the guard — IGNORE boundary (unchanged by patch)
    ("anom=0.70 normal conf=0.35", 0.70, "normal", 0.35, "IGNORE"),
]

print("Label                                    Got     Expected  Status")
print("-" * 70)
all_ok = True
for label, anom, atk, conf, expected in cases:
    r = engine.decide(anomaly_score=anom, attack_type=atk, confidence=conf)
    got = r["decision"]
    status = "PASS" if got == expected else "FAIL"
    if status == "FAIL":
        all_ok = False
    print(f"{label:42} {got:7} {expected:9} {status}")

print()
print("ALL PASS" if all_ok else "!! FAILURES DETECTED !!")
