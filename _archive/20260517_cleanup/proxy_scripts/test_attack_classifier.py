"""
Verify attack_classifier loads and correctly classifies an XSS payload.
"""
import sys
sys.path.insert(0, ".")
from ml.attack_classifier import AttackClassifier

print("[1] Instantiating AttackClassifier...")
clf = AttackClassifier()
print(f"    is_trained={clf.is_trained}  model={type(clf.model).__name__}")

print("\n[2] Running XSS payload...")
request = {
    "method": "GET",
    "path": "/search",
    "query_params": {"q": "<img src=x onerror=alert(1)>"},
    "body": "",
    "headers": {},
}
result = clf.predict(request)
print(f"    result      : {result}")

if isinstance(result, tuple):
    atk, conf = result[0], result[1]
elif isinstance(result, dict):
    atk, conf = result.get("attack_type", ""), float(result.get("confidence") or 0)
else:
    atk, conf = str(result), 0.0

print(f"    attack_type : {atk}")
print(f"    confidence  : {conf}")

assert "xss" in str(atk).lower() or "script" in str(atk).lower(), \
    f"FAIL: expected XSS, got {atk}"
assert float(conf) > 0, f"FAIL: confidence={conf}"
print("\n[3] PASS — attack_type=XSS confidence>0  (multi_class fix verified)")
