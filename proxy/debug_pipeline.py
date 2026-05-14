"""
debug_pipeline.py — trace EXACTLY where IGNORE / confidence=0 comes from.
Run from: c:\\Users\\natha\\OneDrive\\Desktop\\Documents\\CIT\\TA\\MoodleSec\\proxy
  python debug_pipeline.py
"""

import sys, os
sys.path.insert(0, os.path.dirname(__file__))

# ── 1. Payloads ──────────────────────────────────────────────────────────────
PAYLOADS = [
    {
        "name": "SQLi – OR 1=1",
        "method": "GET",
        "path": "/login/index.php",
        "query_params": "q=' OR 1=1--",
        "body": "",
        "headers": "User-Agent: Mozilla/5.0",
        "request_raw": "",
    },
    {
        "name": "XSS – img onerror",
        "method": "GET",
        "path": "/search",
        "query_params": "q=<img src=x onerror=alert(1)>",
        "body": "",
        "headers": "User-Agent: Mozilla/5.0",
        "request_raw": "",
    },
    {
        "name": "XSS – URL-encoded",
        "method": "GET",
        "path": "/login/index.php",
        "query_params": "q=%3Csvg%2Fonload%3Dalert(1)%3E",
        "body": "",
        "headers": "User-Agent: Mozilla/5.0",
        "request_raw": "",
    },
]

SEP = "=" * 70

# ── 2. Stage 1: AnomalyDetector ──────────────────────────────────────────────
print(f"\n{SEP}\nSTAGE 1 — AnomalyDetector\n{SEP}")
try:
    from proxy.ml.anomaly_detector import AnomalyDetector
    ad = AnomalyDetector()
    print(f"  is_trained     : {ad.is_trained}")
    print(f"  decision_threshold: {ad.decision_threshold}")
    print(f"  meta_classifier: {'loaded' if ad.meta_classifier else 'None'}")
except Exception as e:
    print(f"  [ERROR] AnomalyDetector init: {e}")
    ad = None

for p in PAYLOADS:
    print(f"\n  Payload: {p['name']}")
    if ad is None:
        print("    [SKIP] AnomalyDetector not available")
        continue
    anomaly_input = {
        "request": {
            "url": f"{p['path']}?{p['query_params']}",
            "method": p["method"],
            "headers": {},
            "body": p["body"],
        },
        "response": {"status_code": 200, "size": 0, "time": 0, "headers": {}},
        "request_count_last_minute": 1,
        "unique_ips_last_minute": 1,
        "error_rate_last_minute": 0.0,
    }
    try:
        is_anomaly, score, reason = ad.detect(anomaly_input)
        print(f"    is_anomaly={is_anomaly}  score={score:.4f}  reason={reason[:80]}")
    except Exception as e:
        print(f"    [ERROR] detect(): {e}")
        try:
            is_anomaly, score, reason = ad._heuristic_detection(anomaly_input)
            print(f"    HEURISTIC fallback: is_anomaly={is_anomaly}  score={score:.4f}  reason={reason[:80]}")
        except Exception as e2:
            print(f"    [ERROR] heuristic fallback: {e2}")

# ── 3. Stage 2: AttackClassifier ─────────────────────────────────────────────
print(f"\n{SEP}\nSTAGE 2 — AttackClassifier\n{SEP}")
try:
    from proxy.ml.attack_classifier import AttackClassifier
    ac = AttackClassifier()
    print(f"  is_trained     : {ac.is_trained}")
    print(f"  model          : {type(ac.model).__name__ if ac.model else 'None'}")
except Exception as e:
    print(f"  [ERROR] AttackClassifier init: {e}")
    ac = None

for p in PAYLOADS:
    print(f"\n  Payload: {p['name']}")
    if ac is None:
        print("    [SKIP] AttackClassifier not available")
        continue

    request = {k: v for k, v in p.items() if k != "name"}

    # a) Raw feature vector
    try:
        fv = ac.extract_features(request)
        print(f"    feature_vector shape={fv.shape}  sum={fv.sum():.2f}  nonzero={int((fv != 0).sum())}")
    except Exception as e:
        print(f"    [ERROR] extract_features: {e}")

    # b) Model predict (bypass postprocess)
    if ac.model and ac.is_trained:
        try:
            import numpy as np
            fv2 = ac.extract_features(request).reshape(1, -1)
            if ac.scaler:
                fv2 = ac.scaler.transform(fv2)
            raw_pred = ac.model.predict(fv2)[0]
            raw_label = ac._decode_label(raw_pred)
            raw_conf  = ac._predict_confidence(fv2)
            print(f"    model.predict()  raw_label={raw_label!r}  raw_conf={raw_conf:.4f}")
        except Exception as e:
            print(f"    [ERROR] model.predict: {e}")
    else:
        print("    model not trained — predict() will return ('unknown', 0.0)")

    # c) Full predict (with postprocess)
    try:
        attack_type, conf = ac.predict(request)
        dbg = ac.last_debug_info
        print(f"    predict() → attack_type={attack_type!r}  confidence={conf:.4f}")
        print(f"      has_strong_evidence : {dbg.get('has_strong_evidence')}")
        print(f"      keyword_only        : {dbg.get('keyword_only')}")
        print(f"      encoded_payload     : {dbg.get('encoded_payload')}")
        print(f"      sqli_signals        : {dbg.get('signals',{}).get('sqli')}")
        print(f"      xss_signals         : {dbg.get('signals',{}).get('xss')}")
        print(f"      educational_hits    : {dbg.get('educational_hits')}")
        print(f"      explanation         : {dbg.get('explanation')}")
    except Exception as e:
        print(f"    [ERROR] predict: {e}")

# ── 4. Stage 3: DecisionEngine ───────────────────────────────────────────────
print(f"\n{SEP}\nSTAGE 3 — DecisionEngine (with synthetic scores)\n{SEP}")
try:
    from proxy.ml.decision_engine import DecisionEngine
    de = DecisionEngine()
    test_cases = [
        ("sqli",  0.75, 0.72),
        ("XSS",   0.75, 0.72),
        ("XSS",   0.75, 0.0),   # confidence=0 path
        ("unknown", 0.75, 0.0),  # typical fallback path
        ("normal",  0.72, 0.0),  # normal prediction path
    ]
    for atype, ascore, aconf in test_cases:
        r = de.decide(anomaly_score=ascore, attack_type=atype, confidence=aconf)
        print(f"  [{atype:12s}] anomaly={ascore:.2f} conf={aconf:.2f} → {r['decision']:6s} ({r['reason'][:60]})")
except Exception as e:
    print(f"  [ERROR] DecisionEngine: {e}")

# ── 5. Full pipeline (ml_pipeline_integration) ───────────────────────────────
print(f"\n{SEP}\nSTAGE 4 — Full process_http_request()\n{SEP}")
try:
    from integrations.ml_pipeline_integration import process_http_request, _pipeline_init_error
    if _pipeline_init_error:
        print(f"  [PIPELINE INIT ERROR]: {_pipeline_init_error}")
    for p in PAYLOADS:
        req = {k: v for k, v in p.items() if k != "name"}
        result = process_http_request(req)
        print(f"\n  {p['name']}")
        print(f"    decision     = {result['decision']}")
        print(f"    confidence   = {result['confidence']}")
        print(f"    anomaly_score= {result['anomaly_score']}")
        print(f"    attack_type  = {result['attack_type']}")
        print(f"    reason       = {result['reason'][:80]}")
except Exception as e:
    import traceback
    print(f"  [ERROR] process_http_request: {e}")
    traceback.print_exc()

print(f"\n{SEP}\nDONE\n{SEP}\n")
