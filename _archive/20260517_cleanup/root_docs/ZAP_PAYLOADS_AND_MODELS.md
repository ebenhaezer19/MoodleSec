# 🎯 ZAP PAYLOADS & MODEL REQUIREMENTS

## ❓ PERTANYAAN

"Saya mau ngambil payload dari scanner ZAP untuk tau FP dan TPnya. Model yang mana yang sebenarnya TIDAK perlu ZAP payloads?"

---

## 📌 RINGKAS JAWAB

**ZAP (OWASP Zed Attack Proxy) = Security Scanner**
- Detects vulnerabilities dengan inject payloads
- Output: Findings dengan severity levels, payloads, evidence

**DARI 4 MODEL, YANG TIDAK PERLU ZAP PAYLOADS:**
- ✅ **ANOMALY DETECTOR** (tidak perlu payloads sama sekali!)

**YANG PERLU ZAP PAYLOADS:**
- ❌ FP Reducer (perlu tau payload mana FP, mana TP)
- ❌ Severity Predictor (perlu tau severity dari payload)
- ❌ Rate Limiter (perlu tau risk score dari payload)
- ❌ Anomaly Detector (perlu NORMAL baseline, bukan attack payloads)

---

## 📊 PERBANDINGAN: YANG PERLU vs TIDAK PERLU ZAP

```
MODEL               ZAP PAYLOADS?   REASON
──────────────────────────────────────────────────────────────
FP Reducer          ✅ PERLU        Identify which payloads 
                                     result in FP vs TP

Severity            ✅ PERLU        Label findings by severity
Predictor                            based on ZAP detection

Rate Limiter        ✅ PERLU        Score risk based on 
                                     payload type/complexity

Anomaly             ❌ TIDAK PERLU   Train dari NORMAL behavior,
Detector                             bukan attack payloads
```

---

## 🔴 MODEL YANG TIDAK PERLU ZAP PAYLOADS: ANOMALY DETECTOR

### **KENAPA?**

```
Anomaly Detector = Unsupervised Learning
  ↓
Belajar dari NORMAL/baseline behavior
  ↓
Detects deviations from normal
  ↓
TIDAK perlu inject payloads!

SEBALIKNYA:
- Payload injection MERUSAK training
- Model akan think attacks = normal
- Tidak valid untuk detect anomalies
```

### **ANOMALY DETECTOR DATA SOURCE**

```
✅ GUNAKAN: Normal/benign requests
  - Admin logins
  - User portal access
  - API calls
  - File downloads
  - Page loads

❌ JANGAN: Attack payloads dari ZAP
  - SQL injection payloads
  - XSS payloads
  - CSRF payloads
  - dll

DARI DATA 346 ANDA:
✅ Gunakan: 306 FP samples (normal/benign)
❌ JANGAN: 40 TP samples (actual attacks)
```

---

## ✅ MODEL YANG PERLU ZAP PAYLOADS

### **1. FALSE POSITIVE REDUCER**

```
TUJUAN: Distinguish real findings vs false alarms

GUNAKAN ZAP PAYLOADS:
  - TP: ZAP payload yang BENAR-BENAR vulnerable
        Misalnya: SQL injection actual impact
        
  - FP: ZAP payload yang FALSE
        Misalnya: Sanity check atau misconfiguration
                  yang tidak benar-benar vulnerable

DARI DATA ANDA:
  - 40 TP: Payloads yang ZAP detected correctly
  - 306 FP: Payloads yang ZAP detected incorrectly
```

### **2. SEVERITY PREDICTOR**

```
TUJUAN: Label findings dengan severity level

GUNAKAN ZAP PAYLOADS:
  - Input: ZAP findings dengan evidence/payload
  - Output: Label severity (info/low/medium/high/critical)
  
CONTOH:
  - SQL injection payload → likely = high/critical
  - Missing header → likely = info/low
  - XSS payload → likely = medium/high

DARI DATA ANDA:
  - Need to map 346 findings → severity levels
  - ZAP already detected, need to label severity
```

### **3. RATE LIMITER**

```
TUJUAN: Score risk for adaptive rate limiting

GUNAKAN ZAP PAYLOADS:
  - Input: Request dengan payload
  - Output: Risk score (0-100)
  
CONTOH RISK SCORING:
  - Normal request: 0-10 risk
  - Suspicious: 30-70 risk
  - Attack payload: 80-100 risk
  
DARI DATA ANDA:
  - 40 TP payloads = high risk (70-100)
  - 306 FP payloads = medium risk (30-70)
  - Need more normal requests = low risk (0-30)
```

---

## 🔄 WORKFLOW: DARI ZAP PAYLOADS KE MODEL TRAINING

```
┌─────────────────────────────────────────────────────────┐
│ STEP 1: RUN ZAP SCANNER                                 │
│ Output: Findings dengan payload, evidence, severity      │
│         (auto_labeled_20251219_033444.json)              │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ STEP 2: CLASSIFY FINDINGS                               │
│                                                          │
│ TP (True Positive):                                      │
│   - Payload is real vulnerability                       │
│   - Actually exploitable                                │
│   - Impact verified                                      │
│   - 40 samples in your data                             │
│                                                          │
│ FP (False Positive):                                    │
│   - Payload is not real vulnerability                  │
│   - False alarm                                         │
│   - No actual impact                                    │
│   - 306 samples in your data                           │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│ STEP 3: ROUTE TO MODELS                                 │
│                                                          │
│ TP + FP Payloads → FP Reducer (train/test)            │
│ All Payloads + Severity → Severity Predictor (need label)│
│ All Payloads + Risk Score → Rate Limiter (need label)  │
│ Normal/Benign → Anomaly Detector (306 FP samples)      │
└─────────────────────────────────────────────────────────┘
```

---

## 💡 PRAKTIK: HOW TO USE ZAP PAYLOADS

### **SCENARIO 1: FP Reducer (PERLU ZAP Payloads)**

```python
# From ZAP findings
finding = {
    "payload": "<script>alert('xss')</script>",
    "url": "/search.php?q=...",
    "severity": "medium",
    "is_verified": True  # ← This determines TP vs FP!
}

# Classification
if finding['is_verified'] and finding['evidence']:
    label = "TP"  # Real vulnerability
else:
    label = "FP"  # False alarm

# Training data
training_data.append({
    "payload": finding['payload'],
    "url": finding['url'],
    "headers": finding['headers'],
    "label": label  # TP or FP
})

# Train model
fp_reducer.train(training_data)
```

### **SCENARIO 2: Severity Predictor (PERLU ZAP Payloads)**

```python
# From ZAP findings
finding = {
    "payload": "<script>alert('xss')</script>",
    "type": "Stored XSS",
    "cvss_score": 6.1,
    "confidence": 100
}

# Severity labeling (manual or heuristic)
if finding['cvss_score'] >= 9.0:
    severity = "critical"
elif finding['cvss_score'] >= 7.0:
    severity = "high"
elif finding['cvss_score'] >= 4.0:
    severity = "medium"
else:
    severity = "low"

# Training data
training_data.append({
    "payload": finding['payload'],
    "cvss_score": finding['cvss_score'],
    "finding_type": finding['type'],
    "severity": severity  # Label!
})

# Train model
severity_predictor.train(training_data)
```

### **SCENARIO 3: Rate Limiter (PERLU ZAP Payloads)**

```python
# From ZAP findings (attacks)
finding = {
    "payload": "' OR '1'='1",
    "type": "SQL Injection",
    "is_verified": True
}

# Risk scoring from payloads
if finding['is_verified']:
    if finding['type'] in ['SQL Injection', 'RCE', 'XXE']:
        risk_score = 85.0  # Critical payload
    elif finding['type'] in ['XSS', 'CSRF']:
        risk_score = 65.0  # High payload
    else:
        risk_score = 45.0  # Medium

# Training data
training_data.append({
    "url": finding['url'],
    "payload": finding['payload'],
    "payload_type": finding['type'],
    "risk_score": risk_score  # Label!
})

# Also add normal requests for baseline
normal_request = {
    "url": "/user.php?id=1",
    "headers": {...},
    "risk_score": 5.0  # Very low
}
training_data.append(normal_request)

# Train model
rate_limiter.train(training_data)
```

### **SCENARIO 4: Anomaly Detector (TIDAK PERLU ZAP Payloads!)**

```python
# From normal/benign requests (FP samples = false alarms)
finding = {
    "url": "/admin/dashboard.php",
    "method": "GET",
    "status_code": 200,
    "response_time": 120,
    "is_false_positive": True  # FP = normal/benign!
}

# NO LABELING NEEDED - just use as-is
training_data.append({
    "request": {
        "url": finding['url'],
        "method": finding['method'],
        "headers": finding['headers'],
        "body": finding['body']
    },
    "response": {
        "status_code": finding['status_code'],
        "size": finding['response_size'],
        "time": finding['response_time']
    },
    # NO LABEL FIELD NEEDED!
})

# Train model (unsupervised)
anomaly_detector.train(training_data)
```

---

## 🎯 ACTIONABLE: UNTUK DATA 346 ANDA

### **ZAP PAYLOADS YANG SUDAH ANDA PUNYA:**

```json
auto_labeled_20251219_033444.json:
  - 40 TP payloads (actual vulnerabilities)
  - 306 FP payloads (false alarms/benign)
  - Average confidence: 80.43%
```

### **GUNAKAN UNTUK MODEL MANA?**

```
FP REDUCER:
  ✅ USE: 40 TP + 306 FP payloads
  ✅ Label: "TP" and "FP" (sudah jelas)
  ✅ Target: Reduce false alarms (306 FP)
  ✅ Test result: Identify mana next FP
  
SEVERITY PREDICTOR:
  ✅ USE: All 346 payloads
  ⚠️  NEED: Severity label (info/low/medium/high/critical)
  ⚠️  CURRENT: 0 critical examples (need to add!)
  📌 Action: Map 346 → 5 severity levels
  
RATE LIMITER:
  ✅ USE: All 346 payloads
  ⚠️  NEED: Risk scores (0-100)
  ⚠️  CURRENT: No normal requests (<5% of dataset)
  📌 Action: Add 1000+ normal request baselines
  
ANOMALY DETECTOR:
  ✅ USE: 306 FP payloads ONLY
  ❌ DONT: Use 40 TP (attack payloads)
  ℹ️  REASON: Train dari normal/benign behavior
  ✅ NO LABELS NEEDED (unsupervised!)
  ✅ READY TO TRAIN: 306 samples sudah cukup!
```

---

## 🚀 NEXT STEPS

### **UNTUK ANOMALY DETECTOR (Tidak perlu ZAP Payloads)**

```
1. Extract 306 FP samples dari auto_labeled data
2. Train dengan: anomaly_detector.train(306_fp_samples)
3. Test dengan: 40 TP samples (detect as anomalies)
4. DONE! Unsupervised, no labels needed
```

### **UNTUK FP REDUCER (Perlu ZAP Payloads)**

```
1. Extract TP: 40 payloads dengan label "TP"
2. Extract FP: 306 payloads dengan label "FP"
3. Augment: 20x + synthetic → 3000 total
4. Train: fp_reducer.train(1500_tp + 1500_fp)
5. Validate: Detection rate
```

### **UNTUK SEVERITY PREDICTOR (Perlu ZAP Payloads + Labels)**

```
1. Extract 346 payloads
2. ADD: Severity labels (0 critical → need to fix!)
3. Supplement: dengan critical examples
4. Balance: 200 per severity level
5. Train: severity_predictor.train(1200_balanced)
```

### **UNTUK RATE LIMITER (Perlu ZAP Payloads + Risk Scores)**

```
1. Extract 346 payloads → score as high risk (70-100)
2. Generate: 1000+ normal requests → score as low (0-20)
3. Generate: 500+ suspicious requests → score medium (30-70)
4. Balance: 2000+ total
5. Train: rate_limiter.train(2000_diverse)
```

---

## 📝 SUMMARY

```
ZAP PAYLOADS dari scanner output:

✅ GUNAKAN UNTUK:
   - FP Reducer (identify TP vs FP)
   - Severity Predictor (label severity)
   - Rate Limiter (assign risk scores)

❌ JANGAN UNTUK:
   - Anomaly Detector (tidak perlu payloads!)
   - Anomaly Detector butuh normal behavior, bukan attacks
   - 306 FP samples = perfect untuk training

ANOMALY DETECTOR UNIK:
- Tidak perlu ZAP payloads
- Tidak perlu labels
- Hanya butuh normal baseline (306 FP samples dah cukup!)
- Unsupervised = paling mudah untuk train
```

**JADI: ZAP payloads PERLU untuk 3 model, TIDAK PERLU untuk Anomaly Detector!** 🎯
