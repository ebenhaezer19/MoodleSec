# 🎯 KLARIFIKASI: DATA REQUIREMENT PER MODEL

## ❓ PERTANYAAN

"1500 TP dan FP itu untuk model yang mana?"

---

## ✅ JAWAB

**1500 TP + 1500 FP HANYA untuk MODEL: FALSE POSITIVE REDUCER**

Untuk model lainnya BERBEDA requirement!

---

## 📊 REQUIREMENT PER MODEL

### **MODEL 1: FALSE POSITIVE REDUCER** ✅

```
BUTUH: 1500 TP + 1500 FP = 3000 total
       (atau minimum 600 TP + 600 FP = 1200)

TUJUAN: Binary classification (True Positive vs False Positive)

LABEL DATA:
  - TP (True Positive = Real vulnerability) = class 0
  - FP (False Positive = Not real) = class 1

REQUIREMENT:
  ✅ BALANCED: 50% TP (1500) + 50% FP (1500)
  ✅ MUST HAVE: Real findings vs False alarms
  ✅ PURPOSE: Reduce false positives dari scanner

DATA:
  - TP: Real SQL injection, XSS, auth bypass (sebenarnya ada)
  - FP: False findings, misconfig that's not real (sebenarnya tidak ada)
```

---

### **MODEL 2: SEVERITY PREDICTOR** ❌ (TIDAK 1500 TP/FP!)

```
BUTUH: 1000-1500 TOTAL (bukan TP/FP split!)
       Tapi BALANCED per severity level

TUJUAN: Classification ke 5 severity levels

LABEL DATA:
  - info = class 0
  - low = class 1
  - medium = class 2
  - high = class 3
  - critical = class 4

REQUIREMENT:
  ✅ BALANCED: 200-300 per severity level (bukan TP/FP!)
  ✅ Info: 200-300 samples
  ✅ Low: 200-300 samples
  ✅ Medium: 200-300 samples
  ✅ High: 200-300 samples
  ✅ Critical: 200-300 samples (HARUS ADA!)
  ✅ PURPOSE: Predict severity of ANY finding

DATA:
  - Setiap sample adalah 1 finding
  - Label: severity level (info/low/medium/high/critical)
  - TIDAK perlu TP/FP, perlu severity rating!

EXAMPLE:
  {
    "url": "/admin/panel",
    "finding": "Missing login required",
    "severity": "info"  ← Label ini!
  }
```

---

### **MODEL 3: RATE LIMITER** ❌ (TIDAK 1500 TP/FP!)

```
BUTUH: 2000-2500 TOTAL (bukan TP/FP split!)

TUJUAN: Predict risk score (0-100) untuk requests

LABEL DATA:
  - risk_score: Float 0-100 (bukan kategori!)

REQUIREMENT:
  ✅ DIVERSE: Mix of different risk levels
  ✅ Normal requests: 1000 (risk 0-30)
  ✅ Suspicious requests: 500 (risk 30-70)
  ✅ Malicious requests: 1000 (risk 70-100)
  ✅ TIDAK harus balanced, but perlu distribution
  ✅ PURPOSE: Predict risk scores untuk adaptive rate limiting

DATA:
  - Setiap sample adalah 1 request
  - Label: risk score (numeric 0-100, bukan kategori!)
  - CONTOH: "/user.php?id=1' OR '1'='1" = 85.5 risk

EXAMPLE:
  {
    "url": "/user.php?id=1' OR '1'='1",
    "risk_score": 85.5  ← Label ini (angka, bukan kategori)
  }
```

---

## 🎓 RINGKAS PERBEDAAN

```
MODEL                TYPE            LABEL           BUTUH         BALANCED?
──────────────────────────────────────────────────────────────────────────
FP Reducer      Binary Classifier  TP/FP category  1500+1500     ✅ YES 50/50
Severity        Multi-class        Severity level  1000 total     ✅ YES ~200 each
Rate Limiter    Regression Predict Risk_score      2000-2500      🔶 NO strict
```

---

## 🔴 COMMON MISTAKES

### ❌ KESALAHAN 1: Campur Label TP/FP ke Severity

```
SALAH:
  {
    "finding": "SQL Injection",
    "severity": "critical",
    "label": "TP"  ← TIDAK buat severity predictor!
  }

BENAR untuk Severity Predictor:
  {
    "finding": "SQL Injection",
    "severity": "critical"  ← Label hanya ini!
    (tidak perlu "label": "TP")
  }
```

### ❌ KESALAHAN 2: Pakai Risk Score untuk FP Reducer

```
SALAH:
  {
    "finding": "Missing header",
    "risk_score": 0.5,
    "label": "FP"  ← Mixing FP label dengan risk score!
  }

BENAR:
  Untuk FP Reducer:
    "label": "TP" atau "FP" (kategori, bukan risk score)
  
  Untuk Rate Limiter:
    "risk_score": 0.5 (numeric, bukan TP/FP label)
```

### ❌ KESALAHAN 3: Missing Critical Level di Severity

```
SALAH:
  Severity data punya: Info, Low, Medium, High (NO CRITICAL!)
  Label akan error karena missing class

BENAR:
  HARUS punya semua 5: Info, Low, Medium, High, Critical
  Atau minimal 3-4 saja tapi jangan mix dengan model lain
```

---

## 📋 DATA FORMAT PER MODEL

### **FALSE POSITIVE REDUCER Data Format**

```json
{
  "finding": {
    "severity": "critical",
    "category": "SQL Injection",
    "description": "...",
    "evidence": "...",
    "cvss_score": 9.8,
    "url": "..."
  },
  "label": "TP"  ← ONLY THIS! (TP atau FP)
}
```

---

### **SEVERITY PREDICTOR Data Format**

```json
{
  "finding": {
    "severity": "high",  ← Part of feature, not the label!
    "category": "SQL Injection",
    "description": "...",
    "evidence": "...",
    "cvss_score": 9.8,
    "url": "..."
  },
  "context": {...},
  "label": "critical"  ← LABEL is severity level (info/low/medium/high/critical)
}
```

---

### **RATE LIMITER Data Format**

```json
{
  "request": {
    "url": "/user.php?id=1' OR '1'='1",
    "method": "GET",
    "body": "",
    "headers": {}
  },
  "ip": "192.168.1.1",
  "risk_score": 85.5  ← LABEL is numeric risk score (0-100)
}
```

---

## 🎯 QUICK REFERENCE TABLE

```
MODEL               NEEDS              EXAMPLE LABEL          FORMAT
──────────────────────────────────────────────────────────────────
FP Reducer          600-1500           "TP" or "FP"          String
                    TP + FP pair                              Category

Severity            1000-1500          "critical"            String
Predictor           per level          "high"                Category
                    200-300 each        "medium"
                                        "low"
                                        "info"

Rate                2000-2500          85.5                  Float
Limiter             diverse            42.1                  0-100
                                        0.0
```

---

## 💡 UNTUK DATA ANDA (346 samples)

### SAAT INI PUNYA:

```
auto_labeled_20251219_033444.json:
  - 40 TP
  - 306 FP
  - Average confidence: 80.43%

DIGUNAKAN UNTUK: FALSE POSITIVE REDUCER ✅
  ✅ COCOK! Punya TP dan FP
  ❌ TAPI IMBALANCE (88% FP, 12% TP)
  ⚠️ PERLU rebalance atau augment

TIDAK COCOK UNTUK:
  ❌ Severity Predictor (tidak punya severity labels)
  ❌ Rate Limiter (tidak punya risk scores)
```

---

## 🎯 ACTION PER MODEL

### **FOR FALSE POSITIVE REDUCER:**

```
Punya: 40 TP + 306 FP
Butuh: 600 TP + 600 FP (minimum)
       atau 1500 TP + 1500 FP (optimal)

Strategy:
  1. Rebalance existing: 40 TP + 40 FP
  2. Augment 20x: 800 + 800
  3. Collect new: +700 TP dari testing
  4. Result: 1540 TP + 1540 FP ✅
```

### **FOR SEVERITY PREDICTOR:**

```
Punya: 346 findings (tapi no severity label!)
Butuh: 1000-1500 findings WITH severity label
       200-300 per severity level (info/low/medium/high/critical)

Strategy:
  1. Take existing 346 findings
  2. Add severity label (perlu mapping/manual review)
  3. Supplement dengan critical findings (0 sekarang)
  4. Target: 200 info + 200 low + 200 medium + 200 high + 200 critical = 1000
```

### **FOR RATE LIMITER:**

```
Punya: 346 findings (tapi no risk scores!)
Butuh: 2000-2500 requests WITH risk scores (0-100)

Strategy:
  1. Take existing 346 findings
  2. Convert to requests with risk scores
  3. Add normal request examples (1000)
  4. Generate malicious requests (1000)
  5. Total: 2300+ samples
```

---

## 🚀 NOW WHAT?

### CLEAR ANSWER TO YOUR QUESTION:

```
1500 TP + 1500 FP adalah UNTUK: FALSE POSITIVE REDUCER ONLY

Untuk model lain:
- Severity Predictor: 1000-1500 balanced per severity level (bukan TP/FP!)
- Rate Limiter: 2000-2500 dengan diverse risk scores (bukan TP/FP!)
```

### NEXT STEPS:

```
1. UNTUK FP REDUCER (using 346 data):
   ✅ Rebalance + Augment → 1500 TP + 1500 FP
   ✅ Already in correct format!

2. UNTUK SEVERITY PREDICTOR:
   ✅ Take 346 findings
   ✅ Add severity labels
   ✅ Add critical examples
   ✅ Target: 1000+ with balance

3. UNTUK RATE LIMITER:
   ✅ Convert findings to requests
   ✅ Add risk scores
   ✅ Add normal + malicious patterns
   ✅ Target: 2000+ diverse
```

---

## 📝 SUMMARY

**1500 TP + 1500 FP requirement ONLY untuk FALSE POSITIVE REDUCER**

Untuk model lain:
- **Severity**: 1000-1500 total, balanced across 5 levels
- **Rate Limiter**: 2000-2500 total, diverse risk scores

Data anda (346) cocok untuk FP Reducer, perlu augment/collect untuk optimal! 🚀
