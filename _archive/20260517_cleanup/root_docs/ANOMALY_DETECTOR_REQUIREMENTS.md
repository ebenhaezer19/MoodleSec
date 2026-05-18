# 🎯 ANOMALY DETECTOR - DATA REQUIREMENTS

## ❓ PERTANYAAN

"Kalau anomaly detector?"

---

## ✅ JAWAB

**Anomaly Detector BERBEDA dari 3 model lainnya!**

Tidak perlu label TP/FP, tidak perlu severity level, tidak perlu risk scores.

---

## 📊 ANOMALY DETECTOR - KARAKTERISTIK

### **TUJUAN**

```
Detect UNUSUAL PATTERNS dalam:
- Request patterns (frequency, timing, format)
- Response patterns (status codes, sizes, headers)
- Finding patterns (severity distribution, type combinations)
- User behavior patterns (IPs, timing, volumes)
```

### **ALGORITHM**

```
Isolation Forest (Unsupervised Learning)
- Detects outliers/anomalies
- NO labels needed!
- Uses: Contamination ≈ 10% (expected anomalies)
```

### **FITUR (26 total)**

```
REQUEST FEATURES (5):
  - URL length
  - Path depth (/)
  - Query parameters (?)
  - Header count
  - Body size

RESPONSE FEATURES (4):
  - Status code
  - Response size
  - Response time
  - Response header count

FINDING FEATURES (3):
  - Severity (critical/high/medium/low/info)
  - Risk score
  - CVSS score

TEMPORAL FEATURES (2):
  - Hour of day
  - Day of week

BEHAVIORAL FEATURES (3):
  - Request count (last minute)
  - Unique IPs (last minute)
  - Error rate (last minute)

ENHANCED FEATURES (8):
  - Payload entropy (injection detection)
  - Suspicious payload patterns
  - User-Agent bot detection
  - Missing security headers
  - Status code abnormality
  - Request frequency spike
  - Response time deviation
  - Risk aggregation
```

---

## 🎯 DATA REQUIREMENT

### **BERAPA SAMPLES DIBUTUHKAN?**

```
MINIMUM:       20 samples of NORMAL behavior
RECOMMENDED:   100-500 samples of NORMAL behavior
OPTIMAL:       500-2000 samples of NORMAL behavior

TIDAK ADA label yang diperlukan!
```

### **JENIS DATA**

```
BUTUH: Normal/baseline behavior data
       (requests that DON'T represent attacks)

CONTOH DATA:
  - Legitimate admin logins
  - Normal user browsing patterns
  - Standard API calls
  - Regular report generation
  - Scheduled backups
  - Normal page loads

JANGAN: Only attack data
       Tidak cocok karena anomaly detector 
       belajar dari NORMAL behavior
```

### **LABEL/ANNOTATION**

```
❌ TIDAK PERLU TP/FP labels
❌ TIDAK PERLU severity labels
❌ TIDAK PERLU risk scores
✅ HANYA PERLU: Normal/baseline behavior

Unsupervised learning = no manual labels needed!
```

---

## 🆚 COMPARISON: SEMUA 4 MODEL

```
MODEL               TYPE            LABELS NEEDED    MIN SAMPLES
──────────────────────────────────────────────────────────────
FP Reducer      Binary Class    ✅ TP/FP          600
Severity        Multi-class     ✅ Level          1000
Rate Limiter    Regression      ✅ Risk score     2000
Anomaly Det.    Unsupervised    ❌ NONE NEEDED    20
```

---

## 💡 BAGAIMANA CARA TRAINING?

### **APPROACH 1: Collect Normal Behavior**

```
Step 1: Run application normally (no attacks)
Step 2: Capture 500 legitimate requests
Step 3: Train anomaly detector
Step 4: Model learns "normal" baseline
Step 5: Can detect when things deviate
```

### **APPROACH 2: Use Existing Clean Data**

```
Dari 346 auto-labeled data:
- Take ONLY the FP (False Positives) = 306 samples
- FP = not real attacks = normal behavior!
- Can use langsung untuk training!

Dari 346 auto-labeled:
- TP (True Positives) = 40 = actual attacks
- FP (False Positives) = 306 = normal/benign
- ✅ Use 306 FP for anomaly detector training!
```

### **APPROACH 3: Hybrid**

```
Normal behavior dari multiple sources:
- 306 FP dari auto-labeled data
- 200 legitimate requests dari production logs
- 100 admin operations
- 100 user logins
Total: 706 normal baseline samples
```

---

## 🔴 COMMON MISTAKES

### ❌ KESALAHAN 1: Training dengan Attack Data

```
SALAH:
  training_data = all 346 samples (40 TP + 306 FP)
  anomaly_detector.train(training_data)
  
  Masalah: 40 attacks akan jadi "normal"
  
BENAR:
  training_data = 306 FP only (normal/benign)
  anomaly_detector.train(training_data)
  
  Model learns: "These are normal"
  Detects: Deviations from this pattern
```

### ❌ KESALAHAN 2: Menggunakan Labels

```
SALAH:
  data = {
    "request": {...},
    "response": {...},
    "label": "normal"  ← TIDAK PERLU!
  }

BENAR:
  data = {
    "request": {...},
    "response": {...}
  }
  
  No labels needed - unsupervised!
```

### ❌ KESALAHAN 3: Terlalu Sedikit Data

```
SALAH:
  anomaly_detector.train([sample1, sample2])  # 2 samples
  
  Masalah: Isolation Forest butuh cukup data
           untuk belajar "normal" pattern

BENAR:
  anomaly_detector.train(samples)  # minimum 20, recommended 100+
```

---

## 📋 DATA FORMAT

```json
{
  "request": {
    "url": "/admin/dashboard.php",
    "method": "GET",
    "headers": {
      "User-Agent": "Mozilla/5.0...",
      "Authorization": "Bearer token..."
    },
    "body": ""
  },
  "response": {
    "status_code": 200,
    "size": 15234,
    "time": 120,
    "headers": {
      "Content-Type": "text/html",
      "X-Frame-Options": "DENY"
    }
  },
  "request_count_last_minute": 5,
  "unique_ips_last_minute": 1,
  "error_rate_last_minute": 0.0
}
```

**CATATAN: Tidak ada `finding` field diperlukan untuk training!**

---

## 🎯 UNTUK DATA 346 ANDA

### **SAAT INI PUNYA:**

```json
auto_labeled_20251219_033444.json:
  - 40 TP (True Positive = real attacks)
  - 306 FP (False Positive = normal/benign)

GUNAKAN:
  ✅ 306 FP samples → Training Anomaly Detector
  ✅ Already in correct format!
  ✅ No additional labeling needed!
  
JANGAN:
  ❌ TP samples (attacks) untuk training normal behavior
  ❌ Mixed TP+FP untuk training
```

### **STRATEGI**

```
1. Extract 306 FP dari auto_labeled data
   ↓
2. Train Anomaly Detector (no labels needed)
   ↓
3. Test dengan 40 TP samples
   ↓
4. Measure: Anomaly Detector harus detect TP as anomalies
```

---

## 🚀 ACTIONABLE NEXT STEPS

### **UNTUK ANOMALY DETECTOR:**

```
Punya: 306 FP (normal/benign samples)
Butuh: 20+ untuk training (punya 306 = sudah lebih dari cukup!)

Action:
  1. Extract 306 FP dari auto_labeled_20251219_033444.json
  2. Train model: anomaly_detector.train(306_fp_samples)
  3. Test dengan 40 TP → Harus detect as anomalies
  4. Expected: 80-90% anomaly detection rate
```

---

## 📝 RINGKAS

```
ANOMALY DETECTOR:
✅ Unsupervised (no labels needed)
✅ Use NORMAL behavior data
✅ From 346 samples: use 306 FP (benign)
✅ Minimum 20 samples, punya 306 = excellent!
❌ JANGAN pakai TP (attacks) untuk training

BERBEDA dengan:
- FP Reducer: Butuh TP/FP labels
- Severity: Butuh severity labels
- Rate Limiter: Butuh risk scores
```

**DATA 346 ANDA COCOK UNTUK ANOMALY DETECTOR!** 🎯

Bahkan bisa langsung pakai 306 FP samples tanpa preprocessing!
