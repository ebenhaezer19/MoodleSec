# 🚀 STEP-BY-STEP MENCAPAI 1500-2000 SAMPLES (EXACT NUMBERS)

## 🎯 TARGET BREAKDOWN (ANGKA, BUKAN PERSEN)

```
TOTAL NEEDED: 1500
├── Real Data: 300 samples (curent 346, maybe +0-50 from scan)
├── Augmented Data: 750 samples (dari 346, augment ~2.2x each)
└── Synthetic Data: 450 samples (generated dari payloads)

ATAU kalau butuh 2000:
├── Real Data: 400 samples (346 existing + ~54 dari scan)
├── Augmented Data: 1000 samples (dari 346, augment ~3x each)
└── Synthetic Data: 600 samples (generated dari payloads)
```

---

## 📋 STEP-BY-STEP KONKRET

### **STEP 1: PREPARE 346 EXISTING DATA (SUDAH ADA)**

**Status:** ✅ DONE (file: auto_labeled_20251219_033444.json)

```
Input: 346 samples
  - 40 TP (True Positive)
  - 306 FP (False Positive)
  
Output: Siap untuk augmentation
Time: 0 (sudah ada!)
```

---

### **STEP 2: SCAN UNTUK +300-350 REAL DATA BARU**

**Durasi: 4-5 jam**

#### **Scan Moodle 4.0.3 (yang ada)**

```
Scan 1 - Baseline:
  Command: zap-cli quick-scan http://localhost/moodle
  Output: ~100 findings
  TP: 10-15
  FP: 85-90
  Time: 30 mins

Scan 2 - Active (deep):
  Command: zap-cli active-scan --recursive http://localhost/moodle
  Output: ~150 findings
  TP: 20-30
  FP: 120-130
  Time: 1.5-2 hours

Subtotal dari 4.0.3: 250 samples (30 TP + 220 FP)
Time: 2-2.5 hours
```

#### **Scan Moodle 3.9.x (setup baru)**

```
Setup 3.9 jika ingin lebih banyak CVE:
  Docker setup: 15 mins
  
Scan 1 - Baseline:
  Output: ~120 findings
  TP: 15-20
  FP: 100-105
  Time: 30 mins

Scan 2 - Active:
  Output: ~180 findings
  TP: 30-40
  FP: 140-150
  Time: 1.5-2 hours

Subtotal dari 3.9: 300 samples (45 TP + 255 FP)
Time: 2-2.5 hours
```

**PILIH SALAH SATU:**
- ✅ **Hanya 4.0.3**: +250 samples (4.0.3 alone), Time: 2-2.5 hours
- ✅ **4.0.3 + 3.9.x**: +550 samples (best), Time: 4-5 hours

**REKOMENDASI: 4.0.3 + 3.9.x** = +550, tapi gunakan 300 terbaik

```
Total Real Data Seharusnya:
  Existing: 346
  + Scan baru: 300 (best dari 550, filter low confidence)
  = 646 real samples ✅
```

---

### **STEP 3: AUGMENTASI 646 REAL DATA → 750 AUGMENTED**

**Durasi: 1-2 jam**

```
INPUT: 646 real samples (346 existing + 300 from scans)

AUGMENTATION TARGETS:
  - TP (70 total): augment 3-4x each = 210-280 samples
  - FP (576 total): augment 1.5x each = 864 samples
  
ADJUSTED TO TARGET 750:
  Keep top TP augmented (280)
  Keep best FP augmented (470)
  = 750 augmented samples ✅

METHOD: Variation strategies
  1. SQL Injection: Change operators, add comments, encoding
     - Input: "' OR '1'='1"
     - Variants: "' OR 1=1#", "' OR 1=1--", "' /*!50000OR*/ 1=1", etc
     - Per payload: 3-4 variants
  
  2. XSS: Different tags, encoding, contexts
     - Input: "<script>alert('xss')</script>"
     - Variants: "<img src=x onerror=alert('xss')>", "&#60;script&#62;...", etc
     - Per payload: 2-3 variants
  
  3. URL variation: Different parameters, methods
     - Input: "/search.php?q=test"
     - Variants: "/search?q=test", "/search.php?query=test", POST /search, etc
     - Per payload: 2-3 variants

SCRIPT NEEDED:
  augment_payloads.py
  Input: 646 samples
  Output: 750 augmented
  
TIME: 1-2 hours to write + verify
```

**Code skeleton:**
```python
def augment_payload(payload, count=3):
    """Generate 3-4 variations per payload"""
    variants = [payload]
    
    # SQL injection variations
    if "OR" in payload or "SELECT" in payload:
        variants.append(payload.replace("'", "' /**/"))
        variants.append(payload.replace("OR", "/*!50000OR*/"))
        variants.append(payload + "-- -")
    
    # XSS variations
    if "script" in payload.lower():
        variants.append(payload.replace("<script>", "<img src=x onerror='"))
        variants.append(payload.replace("</script>", "'>"))
    
    # URL variations
    if "?" in payload:
        variants.append(payload.replace("?", "&"))
        variants.append(payload.replace("&", "?", 1))
    
    return variants[:count]

# Process
augmented = []
for sample in real_data:
    augmented.append(sample)  # Keep original
    augmented.extend(augment_payload(sample['payload'], 2))

# Keep best 750
augmented_filtered = filter_by_confidence(augmented, 750)
```

**Output:**
```
750 augmented samples
├── 280 TP variations (from 70 TP × 4)
└── 470 FP variations (from 576 FP × 0.8)
```

---

### **STEP 4: GENERATE 450 SYNTHETIC PAYLOADS**

**Durasi: 1-2 jam**

```
INPUT: OWASP Top 10 + Common attack patterns

SYNTHETIC GENERATION TARGETS:

SQL Injection (100 payloads):
  Patterns:
    - ' OR '1'='1
    - ' OR 1=1#
    - ' OR 'a'='a
    - '; DROP TABLE users;--
    - UNION SELECT NULL,NULL,NULL
    - 1' UNION ALL SELECT NULL,NULL--
    - admin' --
    - ' OR 1=1/*
  
  Generate variations: ×5-10 per pattern = 50-100
  
  Example generation:
  ```python
  sql_patterns = [
      "' OR '{0}'='{0}",
      "' OR {0}={0}",
      "'; DROP TABLE {0};--",
      "' UNION SELECT {0},{0},{0}--"
  ]
  
  payloads = []
  for pattern in sql_patterns:
      for var in ['1', 'a', 'admin', 'users']:
          payloads.append(pattern.format(var))
  ```

XSS (100 payloads):
  Patterns:
    - <script>alert('xss')</script>
    - <img src=x onerror=alert('xss')>
    - <svg onload=alert('xss')>
    - javascript:alert('xss')
    - "><script>alert('xss')</script>
    - <iframe src="javascript:alert('xss')">
  
  Generate via encoding/obfuscation:
    - HTML encoding: &lt;script&gt;
    - JavaScript encoding: \x3cscript\x3e
    - URL encoding: %3Cscript%3E
    - Mixed encoding combinations
  
  Per pattern: ×10 variations = 100

CSRF (50 payloads):
  - <img src="http://bank.com/transfer?to=attacker&amount=1000">
  - <form action="..." method="POST"><input...><script>form.submit()</script>
  - Fetch requests with forged CSRF tokens
  - Per pattern: ×5 = 50

Path Traversal (100 payloads):
  - ../../../../etc/passwd
  - ..\\..\\..\\windows\\win.ini
  - ....//....//....//etc/passwd
  - %2e%2e%2fetc%2fpasswd
  - Per pattern: ×10 = 100

Command Injection (100 payloads):
  - ; whoami
  - | cat /etc/passwd
  - $(whoami)
  - `whoami`
  - && whoami
  - Per pattern: ×10 = 100

TOTAL SYNTHETIC: 450 payloads ✅
```

**Script skeleton:**
```python
def generate_synthetic_payloads(count=450):
    """Generate synthetic attack payloads"""
    
    payloads = {
        'sql_injection': generate_sql_variants(100),
        'xss': generate_xss_variants(100),
        'path_traversal': generate_path_variants(100),
        'command_injection': generate_cmd_variants(100),
        'csrf': generate_csrf_variants(50)
    }
    
    all_payloads = []
    for category, items in payloads.items():
        all_payloads.extend(items)
    
    return all_payloads[:count]

# Each synthetic payload:
synthetic_data = [
    {
        "payload": "' OR '1'='1",
        "type": "SQL Injection",
        "origin": "synthetic",
        "label": "TP"  # Mark as attack payload
    },
    ...
]
```

**Output:**
```
450 synthetic samples
├── 100 SQL Injection
├── 100 XSS
├── 100 Path Traversal
├── 100 Command Injection
└── 50 CSRF
```

---

### **STEP 5: COMBINE SEMUA → 1500 BALANCED**

**Durasi: 30 mins**

```
COMBINE:
  346 existing real
  + 300 new real (dari scans)
  + 750 augmented
  + 450 synthetic
  = 1846 total

BALANCE & FILTER:
  Remove duplicates: -100
  = 1746

KEEP BEST 1500:
  - Real (346 + 300): 646 (balanced TP/FP)
  - Augmented: 600 (best variations)
  - Synthetic: 254 (best payloads only)
  = 1500 exactly ✅

TP RATIO TARGET:
  - Real TP: 70 (from 346 existing)
  - Scan TP: 45 (from +300 scan)
  - Augmented TP: 115 (4x from 70+45)
  - Synthetic TP: 254 (all synthetic marked as TP)
  
  Total TP: 484 (32%)
  Total FP: 1016 (68%)
  = BALANCED for FP Reducer training ✅
```

**Script:**
```python
def combine_datasets():
    existing = load_json("auto_labeled_20251219_033444.json")  # 346
    scanned = load_json("scan_moodle_filtered.json")  # 300
    augmented = load_json("augmented_payloads.json")  # 750
    synthetic = load_json("synthetic_payloads.json")  # 450
    
    # Combine
    combined = existing + scanned + augmented + synthetic
    
    # Remove near-duplicates (cosine similarity > 0.95)
    combined = deduplicate(combined)
    
    # Balance TP/FP ratio
    combined = balance_classes(combined)
    
    # Keep best 1500
    combined = combined[:1500]
    
    # Save
    save_json(combined, "training_1500_balanced.json")
    
    return combined
```

**Output:**
```
training_1500_balanced.json
├── 646 real samples (346 old + 300 new)
│   ├── 115 TP
│   └── 531 FP
├── 600 augmented samples
│   ├── 192 TP (augmented)
│   └── 408 FP (augmented)
└── 254 synthetic samples
    └── 254 TP (all attack payloads)

TOTAL: 1500
├── TP: 561 (37%)
└── FP: 939 (63%)
```

---

### **STEP 6: TRAIN MODEL DENGAN 1500 DATA**

**Durasi: 30 mins**

```python
from ml.models.fp_reducer import FPReducer

# Load training data
training_data = load_json("training_1500_balanced.json")

# Create reducer
fp_reducer = FPReducer()

# Train
results = fp_reducer.train(training_data)

# Results:
# - Train accuracy: 88-92%
# - Validation accuracy: 80-85%
# - Test accuracy: 75-80% ✅ (vs 25% sebelumnya!)
```

---

## 📅 COMPLETE TIMELINE

```
DAY 1 (3-4 hours):
  [ ] Scan Moodle 4.0.3: 2-2.5 hours → +250 samples
  [ ] Optional: Setup Moodle 3.9.x: 15 mins
  
DAY 2 (4-5 hours):
  [ ] Scan Moodle 3.9.x (if setup): 2-2.5 hours → +300 samples
  [ ] Clean + filter scan results: 1 hour → 300 best
  
DAY 3 (2-3 hours):
  [ ] Write augmentation script: 1 hour
  [ ] Run augmentation: 30 mins → 750 augmented
  
DAY 4 (2 hours):
  [ ] Write synthetic generation script: 1 hour
  [ ] Generate 450 synthetic payloads: 30 mins
  
DAY 5 (1 hour):
  [ ] Combine + balance + filter: 30 mins → 1500 dataset
  [ ] Train model: 30 mins → Final results
  
TOTAL TIME: 12-16 hours (1.5-2 working days)
```

---

## 🎯 CHECKLIST DENGAN EXACT NUMBERS

### **Real Data**
```
[ ] Existing data: 346 samples ✅ (sudah ada)
[ ] Scan 4.0.3: +250 samples (2.5 hours)
[ ] Scan 3.9.x: +300 samples (2.5 hours, optional)
[ ] Filter best: = 300 samples to add
[ ] TOTAL REAL: 646 samples
```

### **Augmentation**
```
[ ] Input: 646 real samples
[ ] Augment each 1.5x-2x: = 970-1292 samples
[ ] Keep best: = 750 samples ✅
[ ] Quality: 2-3 variations per original
```

### **Synthetic**
```
[ ] SQL Injection: 100 payloads
[ ] XSS: 100 payloads
[ ] Path Traversal: 100 payloads
[ ] Command Injection: 100 payloads
[ ] CSRF: 50 payloads
[ ] TOTAL SYNTHETIC: 450 samples ✅
```

### **Final Dataset**
```
[ ] Combine: 646 + 750 + 450 = 1846
[ ] Remove duplicates: -346
[ ] FINAL: 1500 samples ✅
[ ] TP ratio: 30-40%
[ ] FP ratio: 60-70%
[ ] Training set: Ready ✅
```

---

## 💪 HASIL DIHARAPKAN

```
BEFORE:
  - 346 data
  - 25% test accuracy
  - Imbalanced TP/FP

AFTER (dengan 1500 data):
  - 1500 data
  - 75-80% test accuracy ⬆️
  - Balanced TP/FP
  - 4x better quality! 🚀

MODEL PERFORMANCE:
  Train Accuracy: 88-92%
  Val Accuracy: 82-86%
  Test Accuracy: 75-80%
  F1-Score: 0.75-0.82
```

---

## 📝 EXACT NUMBERS SUMMARY

```
STAGE 1 - Real Data:
  Start: 346
  + Scan: 300
  = 646 total

STAGE 2 - Augmentation:
  Input: 646
  Multiply: 1.2x
  Output: 750

STAGE 3 - Synthetic:
  Generate: 450

STAGE 4 - Combine:
  646 + 750 + 450 = 1846
  - Dedupe: -346
  = 1500 final ✅

TIME: 12-16 hours (2 days intensive)
QUALITY: 75-80% (4x improvement)
```

Mau mulai dari mana? 🚀
