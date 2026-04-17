# 🎯 DATA ASLI UNTUK MENCAPAI 1500: STRATEGI SCANNING

## ❓ SITUASI ANDA

```
Data sekarang:
  - 346 auto-labeled (scan ZAP lama)
  - 150 sintetik (generated)
  = 496 total ❌

Target: 1500 (FP Reducer training)

KEKURANGAN: 1000+ data asli
```

---

## ✅ JAWAB: DARI MANA DAPAT 1000 DATA ASLI?

### **OPSI 1: SCAN MOODLE 4.0.3 (YANG SUDAH ADA) - 3-4x**

```
STRATEGI: Scan Moodle 4.0.3 anda berkali-kali

SCAN 1 (Baseline):
  - Jenis: Baseline scan (cepat, 20-30 findings)
  - Findings: 10-20 TP + 50-100 FP
  
SCAN 2 (Active/Deep):
  - Jenis: Active scan lebih aggressive
  - Findings: 15-30 TP + 80-150 FP
  
SCAN 3 (Dengan auth):
  - Jenis: Scan dengan login (akses lebih dalam)
  - Findings: 10-20 TP + 60-120 FP
  
SCAN 4 (API endpoints):
  - Jenis: Scan REST API/custom endpoints
  - Findings: 5-15 TP + 40-80 FP

TOTAL PER SCAN: 60-120 samples
4x SCANS: 240-480 samples

PLUS yang sudah ada: 496
GRAND TOTAL: 736-976 ❌ (masih kurang)
```

### **OPSI 2: SCAN MOODLE 4.0.3 + 3.9.x (2 VERSI) - 2x masing2**

```
SCAN VERSI 4.0.3:
  SCAN 1 (Baseline): 70-120 samples
  SCAN 2 (Active): 100-180 samples
  Subtotal: 170-300 samples

SCAN VERSI 3.9.x:
  SCAN 1 (Baseline): 80-150 samples (lebih banyak CVE)
  SCAN 2 (Active): 150-250 samples (lebih aggressive)
  Subtotal: 230-400 samples

PLUS yang sudah ada: 496
GRAND TOTAL: 896-1196 ✅ (nyaris cukup!)

ATAU SCAN 3x masing2:
GRAND TOTAL: 1000-1500+ ✅✅ (cukup!)
```

### **OPSI 3: SCAN MOODLE + TAMBAH SOURCE LAIN**

```
Scan ZAP ke Moodle:
  - 4.0.3: 2 scans = 200-300
  - 3.9.x: 2 scans = 300-400
  Subtotal: 500-700

PLUS dari source lain:
  - CVE database dump: 100-200 (known CVE payloads)
  - OWASP samples: 50-100 (standard payloads)
  - Manual penetration: 50-100 (custom findings)
  
GRAND TOTAL: 700-1100+ ✅
```

---

## 🎯 REKOMENDASI: OPSI 2 (PALING PRAKTIS)

### **SETUP 2 VERSI MOODLE**

```
MOODLE 4.0.3 (yang sudah ada sekarang):
  ✅ Already running
  ✅ Minimal setup
  ❌ Fewer CVEs
  
MOODLE 3.9.x (setup baru, 15 mins):
  ✅ More vulnerabilities documented
  ✅ Better TP/FP ratio
  ⚠️  Setup required
```

### **SCANNING SCHEDULE**

```
MOODLE 4.0.3:
  Scan 1 (Baseline): 70-120 samples
  Scan 2 (Active): 100-180 samples
  Time: 1-2 hours
  
MOODLE 3.9.x:
  Scan 1 (Baseline): 80-150 samples
  Scan 2 (Active): 150-250 samples
  Time: 1-2 hours

TOTAL TIME: 3-4 hours
TOTAL DATA: 400-700 samples

PLUS 346 existing: 746-1046
AUGMENT + SYNTHETIC: 1200-1400+ ✅
```

---

## 📋 EXACT ACTIONS

### **ACTION 1: SCAN MOODLE 4.0.3 SEKARANG (SUDAH ADA)**

```bash
# SCAN 1: Baseline (cepat)
cd C:\path\to\ZAP
zap-cli --zap-options '-config api.disablekey=true' \
  quick-scan --self-signed \
  http://localhost/moodle

Output: zap_moodle403_baseline.json
Samples: 70-120

# SCAN 2: Active (more aggressive)
zap-cli --zap-options '-config api.disablekey=true' \
  active-scan \
  --recursive \
  http://localhost/moodle

Output: zap_moodle403_active.json
Samples: 100-180

TOTAL: 170-300 samples dari 4.0.3
```

### **ACTION 2: SETUP MOODLE 3.9.x (15 MINS SETUP)**

```bash
# OPTION A: Docker (fastest)
docker run -d \
  --name moodle39-scan \
  -p 8081:80 \
  -e MOODLE_DATABASE_HOST=mysql39 \
  -e MOODLE_DATABASE_USER=moodle \
  -e MOODLE_DATABASE_PASSWORD=moodlepassword \
  -e MOODLE_DATABASE_NAME=moodle39 \
  moodle:3.9

# OPTION B: Quick setup script (bernada anda install_moodle.sh)
bash install_moodle.sh --version 3.9

URL: http://localhost:8081
```

### **ACTION 3: SCAN MOODLE 3.9.x**

```bash
# SCAN 1: Baseline
zap-cli quick-scan --self-signed \
  http://localhost:8081

Output: zap_moodle39_baseline.json
Samples: 80-150

# SCAN 2: Active (lebih banyak CVE di versi 3.9)
zap-cli active-scan --recursive \
  http://localhost:8081

Output: zap_moodle39_active.json
Samples: 150-250

TOTAL: 230-400 samples dari 3.9
```

### **ACTION 4: COMBINE ALL DATA**

```python
# Pseudocode
existing_346 = load_auto_labeled()  # 346
scan40_170 = load_zap_scan("moodle403_baseline.json")  # 70-120
scan40_240 = load_zap_scan("moodle403_active.json")  # 100-180
scan39_115 = load_zap_scan("moodle39_baseline.json")  # 80-150
scan39_200 = load_zap_scan("moodle39_active.json")  # 150-250

total = 346 + 170 + 240 + 115 + 200
      = 1071 real data! ✅

# Augment 20%, add synthetic 20%
augmented = total * 1.4 = 1500+ ✅✅
```

---

## 🎯 ALTERNATIVE: KALAU MALU SETUP 3.9

```
Jika setup 3.9 terlalu ribet, atau waktu terbatas:

OPTION: Scan 4.0.3 aja, tapi LEBIH DALAM

SCAN 1: Quick scan = 70-120
SCAN 2: Active scan = 100-180
SCAN 3: Active + auth (login) = 120-200
SCAN 4: API endpoints only = 50-100

TOTAL: 340-600 dari 4.0.3 saja

PLUS existing: 346
TOTAL: 686-946

THEN:
- Augment 20x: 6860-9460 (tapi dicrop ke 1200)
- Add synthetic: +300
- FINAL: 1200-1500 ✅
```

---

## 📊 COMPARISON TABLE

```
STRATEGY                   SCANS    TIME     SAMPLES    EFFORT
──────────────────────────────────────────────────────────────
4.0.3 alone (4 scans)      4        2-3h     340-600    Easy ⭐
4.0 + 3.9 (2x2 scans)      4        3-4h     600-900    Medium ⭐⭐
4.0 + 3.9 (3x2 scans)      6        5-6h     900-1200   Hard ⭐⭐⭐
4.0 only (6 scans)         6        3-4h     600-900    Medium ⭐⭐
```

---

## 🚀 RECOMMENDED PLAN

### **JIKA WAKTU TERBATAS (1-2 hari)**

```
STEP 1: Scan Moodle 4.0.3 (4 scans)
  Time: 2-3 hours
  Data: 340-600 samples
  
STEP 2: Augment existing + new
  Time: 1 hour
  Data: existing 346 + new 400 = 746
  
STEP 3: Augment 20x + synthetic
  Time: 1-2 hours
  Data: 1200-1500 ✅
  
TOTAL: 4-6 hours ⚡⚡⚡
```

### **JIKA WAKTU CUKUP (3-4 hari)**

```
STEP 1: Setup Moodle 3.9.x
  Time: 15 mins
  
STEP 2: Scan 4.0.3 (2 scans)
  Time: 1-2 hours
  Data: 170-300
  
STEP 3: Scan 3.9.x (2 scans)
  Time: 1-2 hours
  Data: 230-400
  
STEP 4: Combine + Augment
  Time: 1-2 hours
  Data: 346 + 400 = 746 + augment = 1400+ ✅
  
TOTAL: 4-7 hours, lebih quality ✅✅✅
```

### **JIKA WAKTU LONGGAR (1 minggu)**

```
MOODLE 4.0.3: 4-5 scans
MOODLE 3.9.x: 4-5 scans
MOODLE 4.1.x: 2-3 scans (jika ingin 3 versi)

TOTAL: 1500-2000+ samples
QUALITY: 80-90%
```

---

## 🎯 KALAU SINGKAT, JAWAB ANDA

```
Q: Data asli 1000 itu dari scan versi Moodle berapa?

A: 
  Option 1 (Fast): Moodle 4.0.3 aja, tapi 4-6 scans
                   = 600-900 samples, time 3-4h
                   
  Option 2 (Best): Moodle 4.0.3 + 3.9.x, 2 scans each
                   = 600-900 samples, time 3-4h
                   + setup 3.9 = +15 mins
                   
  Recommended: Option 2 (karena 3.9 punya lebih banyak CVE)
```

---

## ✅ FINAL CHECKLIST

```
[ ] Decide: 4.0.3 alone vs 4.0.3 + 3.9.x
[ ] Setup second Moodle version (if needed) - 15 mins
[ ] Write script to run 4+ ZAP scans
[ ] Execute scans (2-4 hours)
[ ] Export JSON findings
[ ] Merge dengan 346 existing data
[ ] Classify TP/FP pada new findings
[ ] Combine: 346 + (~600) = 946
[ ] Augment + Synthetic: 1200-1500 ✅
[ ] Train models
```

---

## 📝 SUMMARY

**Data asli 1000 itu dari:**

1. **Moodle 4.0.3** (yang sudah ada): 400-600 samples (4-6 scans)
2. **Moodle 3.9.x** (setup baru, optional): 300-400 samples (2 scans)

**Pick one:**
- ✅ **4.0.3 alone**: 600-900 + augment = 1200 ✅ (time: 3-4h)
- ✅ **4.0.3 + 3.9.x**: 900-1200 + augment = 1500+ ✅ (time: 4-5h)

**Recommendation: 4.0.3 + 3.9.x** (better quality, still fast) 🚀
