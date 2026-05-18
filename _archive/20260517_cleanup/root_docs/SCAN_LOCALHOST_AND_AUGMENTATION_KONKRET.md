# 🎯 SCAN MOODLE 3.9 LOCALHOST + AUGMENTATION KONKRET

## ❓ PERTANYAAN 1: BAGAIMANA SCAN MOODLE 3.9 YANG SUDAH INSTALL?

### **SETUP LOCALHOST**

Pastikan Moodle 3.9 running:

```bash
# Kalau pakai WSL/Ubuntu
sudo service apache2 start
sudo service mysql start

# Check running
curl http://localhost/moodle
# atau browser: http://localhost/moodle

# Kalau pakai Docker
docker ps  # check container running
docker logs moodle39  # check status
```

**Tentukan URL:**
```
http://localhost  (root)
http://localhost/moodle  (if installed in subfolder)
http://127.0.0.1:8080  (if port 8080)
```

---

### **INSTALL ZAP (jika belum)**

```bash
# Windows: Download
https://www.zaproxy.org/download/ → Download & install

# Atau via PowerShell
# Windows butuh manual download, tidak ada package manager

# Verifikasi sudah install
zap-cli --version
# Should output: version 2.x.x
```

---

### **SCAN LANGSUNG DARI POWERSHELL**

#### **SCAN 1: BASELINE (Cepat, 5-10 menit)**

```powershell
# Buka PowerShell di folder manapun

# BASIC BASELINE SCAN
zap-cli quick-scan --self-signed http://localhost/moodle

# Output: akan generate findings
# tunggu sampai selesai (5-10 mins)
```

#### **SCAN 2: ACTIVE SCAN (Dalam, 30-45 menit)**

```powershell
# DEEP ACTIVE SCAN (lebih banyak findings)
zap-cli active-scan --recursive --follow-redirects http://localhost/moodle

# Ini akan scan lebih dalam, temukan lebih banyak findings
# Tunggu sampai selesai
```

#### **EXPORT HASIL SCAN (PENTING!)**

```powershell
# Setelah scan selesai, export hasil ke JSON
zap-cli report --output-format json --output-file zap_moodle39_findings.json

# Atau kalau ZAP masih running:
zap-cli report --output-format json > zap_moodle39_findings.json
```

---

### **LEBIH DETAIL: SCAN DENGAN UI (KALAU MAU VISUAL)**

```
1. Buka ZAP Desktop Application
2. Click Tools → Options → Network → Local Proxy
3. Pastikan proxy port = 8080
4. Di browser: Set proxy ke localhost:8080
5. Browse ke http://localhost/moodle
6. Click Spider/Scanner di ZAP
7. Right-click → Scan
8. Tunggu scan selesai
9. Export hasil ke JSON
```

---

### **ALTERNATIVE: QUICK SCRIPT APPROACH**

```powershell
# Simpan ini ke file scan_moodle.ps1

$MOODLE_URL = "http://localhost/moodle"
$OUTPUT_FILE = "zap_moodle39_findings.json"

Write-Host "Starting ZAP Baseline Scan..."
zap-cli quick-scan --self-signed $MOODLE_URL

Write-Host "Starting ZAP Active Scan..."
zap-cli active-scan --recursive $MOODLE_URL

Write-Host "Generating report..."
zap-cli report --output-format json --output-file $OUTPUT_FILE

Write-Host "Done! Results saved to $OUTPUT_FILE"
```

**Jalankan:**
```powershell
.\scan_moodle.ps1
# Tunggu 30-40 mins
```

---

## ❓ PERTANYAAN 2: AUGMENTATION KONKRET (BUKAN ABSTRAK)

Saya jelaskan dengan CONTOH ASLI payloads!

### **CONTOH 1: SQL INJECTION AUGMENTATION**

**ORIGINAL PAYLOAD (1):**
```
' OR '1'='1
```

**AUGMENTED VARIATIONS (3-4 hasil):**

```
Variasi 1 (Comments):
' OR '1'='1' --

Variasi 2 (Comments style lain):
' OR '1'='1' # 

Variasi 3 (Encoding):
' OR '1'='1' /**/

Variasi 4 (Different quote):
" OR "1"="1
```

**Kenapa beda?** Beberapa sistem mungkin filter satu bentuk tapi tidak yang lain!

---

### **CONTOH 2: XSS AUGMENTATION**

**ORIGINAL PAYLOAD (1):**
```
<script>alert('xss')</script>
```

**AUGMENTED VARIATIONS (2-3 hasil):**

```
Variasi 1 (Different tag):
<img src=x onerror=alert('xss')>

Variasi 2 (Even tag):
<svg onload=alert('xss')>

Variasi 3 (Encoding HTML entities):
&#60;script&#62;alert('xss')&#60;/script&#62;
```

**Kenapa beda?** Kalau system block `<script>` tag, mungkin `<img>` masih lolos!

---

### **CONTOH 3: URL PARAMETER AUGMENTATION**

**ORIGINAL REQUEST (1):**
```
GET /search.php?q=test
```

**AUGMENTED VARIATIONS (2-3 hasil):**

```
Variasi 1 (Different parameter name):
GET /search.php?query=test

Variasi 2 (POST method):
POST /search.php
Body: q=test

Variasi 3 (Different endpoint, same function):
GET /search.jsp?q=test
```

**Kenapa beda?** Developers mungkin filter endpoint tertentu tapi tidak semuanya!

---

## 🎓 PRAKTIS: BAGAIMANA AUGMENTATION BEKERJA?

### **Tahap 1: Input 346 Real Data**

```json
[
  {
    "payload": "' OR '1'='1",
    "url": "/search.php?q=...",
    "finding_type": "SQL Injection",
    "label": "TP"
  },
  {
    "payload": "<script>alert('xss')</script>",
    "url": "/comment.php?text=...",
    "finding_type": "XSS",
    "label": "FP"
  },
  // ... 344 lebih
]
```

### **Tahap 2: Augment SETIAP PAYLOAD (Buat 1-2 varian per payload)**

```json
[
  // ORIGINAL
  {
    "payload": "' OR '1'='1",
    "url": "/search.php?q=...",
    "label": "TP",
    "origin": "real"
  },
  // AUGMENTED VARIAN 1
  {
    "payload": "' OR '1'='1' --",  ← BEDA!
    "url": "/search.php?q=...",
    "label": "TP",
    "origin": "augmented"
  },
  // AUGMENTED VARIAN 2
  {
    "payload": "\" OR \"1\"=\"1",  ← BEDA!
    "url": "/search.php?q=...",
    "label": "TP",
    "origin": "augmented"
  },
  
  // ORIGINAL XSS
  {
    "payload": "<script>alert('xss')</script>",
    "url": "/comment.php?text=...",
    "label": "FP",
    "origin": "real"
  },
  // AUGMENTED VARIAN 1
  {
    "payload": "<img src=x onerror=alert('xss')>",  ← BEDA!
    "url": "/comment.php?text=...",
    "label": "FP",
    "origin": "augmented"
  },
  // AUGMENTED VARIAN 2
  {
    "payload": "<svg onload=alert('xss')>",  ← BEDA!
    "url": "/comment.php?text=...",
    "label": "FP",
    "origin": "augmented"
  }
  // ... dan seterusnya untuk 346 payloads
]
```

### **Tahap 3: HASIL**

Input: 346 payloads
× 1.2 augment (setiap payload buat 1-2 varian)
= ~750 augmented payloads ✅

---

## 💡 SIMPEL: AUGMENTATION MAKSUDNYA

**JANGAN COPY-PASTE SAMA PERSIS!**

Dari 1 payload, buat 2-3 varian yang **BERBEDA SEDIKIT** tapi **MASIH SAMA FUNGSI**:

```
ORIGINAL: ' OR '1'='1
├─ VARIAN 1: ' OR '1'='1' --
├─ VARIAN 2: ' OR 1=1 #
└─ VARIAN 3: " OR "1"="1
= 4 payloads dari 1 original ✅

ORIGINAL: <script>alert('xss')</script>
├─ VARIAN 1: <img src=x onerror=alert('xss')>
└─ VARIAN 2: <svg onload=alert('xss')>
= 3 payloads dari 1 original ✅
```

---

## 🚀 CODE UNTUK AUGMENTATION

Kalau anda mau bikin script augmentation:

```python
import json
import random

def augment_sql_injection(payload):
    """Generate SQL injection variants"""
    variations = [payload]  # Original
    
    # Add comment style 1
    variations.append(payload + "' --")
    
    # Add comment style 2
    variations.append(payload + "' #")
    
    # Change quote style
    if "'" in payload:
        variations.append(payload.replace("'", '"'))
    
    return variations

def augment_xss(payload):
    """Generate XSS variants"""
    variations = [payload]  # Original
    
    # Alternative XSS vectors
    if "<script>" in payload:
        variations.append(payload.replace("<script>", "<img src=x onerror="))
        variations.append(payload.replace("</script>", ">"))
    
    # SVG vector
    variations.append(payload.replace("<script>", "<svg onload=").replace("</script>", ">"))
    
    return variations

def augment_payload(sample):
    """Augment single payload"""
    payload = sample['payload']
    finding_type = sample.get('finding_type', '')
    
    variations = []
    
    if 'SQL' in finding_type.upper() or 'INJECTION' in finding_type.upper():
        variations = augment_sql_injection(payload)
    elif 'XSS' in finding_type.upper():
        variations = augment_xss(payload)
    else:
        # Default: add slight encoding
        variations = [payload, payload.replace(" ", "%20")]
    
    # Create new samples for each variation
    augmented_samples = []
    for var in variations:
        new_sample = sample.copy()
        new_sample['payload'] = var
        new_sample['origin'] = 'augmented' if var != payload else 'real'
        augmented_samples.append(new_sample)
    
    return augmented_samples

# MAIN AUGMENTATION
def augment_all_data(input_file, output_file):
    # Load original data
    with open(input_file) as f:
        original_data = json.load(f)
    
    # Augment setiap payload
    augmented_data = []
    for sample in original_data:
        augmented = augment_payload(sample)
        augmented_data.extend(augmented)
    
    # Batas ke 750
    augmented_data = augmented_data[:750]
    
    # Save
    with open(output_file, 'w') as f:
        json.dump(augmented_data, f, indent=2)
    
    print(f"Original: {len(original_data)}")
    print(f"Augmented: {len(augmented_data)}")
    return augmented_data

# RUN
if __name__ == "__main__":
    augment_all_data("auto_labeled_20251219_033444.json", "augmented_750.json")
```

**Jalankan:**
```bash
python augment_payloads.py
# Output: augmented_750.json dengan 750 payloads ✅
```

---

## 📋 CHECKLIST: SCAN & AUGMENT

### **SCAN (1-2 jam)**

```
[ ] Install ZAP
[ ] Pastikan Moodle 3.9 running: http://localhost/moodle
[ ] Run Scan 1 (Baseline): zap-cli quick-scan ...
[ ] Run Scan 2 (Active): zap-cli active-scan ...
[ ] Export hasil: zap-cli report --output-format json
[ ] OUTPUT: zap_moodle39_findings.json (~250-300 findings)
```

### **AUGMENTATION (30 mins)**

```
[ ] Copy augment_payloads.py code (di atas)
[ ] Run: python augment_payloads.py
[ ] INPUT: auto_labeled_20251219_033444.json (346)
[ ] OUTPUT: augmented_750.json dengan 750 payloads
[ ] Check: Open file, pastikan ada varian yang berbeda
```

---

## 🎯 SUMMARY

**SCAN MOODLE 3.9:**
```bash
1. zap-cli quick-scan http://localhost/moodle
2. zap-cli active-scan http://localhost/moodle
3. zap-cli report --output-format json > hasil.json
```

**AUGMENTATION:**
```python
1 original payload → 2-3 variations
345 payloads × 2.2x = 750 augmented
Contoh: "' OR '1'='1" jadi 3 versi beda
```

**Bisa dimulai hari ini!** 🚀
