# 🎯 NEXT STEPS: SCANNING STRATEGY UNTUK DATA COLLECTION

## ❓ PERTANYAAN ANDA

1. "Data apa saja yang diperlukan untuk scan?"
2. "Apakah Moodle versi tertentu saja atau boleh semua versi?"
3. "Website apa yang disarankan untuk di-scan?"
4. "Bagaimana mendapatkan TP dan FP dari ZAP?"
5. "Specific next steps untuk scan?"

---

## ✅ JAWAB: REKOMENDASI SETUP SCANNING

### **PILIHAN YANG SUDAH ANDA PUNYA**

Dari install_moodle.sh anda:
```bash
MOODLE_VERSION: MOODLE_403_STABLE (Moodle 4.0.3)
SETUP: WSL/Ubuntu, Apache2, MySQL, PHP 8.1
```

---

## 🎯 REKOMENDASI: FOKUS KE 1 MOODLE VERSION (TUJUAN ANDA)

### **ALASAN**

```
✅ Fokus ke 1 versi:
   - Setup lebih simple
   - Data lebih konsisten
   - Training model lebih akurat
   - Faster iteration untuk testing
   - Easier troubleshooting

❌ Multi-versi (phase 2):
   - Complex setup (3+ docker containers)
   - Mixed findings (versi 3.9 vs 4.0 punya CVE berbeda)
   - Training data lebih "noisy"
   - Overkill untuk MVP
```

---

## 🎓 RECOMMENDED: MOODLE VERSION 3.9.x vs 4.0.3

### **OPTION 1: Moodle 3.9.x (RECOMMENDED FOR YOUR CASE)**

```
✅ ALASAN PILIH:
   - Known vulnerable (CVE-2021-36393)
   - Lots of public CVEs documented
   - Easy to find TP payloads
   - Well-studied, predictable findings
   - Already punya guide di workspace (CVE_2021_36393_GUIDE.md)

👍 DATA QUALITY:
   - TP findings = easier to verify
   - FP findings = clearer distinction
   - Documentation available

⏱️  TIME: 
   - Setup: 30 mins
   - Scanning: 2-3 hours
   - Data cleaning: 1-2 hours

📊 EXPECTED:
   - TP: 20-40 real vulnerabilities
   - FP: 100-200 false alarms
   - Total: 120-240 samples
```

### **OPTION 2: Moodle 4.0.3 (WHAT YOU HAVE)**

```
❌ DOWNSIDE:
   - Newer = less documented vulnerabilities
   - Harder to verify TP vs FP
   - Fewer public exploits

✅ UPSIDE:
   - Already installed
   - No extra setup needed
   - Modern features

⏱️  TIME:
   - Setup: 0 mins (already ready!)
   - Scanning: 2-3 hours
   - Data cleaning: 1-2 hours

📊 EXPECTED:
   - TP: 5-15 vulnerabilities (fewer than 3.9)
   - FP: 150-250 false alarms
   - Total: 155-265 samples
```

---

## 🚀 RECOMMENDATION: START WITH MOODLE 3.9.x

### **WHY?**

```
1. Better TP/FP distinction
2. Known vulnerabilities documented
3. Payload patterns well-researched
4. Training data quality higher
5. Can extend to 4.0.3 later (phase 2)

PHASE 1 (Next 2 weeks): Moodle 3.9.x
PHASE 2 (Later): Moodle 4.0.3 + other versions
```

---

## 📋 SPECIFIC NEXT STEPS: SCANNING WORKFLOW

### **STEP 1: SETUP MOODLE 3.9.x (VULNERABLE VERSION)**

```bash
# Option A: Docker (RECOMMENDED - 10 mins)
docker pull moodle:3.9

docker run -d \
  --name moodle39-vuln \
  -p 8080:80 \
  -e MOODLE_DATABASE_HOST=mysql39 \
  -e MOODLE_DATABASE_USER=moodle \
  -e MOODLE_DATABASE_PASSWORD=moodlepassword \
  -e MOODLE_DATABASE_NAME=moodle39 \
  moodle:3.9
```

# OR Option B: WSL/Ubuntu (30 mins)
# Follow install_moodle.sh but change branch:
# git clone -b MOODLE_39_STABLE ...

URL: http://localhost:8080
```

### **STEP 2: SETUP ZAP (AUTOMATED SCANNING)**

```bash
# Install ZAP (if not already)
# Windows: Download from https://www.zaproxy.org/download/

# OR Docker ZAP
docker run -t owasp/zap2docker-stable \
  zap-baseline.py -t http://localhost:8080 \
  -r zap_report.html
```

### **STEP 3: RUN ZAP BASELINE SCAN**

```bash
# Simple baseline scan (quick)
zap-cli --zap-options '-config api.disablekey=true' \
  quick-scan --self-signed \
  http://localhost:8080

# Output: ZAP findings JSON/HTML
```

### **STEP 4: PARSE ZAP OUTPUT**

```bash
# ZAP generates findings:
{
  "site": "http://localhost:8080",
  "alerts": [
    {
      "alert": "SQL Injection",
      "severity": "High",
      "instances": [
        {
          "uri": "http://localhost:8080/search.php?q=...",
          "method": "GET",
          "param": "q",
          "attack": "' OR '1'='1",  ← Payload
          "evidence": "..."
        }
      ]
    }
  ]
}
```

### **STEP 5: MANUAL VERIFICATION (TP vs FP)**

```
UNTUK SETIAP FINDING:

1. VERIFY TP (True Positive = benar-benar vulnerable):
   ✅ Payload actually executes
   ✅ Impact verified (data leaked, code executed, etc)
   ✅ Repeatable
   ✅ Documented in CVE database
   
   Example: CVE-2021-36393 SQL Injection
   - Known vulnerability
   - Public exploit available
   - Moodle 3.9.0-3.9.7 affected
   
2. CLASSIFY FP (False Positive = false alarm):
   ✅ Payload doesn't actually work
   ✅ False positive due to misconfiguration detection
   ✅ Security measure blocks it
   ✅ Not actually exploitable
```

### **STEP 6: DATA EXTRACTION (346 → 1500+ strategy)**

```
FROM ZAP FINDINGS:
  - 20-40 TP (real vulnerabilities)
  - 100-200 FP (false alarms)
  - Total: 120-240 samples

EXPAND USING AUGMENTATION:
  - Augment 20x: 120-240 → 2400-4800
  - Downsample balanced: → 1200-1500
  
FINAL DATASET:
  ✅ 600 TP (real vulnerabilities, varied)
  ✅ 600 FP (false alarms, diverse)
  ✅ 1200 total for FP Reducer training
```

---

## 🎯 EXACT MOODLE 3.9.x SETUP INSTRUCTIONS

### **FASTEST METHOD: Docker**

```bash
# CREATE moodle39-scanning DIRECTORY
mkdir -p ~/moodle39-scanning
cd ~/moodle39-scanning

# CREATE docker-compose FOR QUICK SETUP
cat > docker-compose.yml << 'EOF'
version: '3'
services:
  mysql39:
    image: mysql:5.7
    environment:
      MYSQL_ROOT_PASSWORD: root
      MYSQL_DATABASE: moodle39
      MYSQL_USER: moodle
      MYSQL_PASSWORD: moodlepassword
    ports:
      - "3306:3306"
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 10s
      timeout: 5s
      retries: 5

  moodle39:
    image: moodle:3.9
    environment:
      MOODLE_DATABASE_HOST: mysql39
      MOODLE_DATABASE_USER: moodle
      MOODLE_DATABASE_PASSWORD: moodlepassword
      MOODLE_DATABASE_NAME: moodle39
      MOODLE_URL: http://localhost:8080
      MOODLE_ADMIN_USER: admin
      MOODLE_ADMIN_PASSWORD: P@ssw0rd123!
    ports:
      - "8080:80"
    depends_on:
      mysql39:
        condition: service_healthy
    volumes:
      - moodle_data:/var/www/moodledata

volumes:
  moodle_data:
EOF

# START MOODLE
docker-compose up -d

# WAIT FOR STARTUP (2-3 mins)
docker logs -f moodle39 | grep "installation"

# CHECK MOODLE IS RUNNING
open http://localhost:8080  # atau curl http://localhost:8080
```

### **TIME ESTIMATE**

```
Docker Setup: 5-10 mins
Moodle Startup: 2-3 mins
Login: 1 min
Total: 8-14 mins ✅
```

---

## 🔍 STEP-BY-STEP ZAP SCANNING

### **PART 1: BASELINE SCAN (EASY)**

```bash
# RUN ZAP BASELINE SCAN
zap-cli --zap-options '-config api.disablekey=true' \
  quick-scan --self-signed \
  http://localhost:8080

# OR using Docker
docker run --rm \
  --network host \
  -v $(pwd):/zap/wrk:rw \
  owasp/zap2docker-stable \
  zap-baseline.py -t http://localhost:8080 \
  -r /zap/wrk/baseline_scan.html

# OUTPUT: baseline_scan.html
```

### **PART 2: AUTHENTICATED SCAN (BETTER TP/FP)**

```bash
# First login to Moodle as admin
# user: admin
# pass: P@ssw0rd123!

# Then run authenticated scan
zap-cli --zap-options '-config api.disablekey=true' \
  auth \
  --auth-username admin \
  --auth-password P@ssw0rd123! \
  --auth-url http://localhost:8080/login/index.php \
  quick-scan --self-signed \
  http://localhost:8080

# OR using ZAP GUI:
# 1. Open ZAP GUI
# 2. Add context: http://localhost:8080
# 3. Set authentication (login form)
# 4. Run scan with context
```

### **PART 3: ACTIVE SCAN (MORE FINDINGS)**

```bash
# More aggressive scan (longer, more findings)
zap-cli --zap-options '-config api.disablekey=true' \
  active-scan \
  --recursive \
  --follow-redirects \
  http://localhost:8080

# OUTPUT: attack_scan.json
```

---

## 📊 EXPECTED ZAP OUTPUT FORMAT

### **JSON Format**

```json
{
  "site": [
    {
      "@name": "http://localhost:8080",
      "alerts": [
        {
          "pluginid": "40016",
          "alertRef": "40016",
          "alert": "Password Autocomplete in Browser",
          "name": "Password Autocomplete in Browser",
          "riskcode": "1",
          "confidence": "2",
          "riskdesc": "Low",
          "desc": "The password autocomplete attribute is not disabled on an HTML FORM/INPUT attribute.",
          "instances": [
            {
              "uri": "http://localhost:8080/login/index.php",
              "method": "POST",
              "param": "password",
              "attack": "",
              "evidence": "found password field with autocomplete enabled"
            }
          ],
          "count": "1",
          "solution": "Disable autocomplete on password fields",
          "reference": "https://..."
        }
      ]
    }
  ]
}
```

---

## 🎯 CLASSIFY TP vs FP

### **EXAMPLE: CVE-2021-36393 (SQL Injection)**

```
ZAP FINDING:
{
  "alert": "SQL Injection",
  "param": "q",
  "attack": "' OR '1'='1",
  "uri": "http://localhost:8080/search.php?q=..."
}

CLASSIFICATION:

TP (True Positive):
  ✅ Attack succeeds: ' OR '1'='1 returns all records
  ✅ Evidence: Response shows unfiltered data
  ✅ CVE-2021-36393 confirmed vulnerable
  ✅ Moodle 3.9.0-3.9.7 affected
  ✅ Repeatable with different payloads
  
LABEL: "TP"
REASON: "Confirmed SQL Injection in search parameter"

---

FP (False Positive):
  ❌ Attack fails: Database rejects malformed query
  ❌ Input is properly escaped
  ❌ Response identical to benign input
  ❌ ZAP false alarm based on response change
  
LABEL: "FP"
REASON: "Input properly escaped, no actual vulnerability"
```

---

## 📋 DATA COLLECTION CHECKLIST

```
[ ] Step 1: Setup Moodle 3.9.x
    Time: 10-15 mins
    Check: http://localhost:8080 loads
    
[ ] Step 2: Create admin account
    User: admin
    Pass: P@ssw0rd123!
    Time: 2 mins
    
[ ] Step 3: Install ZAP
    Time: 5-10 mins
    Check: zap-cli --version
    
[ ] Step 4: Run baseline scan
    Time: 5-10 mins
    Output: baseline_scan.html/.json
    
[ ] Step 5: Run active scan
    Time: 10-20 mins
    Output: active_scan.json
    
[ ] Step 6: Manual verification
    Time: 1-2 hours
    TP count: ?
    FP count: ?
    
[ ] Step 7: Data extraction
    Time: 30 mins
    Format: JSON with TP/FP labels
    
[ ] Step 8: Augmentation + training
    Time: 1-2 hours
    Result: 1500+ samples
    Pass rate: 70%+
```

---

## 🚀 IMMEDIATE ACTION ITEMS

### **TODAY (1-2 hours)**

```
1. Setup Moodle 3.9.x Docker
   docker-compose up -d
   
2. Verify Moodle loads
   http://localhost:8080
   
3. Login with admin account
   
4. Install ZAP (if needed)
   https://www.zaproxy.org/download/
```

### **TOMORROW (2-3 hours)**

```
1. Run ZAP baseline scan
   baseline_scan.html
   
2. Run ZAP active scan
   active_scan.json
   
3. Export findings
   zap_findings.json
```

### **DAY 3 (2-3 hours)**

```
1. Manual verification
   - Classify TP
   - Classify FP
   
2. Extract structured data
   - TP payloads: 20-40
   - FP payloads: 100-200
   
3. Export JSON format
   auto_labeled_manual.json
```

### **DAY 4+ (1-2 hours)**

```
1. Augmentation script
   20x variants
   
2. Data synthesis
   +500 synthetic samples
   
3. Training + validation
   1500 balanced dataset
   Pass rate: 70-80%
```

---

## 💡 TIPS & TRICKS

### **MAKE MOODLE VULNERABLE (TEST BETTER CVE)**

```bash
# Downgrade Moodle 3.9 to vulnerable version
docker exec moodle39 \
  git checkout MOODLE_39_STABLE
  
# Then update to vulnerable commit
docker exec moodle39 \
  git reset --hard COMMIT_HASH

# Reinstall
docker exec moodle39 \
  php admin/cli/install.php --non-interactive
```

### **OPTIMIZE ZAP SCANNING**

```bash
# Faster scan: Exclude non-vulnerable endpoints
zap-cli quick-scan \
  --exclude-url-regex ".*\.(css|js|gif|jpg|png)$" \
  --exclude-url-regex ".*/static/.*" \
  http://localhost:8080

# More findings: Include default scanners
zap-cli active-scan \
  --scan-type all \
  http://localhost:8080
```

### **AUTOMATE VERIFICATION**

```bash
# Create script to verify TP
# 1. Extract payload
# 2. Manual test: inject into Moodle
# 3. Check response
# 4. Classify as TP/FP
```

---

## 📝 SUMMARY

```
🎯 TARGET: Moodle 3.9.x (vulnerable, well-documented)

📅 TIMELINE:
   - Setup: 15 mins
   - Scanning: 1-2 hours  
   - Analysis: 2-3 hours
   - Total: 4-6 hours for 120+ samples

📊 EXPECTED OUTCOME:
   - TP: 20-40 vulnerabilities
   - FP: 100-200 false alarms
   - Total: 120-240 samples
   
🚀 NEXT: Augment to 1500 + train models

💪 STRATEGY: Start with 1 version, expand later!
```

**Next step: Start dengan Moodle 3.9.x setup ya!** 🎯
