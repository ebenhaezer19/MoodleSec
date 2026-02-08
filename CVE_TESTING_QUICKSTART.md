# CVE Testing Automation - Quick Reference

## 🚀 Quick Start

### 1. List Available CVEs
```powershell
cd MoodleSec
python test_cve_automated.py --list-cves
```

### 2. Test CVE-2021-36393 (Automated)
```powershell
# Start Moodle first
.\setup_moodle_docker.ps1

# Start OWASP ZAP
zap.sh -daemon -port 8090 -config api.disablekey=true

# Run automated test (15 minutes)
python test_cve_automated.py --cve CVE-2021-36393
```

### 3. Test with Custom Credentials
```powershell
python test_cve_automated.py --cve CVE-2021-36393 --target http://localhost:8080 --username admin --password Admin123!
```

---

## 📋 Features

✅ **Automated Workflow:**
1. Clones exploit from GitHub automatically
2. Installs dependencies
3. Runs exploit against target
4. Scans with OWASP ZAP
5. Extracts findings
6. Labels as TP/FP
7. Adds to training dataset
8. Updates CVE tracker
9. Updates progress log

✅ **Supported CVEs:**
- CVE-2021-36393: SQL Injection (Automated exploit ✅)
- CVE-2021-36394: XSS User Profile (Manual ⚠️)
- CVE-2020-14321: SQL Injection Forum (Manual ⚠️)
- CVE-2023-28329: XSS Calendar (Manual ⚠️)
- CVE-2020-14318: CSRF Course (Manual ⚠️)

---

## 🎯 Usage Examples

### Example 1: Full Automated Test
```powershell
python test_cve_automated.py --cve CVE-2021-36393
```

**Output:**
```
[INFO] Cloning exploit from https://github.com/T0X1Cx/CVE-2021-36393-Exploit.git
[SUCCESS] Exploit cloned to CVE-2021-36393-Exploit
[INFO] Installing exploit dependencies...
[INFO] Running exploit: CVE-2021-36393
[INFO] Target: http://localhost:8080
[SUCCESS] ✅ Exploit successful! Vulnerability confirmed.
[INFO] Starting OWASP ZAP scan...
[SUCCESS] Active scan completed
[SUCCESS] ✅ Scanner detected vulnerability!
[SUCCESS] ✅ Finding added! Total samples: 273
[INFO] Current dataset: 9 TP, 238 FP
[INFO] Imbalance ratio: 26.4:1
[SUCCESS] CVE tracker updated: 1/5 completed
✅ CVE CVE-2021-36393 Testing Complete!
```

### Example 2: Skip Exploit (Scan Only)
```powershell
python test_cve_automated.py --cve CVE-2021-36394 --skip-exploit
```

### Example 3: Skip Scanner (Exploit Only)
```powershell
python test_cve_automated.py --cve CVE-2021-36393 --skip-scan
```

---

## 🔧 Integration with Existing Tools

### Plugin Integration Path

```
MoodleSec/
├── test_cve_automated.py          ← New automated tester
├── CVE-2021-36393-Exploit/        ← Auto-cloned exploit
├── ml/
│   ├── training_data/
│   │   ├── cve_tracker.json       ← Auto-updated tracker
│   │   └── real_data/
│   │       └── processed_findings_*.json  ← Auto-appended findings
├── TRAINING_PROGRESS_LOG.md       ← Auto-updated log
└── moodle-plugin/
    ├── false_positive_reducer.php ← Uses training data
    └── ml_dashboard.php           ← Shows CVE findings
```

### Workflow Integration

```powershell
# 1. Test CVE
python test_cve_automated.py --cve CVE-2021-36393

# 2. Retrain model with new TP sample
cd ml
python retrain_models.py

# 3. Test overfitting
python test_overfitting.py

# 4. Benchmark performance
python benchmark_performance.py

# 5. Deploy to plugin
Copy-Item false_positive_reducer_model.pkl ..\moodle-plugin\ml_models\
Copy-Item severity_predictor_model.pkl ..\moodle-plugin\ml_models\
```

---

## 📊 Output Files

### Scan Results
```
cve_CVE_2021_36393_scan_20260208_143022.json
```

### Updated Files
- `ml/training_data/real_data/processed_findings_*.json` (new TP added)
- `ml/training_data/cve_tracker.json` (progress updated)
- `TRAINING_PROGRESS_LOG.md` (test documented)

### Backups
- `processed_findings_*.backup_20260208_143022.json` (auto-created)

---

## 🎓 Training Dataset Impact

| Before | After 1 CVE | After 5 CVEs |
|--------|------------|--------------|
| 272 samples | 273 samples | 277 samples |
| 8 TP | 9 TP | 13 TP |
| 238 FP | 238 FP | 238 FP |
| **29.75:1 ratio** | **26.4:1 ratio** | **18.3:1 ratio** |

---

## 🆘 Troubleshooting

### Error: OWASP ZAP not running
```powershell
# Start ZAP in daemon mode
zap.sh -daemon -port 8090 -config api.disablekey=true

# Or on Windows
"C:\Program Files\OWASP\Zed Attack Proxy\zap.bat" -daemon -port 8090 -config api.disablekey=true
```

### Error: Git clone failed
```powershell
# Manual clone
cd MoodleSec
git clone https://github.com/T0X1Cx/CVE-2021-36393-Exploit.git
pip install -r CVE-2021-36393-Exploit/requirements.txt

# Then run with --skip-exploit if needed
python test_cve_automated.py --cve CVE-2021-36393 --skip-exploit
```

### Error: Training data file not found
```powershell
# Check file exists
ls ml\training_data\real_data\processed_findings_*.json

# If missing, process data first
cd ml\training_data\real_data
python ..\..\process_new_training_data.py
```

### Error: Exploit timeout
```powershell
# Increase timeout in test_cve_automated.py line ~250
# Change: timeout=60 to timeout=120
```

---

## 📈 Progress Tracking

### Check CVE Tracker
```powershell
cat ml\training_data\cve_tracker.json
```

**Output:**
```json
{
  "cves": {
    "CVE-2021-36393": {
      "status": "completed",
      "tested_date": "2026-02-08T14:30:22",
      "scanner_detected": true,
      "cvss": 9.8
    }
  },
  "summary": {
    "total_cves": 5,
    "completed": 1,
    "scanner_detection_rate": "1/1",
    "last_updated": "2026-02-08T14:30:22"
  }
}
```

### View Progress Log
```powershell
tail -n 50 TRAINING_PROGRESS_LOG.md
```

---

## 🔄 Batch Testing (Future Enhancement)

```powershell
# Test all CVEs sequentially (NOT YET IMPLEMENTED)
foreach ($cve in @("CVE-2021-36393", "CVE-2021-36394", "CVE-2020-14321")) {
    python test_cve_automated.py --cve $cve
    Start-Sleep -Seconds 60  # Cool down between tests
}
```

---

## 🎯 Expected Results

### CVE-2021-36393 (SQL Injection - Critical)
- **Exploit Success:** 95% (automated tool)
- **Scanner Detection:** 65%
- **Time:** 15 minutes
- **Value:** HIGH (Critical CVSS 9.8)

### CVE-2021-36394 (XSS - High)
- **Exploit Success:** Manual required
- **Scanner Detection:** 80%
- **Time:** 30 minutes
- **Value:** MEDIUM (High CVSS 7.5)

### CVE-2020-14321 (SQL Injection - Critical)
- **Exploit Success:** Manual required
- **Scanner Detection:** 70%
- **Time:** 40 minutes
- **Value:** HIGH (Critical CVSS 8.8)

---

## 📚 Next Steps

1. **Test Priority CVE:**
   ```powershell
   python test_cve_automated.py --cve CVE-2021-36393
   ```

2. **Review Results:**
   ```powershell
   # Check dataset
   python ml/analyze_training_data.py
   
   # Check tracker
   cat ml/training_data/cve_tracker.json
   ```

3. **Retrain Model:**
   ```powershell
   cd ml
   python retrain_models.py
   ```

4. **Test New Model:**
   ```powershell
   python test_overfitting.py
   python benchmark_performance.py
   ```

5. **Document for TA:**
   - Update BAB IV with CVE findings
   - Include scanner detection rates
   - Show dataset improvement (8 TP → 9 TP)
   - Discuss scanner blind spots

---

**Estimated Time Investment:**
- CVE-2021-36393: 15 minutes (automated)
- 4 more CVEs: 2-3 hours (manual/semi-automated)
- **Total: 3-4 hours to collect 5 CVE samples**
- **Result: 8 TP → 13 TP (62.5% increase)**
- **Imbalance: 29.75:1 → 18.3:1 (38% improvement)**
