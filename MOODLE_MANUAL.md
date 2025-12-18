# 📘 Panduan Manual Moodle Security Plugin

**Adaptive Moodle Security System**  
**Version:** 1.0  
**Last Updated:** December 2025

---

## 📋 Daftar Isi

1. [Instalasi Plugin](#instalasi-plugin)
2. [Konfigurasi Awal](#konfigurasi-awal)
3. [Menggunakan Security Scanner](#menggunakan-security-scanner)
4. [Membaca Hasil Scan](#membaca-hasil-scan)
5. [Troubleshooting](#troubleshooting)

---

## 🔧 Instalasi Plugin

### Prasyarat

- Moodle 3.9 atau lebih baru
- PHP 7.4 atau lebih baru
- MySQL/PostgreSQL database
- Security Proxy running (port 5000)

### Langkah Instalasi

#### 1. Copy Plugin ke Moodle

```bash
# Navigate to Moodle directory
cd /path/to/moodle

# Copy plugin
cp -r /path/to/MoodleSec/moodle-plugin local/securityscanner

# Set permissions
chmod -R 755 local/securityscanner
chown -R www-data:www-data local/securityscanner
```

#### 2. Install via Moodle Admin

1. Login sebagai administrator
2. Navigate ke: **Site administration → Notifications**
3. Moodle akan detect plugin baru
4. Click **"Upgrade Moodle database now"**
5. Konfirmasi instalasi

#### 3. Verifikasi Instalasi

1. Go to: **Site administration → Plugins → Local plugins**
2. Cari "Security Scanner"
3. Status harus "Enabled"

---

## ⚙️ Konfigurasi Awal

### 1. Akses Halaman Konfigurasi

**Path:** Site administration → Plugins → Local plugins → Security Scanner → Settings

### 2. Konfigurasi Security Proxy

```
Proxy URL: http://localhost:5000
API Key: [leave blank for local testing]
Timeout: 300 seconds
```

### 3. Konfigurasi Scanner

**OWASP ZAP:**
```
ZAP API URL: http://localhost:8080
ZAP API Key: [your-zap-api-key]
```

**Acunetix:**
```
Acunetix URL: https://acunetix.example.com
API Key: [your-acunetix-api-key]
```

### 4. Konfigurasi Notifikasi

```
☑ Email notifications
☑ Dashboard alerts
☐ Slack integration (optional)
```

### 5. Save Settings

Click **"Save changes"** di bagian bawah halaman.

---

## 🔍 Menggunakan Security Scanner

### A. Akses Security Dashboard

1. Login sebagai administrator
2. Navigate ke: **Site administration → Security → Security Scanner**
3. Atau direct URL: `https://your-moodle.com/local/securityscanner/scan.php`

### B. Memulai Scan Baru

#### Quick Scan (Recommended untuk Demo)

1. Click tombol **"New Scan"**
2. Pilih **"Quick Scan"**
3. Scanner: **"OWASP ZAP"** (lebih cepat)
4. Target: `https://your-moodle.com` (otomatis terisi)
5. Click **"Start Scan"**

**Durasi:** ~2-5 menit

#### Full Scan (Comprehensive)

1. Click tombol **"New Scan"**
2. Pilih **"Full Scan"**
3. Scanner: **"Acunetix"** atau **"OWASP ZAP"**
4. Options:
   - ☑ Scan all pages
   - ☑ Test authentication
   - ☑ Deep crawl
5. Click **"Start Scan"**

**Durasi:** ~30-60 menit

### C. Monitoring Scan Progress

**Real-time Progress Bar:**
```
Scanning... [████████░░] 80%
Endpoints discovered: 45
Endpoints scanned: 36
Findings: 12
```

**Status Indicators:**
- 🟡 **Queued** - Scan dalam antrian
- 🔵 **Running** - Scan sedang berjalan
- 🟢 **Completed** - Scan selesai
- 🔴 **Failed** - Scan gagal

### D. Scan History

**View Previous Scans:**
1. Navigate ke **"Scan History"** tab
2. List menampilkan:
   - Scan ID
   - Date & Time
   - Target URL
   - Scanner used
   - Findings count
   - Status

**Actions:**
- 👁️ **View** - Lihat detail hasil
- 🔄 **Re-scan** - Ulangi scan dengan config sama
- 🗑️ **Delete** - Hapus hasil scan

---

## 📊 Membaca Hasil Scan

### A. Dashboard Overview

**Security Score:**
```
┌─────────────────────────────┐
│   SECURITY SCORE: 72/100    │
│   Status: MODERATE RISK     │
└─────────────────────────────┘
```

**Findings Summary:**
```
Critical:  2  🔴
High:      5  🟠
Medium:    8  🟡
Low:      15  🟢
Info:     23  ⚪
─────────────────
Total:    53
```

### B. Findings List

**Kolom Informasi:**

| Field | Description |
|-------|-------------|
| **Severity** | Critical/High/Medium/Low/Info |
| **Category** | Jenis vulnerability (SQL Injection, XSS, etc.) |
| **URL** | Endpoint yang terpengaruh |
| **Confidence** | ML confidence score (0-100%) |
| **Status** | Open/Fixed/False Positive |

**Filter Options:**
- Filter by severity
- Filter by category
- Filter by confidence
- Search by keyword

### C. Detail Finding

**Click pada finding untuk melihat detail:**

```
┌─────────────────────────────────────────────────┐
│ SQL Injection Vulnerability                    │
├─────────────────────────────────────────────────┤
│ Severity: HIGH                                  │
│ Confidence: 92.5%                               │
│ CVSS Score: 8.2                                 │
│ Category: Injection                             │
├─────────────────────────────────────────────────┤
│ Description:                                    │
│ SQL injection vulnerability detected in login   │
│ form. Attacker can bypass authentication.       │
├─────────────────────────────────────────────────┤
│ Affected URL:                                   │
│ https://moodle.com/login/index.php?id=1'        │
├─────────────────────────────────────────────────┤
│ Evidence:                                       │
│ Error: You have an error in your SQL syntax    │
├─────────────────────────────────────────────────┤
│ Recommendation:                                 │
│ • Use parameterized queries                     │
│ • Validate all user inputs                      │
│ • Implement prepared statements                 │
├─────────────────────────────────────────────────┤
│ ML Analysis:                                    │
│ Label: TRUE POSITIVE                            │
│ Confidence: 92.5%                               │
│ Strategy: severity:critical_high_tp             │
│ Reason: High severity with SQL keywords         │
└─────────────────────────────────────────────────┘
```

**Actions:**
- 🔧 **Mark as Fixed** - Tandai sudah diperbaiki
- ❌ **Mark as False Positive** - Tandai sebagai FP
- 📋 **Export Report** - Export ke PDF/JSON
- 🔗 **Copy Link** - Share finding

### D. ML Confidence Interpretation

**Confidence Levels:**

| Range | Interpretation | Action |
|-------|----------------|--------|
| **90-100%** | Very High Confidence | Prioritize immediately |
| **80-89%** | High Confidence | Review and fix |
| **70-79%** | Medium Confidence | Manual verification needed |
| **60-69%** | Low Confidence | Likely false positive |
| **<60%** | Very Low | Probably false positive |

**ML Label:**
- ✅ **TRUE POSITIVE** - Real vulnerability, needs fixing
- ❌ **FALSE POSITIVE** - Not a real issue, can ignore
- ⚠️ **NEEDS REVIEW** - Manual verification required

---

## 🎯 Workflow Rekomendasi

### 1. Prioritas Berdasarkan Severity

**Critical & High (Prioritas 1):**
1. Review semua findings Critical/High
2. Verify dengan manual testing
3. Fix immediately
4. Re-scan untuk verify fix

**Medium (Prioritas 2):**
1. Review findings dengan confidence >80%
2. Schedule fix dalam sprint berikutnya
3. Document workarounds jika belum fix

**Low & Info (Prioritas 3):**
1. Review findings dengan confidence >90%
2. Fix saat ada waktu
3. Bisa di-defer untuk release berikutnya

### 2. Filter False Positives

**Gunakan ML Confidence:**
```
1. Sort by confidence (descending)
2. Focus pada confidence >80%
3. Mark low confidence (<70%) as FP
4. Re-train model dengan feedback
```

**Manual Verification:**
```
1. Test exploit di staging environment
2. Verify dengan security tools lain
3. Konsultasi dengan security team
4. Update status di dashboard
```

### 3. Export & Reporting

**Generate Report:**
1. Click **"Export Report"** button
2. Choose format:
   - PDF (untuk management)
   - JSON (untuk integration)
   - CSV (untuk analysis)
3. Select findings to include
4. Download report

**Report Contents:**
- Executive summary
- Findings by severity
- Trend analysis
- Recommendations
- ML confidence scores

---

## 🔄 Scheduled Scans

### Setup Automated Scans

**Via Moodle Cron:**

1. Navigate ke: **Site administration → Server → Scheduled tasks**
2. Find: **"Security Scanner - Automated Scan"**
3. Configure schedule:
   ```
   Minute: 0
   Hour: 2
   Day: *
   Month: *
   Weekday: 1  (Monday)
   ```
4. Enable task
5. Save changes

**Result:** Scan akan jalan setiap Senin jam 2 pagi

### Email Notifications

**Configure Email Alerts:**

1. Go to: **Security Scanner → Settings → Notifications**
2. Enable:
   ```
   ☑ Send email on scan complete
   ☑ Send email on critical findings
   ☑ Weekly summary report
   ```
3. Recipients:
   ```
   admin@example.com
   security@example.com
   ```
4. Save settings

---

## 🛠️ Troubleshooting

### Problem 1: Scan Tidak Bisa Start

**Symptoms:**
- Error: "Cannot connect to proxy"
- Scan status stuck di "Queued"

**Solutions:**

```bash
# 1. Check proxy status
curl http://localhost:5000/health

# 2. Restart proxy
cd ~/TA/adaptive-moodle-security/MoodleSec/proxy
source ~/TA/venv/bin/activate
python3 app.py

# 3. Check firewall
sudo ufw allow 5000

# 4. Check logs
tail -f /var/log/moodle/security_scanner.log
```

### Problem 2: No Findings Returned

**Symptoms:**
- Scan complete tapi 0 findings
- Scanner tidak detect vulnerabilities

**Solutions:**

```bash
# 1. Verify scanner configuration
# Check ZAP/Acunetix API keys

# 2. Test scanner manually
zap-cli quick-scan http://localhost:8998

# 3. Check target accessibility
curl -I http://your-moodle.com

# 4. Review scan logs
cat data/scan_history.db
```

### Problem 3: ML Model Error

**Symptoms:**
- Error: "Model not trained"
- Confidence always 50%

**Solutions:**

```bash
# 1. Check model file
ls -lh ml/models/fp_reducer.pkl

# 2. Retrain model
cd proxy
python3 retrain_models.py

# 3. Verify training data
ls ml/training_data/

# 4. Reset model
rm ml/models/*.pkl
python3 retrain_models.py
```

### Problem 4: Database Error

**Symptoms:**
- Error: "no such column"
- Database locked

**Solutions:**

```bash
# 1. Delete old database
rm data/scan_history.db

# 2. Restart proxy (will recreate DB)
python3 app.py

# 3. Re-import data if needed
python3 import_organized_data.py
```

### Problem 5: Permission Denied

**Symptoms:**
- Cannot write to database
- Cannot create files

**Solutions:**

```bash
# 1. Fix permissions
chmod -R 755 local/securityscanner
chown -R www-data:www-data local/securityscanner

# 2. Check SELinux (if enabled)
sudo setenforce 0

# 3. Check directory ownership
ls -la local/securityscanner
```

---

## 📞 Support & Contact

### Documentation
- GitHub: https://github.com/ebenhaezer19/MoodleSec
- Wiki: https://github.com/ebenhaezer19/MoodleSec/wiki

### Bug Reports
- Issues: https://github.com/ebenhaezer19/MoodleSec/issues
- Email: [your-email]

### Feature Requests
- Discussions: https://github.com/ebenhaezer19/MoodleSec/discussions

---

## 📝 Changelog

### Version 1.0 (December 2025)
- ✅ Initial release
- ✅ OWASP ZAP integration
- ✅ Acunetix integration
- ✅ ML-powered false positive reduction
- ✅ Auto-labeling engine (87% coverage)
- ✅ Calibrated ensemble model (89.66% accuracy)
- ✅ Real-time scanning
- ✅ Scheduled scans
- ✅ Email notifications

---

## 📄 License

MIT License - See LICENSE file for details

---

**© 2025 Adaptive Moodle Security System**
