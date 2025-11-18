# 🚀 Slack Integration - Complete Step-by-Step Guide

## Overview
Integrate MoodleSec Scanner dengan Slack untuk mendapatkan **real-time notifications** saat scan selesai atau vulnerability ditemukan.

**100% GRATIS** - Tidak ada biaya sama sekali!

---

## 📋 Prerequisites
- Akun Slack (gratis)
- MoodleSec Scanner sudah terinstall

---

## PART 1: Setup Slack Workspace (5 menit)

### Step 1: Buat Slack Workspace (Skip jika sudah punya)

1. Buka: https://slack.com/get-started
2. Klik **"Create a new workspace"**
3. Masukkan **email** Anda
4. Cek email, klik **link verifikasi**
5. Workspace name: **"MoodleSec Security"** (atau nama lain)
6. Buat channel: **`#security-alerts`**
7. Done! ✅

### Step 2: Buat Slack App

1. Buka: https://api.slack.com/apps
2. Klik **"Create New App"**
3. Pilih **"From scratch"**
4. App Name: **"MoodleSec Scanner"**
5. Workspace: Pilih workspace yang tadi dibuat
6. Klik **"Create App"**

### Step 3: Enable Incoming Webhooks

1. Di sidebar kiri, klik **"Incoming Webhooks"**
2. Toggle **"Activate Incoming Webhooks"** → **ON** (hijau)
3. Scroll ke bawah, klik **"Add New Webhook to Workspace"**
4. Pilih channel: **`#security-alerts`**
5. Klik **"Allow"**
6. **COPY** webhook URL yang muncul

**Webhook URL format:**
```
https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX
```

✅ **Simpan URL ini! Kita akan pakai di Step berikutnya.**

---

## PART 2: Test Webhook (2 menit)

### Test dari Windows PowerShell:

```powershell
# Ganti dengan webhook URL Anda
$webhook = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

$body = @{
    text = "🎉 Test from MoodleSec Scanner!"
} | ConvertTo-Json

Invoke-RestMethod -Uri $webhook -Method Post -Body $body -ContentType "application/json"
```

✅ **Cek Slack channel `#security-alerts`, harus muncul message!**

---

## PART 3: Configure MoodleSec (3 menit)

### Step 1: Edit `config.py`

Buka file: `proxy/config.py`

Tambahkan webhook URL Anda:

```python
# Slack Integration (Optional - for notifications)
SLACK_WEBHOOK_URL: str = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"  # Paste webhook URL di sini
SLACK_ENABLED: bool = True  # Set ke True untuk enable notifications
```

**Contoh lengkap:**
```python
"""
Configuration constants for the Moodle proxy service.
"""

# Target Moodle instance base URL
MOODLE_URL: str = "http://localhost:8998"

# Port for the proxy service to listen on
LISTEN_PORT: int = 8999

# Directory for storing log files
LOG_DIR: str = "logs"

# Maximum number of log entries to return
MAX_LOG_ENTRIES: int = 100

# Slack Integration
SLACK_WEBHOOK_URL: str = "https://hooks.slack.com/services/T09TPQFN1NW/B09U2PLEDC1/XXXX"
SLACK_ENABLED: bool = True
```

### Step 2: Restart Proxy Service

**Di WSL:**
```bash
cd ~/TA/adaptive-moodle-security/MoodleSec/proxy

# Stop proxy
pkill -f "python app.py"

# Start proxy dengan Slack enabled
python app.py &
```

**Di Windows (jika run lokal):**
```powershell
# Stop proxy (Ctrl+C)
# Start proxy
cd proxy
python app.py
```

✅ **Proxy sekarang akan send notifications ke Slack!**

---

## PART 4: Test Integration (2 menit)

### Test 1: Run Full Site Scan

1. Buka Moodle plugin: `http://localhost:8998/local/security_dashboard`
2. Klik **"Full Site Scan"**
3. Klik **"Start Full Scan"**
4. Tunggu scan selesai

✅ **Cek Slack channel - Harus muncul notification!**

**Contoh notification:**

```
🚨 Security Scan Complete
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scan ID: full_scan_20251118_132809
Target: http://localhost:8998
Endpoints Scanned: 10
Total Findings: 5

Vulnerability Breakdown:
🔴 Critical: 1
🟠 High: 2
🟡 Medium: 1
🟢 Low: 1

MoodleSec Scanner | 2025-11-18 13:28:09 UTC
```

### Test 2: Critical Vulnerability Alert

Jika ada critical vulnerability, akan muncul alert terpisah:

```
🚨 CRITICAL VULNERABILITY DETECTED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Category: SQL Injection
Severity: 🔴 Critical
URL: http://localhost:8998/login
Risk Score: 9.8

Description:
SQL injection vulnerability detected in login form

Evidence:
' OR '1'='1

Scan ID: full_scan_20251118_132809
MoodleSec Scanner
```

---

## 📊 Notification Types

### 1. Scan Complete Notification
- ✅ Dikirim setiap kali scan selesai
- ✅ Summary: Total findings, breakdown by severity
- ✅ Metadata: Scan ID, target URL, endpoints scanned

### 2. Critical Vulnerability Alert
- ✅ Dikirim untuk **top 3 critical findings**
- ✅ Detail lengkap: Category, severity, URL, risk score
- ✅ Evidence dan description

### 3. Custom Messages (Optional)
Anda bisa send custom message via API:

```python
# Di app.py atau script lain
if slack_notifier:
    await slack_notifier.send_simple_message("✅ Scheduler started successfully!")
```

---

## 🎨 Customization

### Ubah Channel Notification

1. Go to: https://api.slack.com/apps
2. Pilih app **"MoodleSec Scanner"**
3. Klik **"Incoming Webhooks"**
4. Klik **"Add New Webhook to Workspace"**
5. Pilih channel baru (e.g., `#critical-alerts`)
6. Update `SLACK_WEBHOOK_URL` di `config.py`

### Disable Notifications

Set di `config.py`:
```python
SLACK_ENABLED: bool = False
```

### Filter Notifications

Edit `app.py` line 353-362:

```python
# Hanya notify jika ada critical atau high
if slack_notifier and (summary['critical'] > 0 or summary['high'] > 0):
    await slack_notifier.send_scan_complete(result)
```

---

## 🔧 Troubleshooting

### Problem: Notification tidak muncul

**Check 1: Webhook URL benar?**
```bash
# Test manual
curl -X POST -H 'Content-type: application/json' \
--data '{"text":"Test"}' \
YOUR_WEBHOOK_URL
```

**Check 2: SLACK_ENABLED = True?**
```python
# Di config.py
SLACK_ENABLED: bool = True  # Harus True
```

**Check 3: Proxy restart?**
```bash
# Restart proxy setelah edit config.py
pkill -f "python app.py"
python app.py &
```

### Problem: Error di console

**Error:** `[Slack] Notification failed: ...`

**Solution:** Check webhook URL format:
```
✅ Correct: https://hooks.slack.com/services/T00/B00/XXX
❌ Wrong: https://hooks.slack.com/services/
❌ Wrong: Missing parts
```

---

## 📈 Advanced Usage

### Multiple Channels

Buat webhook untuk berbagai channel:

```python
# config.py
SLACK_WEBHOOK_CRITICAL: str = "https://hooks.slack.com/services/..."  # #critical-alerts
SLACK_WEBHOOK_GENERAL: str = "https://hooks.slack.com/services/..."   # #security-general

# app.py
critical_notifier = SlackNotifier(SLACK_WEBHOOK_CRITICAL)
general_notifier = SlackNotifier(SLACK_WEBHOOK_GENERAL)

# Send ke channel berbeda
if critical_count > 0:
    await critical_notifier.send_critical_alert(finding, scan_id)
else:
    await general_notifier.send_scan_complete(result)
```

### Scheduled Reports

Kirim daily summary:

```python
# Tambah endpoint di app.py
@app.get("/slack/daily-summary")
async def send_daily_summary():
    if not slack_notifier:
        return {"error": "Slack not enabled"}
    
    # Get scans from last 24 hours
    scans = scan_history_db.get_scan_history(limit=10)
    
    total_scans = len(scans)
    total_findings = sum(s.get('total_findings', 0) for s in scans)
    
    message = f"""
📊 Daily Security Summary
━━━━━━━━━━━━━━━━━━━━━━
Scans Today: {total_scans}
Total Findings: {total_findings}
━━━━━━━━━━━━━━━━━━━━━━
MoodleSec Scanner
    """
    
    await slack_notifier.send_simple_message(message)
    return {"success": True}
```

---

## 🎯 Best Practices

### 1. Channel Organization
```
#security-critical   → Critical vulnerabilities only
#security-alerts     → All scan results
#security-reports    → Daily/weekly summaries
```

### 2. Notification Filtering
```python
# Hanya notify untuk findings > 0
if result['total_findings'] > 0:
    await slack_notifier.send_scan_complete(result)
```

### 3. Rate Limiting
```python
# Batasi critical alerts (max 3)
for finding in critical_findings[:3]:
    await slack_notifier.send_critical_alert(finding, scan_id)
```

---

## 💡 Tips untuk Demo TA

### Screenshot-Friendly Notifications

Notifications sudah didesign dengan:
- ✅ Emoji untuk visual appeal
- ✅ Color coding (red, orange, yellow, green)
- ✅ Structured data dengan fields
- ✅ Timestamp dan metadata

### Demo Flow

1. **Setup:** Tunjukkan Slack workspace dan channel
2. **Trigger:** Run full site scan di Moodle
3. **Real-time:** Tunjukkan notification muncul di Slack
4. **Explain:** Jelaskan data yang ditampilkan
5. **Critical Alert:** Tunjukkan alert untuk critical finding

### Screenshots untuk Laporan

Ambil screenshot:
- ✅ Slack workspace dengan channel `#security-alerts`
- ✅ Scan complete notification
- ✅ Critical vulnerability alert
- ✅ Multiple notifications (history)

---

## 📚 Resources

- **Slack API Docs:** https://api.slack.com/messaging/webhooks
- **Webhook Testing:** https://webhook.site (untuk test format)
- **Slack Message Builder:** https://app.slack.com/block-kit-builder

---

## ✅ Summary

**Total Setup Time:** ~10 menit
**Cost:** 100% GRATIS
**Benefit:**
- ✅ Real-time security alerts
- ✅ Team collaboration
- ✅ Audit trail di Slack
- ✅ Professional demo untuk TA

**Selamat! Slack integration sudah aktif!** 🎉

Setiap kali scan selesai, team Anda akan langsung dapat notifikasi di Slack.
