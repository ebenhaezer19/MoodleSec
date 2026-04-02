# ZAP Payload Import - Troubleshooting & Usage Guide

## ✅ Status Confirmed

- **ZAP API**: ✅ ACCESSIBLE di `http://localhost:8080`
- **Port 8080**: ✅ OPEN (localhost, 127.0.0.1, 0.0.0.0)
- **HTTP Status**: ✅ 200 OK
- **Response Size**: ✅ 1526 bytes (valid ZAP API response)

---

## 🚀 Usage - Import Payloads dari ZAP

**Script yang benar:**
```bash
cd ~/TA/adaptive-moodle-security/MoodleSec/proxy
python import_zap_payloads_v2.py
```

**Dengan options:**
```bash
# Custom host/port
python import_zap_payloads_v2.py --host localhost --port 8080

# Dengan API key (jika diperlukan)
python import_zap_payloads_v2.py --api-key YOUR_API_KEY

# Custom limit
python import_zap_payloads_v2.py --limit 500
```

---

## 📊 Expected Output

```
╔════════════════════════════════════════════════════════════╗
║  IMPORT REAL PAYLOADS FROM ZAP SCAN HISTORY               ║
╚════════════════════════════════════════════════════════════╝

[1] Checking ZAP Connection...
[✓] ZAP Version Check: Status 200
[✓] ZAP Version: 2.14.0

[2] Fetching alerts from ZAP...
[*] Found 45 alerts

[3] Importing...
[✓] Total imported: 42 payloads

[6] By Vulnerability Type:
    XSS: 15 payloads
    SQL Injection: 20 payloads
    CSRF: 7 payloads

[7] Database After Import:
    Total payloads: 42
    Vulnerable payloads: 42

✅ SUCCESS! Payloads imported to database.
```

---

## 🔧 Troubleshooting

### Problem: "No alerts in ZAP"

**Solution:**
1. Make sure ZAP scan sudah completed
2. Check ZAP GUI: View → Alerts
3. Run new scan if needed

### Problem: "API Key required"

**Solution:**
```bash
# Copy API key dari ZAP:
# Settings → API → Copy key (atau generate baru)

# Then run:
python import_zap_payloads_v2.py --api-key YOUR_KEY_HERE
```

### Problem: "JSON Parse Error"

**Solution:**
- Check ZAP version (update if old)
- Try with verbose: `python -u import_zap_payloads_v2.py`

---

## 📋 After Import

**Check payload stats:**
```bash
curl http://localhost:8999/api/payload-stats | jq .
```

**View top payloads by category:**
```bash
curl "http://localhost:8999/api/payload-top/XSS?limit=10" | jq .
```

**Run Native Auth Scan (will use imported payloads):**
```bash
curl -X POST "http://localhost:8999/api/scan-native-auth" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123","login_url":"http://localhost:8998/login"}'
```

---

## 🎯 Workflow

```
1. ZAP Scan Moodle
   ↓
2. python import_zap_payloads_v2.py
   (Extract 40+ REAL payloads)
   ↓
3. curl /api/payload-stats
   (Verify import successful)
   ↓
4. curl /api/scan-native-auth
   (Native Auth Scan uses these payloads)
   ↓
5. Find more vulnerabilities with proven payloads!
```

