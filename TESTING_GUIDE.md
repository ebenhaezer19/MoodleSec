# Testing Guide - MoodleSec Backend

## Prerequisites

- Python 3.11+ installed
- Moodle 4.0+ installed (for plugin testing)
- Git bash or WSL for running commands

---

## 1. Test CVSS Engine

### Start CVSS Engine
```bash
cd cvss-engine
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python api.py
```

**Expected Output:**
```
INFO:     Started server process [xxxx]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8001
```

### Run Unit Tests
```bash
cd cvss-engine
python tests/test_cvss.py
```

**Expected Output:**
```
======================================================================
CVSS v3.1 Calculator - Unit Tests
======================================================================

Test 1: Critical Vulnerability
  Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
  Score: 9.8
  Severity: Critical
  ✅ PASSED

Test 2: Medium XSS Vulnerability
  Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N
  Score: 6.1
  Severity: Medium
  ✅ PASSED

======================================================================
Test Results: 2 passed, 0 failed
======================================================================
```

### Test API Endpoints

**Test 1: Health Check**
```bash
curl http://localhost:8001/health
```
Expected: `{"status":"ok"}`

**Test 2: Calculate CVSS Score**
```bash
curl -X POST http://localhost:8001/score \
  -H "Content-Type: application/json" \
  -d '{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}'
```
Expected: `{"score":9.8,"severity":"Critical"}`

**Test 3: Invalid Vector**
```bash
curl -X POST http://localhost:8001/score \
  -H "Content-Type: application/json" \
  -d '{"vector":"INVALID"}'
```
Expected: `{"detail":"Vector must start with 'CVSS:3.1/'"}`

---

## 2. Test Proxy Service

### Start Proxy Service
```bash
cd proxy
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

**Expected Output:**
```
INFO:     Started server process [xxxx]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:8999
```

### Test API Endpoints

**Test 1: Health Check**
```bash
curl http://localhost:8999/health
```
Expected: `{"status":"ok"}`

**Test 2: Get Logs (Empty)**
```bash
curl http://localhost:8999/logs
```
Expected: `{"count":0,"logs":[]}`

**Test 3: Trigger DAST Scan**
```bash
curl -X POST http://localhost:8999/scan-trigger \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/login/index.php",
    "method": "POST"
  }'
```

Expected Response (example):
```json
{
  "scan_id": "scan_20241117_140530",
  "target_url": "http://localhost:8080/login/index.php",
  "timestamp": "2024-11-17T14:05:30.123456Z",
  "findings": [
    {
      "severity": "Medium",
      "category": "Authentication",
      "description": "Login page detected - verify CSRF protection is enabled",
      "evidence": "Path contains 'login': /login/index.php"
    }
  ],
  "summary": {
    "high": 0,
    "medium": 1,
    "low": 0,
    "info": 0
  }
}
```

**Test 4: Get Logs (After Scan)**
```bash
curl http://localhost:8999/logs?limit=5
```
Expected: Should return scan logs

**Test 5: Scan Admin Path**
```bash
curl -X POST http://localhost:8999/scan-trigger \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/admin/settings.php",
    "method": "GET"
  }'
```
Expected: Should detect "High" severity finding for admin path

---

## 3. Test Integration (Proxy + CVSS)

### Test Complete Workflow

**Step 1: Start Both Services**
```bash
# Terminal 1
cd cvss-engine && python api.py

# Terminal 2
cd proxy && python app.py
```

**Step 2: Trigger Scan**
```bash
curl -X POST http://localhost:8999/scan-trigger \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/admin/login.php",
    "method": "POST"
  }'
```

**Step 3: Verify Logs**
```bash
curl http://localhost:8999/logs | jq
```

**Step 4: Calculate CVSS for Finding**
```bash
curl -X POST http://localhost:8001/score \
  -H "Content-Type: application/json" \
  -d '{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}'
```

---

## 4. Test Moodle Plugin (Database Layer)

### Prerequisites
- Moodle installed and running
- Plugin copied to `/path/to/moodle/local/security_dashboard/`

### Install Plugin

1. Copy plugin folder:
```bash
cp -r moodle-plugin /path/to/moodle/local/security_dashboard
```

2. Visit Moodle admin:
```
http://your-moodle-site/admin/index.php
```

3. Click "Upgrade Moodle database now"

4. Verify tables created:
```sql
SHOW TABLES LIKE 'mdl_local_security_%';
```

Expected tables:
- `mdl_local_security_scans`
- `mdl_local_security_findings`
- `mdl_local_security_logs`
- `mdl_local_security_config`
- `mdl_local_security_schedules`

### Test Database Functions

**Test 1: Check Tables**
```sql
SELECT COUNT(*) FROM mdl_local_security_scans;
SELECT COUNT(*) FROM mdl_local_security_findings;
SELECT COUNT(*) FROM mdl_local_security_logs;
```

**Test 2: Run Example Script**
```
http://your-moodle-site/local/security_dashboard/examples/database_usage.php
```

Expected: Page showing all 10 examples with data

**Test 3: Test API Client**

Create test file: `/path/to/moodle/local/security_dashboard/test_api.php`

```php
<?php
require_once(__DIR__ . '/../../config.php');
require_once($CFG->dirroot . '/local/security_dashboard/classes/api_client.php');

use local_security_dashboard\api_client;

require_login();

$api = new api_client();

// Test health
$health = $api->check_all_health();
var_dump($health);

// Test CVSS
$cvss = $api->calculate_cvss('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
var_dump($cvss);

// Test scan
$scan = $api->trigger_scan('/test.php', 'GET');
var_dump($scan);
```

Visit: `http://your-moodle-site/local/security_dashboard/test_api.php`

---

## 5. Load Testing (Optional)

### Test Concurrent Requests

**Install Apache Bench:**
```bash
sudo apt-get install apache2-utils
```

**Test CVSS Engine:**
```bash
ab -n 1000 -c 10 -p cvss_payload.json -T application/json http://localhost:8001/score
```

**cvss_payload.json:**
```json
{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
```

**Test Proxy Service:**
```bash
ab -n 100 -c 5 http://localhost:8999/health
```

---

## 6. Error Testing

### Test Error Handling

**Test 1: Invalid CVSS Vector**
```bash
curl -X POST http://localhost:8001/score \
  -H "Content-Type: application/json" \
  -d '{"vector":"INVALID:VECTOR"}'
```
Expected: 400 Bad Request

**Test 2: Missing Required Field**
```bash
curl -X POST http://localhost:8999/scan-trigger \
  -H "Content-Type: application/json" \
  -d '{}'
```
Expected: 422 Unprocessable Entity

**Test 3: Invalid Method**
```bash
curl -X DELETE http://localhost:8999/health
```
Expected: 405 Method Not Allowed

**Test 4: Service Unavailable**

Stop CVSS service, then:
```bash
curl -X POST http://localhost:8001/score \
  -H "Content-Type: application/json" \
  -d '{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}'
```
Expected: Connection refused

---

## 7. Docker Testing (Optional)

### Build and Run with Docker

**CVSS Engine:**
```bash
cd cvss-engine
docker build -t moodlesec-cvss .
docker run -p 8001:8001 moodlesec-cvss
```

**Proxy Service:**
```bash
cd proxy
docker build -t moodlesec-proxy .
docker run -p 8999:8999 moodlesec-proxy
```

**Test:**
```bash
curl http://localhost:8001/health
curl http://localhost:8999/health
```

---

## Troubleshooting

### Port Already in Use
```bash
# Find process using port
lsof -i :8999
lsof -i :8001

# Kill process
kill -9 <PID>
```

### Module Not Found
```bash
# Reinstall dependencies
pip install -r requirements.txt
```

### Database Tables Not Created
```bash
# Check Moodle logs
tail -f /path/to/moodle/moodledata/error.log

# Manually create tables
php admin/cli/upgrade.php
```

### Connection Refused
- Check if services are running
- Verify firewall settings
- Check URLs in Moodle plugin settings

---

## Success Criteria

✅ **CVSS Engine:**
- Unit tests pass (2/2)
- API responds to health check
- Calculates scores correctly
- Handles errors gracefully

✅ **Proxy Service:**
- Health check responds
- Logs are created
- Scans can be triggered
- Findings are returned

✅ **Moodle Plugin:**
- Database tables created
- API client connects to services
- Data can be saved and retrieved
- Examples page works

✅ **Integration:**
- Both services communicate
- End-to-end workflow completes
- Data persists correctly

---

## Next Steps After Testing

1. ✅ All tests pass → Ready for production
2. ⚠️ Some tests fail → Debug and fix issues
3. 🔧 Performance issues → Optimize code
4. 📊 Need more features → Implement enhancements

---

**Last Updated:** 2024-11-17
