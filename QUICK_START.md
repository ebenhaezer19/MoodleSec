# Quick Start Guide - Testing MoodleSec Backend

## 🚀 Fast Testing (5 Minutes)

### Step 1: Install Dependencies

```bash
# Install Python dependencies for test script
pip install requests colorama
```

### Step 2: Start Services

**Terminal 1 - CVSS Engine:**
```bash
cd cvss-engine
pip install -r requirements.txt
python api.py
```

**Terminal 2 - Proxy Service:**
```bash
cd proxy
pip install -r requirements.txt
python app.py
```

### Step 3: Run Tests

**Option A: Python Test Script (Recommended for Windows)**
```bash
python test_all.py
```

**Option B: Bash Test Script (Linux/Mac/WSL)**
```bash
chmod +x test_all.sh
./test_all.sh
```

### Expected Output:

```
============================================================
MoodleSec Backend Testing Suite
============================================================

============================================================
1. Service Health Checks
============================================================

✅ PASSED: CVSS Engine is running
✅ PASSED: Proxy Service is running

============================================================
2. CVSS Engine Tests
============================================================

Testing: CVSS health check
✅ PASSED: CVSS health check
Testing: Calculate critical CVSS score (9.8)
✅ PASSED: Calculate critical CVSS score (9.8)
Testing: Calculate medium CVSS score (6.1)
✅ PASSED: Calculate medium CVSS score (6.1)
Testing: Handle invalid CVSS vector
✅ PASSED: Handle invalid CVSS vector

============================================================
3. Proxy Service Tests
============================================================

Testing: Proxy health check
✅ PASSED: Proxy health check
Testing: Get proxy logs
✅ PASSED: Get proxy logs
Testing: Trigger scan for login page
✅ PASSED: Trigger scan for login page
Testing: Trigger scan for admin page (should detect High severity)
✅ PASSED: Trigger scan for admin page (should detect High severity)
Testing: Get logs after scans
✅ PASSED: Get logs after scans

============================================================
4. Integration Tests
============================================================

Testing: Complete scan workflow
✅ PASSED: Scan triggered successfully (ID: scan_20241117_200530, Findings: 1)
✅ PASSED: Scan logged successfully
Testing: Calculate CVSS for typical finding
✅ PASSED: CVSS calculated: 6.5 (Medium)

============================================================
5. Error Handling Tests
============================================================

Testing: Handle missing required field
✅ PASSED: Missing required field rejected
Testing: Handle invalid CVSS vector
✅ PASSED: Invalid CVSS vector rejected

============================================================
6. Performance Tests
============================================================

Testing: Multiple concurrent requests (20 requests)
✅ PASSED: Handled 20 concurrent requests in 1.23s (20/20 successful)

============================================================
Test Summary
============================================================

Total Tests: 16
Passed: 16
Failed: 0
Pass Rate: 100%

🎉 All tests passed! Backend is ready.
```

---

## 🧪 Manual Testing

### Test CVSS Engine

```bash
# Health check
curl http://localhost:8001/health

# Calculate score
curl -X POST http://localhost:8001/score \
  -H "Content-Type: application/json" \
  -d '{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}'
```

### Test Proxy Service

```bash
# Health check
curl http://localhost:8999/health

# Trigger scan
curl -X POST http://localhost:8999/scan-trigger \
  -H "Content-Type: application/json" \
  -d '{"path":"/login/index.php","method":"POST"}'

# Get logs
curl http://localhost:8999/logs?limit=5
```

---

## 🐛 Troubleshooting

### Port Already in Use

**Windows:**
```powershell
# Find process
netstat -ano | findstr :8999
netstat -ano | findstr :8001

# Kill process
taskkill /PID <PID> /F
```

**Linux/Mac:**
```bash
# Find and kill
lsof -ti:8999 | xargs kill -9
lsof -ti:8001 | xargs kill -9
```

### Module Not Found

```bash
# Reinstall dependencies
pip install -r requirements.txt

# Or install missing module
pip install requests colorama
```

### Connection Refused

1. Check if services are running
2. Verify ports are correct (8001, 8999)
3. Check firewall settings
4. Try `localhost` instead of `0.0.0.0`

---

## ✅ Success Checklist

- [ ] CVSS Engine starts without errors
- [ ] Proxy Service starts without errors
- [ ] All automated tests pass
- [ ] Manual curl commands work
- [ ] Logs are being created in `proxy/logs/`
- [ ] Both services respond to health checks

---

## 📊 Next Steps

After all tests pass:

1. **Test with Moodle Plugin:**
   - Install plugin in Moodle
   - Configure service URLs
   - Test database integration

2. **Load Testing:**
   - Use Apache Bench or similar tools
   - Test with concurrent requests
   - Monitor performance

3. **Production Deployment:**
   - Use Docker for deployment
   - Set up reverse proxy (nginx)
   - Configure SSL/TLS
   - Set up monitoring

---

## 🔗 Useful Commands

### Check Service Status
```bash
# Quick health check
curl http://localhost:8001/health && echo " - CVSS OK"
curl http://localhost:8999/health && echo " - Proxy OK"
```

### View Logs
```bash
# Proxy logs
ls -lh proxy/logs/
cat proxy/logs/proxy_*.jsonl | tail -n 10

# Service logs (if running in terminal)
# Just check the terminal output
```

### Stop Services
```bash
# Press Ctrl+C in each terminal
# Or kill processes:
pkill -f "python api.py"
pkill -f "python app.py"
```

---

## 📝 Test Data Examples

### CVSS Vectors for Testing

```json
// Critical (9.8)
{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}

// High (7.5)
{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}

// Medium (6.1)
{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}

// Low (3.7)
{"vector":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"}
```

### Scan Paths for Testing

```json
// Login page (Medium severity expected)
{"path":"/login/index.php","method":"POST"}

// Admin page (High severity expected)
{"path":"/admin/settings.php","method":"GET"}

// Regular page (Low/Info expected)
{"path":"/course/view.php","method":"GET"}

// API endpoint
{"path":"/webservice/rest/server.php","method":"POST"}
```

---

**Last Updated:** 2024-11-17
