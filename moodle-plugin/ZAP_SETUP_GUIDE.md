# ZAP Integration Setup Guide

## Problem

ZAP is running on Windows, but Moodle (in WSL) cannot access it because:
- **ZAP API** only allows requests from `127.0.0.1` by default
- WSL is trying to connect from `172.19.80.0/24` subnet
- ZAP blocks this subnet for security

## Solution Options

### Option 1: Configure ZAP API Permissions ✅ **RECOMMENDED**

This is the proper production setup.

**Steps:**

1. **Open ZAP** (the application should already be running)
2. Go to: **Tools → Options**
3. Find: **API** section
4. **Enable API checkbox** ✅
5. Scroll down to: **"Addresses permitted to use the API"**
6. Add regex pattern to allow WSL:
   ```
   172\.19\..*
   ```
   Or more specific:
   ```
   172\.19\.80\..*
   ```
7. Click **OK**
8. **Restart ZAP** completely (close and reopen)

**Why this works:**
- Allows the `172.19.80.0/24` subnet (WSL) to access ZAP API
- Proper security configuration
- Works with real vulnerability scanning

**Test connection:**
```bash
# From WSL terminal
curl http://172.19.80.1:8080/JSON/core/view/version
```

This should return:
```json
{"version": "2.17.0"}
```

---

### Option 2: Use Mock ZAP Server for Testing ⚙️

Use this during development when you don't have ZAP configured yet.

**Setup:**

1. **Install Flask**:
   ```bash
   pip install flask
   ```

2. **Run mock server**:

   **Windows:**
   ```powershell
   cd "c:\Users\Admin\OneDrive\Desktop\Kuliah Guwa\TA\MoodleSec\moodle-plugin"
   python mock_zap_server.py
   ```

   **Or use batch file:**
   ```powershell
   .\start_mock_zap.bat
   ```

3. **Configure Moodle plugin**:
   - Admin → Local plugins → Security Dashboard → ZAP Settings
   - Set "ZAP Server Host" to: `localhost` (or `127.0.0.1`)
   - Set "ZAP Server Port" to: `5000`
   - API Key: Any value (not required for mock)

4. **Test connection**:
   ```bash
   curl http://localhost:5000/health
   ```
   Should return: `{"status": "ok", "service": "Mock ZAP Server"}`

**Features:**
- ✅ Simulates ZAP API responses
- ✅ Returns realistic vulnerability alerts
- ✅ Runs spider and active scans (with simulated progress)
- ✅ Perfect for UI testing without real scanning
- ✅ No real vulnerabilities, safe for testing

**Mock Endpoints Included:**
- `/JSON/core/view/version` - Returns version 2.17.0
- `/JSON/spider/action/scan` - Starts spider scan
- `/JSON/spider/view/status` - Gets spider progress
- `/JSON/ascan/action/scan` - Starts active scan  
- `/JSON/ascan/view/status` - Gets active scan progress
- `/JSON/core/view/alerts` - Returns 4 mock vulnerabilities
- `/health` - Health check endpoint

---

### Option 3: Configure ZAP to Listen on All Interfaces

**Windows Firewall:**
```powershell
# Allow ZAP port for external connections
netsh advfirewall firewall add rule name="ZAP Port 8080" dir=in action=allow protocol=tcp localport=8080 profile=any
```

**ZAP Configuration:**
- Tools → Options → Network
- Set "Server port" to: `0.0.0.0:8080` (accept all interfaces)

---

## Quick Decision Tree

```
Do you want to use REAL ZAP scanning?
├─ YES → Option 1: Configure ZAP API Permissions
│         (Allows WSL to access real ZAP)
│
└─ NO (Testing/Development) → Option 2: Mock ZAP Server
                              (Safe, no vulnerabilities, quick setup)
```

---

## Troubleshooting

### Test if Moodle can reach ZAP

From WSL:
```bash
# Option 1: Real ZAP on Windows
curl http://172.19.80.1:8080/JSON/core/view/version

# Option 2: Mock server on Windows
curl http://127.0.0.1:5000/health
```

### Check firewall
```powershell
# Windows Defender Firewall
netsh advfirewall firewall show rule name="ZAP*"
```

### Verify ZAP API is enabled
In ZAP: **Tools → Options → API** → "Enabled" checkbox should be ✅

### Reset Moodle cache
```bash
# Clear all caches
cd /var/www/html/moodle/public
php -r 'require("config.php"); purge_all_caches();'
```

---

## File Locations

- Mock server: `moodle-plugin/mock_zap_server.py`
- Windows launcher: `moodle-plugin/start_mock_zap.bat`
- Linux launcher: `moodle-plugin/start_mock_zap.sh`
- ZAP integration: `moodle-plugin/lib/zap_integration.php`

---

## Next Steps

**When ZAP is configured:**
1. Update Moodle ZAP Settings:
   - Host: `172.19.80.1` (Windows gateway from WSL)
   - Port: `8080`
   - API Key: Your configured key (or disable if not required)
2. Reload the Moodle page
3. ZAP status should show: **Online ✅**
4. Try running a test scan

---

**Contact:** For issues with ZAP connectivity, check ZAP API settings or use the mock server for testing.
