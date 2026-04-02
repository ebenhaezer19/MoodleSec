# ZAP API Import Fix - Debugging Report

## Problem Summary
**Status Code 400 Error** when importing payloads from ZAP API using `httpx` library, while curl worked fine.

### Symptoms
- `curl http://localhost:8080/JSON/core/view/version` → ✅ HTTP 200 OK
- `python3 import_zap_payloads_v2.py` → ❌ Status 400 Error
- Same endpoint, different results between tools

### Root Cause Analysis
The issue was not with the ZAP API or endpoint path - both were correct (`/JSON/core/view/version`). 

**httpx Library Incompatibility**: ZAP API has specific header requirements:
```
Access-Control-Allow-Headers: 'ZAP-Header'
```

The `httpx` library was not properly handling HTTP/1.1 negotiation and header forwarding with ZAP API, resulting in 400 Bad Request.

## Solution Implemented

### Changed from httpx → requests library
**File**: `proxy/import_zap_payloads_v2.py`

**Before**:
```python
import httpx
self.client = httpx.Client(timeout=30.0)
response = self.client.get(url, follow_redirects=True, timeout=10.0)
```

**After**:
```python
import requests
self.session = requests.Session()
self.session.headers.update({
    'User-Agent': 'ZAPPayloadImporter/1.0',
    'Accept': 'application/json'
})
response = self.session.get(url, timeout=10)
```

### Verification Results ✅
```
[*] Using requests library (ZAP API compatible)
[*] Response Status: 200
[✓] ZAP Version: 2.17.0
[✓] Found 0 alerts (no scan executed yet)
```

## Files Updated
1. `proxy/import_zap_payloads_v2.py` - Main import script (requests-based)
2. `proxy/import_zap_payloads_direct.py` - Alternative direct implementation

## Key Findings

### Why requests works when httpx doesn't:
1. **requests** uses urllib3 which has broader compatibility with various HTTP servers
2. **httpx** has stricter HTTP/2 negotiation and connection pooling logic
3. ZAP API may return 400 for HTTP/2 requests - requests defaults to HTTP/1.1

### ZAP API Response Headers
```
Pragma: no-cache
Cache-Control: no-cache, no-store, must-revalidate
Content-Security-Policy: default-src 'none'; script-src 'self'; ...
Access-Control-Allow-Methods: GET,POST,OPTIONS
Access-Control-Allow-Headers: 'ZAP-Header'
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Content-Type: application/json; charset=UTF-8
```

## Next Steps

1. **Run ZAP Scan** to generate findings
   ```bash
   # ZAP should scan the Moodle application
   # This will populate the /JSON/core/view/alerts endpoint
   ```

2. **Import Payloads**
   ```bash
   python3 import_zap_payloads_v2.py
   # Will extract payloads from ZAP findings
   ```

3. **Verify Import**
   ```bash
   curl http://localhost:8999/api/payload-stats
   # Should show imported payloads
   ```

4. **Run Native Auth Scan**
   ```bash
   curl -X POST http://localhost:8999/api/scan-native-auth \
     -H 'Content-Type: application/json' \
     -d '{"username":"admin","password":"admin123","login_url":"http://localhost:8998/login"}'
   ```

## Technical Details

### httpx vs requests Performance Trade-offs
- **httpx**: Faster, supports HTTP/2, async support - but stricter HTTP parsing
- **requests**: Slower, HTTP/1.1 only - but broader server compatibility ✅ CHOSEN

For ZAP API compatibility, the requests library is more reliable.

## Debugging Tools Created
- `test_zap_api.sh` - Curl-based endpoint testing
- `debug_zap_connection.py` - Connection validation script
- `import_zap_payloads_direct.py` - Alternative direct implementation

## Verification Commands

```bash
# 1. Test ZAP connection
curl http://localhost:8080/JSON/core/view/version | python3 -m json.tool

# 2. Check for alerts
curl 'http://localhost:8080/JSON/core/view/alerts?count=5' | python3 -m json.tool

# 3. Test with Python import
python3 import_zap_payloads_v2.py

# 4. Verify FastAPI proxy
curl http://localhost:8999/api/payload-stats
```

## Conclusion
✅ **Problem Solved**: Status 400 error resolved by switching from httpx to requests library
✅ **ZAP API Working**: Successfully connecting and retrieving version info
⏳ **Next**: Awaiting ZAP scan findings to import payloads
