# ZAP Integration Tests

## Overview
Integration tests verify that the ZAPClient can communicate with a real OWASP ZAP instance.

## Running Tests

### Unit Tests (No ZAP Required)
```bash
# Windows
python -m pytest ml/zap_integration/tests -m "not integration" -v

# WSL
./.venv_wsl/bin/python -m pytest ml/zap_integration/tests -m "not integration" -v
```

All unit tests should pass without ZAP running. They use mocked HTTP sessions.

**Status:** ✅ 4/4 tests passing

### Integration Tests (ZAP Required)
```bash
python -m pytest ml/zap_integration/tests -m "integration" -v
```

Integration tests require OWASP ZAP running and accessible.

## ZAP Configuration for Integration Tests

### Windows Setup
1. Start ZAP: `C:\Program Files\ZAP\Zed Attack Proxy\ZAP.exe`
2. Verify it listens on `localhost:8080`:
   ```powershell
   netstat -ano | findstr :8080
   ```
   Should show: `TCP    127.0.0.1:8080 ...` or `TCP    0.0.0.0:8080 ...`

3. Test connectivity:
   ```powershell
   curl http://localhost:8080/JSON/core/view/version
   ```

### WSL Setup
ZAP runs on Windows, WSL needs to reach it at the Windows IP:

1. Get Windows IP in WSL:
   ```bash
   cat /etc/resolv.conf | grep nameserver
   ```
   Use the nameserver IP (typically `10.255.255.254` for WSL2)

2. Configure integration test to use that IP:
   - Either set `ZAP_HOST` environment variable
   - Or modify `test_zap_client.py` to auto-detect

3. Test from WSL:
   ```bash
   curl http://10.255.255.254:8080/JSON/core/view/version
   ```

## Test Output

### When ZAP is NOT running
```
test_live_zap_connection SKIPPED - ZAP not running on localhost:8080
```

### When ZAP IS running
```
test_live_zap_connection PASSED
```

## Troubleshooting

### "Connection refused" on localhost:8080
- ZAP not running or not listening on port 8080
- Check: `netstat -ano | findstr :8080`
- Ensure ZAP is fully started (takes 20-30 seconds)

### WSL cannot reach Windows ZAP
- ZAP listening on 127.0.0.1 only (localhost)
- Need to configure ZAP to listen on `0.0.0.0` or use Windows IP
- Edit `C:\Users\Admin\.ZAP_d\config.xml`:
  ```xml
  <api>
    <localAddress>0.0.0.0</localAddress>
  </api>
  ```

### Port 8080 in use by another process
- Find process: `netstat -ano | findstr :8080`
- Kill it: `taskkill /PID <PID> /F`

## Environment Variables

`ZAP_HOST` (future support):
```bash
ZAP_HOST=10.255.255.254 python -m pytest ml/zap_integration/tests -m integration -v
```

## Files
- `test_zap_client.py` - Unit and integration tests
- `../zap_client.py` - ZAPClient implementation
