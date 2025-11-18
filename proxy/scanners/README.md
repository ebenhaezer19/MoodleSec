# Security Scanners - Traditional DAST Implementation

Comprehensive vulnerability detection scanners for web application security testing.

---

## 📋 Overview

This module implements **Traditional DAST (Dynamic Application Security Testing)** with real vulnerability detection capabilities. It includes multiple specialized scanners orchestrated by a central Scanner Engine.

---

## 🔍 Available Scanners

### 1. SQL Injection Detector (`sql_injection.py`)

**Purpose:** Detect SQL injection vulnerabilities

**Detection Methods:**
- SQL error pattern matching (MySQL, PostgreSQL, MSSQL, Oracle)
- SQL keyword detection in parameters
- Suspicious character analysis (`'`, `"`, `--`, `#`, `;`)
- Parameter validation

**Severity Levels:**
- **Critical**: Sensitive file exposure
- **High**: SQL errors in response
- **Medium**: SQL keywords/characters in parameters

**CWE:** CWE-89  
**OWASP:** A03:2021 - Injection

---

### 2. XSS (Cross-Site Scripting) Detector (`xss_detector.py`)

**Purpose:** Detect XSS vulnerabilities (Reflected, Stored, DOM-based)

**Detection Methods:**
- Reflected XSS detection (parameter values in response)
- Dangerous HTML tag detection (`<script>`, `<iframe>`, `<object>`)
- Inline event handler detection (`onclick`, `onerror`, etc.)
- JavaScript protocol detection (`javascript:`)
- DOM-based XSS indicators (`innerHTML`, `eval`, `document.write`)
- Input field sanitization checks

**Severity Levels:**
- **High**: Reflected XSS, JavaScript protocol, unsafe DOM manipulation
- **Medium**: Dangerous tags, event handlers, DOM sinks
- **Info**: Input fields requiring validation

**CWE:** CWE-79  
**OWASP:** A03:2021 - Injection

---

### 3. CSRF Validator (`csrf_validator.py`)

**Purpose:** Validate CSRF protection mechanisms

**Detection Methods:**
- CSRF token presence in forms
- CSRF token in request parameters/headers
- SameSite cookie attribute validation
- State-changing request protection (POST, PUT, DELETE, PATCH)

**Common Token Names:**
- `csrf`, `csrf_token`, `csrftoken`
- `_csrf`, `_token`, `token`
- `sesskey` (Moodle-specific)
- `authenticity_token`, `xsrf_token`

**Severity Levels:**
- **High**: Missing CSRF protection on state-changing requests
- **Medium**: Missing SameSite attribute, SameSite=None usage

**CWE:** CWE-352  
**OWASP:** A01:2021 - Broken Access Control

---

### 4. Path Traversal Detector (`path_traversal.py`)

**Purpose:** Detect path traversal and directory traversal vulnerabilities

**Detection Methods:**
- Path traversal pattern detection (`../`, `..\\`, URL-encoded variants)
- Sensitive file access attempts (`/etc/passwd`, `c:\\windows\\system32`)
- Absolute path detection
- Directory listing detection
- Sensitive file content in response

**Patterns Detected:**
- Basic: `..`, `../`, `..\`
- URL encoded: `%2e%2e`, `%2e%2e%2f`
- Double encoded: `%252e%252e`
- Unicode: `%c0%af`, `%c1%9c`

**Severity Levels:**
- **Critical**: Sensitive file exposure, access attempts
- **High**: Path traversal patterns in URL
- **Medium**: Traversal in parameters, directory listing, absolute paths

**CWE:** CWE-22, CWE-548  
**OWASP:** A01:2021 - Broken Access Control, A05:2021 - Security Misconfiguration

---

## 🎯 Scanner Engine (`scanner_engine.py`)

**Purpose:** Orchestrate all scanners and aggregate results

**Features:**
- Run all scanners in parallel
- Deduplicate findings
- Sort by severity (Critical → High → Medium → Low → Info)
- Calculate summary statistics
- Enable/disable individual scanners
- Error handling per scanner

**Methods:**
- `scan()` - Run comprehensive scan
- `enable_scanner(name)` - Enable specific scanner
- `disable_scanner(name)` - Disable specific scanner
- `get_scanner_status()` - Get status of all scanners

---

## 🚀 Usage

### Basic Scan

```python
from scanners.scanner_engine import ScannerEngine

# Initialize engine
engine = ScannerEngine()

# Run scan
results = engine.scan(
    url="http://localhost:8998/login/index.php",
    method="GET",
    params={"username": "admin", "password": "test"},
    response_body="<html>...</html>",
    status_code=200
)

# Access results
print(f"Scan ID: {results['scan_id']}")
print(f"Total findings: {results['total_findings']}")
print(f"Summary: {results['summary']}")

for finding in results['findings']:
    print(f"{finding['severity']}: {finding['description']}")
```

### Enable/Disable Scanners

```python
# Disable XSS scanner
engine.disable_scanner('xss')

# Enable it back
engine.enable_scanner('xss')

# Check status
status = engine.get_scanner_status()
print(status)
```

### Via API

```bash
# Trigger scan
curl -X POST http://localhost:8999/scan-trigger \
  -H "Content-Type: application/json" \
  -d '{
    "path": "/login/index.php",
    "method": "GET",
    "parameters": {"username": "test"}
  }'

# Check scanner status
curl http://localhost:8999/scanners/status
```

---

## 📊 Output Format

### Scan Result

```json
{
  "scan_id": "scan_20251118_093237",
  "target_url": "http://localhost:8998/login/index.php",
  "timestamp": "2025-11-18T09:32:37.184167Z",
  "method": "GET",
  "total_findings": 5,
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 1,
    "info": 1
  },
  "findings": [
    {
      "severity": "High",
      "category": "SQL Injection",
      "description": "SQL error message detected in response",
      "evidence": "SQL error pattern found: \"MySQL syntax error\"",
      "recommendation": "Use parameterized queries",
      "cwe": "CWE-89",
      "owasp": "A03:2021 - Injection"
    }
  ],
  "scanner_results": {
    "sql_injection": {"findings_count": 2, "status": "completed"},
    "xss": {"findings_count": 1, "status": "completed"},
    "csrf": {"findings_count": 1, "status": "completed"},
    "path_traversal": {"findings_count": 1, "status": "completed"}
  }
}
```

---

## 🔧 Configuration

### Scanner Settings

Each scanner can be configured in `scanner_engine.py`:

```python
self.scanners = {
    'sql_injection': {
        'name': 'SQL Injection Scanner',
        'detector': self.sql_detector,
        'enabled': True  # Set to False to disable
    },
    # ... other scanners
}
```

### Custom Patterns

Add custom patterns in individual scanner files:

```python
# In sql_injection.py
self.error_patterns = [
    r'SQL syntax.*MySQL',
    r'Your custom pattern here',
]

# In xss_detector.py
self.dangerous_tags = [
    'script', 'iframe', 'your_custom_tag'
]
```

---

## 🧪 Testing

### Unit Tests

```bash
# Test SQL Injection detector
python -m pytest tests/test_sql_injection.py

# Test all scanners
python -m pytest tests/test_scanners.py
```

### Manual Testing

```bash
# Start proxy service
cd ~/TA/adaptive-moodle-security/MoodleSec/proxy
source ../venv/bin/activate
python app.py

# Test scan endpoint
curl -X POST http://localhost:8999/scan-trigger \
  -H "Content-Type: application/json" \
  -d '{"path": "/login/index.php", "method": "GET"}'
```

---

## 📈 Performance

**Typical Scan Times:**
- SQL Injection: ~50ms
- XSS Detection: ~100ms
- CSRF Validation: ~30ms
- Path Traversal: ~40ms
- **Total**: ~220ms per scan

**Resource Usage:**
- Memory: ~50MB per scanner instance
- CPU: Minimal (pattern matching only)

---

## 🔒 Security Considerations

1. **False Positives**: Pattern-based detection may produce false positives. Manual verification recommended.

2. **Coverage**: These scanners detect common vulnerabilities but not all possible attack vectors.

3. **Payload Testing**: Current implementation uses pattern matching. For active testing, implement payload injection carefully.

4. **Rate Limiting**: Implement rate limiting to prevent scanner abuse.

---

## 🚧 Limitations

1. **No Active Exploitation**: Scanners detect patterns but don't actively exploit vulnerabilities.

2. **Context-Dependent**: Some findings require manual verification based on application context.

3. **No Authentication**: Scanners don't handle authenticated sessions (yet).

4. **Limited Coverage**: Focuses on OWASP Top 10 but doesn't cover all vulnerability types.

---

## 🔮 Future Enhancements

### Phase 2: ML Integration
- Anomaly detection
- Vulnerability classification
- False positive reduction
- Adaptive severity scoring

### Phase 3: Advanced Features
- Active payload testing
- Authentication handling
- API security testing
- GraphQL scanning
- WebSocket security

---

## 📚 References

- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [CWE Top 25](https://cwe.mitre.org/top25/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)

---

## 📝 License

Part of MoodleSec - Adaptive Security Testing for Moodle LMS  
Copyright © 2024 Krisopras & Nathanael

---

**Status**: ✅ Phase 1 Complete - Traditional DAST Implementation  
**Next**: Phase 2 - Machine Learning Enhancement
