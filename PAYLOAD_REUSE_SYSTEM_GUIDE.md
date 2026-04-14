# Payload Reuse & Injection System - Implementation Guide

## Overview

Payload reuse system memungkinkan semua scanner (SQL Injection, XSS, CSRF) untuk menggunakan payloads dari repository secara aktif saat melakukan scanning. Ini meningkatkan detection capability dengan menggunakan tested, high-success payloads.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              Payload Repository (Database)               │
│  - Stores all imported payloads from ZAP & custom       │
│  - Tracks success_rate, effectiveness_score             │
│  - Categorized: SQL Injection, XSS, CSRF, etc.          │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│           Payload Injector (payload_injector.py)         │
│  - Loads payloads per category                          │
│  - Injects to parameters, headers, body                 │
│  - Tracks injections with debug logger                  │
│  - Detects vulnerabilities from responses               │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│         Scanner Engine (scanner_engine.py)              │
│  - SQL Injection Scanner                                │
│  - XSS Detector                                         │
│  - CSRF Validator                                       │
│  - Path Traversal Detector                              │
│  - Orchestrates payload injection testing               │
└──────────────────────┬──────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────┐
│         Debug Logger (payload_debug_logger.py)           │
│  - Tracks all injection attempts                        │
│  - Records successful detections                        │
│  - Provides injection statistics                        │
└─────────────────────────────────────────────────────────┘
```

## Components

### 1. PayloadInjector (payload_injector.py)

**Responsibilities:**
- Load payloads from repository per category
- Inject payloads into:
  - Request parameters
  - HTTP headers
  - Request body
- Detect vulnerabilities from payload responses
- Track all injection attempts

**Key Methods:**
```python
async inject_payloads_to_parameters(
    url, params, client, category, scan_id, max_payloads=10
) -> List[Dict]
# Test each parameter with each payload
# Check response for SQL errors, reflected XSS, etc.

async inject_payloads_to_headers(
    url, headers, client, category, scan_id, max_payloads=5
) -> List[Dict]
# Test security-related headers with payloads

async inject_payloads_to_body(
    url, body_content, client, category, scan_id, max_payloads=5
) -> List[Dict]
# Test request body content with payloads
```

### 2. ScannerEngine (scanner_engine.py)

**Enhanced with:**
- Payload repository integration
- Debug logger integration
- PayloadInjector instance
- Active payload injection testing

**New Methods:**
```python
_test_payloads_against_endpoints(
    url, params, method, scan_id
) -> List[Dict]
# Main method for payload injection testing
# Tests SQL Injection, XSS, CSRF payloads

_test_payload_category(
    url, params, category, scan_id
) -> List[Dict]
# Test specific payload category
# Logs all injection attempts
```

**Flow in scan() method:**
```
1. Run pattern-based detectors (existing)
   - SQL Injection patterns
   - XSS patterns
   - CSRF validation

2. Run active payload injection testing (NEW)
   - Test SQL Injection payloads on parameters
   - Test XSS payloads on parameters
   - Test CSRF payloads on parameters
   - Log all injection attempts

3. Deduplicate and sort findings
4. Return combined results
```

### 3. Integration Points

**app.py:**
```python
# Initialize scanner engine
scanner_engine = ScannerEngine()

# Initialize payload repository
payload_repo = PayloadRepositoryManager()

# Update scanner engine with payload repo
scanner_engine.payload_repo = payload_repo
scanner_engine.debug_logger = debug_logger
scanner_engine.initialize_scanners()
```

## Usage Flow

### 1. During Active Scan

**User Action:**
```
Dashboard → Scan → Select "Active Scan"
```

**Backend Flow:**
```
POST /api/scan/active
  ↓
scanner_engine.scan(url, params, method, ...)
  ↓
1. Pattern-based scanners run
2. Payload injector loads payloads from repository
   - Get top SQL Injection payloads
   - Get top XSS payloads
   - Get top CSRF payloads
3. Test each parameter with payloads
   - Inject payload into parameter
   - Record injection attempt in debug logger
   - Check response for vulnerability indicators
4. Return combined findings
```

### 2. During Crawl

**When discovering new endpoints via spider/crawl:**
```
1. Extract parameters from discovered endpoints
2. For each parameter:
   - Inject SQL Injection payloads
   - Inject XSS payloads
   - Inject CSRF payloads
3. Log all injections to debug logger
4. Return vulnerabilities discovered
```

## Vulnerability Detection Logic

### SQL Injection Detection
```python
Payload injected: ' OR '1'='1
Response checked for patterns:
- "SQL syntax error"
- "You have an error in your SQL syntax"
- "Warning: mysql_"
- "PostgreSQL error"
- etc.
```

### XSS Detection
```python
Payload injected: <img src=x onerror="alert('xss')">
Response checked for:
- Payload reflected unescaped
- JavaScript execution indicators
- DOM manipulation patterns
```

## Logging & Tracking

**Injection Attempts Logged:**
- Payload ID
- Category (SQL Injection, XSS, etc.)
- Injection point (parameter/header/body)
- Target URL
- Response status code
- Error messages

**Statistics Available:**
```
GET /api/debug/payload/statistics?scan_id=scan_123

Response:
{
  "total_injections": 45,
  "successful_detections": 3,
  "payload_categories_tested": ["SQL Injection", "XSS", "CSRF"],
  "injection_points": ["parameter:id", "parameter:search", "header:User-Agent"],
  "vulnerabilities_found": [
    {
      "type": "SQL Injection",
      "parameter": "id",
      "payload_id": 42,
      "severity": "Critical"
    }
  ]
}
```

## ZAP Integration Note

**Untuk ZAP OWASP Scans:**
- ZAP payloads tetap di-filter dengan ML models
- ZAP's active scan menggunakan custom scan rules
- Hasil ZAP di-aggregate terpisah dari custom scanners
- ML filtering (False Positive Reducer, Severity Predictor) tetap applied

**Custom Scanner Payloads (Non-ZAP):**
- Menggunakan repository payloads tanpa ML pre-filtering
- All results tracked in debug logger
- User dapat melihat injection points dan success rates

## Configuration

### Default Payload Limits
```python
MAX_PAYLOADS_PER_CATEGORY = 10    # per parameter
MAX_PAYLOADS_FOR_HEADERS = 5      # per header
MAX_PAYLOADS_FOR_BODY = 5         # for body content
```

### Categories Supported
```python
- SQL Injection
- XSS
- CSRF
- RFI
- LFI
- XXE
- Command Injection
- Path Traversal
- SSRF
- Broken Authentication
- Custom (user-defined)
```

## Performance Considerations

**Injection Testing Cost (per endpoint):**
```
10 parameters × 10 SQL payloads = 100 tests
10 parameters × 10 XSS payloads = 100 tests
10 parameters × 5 CSRF payloads = 50 tests
─────────────────────────────────────────
Total = 250 requests per endpoint

(Assuming 100ms per request = 25 seconds per endpoint)
```

**Optimization Strategies:**
1. Limit payload count (MAX_PAYLOADS)
2. Test critical parameters first
3. Cache results for same parameter names
4. Use async requests to parallelize

## Testing the Feature

### Manual Test
```bash
1. Add custom payload via UI:
   Category: SQL Injection
   Payload: ' UNION SELECT NULL,NULL,NULL--

2. Run Active Scan on endpoint:
   POST /api/scan/active
   URL: http://localhost:8998/api/test?id=1

3. Check proxy logs for:
   [PayloadInjector] Testing 1 parameters with 10 payloads
   [Scanner Engine] Found X SQL Injection findings

4. Check debug stats:
   GET /api/debug/payload/statistics

5. View results in dashboard
```

### Debug Output Example
```
[Scanner Engine] Starting active payload injection testing...
[Scanner Engine] Testing SQL Injection payloads...
[PayloadInjector] Testing 3 parameters with 10 payloads
[DB] get_top_payloads() called: category='SQL Injection', limit=10
[DB] Returned 10 vulnerable payloads for category 'SQL Injection'
[PayloadInjector] ✓ Found vulnerability: SQL Injection detected in parameter "id"
[Scanner Engine] Found 1 SQL Injection findings
```

## Future Enhancements

1. **Async Payload Injection**
   - Parallelize injection testing
   - Reduce scan time significantly

2. **Smart Parameter Selection**
   - Prioritize likely injection points
   - Skip obviously safe parameters

3. **Context-Aware Payloads**
   - Use different payloads for different parameter types
   - Image upload: file upload payloads
   - Email: blind SQL injection payloads

4. **Payload Mutation**
   - Auto-generate payload variants
   - Bypass WAF/IDS signatures

5. **Machine Learning Integration**
   - Learn from successful payloads
   - Predict most likely injection type per parameter
   - Adjust testing order based on success rates
