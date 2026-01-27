# 🔄 Penjelasan Main System Flowchart - MoodleSec

## 📌 Overview

**Main System Flowchart** menggambarkan alur kerja lengkap sistem MoodleSec dari **request masuk** hingga **adaptive mitigation response**. Sistem ini beroperasi sebagai **reverse proxy** yang berada di antara user dan Moodle LMS.

---

## 🎯 Arsitektur High-Level

```
┌──────────────────────────────────────────────────────────────────┐
│                     MOODLESEC MAIN SYSTEM                        │
│                   (Adaptive Security Proxy)                      │
└──────────────────────────────────────────────────────────────────┘
                              │
          ┌───────────────────┼───────────────────┐
          │                   │                   │
     [1] REQUEST          [2] PROXY          [3] RESPONSE
      INCOMING            FORWARDING          PROCESSING
          │                   │                   │
          ▼                   ▼                   ▼
   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
   │   Client    │───▶│  MoodleSec  │───▶│   Moodle    │
   │   Browser   │    │    Proxy    │    │   Server    │
   └─────────────┘    └─────────────┘    └─────────────┘
                             │
                             │ [4] ANALYSIS
                             ▼
                      ┌──────────────┐
                      │  Scanning &  │
                      │  ML Pipeline │
                      └──────────────┘
                             │
                             │ [5] DECISION
                             ▼
                      ┌──────────────┐
                      │  Adaptive    │
                      │  Mitigation  │
                      └──────────────┘
```

---

## 🔄 Alur Kerja Lengkap (Step-by-Step)

### **FASE 1: REQUEST INCOMING (Entry Point)**

```
┌─────────────────────────────────────────────────────────────┐
│ STEP 1: Client Request Arrives                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Browser/App Request                                        │
│  ↓                                                          │
│  GET https://moodle.test:8999/login/index.php              │
│  Host: moodle.test                                          │
│  User-Agent: Mozilla/5.0...                                 │
│  Cookie: MoodleSession=abc123                               │
│                                                             │
│  ↓                                                          │
│  [INTERCEPT BY MOODLESEC PROXY - PORT 8999]                │
│                                                             │
│  FastAPI Endpoint: @app.api_route("/{full_path:path}")     │
│  ↓                                                          │
│  Log Request:                                               │
│    • Timestamp                                              │
│    • Method (GET/POST/PUT/DELETE)                           │
│    • URL Path                                               │
│    • Headers                                                │
│    • Query Parameters                                       │
│    • Client IP                                              │
│    • Session Info                                           │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**File:** `proxy/app.py` - Line 1231-1606

**Code:**
```python
@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
async def proxy_request(full_path: str, request: Request):
    """Main proxy handler untuk semua requests."""
    
    # Step 1.1: Log incoming request
    request_log = {
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "method": request.method,
        "path": f"/{full_path}",
        "client_ip": request.client.host,
        "user_agent": request.headers.get("user-agent", "Unknown")
    }
    
    # Step 1.2: Phishing Detection (URL validation)
    is_phishing, reason = phishing_detector.is_phishing_url(f"/{full_path}")
    if is_phishing:
        return Response(
            status_code=403,
            content=f"Blocked: Suspected phishing - {reason}"
        )
    
    # Continue to FASE 2...
```

---

### **FASE 2: PROXY FORWARDING**

```
┌─────────────────────────────────────────────────────────────┐
│ STEP 2: Forward Request to Moodle Backend                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  MoodleSec Proxy (PORT 8999)                                │
│  ↓                                                          │
│  Build Target URL:                                          │
│    http://localhost:8998/login/index.php                    │
│    (MOODLE_URL from config.py)                              │
│                                                             │
│  ↓                                                          │
│  Copy Headers & Parameters:                                 │
│    • Preserve original headers                              │
│    • Add X-Forwarded-For                                    │
│    • Add X-Real-IP                                          │
│    • Maintain session cookies                               │
│                                                             │
│  ↓                                                          │
│  Send Request via HTTPX:                                    │
│    async with httpx.AsyncClient() as client:                │
│      response = await client.request(...)                   │
│                                                             │
│  ↓                                                          │
│  Wait for Moodle Response                                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Code:**
```python
# Step 2.1: Build target URL
target_url = f"{MOODLE_URL}/{full_path}"
if request.url.query:
    target_url += f"?{request.url.query}"

# Step 2.2: Prepare headers
headers = dict(request.headers)
headers.pop("host", None)  # Remove proxy host
headers["X-Forwarded-For"] = request.client.host
headers["X-Real-IP"] = request.client.host

# Step 2.3: Forward request to Moodle
async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
    try:
        # Read request body
        body = await request.body()
        
        # Send to Moodle backend
        moodle_response = await client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body
        )
        
    except httpx.RequestError as e:
        return Response(
            status_code=502,
            content=f"Bad Gateway: {str(e)}"
        )
```

---

### **FASE 3: RESPONSE PROCESSING**

```
┌─────────────────────────────────────────────────────────────┐
│ STEP 3: Process Moodle Response                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Moodle Response Received                                   │
│  ↓                                                          │
│  Status Code: 200 OK                                        │
│  Headers: Content-Type, Set-Cookie, etc.                    │
│  Body: HTML/JSON content                                    │
│                                                             │
│  ↓                                                          │
│  Log Response:                                              │
│    • Status code                                            │
│    • Response time (ms)                                     │
│    • Response size (bytes)                                  │
│    • Content type                                           │
│                                                             │
│  ↓                                                          │
│  Pattern Analysis:                                          │
│    • Check for error messages                               │
│    • Detect SQL error patterns                              │
│    • Identify stack traces                                  │
│    • Look for sensitive info disclosure                     │
│                                                             │
│  ↓                                                          │
│  Decision: Should we scan this endpoint?                    │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Code:**
```python
# Step 3.1: Log response metadata
response_time = (datetime.utcnow() - start_time).total_seconds() * 1000
response_log = {
    "status_code": moodle_response.status_code,
    "response_time_ms": response_time,
    "content_length": len(moodle_response.content),
    "content_type": moodle_response.headers.get("content-type", "")
}

# Step 3.2: Pattern-based quick detection
suspicious_patterns = [
    b"SQL syntax error",
    b"mysql_",
    b"PDOException",
    b"Fatal error:",
    b"Warning:",
    b"Notice:",
    b"Stack trace"
]

is_suspicious = any(pattern in moodle_response.content for pattern in suspicious_patterns)

# Step 3.3: Decide if full scan needed
should_scan = (
    moodle_response.status_code >= 400 or  # Error responses
    is_suspicious or                        # Suspicious patterns
    request.method in ["POST", "PUT"] or   # Mutations
    "login" in full_path or                # Auth endpoints
    "admin" in full_path                   # Admin endpoints
)
```

---

### **FASE 4: SECURITY ANALYSIS (Conditional)**

```
┌──────────────────────────────────────────────────────────────────┐
│ STEP 4: Multi-Layer Security Scanning                           │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  IF should_scan == True:                                         │
│  ↓                                                               │
│  ┌────────────────────────────────────────────────────────┐     │
│  │ LAYER 1: Passive Scanning (Response Analysis)          │     │
│  ├────────────────────────────────────────────────────────┤     │
│  │  • SQL Injection Scanner                                │     │
│  │    - Error-based detection                              │     │
│  │    - Blind SQL injection patterns                       │     │
│  │  • XSS Scanner                                          │     │
│  │    - Reflected XSS detection                            │     │
│  │    - Stored XSS indicators                              │     │
│  │  • Security Headers Scanner                             │     │
│  │    - Missing CSP, HSTS, X-Frame-Options                 │     │
│  │  • Information Disclosure Scanner                       │     │
│  │    - Version disclosure                                 │     │
│  │    - Stack trace exposure                               │     │
│  └────────────────────────────────────────────────────────┘     │
│  ↓                                                               │
│  ┌────────────────────────────────────────────────────────┐     │
│  │ LAYER 2: Active Scanning (Optional - Background)       │     │
│  ├────────────────────────────────────────────────────────┤     │
│  │  • OWASP ZAP Integration                                │     │
│  │    - Full DAST scan                                     │     │
│  │    - Spider crawling                                    │     │
│  │  • Custom Attack Modules                                │     │
│  │    - CSRF testing                                       │     │
│  │    - Path traversal                                     │     │
│  │    - Authentication bypass                              │     │
│  └────────────────────────────────────────────────────────┘     │
│  ↓                                                               │
│  ┌────────────────────────────────────────────────────────┐     │
│  │ LAYER 3: CVSS Risk Scoring                             │     │
│  ├────────────────────────────────────────────────────────┤     │
│  │  For each finding:                                      │     │
│  │    • Calculate Base Score                               │     │
│  │      - Attack Vector (Network/Adjacent/Local)           │     │
│  │      - Attack Complexity (Low/High)                     │     │
│  │      - Privileges Required (None/Low/High)              │     │
│  │      - User Interaction (None/Required)                 │     │
│  │      - Scope (Unchanged/Changed)                        │     │
│  │      - Impact (C/I/A: None/Low/High)                    │     │
│  │    • Calculate Temporal Score                           │     │
│  │    • Calculate Environmental Score                      │     │
│  │    • Final CVSS Score: 0.0 - 10.0                       │     │
│  └────────────────────────────────────────────────────────┘     │
│  ↓                                                               │
│  ┌────────────────────────────────────────────────────────┐     │
│  │ LAYER 4: Machine Learning Filtering                    │     │
│  ├────────────────────────────────────────────────────────┤     │
│  │  For each finding:                                      │     │
│  │    ┌──────────────────────────────────────┐            │     │
│  │    │ ML Model 1: False Positive Reducer   │            │     │
│  │    ├──────────────────────────────────────┤            │     │
│  │    │ • Extract 16 features                 │            │     │
│  │    │ • Predict: True Positive or False Pos│            │     │
│  │    │ • Confidence: 0.0 - 1.0               │            │     │
│  │    │ • Decision: KEEP if TP, FILTER if FP  │            │     │
│  │    └──────────────────────────────────────┘            │     │
│  │    ↓                                                    │     │
│  │    ┌──────────────────────────────────────┐            │     │
│  │    │ ML Model 2: Severity Predictor       │            │     │
│  │    ├──────────────────────────────────────┤            │     │
│  │    │ • Extract 8 features                  │            │     │
│  │    │ • Predict: Critical/High/Med/Low/Info │            │     │
│  │    │ • Adjust severity if needed           │            │     │
│  │    └──────────────────────────────────────┘            │     │
│  │    ↓                                                    │     │
│  │    ┌──────────────────────────────────────┐            │     │
│  │    │ ML Model 3: Anomaly Detector         │            │     │
│  │    ├──────────────────────────────────────┤            │     │
│  │    │ • Check request pattern               │            │     │
│  │    │ • Isolation Forest scoring            │            │     │
│  │    │ • Flag if anomalous                   │            │     │
│  │    └──────────────────────────────────────┘            │     │
│  │    ↓                                                    │     │
│  │    ┌──────────────────────────────────────┐            │     │
│  │    │ ML Model 4: Rate Limiter              │            │     │
│  │    ├──────────────────────────────────────┤            │     │
│  │    │ • Calculate risk score 0.0-1.0        │            │     │
│  │    │ • Recommend rate limit action         │            │     │
│  │    └──────────────────────────────────────┘            │     │
│  └────────────────────────────────────────────────────────┘     │
│  ↓                                                               │
│  Filtered Findings (only True Positives)                        │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

**Code:**
```python
# Step 4.1: Passive scanning
findings = []
if should_scan:
    # SQL Injection detection
    sql_results = scanner_engine.scan_sql_injection(
        target_url, 
        method=request.method,
        response_content=moodle_response.content
    )
    findings.extend(sql_results)
    
    # XSS detection
    xss_results = scanner_engine.scan_xss(target_url, moodle_response.content)
    findings.extend(xss_results)
    
    # Security headers
    header_results = scanner_engine.scan_security_headers(moodle_response.headers)
    findings.extend(header_results)

# Step 4.2: CVSS scoring
for finding in findings:
    cvss_score = risk_scorer.calculate_cvss(
        attack_vector=finding.get('attack_vector', 'network'),
        attack_complexity=finding.get('complexity', 'low'),
        privileges_required=finding.get('privileges', 'none'),
        user_interaction=finding.get('user_interaction', 'none'),
        scope=finding.get('scope', 'unchanged'),
        confidentiality_impact=finding.get('c_impact', 'high'),
        integrity_impact=finding.get('i_impact', 'high'),
        availability_impact=finding.get('a_impact', 'none')
    )
    finding['cvss_score'] = cvss_score

# Step 4.3: ML Filtering
filtered_findings = []
for finding in findings:
    # False Positive Reducer
    is_fp, confidence = ml_manager.classify_finding(finding, context={
        'status_code': moodle_response.status_code,
        'response_time': response_time
    })
    
    if not is_fp or confidence < 0.85:
        # Keep this finding (likely True Positive)
        
        # Severity Predictor
        predicted_severity = ml_manager.predict_severity(finding)
        finding['ml_severity'] = predicted_severity
        
        filtered_findings.append(finding)
```

---

### **FASE 5: ADAPTIVE MITIGATION DECISION**

```
┌──────────────────────────────────────────────────────────────────┐
│ STEP 5: Risk-Based Adaptive Response                            │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Decision Tree Based on CVSS Score:                              │
│                                                                  │
│  ┌────────────────────────────────────────┐                     │
│  │ CVSS: 9.0 - 10.0 (CRITICAL)            │                     │
│  ├────────────────────────────────────────┤                     │
│  │ Action: BLOCK + ALERT + ISOLATE        │                     │
│  │  • Block request immediately            │                     │
│  │  • Send Slack critical alert            │                     │
│  │  • Create Jira ticket (P1)              │                     │
│  │  • Isolate endpoint (WAF rule)          │                     │
│  │  • Generate incident report             │                     │
│  │  • Notify security team                 │                     │
│  └────────────────────────────────────────┘                     │
│  ↓                                                               │
│  ┌────────────────────────────────────────┐                     │
│  │ CVSS: 7.0 - 8.9 (HIGH)                 │                     │
│  ├────────────────────────────────────────┤                     │
│  │ Action: WARN + LOG + MONITOR           │                     │
│  │  • Allow request (with warning header)  │                     │
│  │  • Log detailed information             │                     │
│  │  • Send Slack warning notification      │                     │
│  │  • Create Jira ticket (P2)              │                     │
│  │  • Increase monitoring for endpoint     │                     │
│  │  • Add to watchlist                     │                     │
│  └────────────────────────────────────────┘                     │
│  ↓                                                               │
│  ┌────────────────────────────────────────┐                     │
│  │ CVSS: 4.0 - 6.9 (MEDIUM)               │                     │
│  ├────────────────────────────────────────┤                     │
│  │ Action: LOG + SCHEDULE_REVIEW          │                     │
│  │  • Allow request normally               │                     │
│  │  • Log finding                          │                     │
│  │  • Add to weekly review queue           │                     │
│  │  • No immediate notification            │                     │
│  └────────────────────────────────────────┘                     │
│  ↓                                                               │
│  ┌────────────────────────────────────────┐                     │
│  │ CVSS: 0.1 - 3.9 (LOW/INFO)             │                     │
│  ├────────────────────────────────────────┤                     │
│  │ Action: LOG_ONLY                        │                     │
│  │  • Allow request normally               │                     │
│  │  • Log for analytics                    │                     │
│  │  • No action required                   │                     │
│  └────────────────────────────────────────┘                     │
│                                                                  │
│  Additional Factors:                                             │
│  • Request frequency (rate limiting)                             │
│  • User role (admin vs student)                                  │
│  • Time of day (business hours vs off-hours)                     │
│  • Geographic location                                           │
│  • Historical behavior pattern                                   │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

**Code:**
```python
# Step 5.1: Aggregate risk score
if filtered_findings:
    # Get highest CVSS score
    max_cvss = max(f.get('cvss_score', 0.0) for f in filtered_findings)
    
    # Step 5.2: Adaptive decision
    if max_cvss >= 9.0:
        # CRITICAL - Block and alert
        
        # Send Slack alert
        if slack_notifier:
            await slack_notifier.send_critical_alert(
                title=f"🚨 CRITICAL Vulnerability Detected",
                url=target_url,
                cvss_score=max_cvss,
                findings=filtered_findings
            )
        
        # Create ticket
        ticket_id = await integration_manager.create_jira_ticket(
            summary=f"Critical vulnerability in {full_path}",
            severity="Critical",
            cvss_score=max_cvss,
            findings=filtered_findings
        )
        
        # Block response
        return Response(
            status_code=403,
            content="Access denied: Critical security vulnerability detected",
            headers={"X-MoodleSec-Block-Reason": "Critical vulnerability"}
        )
    
    elif max_cvss >= 7.0:
        # HIGH - Warn and log
        
        # Send warning notification
        if slack_notifier:
            await slack_notifier.send_warning(
                title=f"⚠️ High Severity Finding",
                url=target_url,
                cvss_score=max_cvss
            )
        
        # Add warning header but allow request
        response_headers = dict(moodle_response.headers)
        response_headers["X-MoodleSec-Warning"] = f"High risk: CVSS {max_cvss:.1f}"
        
    elif max_cvss >= 4.0:
        # MEDIUM - Log only
        scan_history_db.save_scan(
            target_url=target_url,
            findings=filtered_findings,
            severity="medium"
        )
    
    else:
        # LOW/INFO - Minimal logging
        pass

# Step 5.3: Return response to client
return Response(
    status_code=moodle_response.status_code,
    content=moodle_response.content,
    headers=response_headers
)
```

---

## 📊 Complete Flow Diagram (Text Version)

```
┌─────────────────────────────────────────────────────────────────────┐
│                      MOODLESEC MAIN SYSTEM FLOW                     │
└─────────────────────────────────────────────────────────────────────┘

[START] Client Request
   │
   ▼
┌──────────────────────┐
│  1. REQUEST ENTRY    │
│  FastAPI @app.route  │
└──────────────────────┘
   │
   ├─── Log: Timestamp, Method, Path, IP, Headers
   │
   ├─── Phishing Check ───[BLOCKED?]──▶ [403 FORBIDDEN]
   │                          │
   │                          └─[PASS]
   ▼
┌──────────────────────┐
│  2. PROXY FORWARD    │
│  httpx.request()     │
└──────────────────────┘
   │
   ├─── Build: target_url = MOODLE_URL + path
   ├─── Copy: headers, cookies, body
   ├─── Send: async request to Moodle
   │
   ▼
┌──────────────────────┐
│  3. MOODLE RESPONSE  │
│  Status + Content    │
└──────────────────────┘
   │
   ├─── Log: Status, Response Time, Size
   ├─── Pattern Check: SQL errors, stack traces
   │
   ├─── Decision: should_scan?
   │       │
   │       ├─[NO]──▶ Return response immediately
   │       │
   │       └─[YES]
   │           ▼
   │   ┌────────────────────────┐
   │   │  4. SECURITY ANALYSIS  │
   │   └────────────────────────┘
   │           │
   │           ├─── Layer 1: Passive Scan (SQL, XSS, Headers)
   │           ├─── Layer 2: Active Scan (ZAP - background)
   │           ├─── Layer 3: CVSS Scoring (0.0-10.0)
   │           └─── Layer 4: ML Filtering
   │                   │
   │                   ├─ ML 1: False Positive Reducer (95% acc)
   │                   ├─ ML 2: Severity Predictor (85% acc)
   │                   ├─ ML 3: Anomaly Detector (89% detection)
   │                   └─ ML 4: Rate Limiter (R²=0.72)
   │                       │
   │                       ▼
   │               Filtered Findings (TP only)
   │                       │
   │                       ▼
   │           ┌────────────────────────┐
   │           │  5. ADAPTIVE DECISION  │
   │           └────────────────────────┘
   │                       │
   │                       ├─[CVSS ≥ 9.0]─▶ BLOCK + ALERT + TICKET
   │                       │                     │
   │                       │                     ├─ Slack Critical Alert
   │                       │                     ├─ Jira P1 Ticket
   │                       │                     ├─ WAF Rule Update
   │                       │                     └─ Return 403
   │                       │
   │                       ├─[CVSS 7.0-8.9]─▶ WARN + LOG + NOTIFY
   │                       │                     │
   │                       │                     ├─ Slack Warning
   │                       │                     ├─ Jira P2 Ticket
   │                       │                     ├─ Add X-Warning Header
   │                       │                     └─ Return response
   │                       │
   │                       ├─[CVSS 4.0-6.9]─▶ LOG + QUEUE REVIEW
   │                       │                     │
   │                       │                     ├─ Save to database
   │                       │                     └─ Return response
   │                       │
   │                       └─[CVSS < 4.0]─▶ LOG_MINIMAL
   │                                             │
   │                                             └─ Return response
   │
   ▼
┌──────────────────────┐
│  6. RESPONSE RETURN  │
│  Back to Client      │
└──────────────────────┘
   │
   ├─── Headers: Original + Security headers
   ├─── Body: Original content
   ├─── Status: Original or modified (403 if blocked)
   │
   ▼
[END] Client receives response
```

---

## 🎯 Key Components Explained

### **1. FastAPI Reverse Proxy**
- **Port:** 8999 (MoodleSec Proxy)
- **Backend:** 8998 (Moodle LMS)
- **Technology:** FastAPI + httpx async client
- **Function:** Intercept semua traffic, transparently forward to Moodle

### **2. Scanner Engine**
- **Passive Scanners:** 6+ custom modules (SQL, XSS, CSRF, Headers, etc.)
- **Active Scanner:** OWASP ZAP integration (background)
- **Speed:** Passive < 50ms, Active 2-30 seconds

### **3. CVSS Risk Scorer**
- **Standard:** CVSS v3.1
- **Input:** Vulnerability characteristics (AV, AC, PR, UI, S, CIA)
- **Output:** Score 0.0-10.0 + severity label
- **Use:** Trigger adaptive mitigation

### **4. ML Pipeline**
- **4 Models:** FP Reducer, Severity Predictor, Anomaly Detector, Rate Limiter
- **Purpose:** Reduce false positives from 60% to <10%
- **Performance:** 95% accuracy (ensemble RF+GB)
- **Features:** 16 features for FP Reducer (keyword ratio, CVSS, severity, etc.)

### **5. Adaptive Mitigation**
- **BLOCK:** CVSS ≥ 9.0 (Critical)
- **WARN:** CVSS 7.0-8.9 (High)
- **LOG:** CVSS 4.0-6.9 (Medium)
- **INFO:** CVSS < 4.0 (Low)

### **6. Integration Layer**
- **Slack:** Real-time notifications
- **Jira:** Automated ticket creation
- **Webhook:** Custom integrations
- **Database:** Scan history, trends, regression detection

---

## 📈 Performance Metrics

| Metric | Value | Description |
|--------|-------|-------------|
| **Proxy Latency** | <10ms | Added delay for passthrough |
| **Passive Scan** | 30-50ms | SQL, XSS, Headers checking |
| **ML Inference** | 5-15ms | All 4 models combined |
| **Total Overhead** | 45-75ms | For scanned requests |
| **Throughput** | 1000+ req/s | Concurrent handling capacity |
| **False Positive Rate** | <10% | After ML filtering |
| **Detection Rate** | >95% | True vulnerabilities caught |

---

## 🔐 Security Features

### **Defense in Depth (6 Layers)**
1. **Phishing Detection** → URL validation
2. **Passive Scanning** → Response analysis
3. **Active Scanning** → OWASP ZAP (background)
4. **CVSS Scoring** → Standardized risk assessment
5. **ML Filtering** → False positive reduction
6. **Adaptive Mitigation** → Risk-based response

### **Logging & Audit**
- All requests logged (timestamp, method, path, IP)
- All findings logged (severity, CVSS, evidence)
- Scan history stored in SQLite database
- Trend analysis (daily/weekly/monthly)
- Regression detection (comparing scans)

### **Notification Channels**
- **Critical:** Slack + Jira + Email
- **High:** Slack + Jira
- **Medium:** Database log + weekly report
- **Low:** Database log only

---

## 📚 Untuk Sempro (3-4 menit explanation)

**Script:**

> "Main System Flowchart MoodleSec menggambarkan 6 fase utama:
> 
> **FASE 1 - Request Entry:** Client request masuk ke proxy port 8999, dilakukan logging dan phishing detection. Jika terdeteksi phishing, langsung di-block dengan 403.
> 
> **FASE 2 - Proxy Forwarding:** Request yang aman di-forward ke Moodle backend di port 8998 menggunakan httpx async client. Headers dan cookies di-preserve agar session tetap berjalan normal.
> 
> **FASE 3 - Response Processing:** Response dari Moodle di-analyze untuk pattern suspicious seperti SQL error, stack trace, atau information disclosure. Decision engine menentukan apakah endpoint ini perlu di-scan lebih dalam.
> 
> **FASE 4 - Security Analysis:** Jika perlu scan, masuk ke 4-layer analysis. Layer 1 passive scanning untuk SQL injection, XSS, security headers. Layer 2 active scanning dengan OWASP ZAP di background. Layer 3 CVSS scoring untuk setiap finding. Layer 4 ML filtering dengan 4 models - False Positive Reducer untuk filter false positive dengan 95% accuracy, Severity Predictor untuk adjust severity level, Anomaly Detector untuk pattern anomali, dan Rate Limiter untuk risk scoring.
> 
> **FASE 5 - Adaptive Decision:** Berdasarkan CVSS score tertinggi, sistem ambil keputusan adaptif. CVSS ≥ 9.0 Critical di-BLOCK langsung plus Slack alert dan Jira P1 ticket. CVSS 7.0-8.9 High di-WARN dengan notification tapi request tetap di-allow. CVSS 4.0-6.9 Medium cukup di-LOG untuk review mingguan. CVSS < 4.0 Low minimal logging.
> 
> **FASE 6 - Response Return:** Response dikembalikan ke client dengan security headers tambahan dan X-MoodleSec-Warning header jika ada risk tinggi.
> 
> Keseluruhan proses ini berjalan dengan overhead latency < 75ms untuk request yang di-scan, sehingga user experience tidak terganggu tapi security tetap terjaga dengan defense-in-depth 6 layer protection."

**Waktu: ~3 menit**

---

**Good luck untuk sempro! 🚀**
