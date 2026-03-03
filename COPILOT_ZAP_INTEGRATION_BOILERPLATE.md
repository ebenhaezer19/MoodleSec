# 🤖 COPILOT ZAP INTEGRATION BOILERPLATE
**Purpose:** Template prompts to generate production-ready ZAP integration code  
**Date Created:** 3 March 2026  
**Status:** Ready to use with Copilot

---

## 📋 HOW TO USE THIS GUIDE

1. **Prerequisite:** Open Copilot in VS Code or browser
2. **For each section:** 
   - Copy the prompt between `<!-- START -->` and `<!-- END -->`
   - Paste into Copilot chat
   - Wait for code generation
   - Review and refine if needed
3. **Integration:** Files will be created in `MoodleSec/ml/zap_integration/` directory
4. **Timeline:** ~30-45 mins total (5-10 mins per prompt)

---

## PART 1️⃣: ZAP API CLIENT (Basic Foundation)

<!-- START PROMPT 1 -->

```
Generate a production-ready Python class ZAPClient for OWASP ZAP API integration with these exact requirements:

## 1. CLASS STRUCTURE:
- Class name: ZAPClient
- Constructor parameters: host="localhost", port=8080, api_key=""
- Instance attributes: base_url, session, logger, retry_config, timeout=30
- Module imports: requests, logging, time, Dict, List, Optional from typing

## 2. CORE METHODS TO IMPLEMENT:

### a) Connection & Initialization:
- __init__(host, port, api_key) → Initialize session, validate ZAP connection
- _validate_connection() → Test ZAP API availability
- set_timeout(seconds) → Update request timeout
- get_status() → Return {"status": "connected", "version": "X.X.X"}

### b) Generic HTTP Request Wrapper:
- request(method, endpoint, params=None, data=None, retry_count=3)
  → Generic HTTP with automatic retry
  → Returns parsed JSON response
  → Raises ZAPConnectionError, ZAPTimeoutError on failure
  → Implement exponential backoff: 1s, 2s, 4s between retries

### c) Basic API Operations:
- get_version() → {"version": "2.X.X"}
- new_session(session_name: str) → Create new scan session
- save_session(session_name: str) → Save current session
- load_session(session_name: str) → Load existing session
- list_sessions() → List all available sessions

## 3. ERROR HANDLING:

Define custom exceptions:
- class ZAPConnectionError(Exception)
- class ZAPTimeoutError(Exception)
- class ZAPConfigError(Exception)

Parameter validation:
- Validate host/port before connection
- Validate api_key format if provided
- Raise ZAPConfigError for invalid params

Retry logic:
- Exponential backoff: base_delay = 1s, multiplier = 2
- Max retries: 3 (configurable)
- Log each retry attempt at DEBUG level
- Final failure raises exception with full context

## 4. LOGGING:

- Create logger with name: "ZAPClient"
- DEBUG: All HTTP requests/responses
- INFO: Session operations
- ERROR: Connection failures, retries exhausted
- Include timestamps and operation details

## 5. TYPE HINTS & DOCUMENTATION:

- Add type hints for all parameters and returns (Python 3.9+)
- Google-style docstrings for all methods
- Example docstring:
  ```
  def request(self, method: str, endpoint: str, params: Optional[Dict] = None) -> Dict:
      """Make HTTP request to ZAP API with automatic retry.
      
      Args:
          method: HTTP method (GET, POST, etc)
          endpoint: ZAP API endpoint (e.g., "core/other/version")
          params: Query parameters or request body
          
      Returns:
          Parsed JSON response from ZAP
          
      Raises:
          ZAPConnectionError: If connection fails after retries
          ZAPTimeoutError: If request exceeds timeout
      """
  ```

## 6. IMPLEMENTATION NOTES:

- Use requests.Session() for connection pooling
- Set default headers: {"Content-Type": "application/json"}
- All API endpoints should be accessed via self.request() method
- Include connection validation during __init__

Generate complete, production-ready code with full error handling and logging.
```

<!-- END PROMPT 1 -->

**Expected Output:** `zap_client.py` (300-400 lines)

**Verification Checklist:**
- ✅ ZAPClient class with all methods
- ✅ 3 custom exceptions defined
- ✅ Retry logic with exponential backoff
- ✅ Logging at DEBUG/INFO/ERROR levels
- ✅ Type hints for all parameters
- ✅ Google-style docstrings

**Next:** After receiving code, save as `MoodleSec/ml/zap_integration/zap_client.py`

---

## PART 2️⃣: AUTHENTICATION HANDLER (Login Management)

<!-- START PROMPT 2 -->

```
Generate ZAPAuthenticationHandler class for managing Moodle login workflow:

## 1. PURPOSE:
- Orchestrate login process (form detection, credential submission, verification)
- Store session tokens for authenticated scanning
- Verify login success before starting scans
- Handle authentication failures gracefully

## 2. CLASS STRUCTURE:
- Name: ZAPAuthenticationHandler
- Constructor: __init__(client: ZAPClient, database_connection=None)
- Dependencies: Use ZAPClient class from previous prompt

## 3. METHODS TO IMPLEMENT:

### a) Authentication Configuration:
- setup_form_auth(context_id: int, login_url: str, username_field: str, password_field: str, extra_fields: Dict = None) -> bool
  → Configure login form fields in ZAP context
  → Parameter names match HTML form field names
  → Return True if successful

- setup_form_based_auth(context_id: int, login_url: str, username: str, password: str) -> bool
  → Full setup: create user, set form fields, verify credentials
  → Return True if login successful

### b) Login Execution:
- execute_login(login_url: str, username: str, password: str, extra_fields: Dict = None) -> (requests.Response, Dict[str, str])
  → Send HTTP POST request to login endpoint
  → Handle cookies and session tokens
  → Return (response, cookies_dict)
  → Raise ZAPAuthError if login fails

### c) Login Verification:
- verify_login(response_text: str, verification_string: str, response_status: int) -> (bool, str)
  → Check if login was successful
  → Verification methods:
    - Status code 200-299 (success)
    - Presence of verification_string in response body
    - Absence of "login" keyword in response
  → Return (success: bool, message: str)

### d) Session Token Management:
- store_session_token(user_id: str, cookie_name: str, cookie_value: str, expires_at: Optional[str] = None) -> bool
  → Save to database (if database provided) or in-memory dict
  → Format: {user_id: {cookie_name: {value, expires_at}}}
  → Log storage action

- retrieve_session_token(user_id: str) -> (Dict[str, str], bool)
  → Retrieve stored cookies/tokens
  → Check if expired
  → Return (token_dict, is_valid: bool)

- clear_expired_tokens() -> int
  → Remove expired tokens
  → Return count removed

### e) User Creation in ZAP Context:
- create_context_user(client: ZAPClient, context_id: int, user_id: str, username: str, password: str) -> bool
  → Create user account in ZAP context
  → Set up credentials for authenticated scanning
  → Return True if successful

## 4. ERROR HANDLING:

Define exceptions:
- class ZAPAuthError(Exception) → Generic auth failure
- class ZAPLoginVerificationError(Exception) → Verification failed
- class ZAPSessionExpiredError(Exception) → Token expired

Error scenarios:
- Invalid credentials → Raise ZAPAuthError
- Non-200 response → Raise ZAPAuthError
- Verification string not found → Raise ZAPLoginVerificationError
- Database write failure → Log error, fallback to in-memory
- Connection timeout → Raise ZAPAuthError with retry suggestion

## 5. LOGGING:

- Logger name: "ZAPAuthenticationHandler"
- DEBUG: Form field names, request bodies (without passwords!)
- INFO: Login attempts, verification results
- ERROR: Login failures, token expiration
- IMPORTANT: Never log passwords or tokens in full

## 6. IMPLEMENTATION NOTES:

- Use ZAPClient.request() for API calls to ZAP
- Store credentials securely (do NOT log or save plaintext)
- Handle both form-based and API-based authentication
- Support MoodleCloud and self-hosted Moodle versions
- Implement timeout: 10 seconds for login request
- Thread-safe token storage for concurrent scans

Generate complete class with full error handling and security best practices.
```

<!-- END PROMPT 2 -->

**Expected Output:** `zap_auth_handler.py` (250-350 lines)

**Verification Checklist:**
- ✅ setup_form_auth() and setup_form_based_auth() methods
- ✅ execute_login() with response handling
- ✅ verify_login() with multiple verification methods
- ✅ Token storage (database + in-memory fallback)
- ✅ 3 custom exceptions defined
- ✅ Never logs passwords
- ✅ Docstrings for all methods

**Next:** Save as `MoodleSec/ml/zap_integration/zap_auth_handler.py`

---

## PART 3️⃣: SPIDER MANAGER (Page Discovery)

<!-- START PROMPT 3 -->

```
Generate ZAPSpiderManager class for orchestrating page discovery phase:

## 1. PURPOSE:
- Start and monitor spider/crawler operations
- Track discovered URLs and pages
- Handle timeout and completion scenarios
- Provide progress updates to calling code

## 2. CLASS STRUCTURE:
- Name: ZAPSpiderManager
- Constructor: __init__(client: ZAPClient)
- Dependencies: Use ZAPClient from Prompt 1

## 3. METHODS TO IMPLEMENT:

### a) Spider Initiation:
- start_spider(url: str, context_id: Optional[int] = None, depth: int = 3, max_children: int = 0) -> (str, float)
  → Start spider on target URL
  → Parameters:
    - url: Target URL to spider
    - context_id: ZAP context ID (optional)
    - depth: Maximum recursion depth (default 3)
    - max_children: Max child nodes (0 = unlimited)
  → Return (scan_id: str, start_time: float)
  → Raise ZAPSpiderError if spider fails to start

### b) Progress Monitoring:
- get_progress(scan_id: str) -> Dict[str, any]
  → Query ZAP for spider progress
  → Return {
      "progress": int (0-100),
      "pages_found": int,
      "status": str ("Running" / "Stopped"),
      "current_url": str,
      "id": str
    }

- wait_for_completion(scan_id: str, timeout_minutes: int = 30, poll_interval: int = 5) -> (bool, List[str], float)
  → Block until spider completes or timeout
  → Poll every poll_interval seconds
  → Parameters:
    - timeout_minutes: Max wait time (default 30)
    - poll_interval: Seconds between status checks (default 5)
  → Return (success: bool, discovered_urls: List[str], duration_seconds: float)
  → Raise ZAPTimeoutError if timeout exceeded

### c) Results Collection:
- get_discovered_urls(scan_id: str) -> List[str]
  → Fetch all discovered URLs from spider
  → Filter duplicates
  → Return sorted list
  → Raise ZAPSpiderError if scan not found

- get_spider_status(scan_id: str) -> Dict
  → Get detailed spider status
  → Return {
      "id": str,
      "progress": int,
      "status": str,
      "pages_found": int,
      "start_time": str,
      "issues": List[str]  // Any errors encountered
    }

### d) Spider Control:
- stop_spider(scan_id: str) -> bool
  → Stop active spider
  → Return True if stopped successf ully
  → Log action at INFO level

- pause_spider(scan_id: str) -> bool
  → Pause (not stop) spider
  → Return True if paused

- resume_spider(scan_id: str) -> bool
  → Resume paused spider
  → Return True if resumed

## 4. PROGRESS TRACKING:

Implement progress callback mechanism:
- progress_callback: Optional[Callable[[Dict], None]]
  → User can provide callback function
  → Called every poll cycle with progress dict
  → Use for UI updates or logging

Example usage:
```python
def on_progress(progress):
    print(f"Spider progress: {progress['progress']}% ({progress['pages_found']} pages)")

manager.wait_for_completion(scan_id, progress_callback=on_progress)
```

## 5. ERROR HANDLING:

Define exceptions:
- class ZAPSpiderError(Exception)
- class ZAPSpiderTimeoutError(Exception)

Error scenarios:
- Spider fails to start → Raise ZAPSpiderError
- Invalid scan_id → Raise ZAPSpiderError
- Timeout exceeded → Raise ZAPSpiderTimeoutError
- Connection lost during polling → Retry with exponential backoff
- Empty results → Return empty list (not error)

## 6. LOGGING:

- Logger name: "ZAPSpiderManager"
- DEBUG: Polling attempts, progress updates, URL discovery
- INFO: Spider started, progress milestones (25%, 50%, 75%, 100%), completion
- ERROR: Timeout, connection failures, invalid scan_id
- Include elapsed time and page count in log messages

## 7. IMPLEMENTATION NOTES:

- Use ZAPClient.request() for all API calls
- Timeout: 300 seconds per request to ZAP
- Progress polling: Default 5-second intervals
- Handle graceful shutdown (SIGTERM)
- Store discovered URLs in set to avoid duplicates
- Thread-safe for concurrent spider operations

Generate complete class with full error handling and progress callbacks.
```

<!-- END PROMPT 3 -->

**Expected Output:** `zap_spider_manager.py` (300-400 lines)

**Verification Checklist:**
- ✅ start_spider() returns (scan_id, start_time)
- ✅ wait_for_completion() with timeout handling
- ✅ get_discovered_urls() with deduplication
- ✅ Progress callback mechanism
- ✅ 2 custom exceptions defined
- ✅ Polling logic with configurable intervals
- ✅ Comprehensive logging

**Next:** Save as `MoodleSec/ml/zap_integration/zap_spider_manager.py`

---

## PART 4️⃣: ACTIVE SCAN ORCHESTRATOR (Vulnerability Scanning)

<!-- START PROMPT 4 -->

```
Generate ZAPActiveScanManager class for coordinating vulnerability scanning:

## 1. PURPOSE:
- Execute active security scans on discovered pages
- Track scan progress and gather findings
- Apply scan policies (aggressive/medium/light)
- Monitor and aggregate vulnerability results

## 2. CLASS STRUCTURE:
- Name: ZAPActiveScanManager
- Constructor: __init__(client: ZAPClient)
- Dependencies: Use ZAPClient from Prompt 1

## 3. METHODS TO IMPLEMENT:

### a) Scan Configuration & Initiation:
- start_ascan(url: str, context_id: int, user_id: int, policy: str = "medium", max_runtime: int = 3600) -> (str, float)
  → Start active vulnerability scan
  → Policy options: "light", "medium", "heavy" (maps to ZAP policy IDs)
  → Parameters:
    - url: Target URL
    - context_id: ZAP context (for authenticated scanning)
    - user_id: User account in context (for authenticated scanning)
    - policy: Scan aggressiveness
    - max_runtime: Max scan duration in seconds (default 1 hour)
  → Return (scan_id: str, start_time: float)

- configure_policy(policy_name: str, policy_settings: Dict) -> bool
  → Create/update custom scan policy
  → Return True if successful

### b) Scan Progress Monitoring:
- get_ascan_progress(scan_id: str) -> Dict[str, any]
  → Query ZAP for active scan progress
  → Return {
      "id": str,
      "progress": int (0-100),
      "status": str ("Running" / "Stopped"),
      "alerts_found": int,
      "requests_sent": int,
      "current_step": str
    }

- wait_for_scan_completion(scan_id: str, timeout_minutes: int = 60, poll_interval: int = 10) -> (bool, List[Dict], float)
  → Block until scan completes or timeout
  → Periodically fetch alerts while scanning
  → Parameters:
    - timeout_minutes: Max wait time
    - poll_interval: Check interval in seconds
  → Return (success: bool, alerts: List[Dict], duration_seconds: float)

### c) Findings Collection:
- get_alerts(scan_id: Optional[str] = None, base_url: Optional[str] = None) -> List[Dict]
  → Fetch all alerts from specific scan or all scans
  → Normalize to standard format:
    {
      "id": str,
      "type": str,  // Alert type (e.g., "SQL Injection")
      "risk": str,  // "High", "Medium", "Low", "Informational"
      "confidence": str,  // "High", "Medium", "Low"
      "url": str,
      "method": str,
      "param": str,
      "wascid": int,
      "cwe": int,
      "description": str,
      "other_info": str,
      "solution": str,
      "reference": str,
      "evidence": str,
      "plugin_id": int
    }
  → Return list of normalized alerts

- get_alerts_by_risk(risk_level: str) -> List[Dict]
  → Filter alerts: risk_level in ["High", "Medium", "Low", "Informational"]
  → Return filtered list
  → Raise ValueError if invalid risk_level

- get_alerts_by_type(alert_type: str) -> List[Dict]
  → Filter by vulnerability type (e.g., "SQL Injection")
  → Return matching alerts

### d) Scan Control:
- stop_ascan(scan_id: str) -> bool
  → Stop active scan
  → Return True if stopped successfully

- pause_ascan(scan_id: str) -> bool
  → Pause scan
  → Return True if paused

- resume_ascan(scan_id: str) -> bool
  → Resume paused scan
  → Return True if resumed

### e) Results Analysis:
- clear_alerts(scan_id: Optional[str] = None) -> int
  → Delete all alerts from scan (or all if scan_id None)
  → Return count deleted
  → WARNING: Use with caution!

- aggregate_findings(alerts: List[Dict]) -> Dict
  → Analyze alerts and return statistics:
    {
      "total": int,
      "by_risk": {"High": int, "Medium": int, "Low": int, "Informational": int},
      "by_type": {"SQL Injection": int, "XSS": int, ...},
      "top_vulnerabilities": List[str],  // Most common types
      "high_risk_count": int,
      "exploitable_percentage": float
    }

## 4. ERROR HANDLING:

Define exceptions:
- class ZAPScanError(Exception)
- class ZAPScanTimeoutError(Exception)
- class ZAPAlertParseError(Exception)

Error scenarios:
- Scan fails to start → Raise ZAPScanError
- Invalid context_id or user_id → Raise ZAPScanError
- Timeout exceeded → Raise ZAPScanTimeoutError
- Alert parsing fails → Raise ZAPAlertParseError, log problematic alert
- Empty results → Return empty list (not error)

## 5. LOGGING:

- Logger name: "ZAPActiveScanManager"
- DEBUG: Polling attempts, alert discovery, policy configuration
- INFO: Scan started/stopped, progress milestones, completion stats
- ERROR: Scan failures, timeout, parsing errors
- Include alert counts and vulnerability distribution in summaries

## 6. IMPLEMENTATION NOTES:

- Use ZAPClient.request() for all API calls
- Normalize all alerts to standard format (handle ZAP API variations)
- Request timeout: 300 seconds
- Polling interval: Default 10 seconds
- Support concurrent scans with separate scan_ids
- Thread-safe alert collection

Generate complete class with full error handling and alert normalization.
```

<!-- END PROMPT 4 -->

**Expected Output:** `zap_ascan_manager.py` (350-450 lines)

**Verification Checklist:**
- ✅ start_ascan() with policy support
- ✅ wait_for_scan_completion() with polling
- ✅ get_alerts() with normalization
- ✅ get_alerts_by_risk() and get_alerts_by_type()
- ✅ Alert aggregation statistics
- ✅ 3 custom exceptions defined
- ✅ Standard alert normalization format

**Next:** Save as `MoodleSec/ml/zap_integration/zap_ascan_manager.py`

---

## PART 5️⃣: FINDINGS AGGREGATOR + ML FILTERING (Final Integration)

<!-- START PROMPT 5 -->

```
Generate ZAPResultAggregator class that collects ZAP findings and applies 3-tier ML filtering pipeline:

## 1. PURPOSE:
- Normalize and collect all ZAP findings
- Apply Rule-based filtering (Tier 1)
- Calculate rarity scores (Tier 2)
- Apply ML-based false positive reduction (Tier 3)
- Return priority-ranked, ML-filtered results

## 2. CLASS STRUCTURE:
- Name: ZAPResultAggregator
- Constructor: __init__(zap_client: ZAPClient, ml_model_path: Optional[str] = None)
- Dependencies: ZAPClient, and import FalsePositiveReducer from ml.false_positive_reducer
- Load ML model during init if ml_model_path provided

## 3. METHODS TO IMPLEMENT:

### a) Data Collection & Normalization:
- get_raw_findings(scan_id: Optional[str] = None) -> List[Dict]
  → Fetch all alerts from ZAP (if scan_id) or all scans
  → Return raw, unnormalized alert list

- normalize_alert(raw_alert: Dict) -> Dict
  → Convert ZAP alert format to ML-friendly format:
    {
      "id": str,                    # Unique alert ID
      "category": str,              # Vulnerability type
      "severity": str,              # High/Medium/Low/Informational
      "url": str,                   # Vulnerable URL
      "method": str,                # HTTP method (GET/POST)
      "param": str,                 # Parameter name
      "description": str,           # Full description
      "evidence": str,              # Proof/payload
      "cwe": int,                   # CWE-ID
      "wascid": int,                # WASC-ID
      "cvss_score": float,          # CVSS if available
      "scanner": str,               # "zap"
      "timestamp": str              # ISO 8601
    }
  → Handle missing fields gracefully
  → Return normalized dict

### b) Tier 1: Rule-Based Filtering:
- apply_tier1_filtering(findings: List[Dict]) -> (List[Dict], Dict)
  → Remove obvious false positives using rules:
  
  Rules:
  1. Remove if severity == "Informational"
  2. Remove if contains keywords: ["deprecated", "recommendation", "best practice", "missing header"]
  3. Remove if evidence is empty or less than 3 characters
  4. Remove if category matches: ["Information Disclosure", "Server Technology Identified"] AND evidence is generic
  5. Keep all High/Critical severity findings
  6. Keep all OWASP Top 10 categories
  
  → Return (filtered_findings, stats: {removed_count, removed_reasons: {}})

### c) Tier 2: Rarity-Based Filtering:
- calculate_rarity_score(finding: Dict, all_findings: List[Dict]) -> float
  → For each finding, calculate how rare/unique it is:
  
  Scoring:
  - Count similar findings (same category + same URL pattern)
  - If count == 1: rarity = 1.0 (unique, likely genuine)
  - If count == 2-5: rarity = 0.7 (moderately common, investigate)
  - If count > 5: rarity = 0.3 (very common, likely false positive)
  
  - Adjust by severity:
    - High/Critical: +0.2 multiplier
    - Low/Informational: -0.2 multiplier
  
  → Return float between 0.0 and 1.0

- apply_tier2_filtering(findings: List[Dict], rarity_threshold: float = 0.5) -> (List[Dict], Dict)
  → Calculate rarity for each finding
  → Keep findings with rarity_score >= threshold
  → Return (high_rarity_findings, stats: {removed_count, rarity_map: {}})

### d) Tier 3: ML-Based Filtering:
- extract_ml_features(finding: Dict) -> Dict
  → Extract 16 features for ML model (from ml/false_positive_reducer.py):
  - severity_encoded, category_encoded, evidence_length, description_length
  - url_complexity, has_params, cvss_score, risk_score
  - tp_keyword_count, fp_keyword_count, keyword_ratio, is_informational
  - [+ 4 context features]
  → Return feature dict

- apply_tier3_ml_filtering(findings: List[Dict], confidence_threshold: float = 0.75) -> (List[Dict], Dict)
  → For each finding:
    1. Extract ML features using extract_ml_features()
    2. Call ML model.predict_proba() to get TP probability
    3. Keep if TP_probability >= confidence_threshold
  
  → Return (ml_filtered_findings, stats: {
      removed_count,
      model_predictions: {finding_id: probability},
      confidence_threshold_used: float
    })

### e) Full Pipeline Orchestration:
- aggregate_and_filter(findings: List[Dict], apply_tier1: bool = True, apply_tier2: bool = True, apply_tier3: bool = True) -> Dict
  → Run complete filtering pipeline:
  
  1. Normalize all findings
  2. Apply Tier 1 (if enabled)
  3. Apply Tier 2 (if enabled)
  4. Apply Tier 3 (if enabled and ML model loaded)
  5. Rank by severity + ML confidence
  
  → Return {
      "input_count": int,
      "tier1_removed": int,
      "tier2_removed": int,
      "tier3_removed": int,
      "output_count": int,
      "filtered_findings": List[Dict],  // Final results
      "removed_findings": List[Dict],   // What was filtered
      "statistics": {
        "by_tier": {"tier1": int, "tier2": int, "tier3": int},
        "by_severity": {"High": int, "Medium": int, "Low": int},
        "processing_time_seconds": float,
        "filtering_percentage": float  // (removed/input) * 100
      },
      "ml_confidence_scores": Dict  // If ML applied
    }

### f) Result Export:
- export_findings(findings: List[Dict], format: str = "json", filepath: Optional[str] = None) -> str
  → Export findings to JSON/CSV
  → Return filepath or JSON string

- generate_report(filtered_findings: List[Dict], removed_findings: List[Dict]) -> str
  → Generate human-readable report
  → Include summary, top vulnerabilities, statistics
  → Return markdown report

## 4. FEATURE EXTRACTION (from ML model):

Keywords:
- TP keywords: ["injection", "xss", "csrf", "overflow", "execute", "exploit", "malicious", ...]
- FP keywords: ["missing", "not set", "header", "information", "recommendation", ...]

Severity mapping:
- "Critical" → 4
- "High" → 3
- "Medium" → 2
- "Low" → 1
- "Informational" → 0

## 5. ERROR HANDLING:

Define exceptions:
- class ZAPAggregatorError(Exception)
- class ZAPMLPredictionError(Exception)
- class ZAPFeatureExtractionError(Exception)

Error scenarios:
- ML model fails to load → Log warning, disable Tier 3
- Feature extraction fails → Raise ZAPFeatureExtractionError
- ML prediction fails → Skip that finding, log error
- Empty findings list → Return empty result (not error)
- Export path invalid → Raise ZAPAggregatorError

## 6. LOGGING:

- Logger name: "ZAPResultAggregator"
- DEBUG: Feature extraction, ML predictions, filtering decisions
- INFO: Pipeline start/completion, counts per tier, final statistics
- ERROR: Model loading failures, prediction errors, export failures
- Include detailed filtering statistics in final report

## 7. IMPLEMENTATION NOTES:

- Import FalsePositiveReducer: from ml.false_positive_reducer import FalsePositiveReducer
- ML model optional (graceful degradation without model)
- Feature extraction must match ML model's 16-feature format exactly
- Thread-safe for concurrent scanning operations
- Cache feature extraction to avoid recalculation
- Performance target: <2 seconds per 100 findings

Generate complete class with full error handling and feature extraction.
```

<!-- END PROMPT 5 -->

**Expected Output:** `zap_result_aggregator.py` (400-500 lines)

**Verification Checklist:**
- ✅ normalize_alert() converts raw findings
- ✅ Tier 1: Rule-based filtering (informational, keywords, empty evidence)
- ✅ Tier 2: Rarity calculation and filtering
- ✅ Tier 3: ML prediction (uses FalsePositiveReducer)
- ✅ aggregate_and_filter() orchestrates all tiers
- ✅ Feature extraction matches 16-feature model
- ✅ Detailed statistics and reporting
- ✅ 3 custom exceptions defined

**Next:** Save as `MoodleSec/ml/zap_integration/zap_result_aggregator.py`

---

## PART 6️⃣: MAIN ORCHESTRATOR (Integration Wrapper)

<!-- START PROMPT 6 -->

```
Generate ZAPIntegrationManager class that orchestrates the complete ZAP scanning pipeline:

## 1. PURPOSE:
- Unified interface for all ZAP operations
- Coordinate spider → active scan → ML filtering workflow
- Provide simple methods for common scanning tasks
- Handle error recovery and retry logic

## 2. CLASS STRUCTURE:
- Name: ZAPIntegrationManager
- Constructor: __init__(host="localhost", port=8080, api_key="", ml_model_path=None)
- Initialized attributes: ZAPClient, ZAPAuthenticationHandler, ZAPSpiderManager, ZAPActiveScanManager, ZAPResultAggregator
- All dependencies from previous prompts

## 3. METHODS TO IMPLEMENT:

### a) Setup & Configuration:
- initialize() -> bool
  → Create ZAPClient, test connection, validate all components
  → Return True if all OK

- configure_moodle_auth(context_id: int, moodle_url: str, username: str, password: str) -> bool
  → Configure Moodle-specific authentication
  → Set login URL: moodle_url + "/login/index.php"
  → Username field: "username"
  → Password field: "password"
  → Return True if configured

### b) Complete Scanning Workflow:
- scan_with_authentication(target_url: str, spider_depth: int = 3, scan_policy: str = "medium", username: str = None, password: str = None) -> Dict
  → Full workflow: auth → spider → scan → filter
  
  Parameters:
  - target_url: URL to scan
  - spider_depth: Recursion depth (default 3)
  - scan_policy: light/medium/heavy
  - username/password: For authenticated scanning
  
  Returns:
  {
    "success": bool,
    "spider_scan_id": str,
    "ascan_scan_id": str,
    "total_findings": int,
    "filtered_findings": int,
    "alerts": List[Dict],
    "statistics": Dict,
    "duration_seconds": float,
    "errors": List[str]
  }

- scan_unauthenticated(target_url: str, spider_depth: int = 3, scan_policy: str = "medium") -> Dict
  → Same as above but without authentication step
  → Return same format

- parallel_scan_multiple_urls(urls: List[str], scan_policy: str = "medium") -> List[Dict]
  → Scan multiple URLs sequentially (not parallel for ZAP API limits)
  → Return list of results (one dict per URL)

### c) Progressive Scanning (Step-by-Step):
- spider_target(target_url: str, context_id: int = None, depth: int = 3) -> (str, List[str])
  → Start spider, wait for completion, return results
  → Use wait_completion internally
  → Return (scan_id, discovered_urls)

- scan_discovered_urls(discovered_urls: List[str], context_id: int, user_id: int, scan_policy: str = "medium") -> (str, List[Dict])
  → Run active scan on discovered URLs
  → Return (scan_id, alerts)

### d) Result Processing:
- filter_results(findings: List[Dict], apply_ml: bool = True) -> Dict
  → Apply filtering pipeline
  → Return filtered results with statistics

- export_results(findings: List[Dict], filepath: str, format: str = "json") -> bool
  → Export to file
  → Return True if successful

- generate_scan_report(scan_results: Dict) -> str
  → Generate comprehensive markdown report
  → Include timeline, statistics, filtering details
  → Return report text

### e) Session Management:
- create_scan_session(session_name: str) -> bool
  → Create new ZAP session
  → Return True if successful

- save_scan_session(session_name: str) -> bool
  → Save session for later reuse
  → Return True if successful

- load_previous_session(session_name: str) -> bool
  → Load existing session
  → Return True if successful

## 4. ERROR HANDLING & RECOVERY:

Recovery mechanisms:
- Connection failures → Retry up to 3 times with backoff
- Timeout during scanning → Save partial results, report error
- Authentication failure → Raise error, don't continue with unauthenticated scan
- ML model failure → Continue with Tier 1+2 filtering only

Return format always includes "errors" list for problem reporting.

## 5. LOGGING:

- Logger name: "ZAPIntegrationManager"
- INFO: Workflow start/completion, major steps
- ERROR: Connection failures, scan failures, auth failures
- Include timing information and result summaries

## 6. USAGE EXAMPLE (include in docstring):

```python
# Quick start
manager = ZAPIntegrationManager(host="localhost", port=8080, ml_model_path="path/to/model.pkl")
manager.initialize()

# Authenticated scan
results = manager.scan_with_authentication(
    target_url="https://moodle.example.com",
    spider_depth=3,
    scan_policy="medium",
    username="admin",
    password="password123"
)

# Export results
manager.export_results(results["alerts"], "scan_results.json")

# Generate report
report = manager.generate_scan_report(results)
print(report)
```

## 7. IMPLEMENTATION NOTES:

- All components (auth, spider, ascan, aggregator) initialized lazily
- Clean separation of concerns
- All errors caught and reported in results
- Comprehensive logging throughout
- Support for both CLI and programmatic usage

Generate complete orchestrator class with full workflow support.
```

<!-- END PROMPT 6 -->

**Expected Output:** `zap_integration_manager.py` (300-400 lines)

**Verification Checklist:**
- ✅ scan_with_authentication() - full workflow
- ✅ scan_unauthenticated() - simplified workflow
- ✅ Progressive scanning methods
- ✅ Result filtering and export
- ✅ Session management
- ✅ Error recovery with retries
- ✅ Example usage in docstrings

**Next:** Save as `MoodleSec/ml/zap_integration/zap_integration_manager.py`

---

## 📁 FINAL DIRECTORY STRUCTURE

After completing all 6 prompts, your directory will look like:

```
MoodleSec/ml/zap_integration/
├── __init__.py                    # Package init
├── zap_client.py                  # Prompt 1 - Basic API client
├── zap_auth_handler.py            # Prompt 2 - Authentication
├── zap_spider_manager.py          # Prompt 3 - Page discovery
├── zap_ascan_manager.py           # Prompt 4 - Vulnerability scan
├── zap_result_aggregator.py       # Prompt 5 - Results + ML filtering
├── zap_integration_manager.py     # Prompt 6 - Main orchestrator
├── examples/
│   ├── basic_scan.py              # Simple scan example
│   ├── authenticated_scan.py      # Moodle scan example
│   └── ml_filtered_scan.py        # With ML filtering
└── README.md                      # Usage documentation
```

---

## 🚀 NEXT STEPS AFTER CODE GENERATION

### Step 1: Create Package Structure
```bash
cd MoodleSec/ml
mkdir -p zap_integration/examples
touch zap_integration/__init__.py
```

### Step 2: Paste Generated Files
- Copy each generated class into corresponding file
- Review code quality and error handling

### Step 3: Create Examples
Generate example files showing usage:
- `basic_scan.py` - Unauthenticated scan
- `authenticated_scan.py` - Moodle with login
- `ml_filtered_scan.py` - With ML filtering integration

### Step 4: Unit Tests
Generate basic unit tests for each class

### Step 5: Integration Tests
Test full workflow end-to-end

### Step 6: Update Main README
Document new ZAP integration module

---

## ✅ USAGE CHECKLIST

- [ ] Prompt 1: ZAPClient generated
- [ ] Prompt 2: ZAPAuthenticationHandler generated
- [ ] Prompt 3: ZAPSpiderManager generated
- [ ] Prompt 4: ZAPActiveScanManager generated
- [ ] Prompt 5: ZAPResultAggregator generated
- [ ] Prompt 6: ZAPIntegrationManager generated
- [ ] All files saved to correct locations
- [ ] Imports verified between modules
- [ ] Example scripts created
- [ ] Documentation updated

---

## 📞 TROUBLESHOOTING

**If Copilot output is incomplete:**
- Ask: "Continue generating the [missing methods] part"
- Provide context about what's missing
- Paste partial output and ask to complete

**If imports fail:**
- Ensure all dependencies installed: `pip install requests scikit-learn numpy pandas`
- Verify file paths match imports
- Add __init__.py to zap_integration directory

**If ML model integration fails:**
- Verify false_positive_reducer.py exists and is importable
- Check model file path is correct
- Test FalsePositiveReducer separately first

---

**Document Version:** 1.0  
**Created:** 3 March 2026  
**Status:** Ready for use

