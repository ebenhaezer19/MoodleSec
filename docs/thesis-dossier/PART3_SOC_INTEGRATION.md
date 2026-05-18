# MoodleSec Technical Dossier — Part 3: SOC, Dashboard & Integration

---

## 12. SOC ALERT QUEUE — STATE MACHINE

Source: `proxy/utils/alert_queue.py` (512 lines)

### 12.1 State Machine

```
ML_DETECTED ──▶ PENDING_ADMIN_ACTION ──▶ ADMIN_BLOCK
                                      ──▶ ADMIN_ALLOW
                                      ──▶ ADMIN_IGNORE

PENDING_ADMIN_ACTION ──▶ ENFORCED_BLOCK  (auto, via enforcement gate)

ENFORCED_BLOCK ──▶ RESET  (admin demo/testing reset)
```

### 12.2 AlertQueue Architecture

| Feature | Implementation |
|---|---|
| **Storage** | In-memory `deque(maxlen=1000)` + JSON file persistence |
| **Thread Safety** | `threading.Lock` on all mutations |
| **Dedup** | Fingerprint index (`method:path:ip`) prevents duplicate PENDING alerts |
| **Override Index** | `(attack_type, client_ip)` → admin action for O(1) lookup |
| **Blocked Set** | `_blocked_fingerprints` set for O(1) enforcement check |
| **Persistence** | `logs/alert_queue.json` — loaded on startup, written on every mutation |
| **Eviction** | FIFO — oldest alert evicted when deque reaches 1000 |

### 12.3 Alert ID Format

```
ALT-YYYYMMDD-HHMMSS-NNNN
```
Example: `ALT-20260517-143022-4821`

### 12.4 Fingerprint-Based Enforcement

```python
# Fingerprint format (normalized):
fingerprint = f"{method}:{path_with_leading_slash}:{client_ip}"

# Example:
# "GET:/login/index.php:192.168.0.100"
```

- Trailing slashes normalized (`/search` == `/search/`)
- Leading slash always ensured
- Fingerprint survives server restarts (rebuilt from persisted JSON)

### 12.5 Admin Override Flow

1. Admin calls `POST /soc/alerts/{alert_id}/resolve` with `action=BLOCK|ALLOW|IGNORE`
2. AlertQueue updates alert status + adds to override index
3. If BLOCK → fingerprint added to `_blocked_fingerprints`
4. If ALLOW/IGNORE → fingerprint removed from blocked set
5. Future matching requests check override index first (short-circuits ML)

### 12.6 Reset Capabilities

| Endpoint | Effect |
|---|---|
| `POST /soc/alerts/reset/{alert_id}` | Single alert → RESET state, clears fingerprint + override |
| `POST /soc/alerts/reset-all` | Clears ALL alerts, overrides, blocked fingerprints |

---

## 13. INCIDENT CORRELATOR

Source: `proxy/utils/incident_correlator.py` (332 lines)

### 13.1 Correlation Algorithm

Groups alerts into incidents using a composite key:

```python
correlation_key = f"{client_ip}|{attack_type}"
```

**Time Window**: 5 minutes (`CORRELATION_WINDOW_SECONDS = 300`)

### 13.2 Severity Escalation Rules

| Condition | Incident Severity |
|---|---|
| 1 alert | Based on attack type |
| 2 alerts | MEDIUM minimum |
| 3+ alerts | HIGH minimum |
| 5+ alerts | **CRITICAL** |
| Any HIGH child alert | At least HIGH |
| Known dangerous attack type (XSS, SQLi, etc.) | MEDIUM floor |

### 13.3 Benign Traffic Filtering

Incidents are NOT created for:
- `attack_type` ∈ {`normal`, `benign`, `unknown`, `none`, `""`}
- `status` ∈ {`IGNORED`, `ADMIN_IGNORE`}

### 13.4 Incident ID Format

```
INC-YYYYMMDD-NNNN
```
Example: `INC-20260517-0042`

### 13.5 Properties

- **Read-only**: Does NOT modify alert state or enforcement
- **Stateless rebuild**: Rebuilds from current alert list on each `correlate()` call
- **FIFO eviction**: Max 500 incidents
- **Thread-safe**: `threading.Lock` protected

---

## 14. PIPELINE TRACE STORE (EXPLAINABLE AI)

Source: `proxy/utils/trace_logger.py` (220 lines)

### 14.1 Trace Stages (ordered)

```python
STAGES_ORDER = [
    "request_received",
    "feature_extraction",
    "anomaly_detection",
    "attack_classifier",
    "fp_reducer",
    "decision_engine",
    "soc_queue",
    "enforcement",
]
```

### 14.2 Trace Event Schema

```json
{
    "request_id": "a1b2c3d4e5f6",
    "stage": "anomaly_detection",
    "status": "completed",
    "timestamp": "2026-05-17T14:30:22Z",
    "details": {
        "anomaly_score": 0.8234,
        "is_anomaly": true
    }
}
```

### 14.3 Storage

- **In-memory**: `OrderedDict` with FIFO eviction (max 200 traces)
- **Persistent**: JSONL append to `logs/pipeline_traces.jsonl`
- **Request ID**: `uuid4().hex[:12]` — 12-char hex string

### 14.4 Thesis Relevance

This trace store enables **Explainable AI (XAI)** for the thesis:
- Every security decision has a full audit trail
- Each ML stage's input/output is recorded
- SOC operators can inspect WHY a request was blocked/allowed
- Dashboard visualizes the pipeline flow in real-time

---

## 15. RISK SCORER — CVSS v3.1

Source: `proxy/risk/risk_scorer.py` (346 lines)

### 15.1 Scoring Components

```
Final Risk Score = CVSS Base Score × Context Multiplier × Exploitability × Business Impact
```

Capped at 10.0.

### 15.2 CVSS Base Vectors (per vulnerability type)

| Category | CVSS Vector | Base Score |
|---|---|---|
| SQL Injection | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H | 10.0 |
| XSS | AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N | 6.1 |
| CSRF | AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L | 6.3 |
| Path Traversal | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N | 7.5 |
| Authentication | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N | 9.1 |
| Access Control | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N | 8.1 |

### 15.3 Business Impact Multipliers

| URL Pattern | Multiplier |
|---|---|
| `/admin`, `/payment`, `/api` | 1.5× |
| `/user`, `/auth`, `/login`, `/data` | 1.2× |
| `/public`, `/static` | 0.8× |
| Default | 1.0× |

### 15.4 Priority Levels

| Risk Score | Priority | SLA |
|---|---|---|
| ≥9.0 | P1 | Immediate action |
| ≥7.0 | P2 | Fix within 24 hours |
| ≥4.0 | P3 | Fix within 1 week |
| ≥1.0 | P4 | Fix within 1 month |
| <1.0 | P5 | Monitor |

---

## 16. SOC DASHBOARD

Source: `proxy/soc-dashboard/` (SPA)

### 16.1 Technology Stack

| Component | Technology |
|---|---|
| Structure | HTML5 semantic elements |
| Styling | Vanilla CSS (4 files: variables, base, components, animations) |
| Charts | Chart.js 4.4.7 (CDN) |
| Typography | Inter + JetBrains Mono (Google Fonts) |
| State | Custom `State` singleton (js/state.js) |
| API | Fetch API with tiered polling (js/polling.js) |
| Routing | Client-side page switching (SPA) |

### 16.2 Dashboard Pages

| Page | ID | Content |
|---|---|---|
| **Overview** | `page-overview` | Metric cards, recent alerts, correlated incidents, threat feed, timeline chart, decision/attack distribution charts |
| **Alerts** | `page-alerts` | Full SOC alert queue table with filters, admin actions (BLOCK/ALLOW/IGNORE), reset queue |
| **ML Pipeline** | `page-pipeline` | Pipeline flow visualization, latest decision detail, SOC workflow timeline |
| **Incidents** | `page-incidents` | Correlated incidents grouped by IP+attack type |
| **Statistics** | `page-statistics` | Attack timeline, attack/severity distribution, decision ratio, top attacker IPs |
| **ML Performance** | `page-mlperf` | Model evaluation metrics, model comparison table, pipeline configuration |
| **Architecture** | `page-architecture` | System architecture diagram |
| **System Health** | `page-health` | Backend status, ML model status, persistence/queue health |
| **Trace Logs** | `page-logs` | Real-time pipeline trace console |

### 16.3 Dashboard Mount

```python
# app.py line 785
_dashboard_dir = Path(__file__).resolve().parent / "soc-dashboard"
app.mount("/dashboard", StaticFiles(directory=str(_dashboard_dir), html=True))
```

Accessible at: `http://localhost:8999/dashboard/`

---

## 17. SOC API ENDPOINT INVENTORY

### 17.1 Alert Management

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/soc/alerts` | List alerts (filters: status, severity, limit) |
| GET | `/soc/alerts/{alert_id}` | Get single alert detail |
| POST | `/soc/alerts/{alert_id}/resolve` | Admin resolve: BLOCK/ALLOW/IGNORE |
| POST | `/soc/resolve` | Flat-body alias (alert_id in body) |
| POST | `/soc/alerts/reset/{alert_id}` | Reset single alert for re-testing |
| POST | `/soc/alerts/reset-all` | Clear entire queue |
| GET | `/soc/alerts/stats` | Queue statistics summary |

### 17.2 Pipeline & Analytics

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/soc/pipeline/trace/latest` | Latest pipeline traces (limit param) |
| GET | `/soc/pipeline/trace/{request_id}` | Full trace for specific request |
| GET | `/soc/incidents` | Correlated incidents |
| GET | `/soc/timeline` | Alert counts bucketed by time |
| GET | `/ml/performance` | ML evaluation metrics |

### 17.3 ML & System Status

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/soc/status` | SOC mode status + alert queue summary |
| GET | `/ml/status` | ML module load status |
| GET | `/ml/demo-status` | DEMO_MODE / SOC_MODE status |
| GET | `/ml/models/info` | Detailed ML model metadata |
| GET | `/ml/anomalies/recent` | Recent proxy anomalies (deque) |
| GET | `/ml/anomalies/runtime` | Traffic window runtime stats |
| POST | `/ml/post-process-zap` | ZAP findings ML post-processing |
| GET | `/ml-test` | Pipeline integration quick check |
| GET | `/health` | FastAPI health check |

---

## 18. MOODLE PLUGIN INTEGRATION

### 18.1 Plugin Identity

```php
$plugin->component = 'local_security_dashboard';
$plugin->version = 2026051200;
$plugin->requires = 2019111800; // Moodle 3.8+
$plugin->maturity = MATURITY_BETA;
$plugin->release = 'v2.1.0-beta';
```

### 18.2 Key Plugin Files

| File | Purpose |
|---|---|
| `index.php` | Main dashboard entry (16.5 KB) |
| `lib.php` | Core library functions (67.6 KB) |
| `ml_dashboard.php` | ML analytics view (24 KB) |
| `scan.php` | Vulnerability scan interface |
| `zap_scan.php` | ZAP integration (12.6 KB) |
| `zap_results.php` | ZAP results display (10.1 KB) |
| `native_auth_scan.php` | Authenticated scanning (12.9 KB) |
| `payload_manager_ui.php` | Payload management (40.7 KB) |
| `vulnerability_map.php` | Vulnerability mapping (22 KB) |
| `proxy_api.php` | Proxy API bridge (4.8 KB) |
| `soc_dashboard.php` | SOC Dashboard iframe embed |

### 18.3 Integration Architecture

```
Moodle Plugin (PHP) ──── REST API ────▶ FastAPI Proxy (Python)
                    ◀── JSON Response ──
                    
SOC Dashboard: Embedded via iframe in soc_dashboard.php
ZAP Results: POST /ml/post-process-zap for ML filtering
```

---

## 19. THESIS CHAPTER MAPPING

### BAB 1 — Pendahuluan (Introduction)

- **Latar Belakang**: Moodle LMS security challenges, OWASP Top 10 relevance
- **Rumusan Masalah**: How to implement ML-based intrusion detection for Moodle
- **Tujuan**: Build AI-powered SOC for real-time threat detection + human-in-the-loop
- **Evidence**: `config.py` modes, architecture topology diagram

### BAB 2 — Tinjauan Pustaka (Literature Review)

- **Reverse Proxy Security**: Cite middleware architecture (Section 4)
- **Machine Learning for IDS**: Cite Isolation Forest, XGBoost (Sections 7-8)
- **False Positive Reduction**: Cite ensemble methods + data leakage prevention (Section 9)
- **CVSS Scoring**: Cite CVSS v3.1 implementation (Section 15)
- **SOC Operations**: Cite alert queue state machine (Section 12)

### BAB 3 — Metodologi (Methodology)

- **System Architecture**: Use Section 2 topology diagram
- **ML Pipeline Design**: Use Section 6 pipeline flow
- **Dataset**: 15,847 samples, 60/20/20 split, synthetic augmentation
- **Training Methodology**: Two-stage with validation-only FP training (Section 9.2)
- **Evaluation Protocol**: Stratified splits, held-out test set

### BAB 4 — Hasil dan Pembahasan (Results)

- **Stage-1 Metrics**: Accuracy 0.934, Recall 0.967, FPR 8.9%
- **Stage-2 Metrics**: Accuracy 0.947, F1 0.936, FPR 5.3%
- **Stage-3 Metrics**: Precision 0.971, FP Reduction 73%
- **End-to-End**: Accuracy 0.941, F1 0.933, Final FPR 2.4%
- **SOC Dashboard**: Screenshot evidence of all 9 pages
- **Incident Correlation**: 5-minute window grouping with severity escalation

### BAB 5 — Kesimpulan dan Saran (Conclusion)

- **Key Achievement**: FPR reduced from 8.9% → 2.4% (73% reduction)
- **System Capability**: Real-time ML detection + human-in-the-loop SOC
- **Limitations**: Demo mode only, single Moodle instance tested
- **Future Work**: Production deployment, additional attack classes, federated learning

---

## 20. KEY DESIGN DECISIONS (for examiner questions)

| Decision | Justification |
|---|---|
| Reverse proxy vs. Moodle plugin ML | Decouples ML from PHP; Python ecosystem for sklearn/XGBoost |
| Isolation Forest for Stage-1 | Unsupervised — no labeled data needed for anomaly detection |
| XGBoost for Stage-2 | State-of-art gradient boosting; handles imbalanced classes well |
| FP Reducer trained on validation only | Prevents data leakage; ensures honest FP reduction metrics |
| In-memory alert queue + JSON persistence | Low latency for real-time SOC; survives restarts |
| Fingerprint-based enforcement | O(1) lookup; deterministic blocking on repeat attacks |
| Demo mode + SOC mode separation | Safe thesis demonstration without breaking live Moodle |
| Lazy model loading | Fast service startup; models load on first real request |
| 5-minute correlation window | Balances grouping accuracy with incident freshness |
| CVSS v3.1 scoring | Industry standard; provides defensible risk quantification |

---

## 21. PRACTICAL OPERATIONAL RESOURCE PROFILE

### 21.1 Server Requirements

| Resource | Minimum | Recommended | Thesis Demo |
|---|---|---|---|
| **CPU** | 2 cores (x86_64) | 4 cores | Intel i5 / Ryzen 5+ |
| **RAM** | 2 GB | 4 GB | 8 GB |
| **Storage** | 500 MB (app + models) | 2 GB (incl. logs) | 10 GB (incl. Moodle + DB) |
| **OS** | Linux / Windows 10+ | Ubuntu 22.04 / Win 11 | Windows 11 |
| **Python** | 3.8+ | 3.10+ | 3.10+ |
| **Network** | Localhost | LAN (192.168.x.x) | LAN demo |

### 21.2 CPU Utilization Profile

| Operation | CPU Impact | Duration | Frequency |
|---|---|---|---|
| FastAPI Boot (Uvicorn async) | Low | < 500ms | Once |
| Model Loading (lazy singleton) | **HIGH** — single-core burst | ~2–5s | First request only |
| Feature Extraction (35 features) | Low | ~1–3ms | Per request |
| Isolation Forest `.predict()` | Medium | ~5–15ms | Per request |
| XGBoost `.predict()` | Medium–High | ~10–30ms | Per anomalous request |
| FP Reducer `.predict()` | Low–Medium | ~3–8ms | Per attack prediction |
| Decision Engine rule evaluation | Negligible | < 1ms | Per anomalous request |
| Alert Queue ops (deque + JSON I/O) | Negligible | ~1–5ms | Per mutation |
| httpx forward to Moodle | Network-bound | 10–200ms | Per request |

- **Idle CPU**: < 1% (Uvicorn event loop idle)
- **Peak CPU under load**: 15–40% single core (ML inference pipeline)

### 21.3 Memory Footprint

| Component | Memory Usage |
|---|---|
| FastAPI + Uvicorn runtime | ~30–50 MB |
| ML Models (after deserialization) | ~180–250 MB |
| Alert Queue (max 1,000 alerts) | ~2–5 MB |
| Incident Correlator (max 500 incidents) | ~1–3 MB |
| Pipeline Trace Store (max 200 traces) | ~1–2 MB |
| Traffic Telemetry deques (5,000 + 200) | ~1 MB |
| **Total Runtime** | **~250–350 MB** |

### 21.4 Storage Consumption

| Component | Size | Growth Rate |
|---|---|---|
| ML Model files (`.pkl` + `.json`) | 48 MB | Static (fixed) |
| `alert_queue.json` (persistence) | 0–5 MB | Per mutation (full overwrite) |
| `pipeline_traces.jsonl` (append log) | 0–50 MB | ~1 KB per request |
| Proxy logs | 0–20 MB | ~0.5 KB per request |
| Python `.venv` | ~300–500 MB | Static |
| **Total (excl. venv)** | **~50–120 MB** | **~1.5 KB/request** |

### 21.5 Latency Budget (Per Proxied Request)

| Stage | Latency | Notes |
|---|---|---|
| Enforcement middleware | < 0.1ms | O(1) set lookup |
| Feature extraction | 1–3ms | String parsing + Shannon entropy |
| Stage-1 Anomaly Detection | 5–15ms | Isolation Forest inference |
| Stage-2 Attack Classification | 10–30ms | XGBoost (only if anomalous) |
| Stage-3 FP Reducer | 3–8ms | Random Forest (only if attack predicted) |
| Decision Engine | < 1ms | Threshold rule evaluation |
| SOC Queue insert + persistence | ~1–5ms | Deque append + JSON write |
| Trace logging | < 1ms | JSONL append (fire-and-forget) |
| httpx forward to Moodle | 10–200ms | Network RTT dependent |
| **Total (normal traffic)** | **~15–210ms** | Feature extract + forward only |
| **Total (full pipeline — attack)** | **~30–260ms** | All 3 ML stages + forward |

**Added latency by MoodleSec over direct Moodle access**: ~5–60ms (ML pipeline overhead)

---

## 22. SCENARIO MECHANICAL CALCULATIONS

### 22.1 Scenario A — Normal Traffic (Benign Request)

```
Request: GET /course/view.php?id=5 (student browsing)

1. Enforcement middleware:
   fingerprint = "GET:/course/view.php:192.168.0.100"
   is_fingerprint_blocked(...) → False
   Cost: < 0.1ms

2. Feature extraction: 35 features computed
   Cost: ~2ms

3. Stage-1 Anomaly Detection:
   anomaly_score = 0.12 (well below LOW_ANOMALY threshold 0.40)
   is_anomaly = False
   → Pipeline STOPS here (Stages 2–3 skipped)
   Cost: ~8ms

4. Decision Engine:
   decision = IGNORE (anomaly_score < 0.40)
   severity = LOW
   → No SOC alert generated

5. Forward to Moodle via httpx:
   Cost: ~30ms (localhost)

Total added latency: ~10ms
SOC impact: None
```

### 22.2 Scenario B — SQL Injection Attack (True Positive)

```
Request: GET /login/index.php?username=admin'--&password=x

1. Enforcement middleware:
   fingerprint = "GET:/login/index.php:192.168.0.50"
   is_fingerprint_blocked(...) → False (first occurrence)
   Cost: < 0.1ms

2. Feature extraction: 35 features
   - Special character density: HIGH (', --)
   - Query parameter count: 2
   Cost: ~2ms

3. Stage-1 Anomaly Detection:
   anomaly_score = 0.87 (above HIGH threshold 0.70)
   is_anomaly = True → Proceed to Stage-2
   Cost: ~10ms

4. Stage-2 Attack Classification:
   attack_type = "sqli"
   confidence = 0.92
   Cost: ~20ms

5. Stage-3 FP Reducer:
   is_false_positive = False
   fp_confidence = 0.15 (< 0.60 → no suppression)
   adjusted_confidence = 0.92 (unchanged)
   Cost: ~5ms

6. Decision Engine:
   anomaly_score (0.87) ≥ HIGH_ANOMALY (0.70) ✓
   confidence (0.92) ≥ HIGH_CONFIDENCE (0.70) ✓
   is_normal_prediction = False ✓
   → decision = BLOCK, severity = HIGH

7. SOC Mode (DEMO_MODE=True, SOC_MODE=True):
   check_admin_override("sqli", "192.168.0.50") → None
   → alert_queue.add_alert(ALT-xxx, sqli, HIGH, 0.92, 0.87)
   → Request FORWARDED (demo mode — never blocks without admin)

8. CVSS Risk Score:
   Base Vector: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
   CVSS Base = 10.0 × Business Impact 1.2 (/login) = 10.0 (capped)
   → Priority P1

Total pipeline latency: ~37ms
SOC alert: PENDING_ADMIN_ACTION
```

### 22.3 Scenario C — False Positive Suppression (Educational Content)

```
Request: POST /mod/forum/post.php
Body: "how to prevent SQL injection in PHP applications"

1. Stage-1 Anomaly Detection:
   anomaly_score = 0.65 (moderate — keyword triggers partial score)
   is_anomaly = True → Proceed to Stage-2

2. Stage-2 Attack Classification:
   attack_type = "sqli" (keyword match)
   confidence = 0.45 (contextual heuristics detect educational content)

3. Stage-3 FP Reducer:
   is_false_positive = True
   fp_confidence = 0.82 (≥ 0.60 → suppression triggered)
   suppression_multiplier = max(0.35, 1.0 − 0.5 × 0.82) = 0.59
   adjusted_confidence = 0.45 × 0.59 = 0.2655

4. Decision Engine:
   anomaly_score (0.65) in MEDIUM range (0.50–0.70)
   adjusted_confidence (0.27) < LOW_CONFIDENCE (0.40)
   weak_attack_evidence = True
   → decision = IGNORE

Result: FALSE POSITIVE SUCCESSFULLY SUPPRESSED
No SOC alert generated. Student forum post passes through.
```

### 22.4 Scenario D — Repeated Attack (Admin Block Enforcement)

```
Timeline:

T+0s:   First attack → ML pipeline → Alert ALT-xxx queued (PENDING)

T+10s:  Admin: POST /soc/alerts/ALT-xxx/resolve {action: "BLOCK"}
        → alert.status = ADMIN_BLOCK
        → fingerprint "GET:/login/index.php:192.168.0.50" → _blocked_fingerprints
        → override: ("sqli", "192.168.0.50") → ADMIN_BLOCK

T+15s:  Same attacker, same request:
        → Enforcement middleware: fingerprint blocked → HTTP 403 IMMEDIATELY
        → ML pipeline NOT invoked (O(1) enforcement)

T+20s:  Same attacker, DIFFERENT path: GET /admin/users.php?id=1' OR 1=1--
        → Enforcement middleware: new fingerprint → not blocked
        → ML pipeline runs → detects sqli
        → check_admin_override("sqli", "192.168.0.50") → ADMIN_BLOCK
        → HTTP 403 (override match on attack_type + IP)
```

### 22.5 Scenario E — Incident Escalation (5+ Alerts)

```
Correlation key: "192.168.0.75|xss"
Correlation window: 5 minutes (300 seconds)

T+0min:  Alert 1 → Incident INC-xxx-0001 created
         alert_count=1, severity=MEDIUM (XSS ∈ HIGH_ATTACK_TYPES → MEDIUM floor)

T+1min:  Alert 2 → Incident updated
         alert_count=2, severity=MEDIUM (count rule: 2 → MEDIUM)

T+2min:  Alert 3 → Incident updated
         alert_count=3, severity=HIGH (3+ alerts rule)

T+3min:  Alerts 4,5 → Incident updated
         alert_count=5, severity=CRITICAL (5+ alerts rule)

Result: Automated severity escalation LOW→MEDIUM→HIGH→CRITICAL
All alerts grouped into single incident (within 5-min window, same IP+type)
```

### 22.6 Throughput Estimates

| Traffic Volume | Pipeline Impact | System Behavior |
|---|---|---|
| < 10 req/min | All ML stages idle between requests | CPU < 5% |
| 10–50 req/min | Typical classroom traffic | CPU 5–15% |
| 50–200 req/min | Heavy usage, multiple concurrent users | CPU 15–30% |
| 200–500 req/min | Stress test / attack simulation | CPU 30–60% |
| > 500 req/min | Above design capacity for single-thread | Queue delays possible |

**Design target**: 50–100 req/min (typical Moodle classroom of 30–50 students)

---

## 23. COMPARATIVE ANALYSIS WITH EXISTING SOC SOLUTIONS

### 23.1 Feature Comparison Matrix

| Feature | **MoodleSec** | **Splunk SIEM** | **Elastic SIEM** | **Wazuh** | **Snort/Suricata** |
|---|---|---|---|---|---|
| Deployment | Single Python process | Enterprise cluster | ES cluster | Agent + Server | Network sensor |
| ML Detection | ✅ 3-stage pipeline | ✅ MLTK add-on | ✅ ML jobs | ❌ Rule-based | ❌ Signature-based |
| FP Reduction | ✅ Dedicated FP Reducer (73%) | ⚠️ Manual tuning | ⚠️ Threshold tuning | ❌ | ❌ |
| Human-in-the-Loop SOC | ✅ Built-in queue | ✅ SOC workflows | ✅ Cases/SOAR | ⚠️ Basic alerts | ❌ |
| Explainable AI (XAI) | ✅ Pipeline traces | ❌ | ❌ | ❌ | ❌ |
| Incident Correlation | ✅ IP+Type+Time | ✅ Advanced | ✅ Detection rules | ⚠️ Basic | ❌ |
| CVSS v3.1 Scoring | ✅ Built-in | ✅ | ✅ (integration) | ✅ | ❌ |
| LMS-Specific Context | ✅ Moodle-aware | ❌ Generic | ❌ Generic | ❌ Generic | ❌ Generic |
| Real-time Dashboard | ✅ SPA (Chart.js) | ✅ | ✅ (Kibana) | ✅ (Wazuh UI) | ⚠️ Console only |
| Cost | Free (open-source) | $$$$ (enterprise) | $$$ (self-host) | Free (open-source) | Free (open-source) |
| Setup Complexity | Low (single process) | Very High | High | Medium | Medium |
| Min Hardware | 2 cores / 2 GB | 16+ cores / 64 GB | 8+ cores / 32 GB | 4 cores / 8 GB | 4 cores / 8 GB |

### 23.2 MoodleSec Advantages

| Advantage | Detail |
|---|---|
| **LMS-specific context awareness** | Contextual heuristics understand Moodle URL patterns, academic content about attacks (forum posts discussing "SQL injection prevention"), and educational workflows — reducing FP that generic solutions would flag |
| **3-stage ML pipeline with dedicated FP Reducer** | No commercial SOC provides a dedicated ML stage specifically for FP reduction. MoodleSec's Stage-3 Random Forest achieves 73% FP reduction, which is not achievable through threshold tuning alone |
| **Explainable AI (XAI) via pipeline traces** | Every security decision is auditable with full stage-by-stage trace. SOC operators can inspect exactly WHY a request was flagged — no other lightweight solution offers this |
| **Zero-cost, zero-infrastructure** | Runs as a single Python process alongside Moodle. No Elasticsearch cluster, no Splunk license, no agent deployment |
| **< 60ms added latency** | ML pipeline adds only 5–60ms per request. Enterprise SIEMs add latency through log shipping, indexing, and cross-node correlation |
| **Human-in-the-loop with enforcement memory** | Admin decisions persist via fingerprint and override indexes. Once an admin blocks an attack pattern, enforcement is O(1) for all future matching requests |
| **Academic demonstration friendly** | DEMO_MODE + SOC_MODE allows safe live demonstration without risk of breaking the actual Moodle instance |

### 23.3 MoodleSec Limitations

| Limitation | Detail | Mitigation |
|---|---|---|
| **Single-threaded** | Uvicorn runs async but ML inference is CPU-bound (GIL) | Sufficient for classroom-scale (< 200 req/min) |
| **In-memory state** | Alert queue and incidents are memory-resident with JSON persistence | JSON persistence survives restarts; max 1000 alerts eviction |
| **No distributed deployment** | Cannot scale horizontally across multiple servers | Not needed for single-institution Moodle deployment |
| **No log aggregation** | Does not ingest external log sources (firewall, OS, etc.) | Focused scope: HTTP-layer protection for Moodle only |
| **6 attack classes only** | Limited to XSS, SQLi, Path Traversal, Cmd Injection, SSRF, Normal | Extensible — new classes can be added by retraining XGBoost |
| **No threat intelligence feeds** | Does not consume external IOC/threat feeds | Can be added as future work (API integration) |
| **Single Moodle instance** | Tested with one Moodle backend only | Architecture supports multi-backend via config change |

### 23.4 Positioning Summary

```
                     Complexity / Cost
                     ▲
                     │
        Splunk ●     │
                     │     ● Elastic SIEM
                     │
                     │  ● Wazuh
                     │
        Snort ●      │
                     │
   MoodleSec ●───────┼──────────────────────▶ ML Capability
                     │
                     │
```

**MoodleSec occupies a unique niche**: lightweight, ML-powered, LMS-specific SOC that is too small for enterprise SIEM but far more intelligent than signature-based IDS. It provides capabilities (XAI, FP reduction, human-in-the-loop) that typically require enterprise-grade investment, packaged in a single-process deployment suitable for educational institutions.
