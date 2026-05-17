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

Source: `proxy/utils/trace_logger.py` (203 lines)

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
# app.py line 2687
app.mount("/dashboard", StaticFiles(directory="soc-dashboard", html=True))
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
| GET | `/soc/health` | System health status |

### 17.3 Scanning & Reports

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/scan-auth` | Authentication security scan |
| POST | `/scan-api` | REST API security scan |
| POST | `/ml/post-process-zap` | ZAP findings ML post-processing |
| GET | `/reports/executive-summary` | PDF report generation |
| GET | `/reports/compliance` | Compliance PDF (OWASP, PCI-DSS) |

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
