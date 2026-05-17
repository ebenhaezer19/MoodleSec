# MoodleSec Technical Dossier — Part 1: Architecture & System Design

> **Purpose**: High-fidelity reference for Perplexity AI to synthesize BAB 1–5 of the Capstone thesis.
> **Generated**: 2026-05-17 | **Source**: Full codebase audit of `MoodleSec/` repository

---

## 1. PROJECT IDENTITY

| Field | Value |
|---|---|
| **Project Name** | MoodleSec — AI-Powered Security Operations Center for Moodle LMS |
| **Plugin Package** | `local_security_dashboard` v2.1.0-beta |
| **Proxy Version** | FastAPI v2.0.0 |
| **Authors** | Krisopras & Nathanael |
| **Copyright** | 2025 |
| **License** | GNU GPL v3 |
| **Python** | 3.8+ required |
| **Moodle Compat** | 3.8+ (requires version 2019111800) |

---

## 2. HIGH-LEVEL ARCHITECTURE

### 2.1 System Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLIENT BROWSER                           │
│                    (Student / Instructor)                        │
└─────────────┬───────────────────────────────────────────────────┘
              │ HTTP :8999
              ▼
┌─────────────────────────────────────────────────────────────────┐
│              MOODLESEC FASTAPI REVERSE PROXY                    │
│                      (proxy/app.py)                             │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐ │
│  │ Enforcement  │  │ SOC Dashboard│  │  CORS Middleware       │ │
│  │ Middleware   │  │ Gate         │  │  (LAN-safe)            │ │
│  └──────┬───────┘  └──────┬───────┘  └───────────────────────┘ │
│         │                 │                                     │
│  ┌──────▼─────────────────▼──────────────────────────────────┐ │
│  │              ML PIPELINE INTEGRATION                       │ │
│  │    (integrations/ml_pipeline_integration.py)               │ │
│  │                                                            │ │
│  │  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐ │ │
│  │  │ Feature     │  │ Pipeline     │  │ Decision         │ │ │
│  │  │ Extraction  │──▶ Orchestrator │──▶ Engine           │ │ │
│  │  │ (35 feats)  │  │              │  │ (BLOCK/ALERT/    │ │ │
│  │  └─────────────┘  └──────────────┘  │  IGNORE)         │ │ │
│  │                                      └──────────────────┘ │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐ │
│  │ Alert Queue  │  │ Incident     │  │ Pipeline Trace Store  │ │
│  │ (SOC state)  │  │ Correlator   │  │ (Explainable AI)      │ │
│  └──────────────┘  └──────────────┘  └───────────────────────┘ │
└─────────────┬───────────────────────────────────────────────────┘
              │ httpx (async forward)
              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   MOODLE LMS BACKEND                            │
│                    (Apache :80)                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Component Inventory

| Component | Location | Purpose |
|---|---|---|
| **FastAPI Proxy** | `proxy/app.py` (3255 lines) | Central gateway, enforcement, SOC API |
| **ML Manager** | `proxy/ml/ml_manager.py` | Lazy-loading singleton for all ML models |
| **Anomaly Detector** | `proxy/ml/anomaly_detector.py` | Stage-1 Isolation Forest |
| **Attack Classifier** | `proxy/ml/attack_classifier.py` | Multi-class attack categorization |
| **FP Reducer** | `proxy/ml/anomaly_false_positive_reducer.py` | Stage-2 Random Forest ensemble |
| **Decision Engine** | `proxy/ml/decision_engine.py` | Threshold-based policy gate |
| **Pipeline Orchestrator** | `proxy/ml/pipeline_orchestrator.py` | Coordinates ML stages |
| **Two-Stage Pipeline** | `proxy/ml/two_stage_pipeline.py` | Training & evaluation workflow |
| **Risk Scorer** | `proxy/risk/risk_scorer.py` | CVSS v3.1 scoring engine |
| **Alert Queue** | `proxy/utils/alert_queue.py` | SOC state machine + persistence |
| **Incident Correlator** | `proxy/utils/incident_correlator.py` | Alert grouping (IP+type+time) |
| **Trace Logger** | `proxy/utils/trace_logger.py` | Pipeline trace store (XAI) |
| **SOC Dashboard** | `proxy/soc-dashboard/` | SPA frontend (HTML/CSS/JS + Chart.js) |
| **Moodle Plugin** | `moodle-plugin/` | PHP plugin (46 files, 8 subdirs) |

### 2.3 Dependency Stack

**Python Backend** (`proxy/requirements.txt`):

| Category | Package | Version |
|---|---|---|
| Web Framework | FastAPI | 0.104.1 |
| ASGI Server | Uvicorn | 0.24.0 |
| Validation | Pydantic | 2.5.0 |
| HTTP Client | httpx[http2] | 0.25.1 |
| ML Core | scikit-learn | ≥1.3.0 |
| ML Boosting | XGBoost | ≥2.0.0 |
| Data | NumPy ≥1.24, Pandas ≥2.0 | — |
| Serialization | joblib | ≥1.3.0 |
| HTML Parsing | BeautifulSoup4 | 4.12.2 |
| PDF Reports | ReportLab | 4.0.7 |
| Database | aiosqlite | 0.19.0 |
| Security | cryptography | ≥41.0.0 |

---

## 3. OPERATIONAL MODES

Source: `proxy/config.py`

### 3.1 Mode Configuration Matrix

| Flag | Value | Effect |
|---|---|---|
| `DEMO_MODE` | `True` | Detects but **never blocks**. All ML pipeline active. |
| `SOC_MODE` | `True` | Requires `DEMO_MODE=True`. Queues alerts for human review. |
| `ANOMALY_DETECTION_ENABLED` | `True` | Post-forward behavioral anomaly detection active |
| `ANOMALY_BLOCK_ON_DETECTION` | `False` | Post-forward anomaly is observability-only |
| `ANOMALY_BLOCK_THRESHOLD` | `0.95` | Would trigger block if enabled |

### 3.2 Current Thesis Demo Configuration

```python
DEMO_MODE = True        # Monitoring-only (safe for live demo)
SOC_MODE = True         # Human-in-the-loop alert queue
MOODLE_URL = "http://localhost/"
LISTEN_PORT = 8999
SOC_ADMIN_TOKEN = "moodlesec2024"
```

### 3.3 Enforcement Decision Tree (from app.py lines 2767–2963)

```
ML Decision = BLOCK or ALERT?
├── YES
│   ├── Trusted scanner request? → BYPASS (forward)
│   ├── DEMO_MODE + SOC_MODE?
│   │   ├── Admin override = BLOCK? → HTTP 403
│   │   ├── Admin override = ALLOW/IGNORE? → Forward
│   │   └── No override? → Queue alert + Forward (PENDING_ADMIN_ACTION)
│   ├── DEMO_MODE only? → Log + Forward (never block)
│   ├── Production BLOCK? → HTTP 403 + enforcement sync
│   └── Production ALERT? → Log + Forward
└── NO (IGNORE) → Forward to Moodle
```

---

## 4. MIDDLEWARE ARCHITECTURE

### 4.1 Enforcement Middleware (app.py line 92–109)

**Purpose**: Blocks replayed attacks using fingerprint memory.

```python
fingerprint = f"{request.method}:{norm_path}:{client_ip}"
if alert_queue.is_fingerprint_blocked(fingerprint):
    return JSONResponse(status_code=403, content={"detail": "Blocked request (policy enforced)"})
```

- Normalizes trailing slashes (`/search` == `/search/`)
- O(1) lookup via `_blocked_fingerprints` set in AlertQueue
- Fires on **every** request before any route handler

### 4.2 SOC Dashboard Gate (app.py line 114–149)

**Purpose**: Protects `/dashboard` and `/soc/` routes.

- Localhost always allowed (127.0.0.1, ::1)
- Remote clients authenticate via `?token=moodlesec2024`
- Sets `soc_session` httponly cookie (24h TTL)
- Returns HTTP 403 for unauthorized remote access

### 4.3 CORS Policy (app.py line 154–166)

Allows: `localhost`, `127.0.0.1`, `192.168.0.235` (all on port 8999).

---

## 5. REVERSE PROXY MECHANISM

### 5.1 Catch-All Route (app.py line 2693)

```python
@app.api_route("/{path:path}", methods=["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"])
async def proxy_request_catchall(request: Request, path: str) -> Response:
```

**MUST be last route** — forwards all unmatched requests to Moodle backend.

### 5.2 Request Processing Flow

1. **Enforcement middleware** checks fingerprint block list
2. **SOC gate** checks dashboard access
3. **ML Pipeline** runs `process_http_request()` pre-forward
4. **Decision enforcement** (BLOCK → 403, else continue)
5. **httpx forward** to `MOODLE_URL/{path}` with 30s timeout
6. **Post-forward anomaly** detection (observability only)
7. **Response logging** with ML metadata

### 5.3 Traffic Telemetry

Rolling window (`deque`) tracks last 60 seconds:
- Request count per minute
- Unique IPs per minute  
- Error rate (HTTP ≥400)

Used by post-forward anomaly detector for behavioral context.
