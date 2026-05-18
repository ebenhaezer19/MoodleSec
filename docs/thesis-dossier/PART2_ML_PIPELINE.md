# MoodleSec Technical Dossier — Part 2: ML Pipeline

---

## 6. ML PIPELINE — TWO-STAGE SECURITY ARCHITECTURE

### 6.1 Pipeline Overview

```
HTTP Request
    │
    ▼
┌───────────────────┐
│ Feature Extraction │  35 statistical features
│ (ml_pipeline_      │  (header entropy, response time,
│  integration.py)   │   traffic patterns, payload analysis)
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│ STAGE 1: Anomaly  │  Isolation Forest (unsupervised)
│ Detector          │  → anomaly_score [0.0 – 1.0]
│ (anomaly_         │  → is_anomaly boolean
│  detector.py)     │
└────────┬──────────┘
         │ anomaly detected?
         ▼
┌───────────────────┐
│ STAGE 2: Attack   │  XGBoost + Contextual Heuristics
│ Classifier        │  → attack_type (xss, sqli, path_traversal,
│ (attack_          │     command_injection, ssrf, normal)
│  classifier.py)   │  → confidence [0.0 – 1.0]
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│ STAGE 3: FP       │  Random Forest Classifier
│ Reducer           │  → is_false_positive boolean
│ (anomaly_false_   │  → fp_confidence
│  positive_        │  → 73% FP reduction rate
│  reducer.py)      │
└────────┬──────────┘
         │
         ▼
┌───────────────────┐
│ Decision Engine   │  Rule-based policy gate
│ (decision_        │  → BLOCK / ALERT / IGNORE
│  engine.py)       │  → severity (HIGH/MEDIUM/LOW)
└───────────────────┘
```

### 6.2 Model Loading Strategy — Lazy Singleton

Source: `proxy/ml/ml_manager.py`

```python
class MLManager:
    """Lazy-loading singleton — models load on FIRST request, not at boot."""
    
    def __init__(self):
        self.enable_ml = True
        self._anomaly_detector = None   # Loaded on first detect_anomaly()
        self._fp_reducer = None         # Loaded on first filter_findings()
        self._severity_predictor = None # Loaded on first filter_findings()
```

**Design Rationale**: FastAPI starts in <500ms; ML models (≈50MB total) load lazily on first request to avoid blocking service availability.

---

## 7. STAGE 1 — ANOMALY DETECTOR

Source: `proxy/ml/anomaly_detector.py`

### 7.1 Algorithm

| Property | Value |
|---|---|
| **Model** | Isolation Forest (scikit-learn) |
| **Type** | Unsupervised anomaly detection |
| **Training** | Normal traffic distribution only |
| **Feature Count** | 35 statistical features |
| **Output** | `anomaly_score` ∈ [0.0, 1.0], `is_anomaly` boolean |

### 7.2 Feature Engineering (35 features)

Features are extracted from raw HTTP request/response pairs:

- **Header entropy** — Shannon entropy of request headers
- **Response time** — Latency in milliseconds
- **Body size ratio** — Request body / response body
- **URL depth** — Path segment count
- **Query parameter count** — Number of URI params
- **Special character density** — In URL, headers, body
- **HTTP method encoding** — Categorical to numeric
- **Status code grouping** — 2xx/3xx/4xx/5xx
- **Traffic rate features** — requests/min, unique IPs/min, error rate
- **Payload structural features** — Token length distribution

### 7.3 Calibration

The anomaly detector uses multi-tiered scaling and calibration:
- Raw Isolation Forest `decision_function` scores → normalized via MinMax to [0,1]
- Calibration parameters maintain recall/FP balance
- Threshold tuning ensures high recall (0.967) while controlling FPR (0.089)

### 7.4 Evaluation Metrics (Stage 1)

| Metric | Value |
|---|---|
| Accuracy | 0.934 |
| Precision | 0.891 |
| Recall | **0.967** |
| F1-Score | 0.928 |
| False Positive Rate | 0.089 (8.9%) |

---

## 8. STAGE 2 — ATTACK CLASSIFIER

Source: `proxy/ml/attack_classifier.py`

### 8.1 Algorithm

| Property | Value |
|---|---|
| **Model** | XGBoost (Gradient Boosted Trees) |
| **Type** | Supervised multi-class classification |
| **Classes** | `normal`, `xss`, `sqli`, `path_traversal`, `command_injection`, `ssrf` |
| **Output** | `attack_type` string, `confidence` ∈ [0.0, 1.0] |

### 8.2 Contextual Heuristics (FP Suppression)

The classifier implements **natural-language context filtering** specifically for academic LMS environments:

- **Academic content detection**: Recognizes tutorial/educational content about XSS, SQL injection (e.g., "how to prevent SQL injection") and suppresses false positives
- **Structural analysis**: Distinguishes active attack payloads from passive educational references
- **Moodle-specific paths**: Context-aware for Moodle URL patterns (course forums, assignment submissions)

### 8.3 Evaluation Metrics (Stage 2)

| Metric | Value |
|---|---|
| Accuracy | 0.947 |
| Precision | 0.932 |
| Recall | 0.941 |
| F1-Score | **0.936** |
| False Positive Rate | 0.053 (5.3%) |

---

## 9. STAGE 3 — FALSE POSITIVE REDUCER

Source: `proxy/ml/anomaly_false_positive_reducer.py`

### 9.1 Algorithm

| Property | Value |
|---|---|
| **Model** | Random Forest Classifier (voting ensemble) |
| **Ensemble** | Random Forest + Gradient Boosting |
| **Calibration** | Sigmoid output calibration |
| **Training Data** | Stage-1 validation predictions ONLY |
| **Output** | `is_false_positive` boolean, `fp_confidence` ∈ [0.0, 1.0] |

### 9.2 Data Leakage Prevention

**Critical Design Decision**: The FP Reducer is trained ONLY on Stage-1 validation set predictions, NOT on training set outputs. This prevents data leakage where the model would learn the training set distribution rather than generalization patterns.

Source: `proxy/ml/two_stage_pipeline.py`

```
Dataset Split (15,847 samples):
├── Training: 60% → Used to train Stage-1 Anomaly Detector
├── Validation: 20% → Stage-1 predicts on this → Used to train FP Reducer
└── Test: 20% → Final evaluation (never seen during any training)
```

### 9.3 Evaluation Metrics (Stage 3)

| Metric | Value |
|---|---|
| Accuracy | 0.962 |
| Precision | **0.971** |
| Recall | 0.943 |
| F1-Score | 0.957 |
| FP Reduction Rate | **73%** |

---

## 10. DECISION ENGINE

Source: `proxy/ml/decision_engine.py` (312 lines)

### 10.1 Threshold Configuration

| Parameter | Value | Purpose |
|---|---|---|
| `high_anomaly` | 0.70 | Anomaly score → HIGH severity |
| `low_anomaly` | 0.40 | Anomaly score → MEDIUM vs LOW |
| `high_confidence` | 0.70 | Classifier confidence → BLOCK |
| `low_confidence` | 0.40 | Classifier confidence → ALERT vs IGNORE |

### 10.2 Decision Matrix

```
                    Confidence
                 HIGH (≥0.70)    MED (0.40-0.70)   LOW (<0.40)
Anomaly  HIGH    BLOCK           ALERT              ALERT
Score    MED     ALERT           ALERT              IGNORE
         LOW     ALERT           IGNORE             IGNORE
```

### 10.3 Severity Mapping

| Decision | Anomaly Score | Severity |
|---|---|---|
| BLOCK | ≥0.70 | HIGH |
| BLOCK | <0.70 | MEDIUM |
| ALERT | ≥0.40 | MEDIUM |
| ALERT | <0.40 | LOW |
| IGNORE | any | LOW |

---

## 11. COMBINED PIPELINE METRICS

### 11.1 End-to-End Performance

| Metric | Value |
|---|---|
| End-to-End Accuracy | **0.941** |
| End-to-End F1 | **0.933** |
| FPR Before FP Reducer | 0.089 (8.9%) |
| FPR After FP Reducer | **0.024 (2.4%)** |
| FP Reduction | **73.0%** |

### 11.2 Dataset Provenance

| Property | Value |
|---|---|
| **Name** | MoodleSec Combined Dataset |
| **Total Samples** | 15,847 |
| **Train Split** | 60% |
| **Validation Split** | 20% |
| **Test Split** | 20% |
| **Attack Types** | XSS, SQL Injection, Path Traversal, Command Injection, SSRF, Normal |
| **Augmentation** | Synthetic payloads + ZAP scanner outputs |

### 11.3 Serialized Model Inventory

| Model File | Size | Purpose |
|---|---|---|
| `anomaly_detector.pkl` | 1.85 MB | Stage-1 Isolation Forest |
| `attack_classifier.pkl` | 44.4 MB | Stage-2 XGBoost classifier |
| `fp_reducer.pkl` | 910 KB | Stage-3 Random Forest FP reducer |
| `severity_predictor.pkl` | 424 KB | Severity prediction model |
| `severity_predictor.json` | 1.47 MB | Severity predictor (JSON format) |
| `rate_limiter.pkl` | 363 KB | Rate limiting model |
| `feature_importance.json` | 1.4 KB | Feature importance rankings |

**Total model footprint**: ~48 MB
