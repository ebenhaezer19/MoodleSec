# RANGKUMAN TEKNIS MOODLESEC — PART 3
## Praktikal Operasional & Perhitungan Mekanis Skenario

---

# BAGIAN A: PRAKTIKAL OPERASIONAL

## A.1 Spesifikasi Server & Lingkungan Deployment

| Komponen | Spesifikasi Development | Rekomendasi Production |
|---|---|---|
| OS | Ubuntu 22.04 (WSL2) | Ubuntu 22.04 LTS Server |
| CPU | Intel i5/i7 (2+ cores) | 4 cores minimum |
| RAM | 4 GB minimum | 8 GB recommended |
| Storage | 5 GB free minimum | 20 GB recommended |
| Python | 3.11+ | 3.11+ |
| PHP | 7.4+ (Moodle native) | 7.4+ |
| Database | MySQL/MariaDB + SQLite | MySQL 8.0 + SQLite |
| Web Server | Apache2 / Nginx | Nginx (reverse proxy) |

## A.2 Storage Requirements (Verified dari Filesystem)

### Model Files (`proxy/ml/models/`)

| File | Ukuran | Fungsi |
|---|---|---|
| `fp_reducer.pkl` | **172.8 KB** | FP Reducer (RF+GB Ensemble) |
| `anomaly_detector.pkl` | **1,812.9 KB** (1.77 MB) | IsolationForest |
| `rate_limiter.pkl` | 384.2 KB | Rate Limiter (future) |
| `severity_predictor.pkl` | 325.5 KB | Severity Predictor (future) |
| `feature_importance.json` | 1.3 KB | Feature importance data |
| JSON config files | ~1,303.6 KB total | Model configs |
| **Total model storage** | **~3.9 MB** | |

### Codebase Size

| Komponen | Ukuran |
|---|---|
| Proxy service (`proxy/`) | ~5–10 MB (kode saja, tanpa venv) |
| Moodle plugin (`moodle-plugin/`) | **0.64 MB** |
| Python venv (`proxy/venv/`) | ~1.9 GB (scikit-learn, numpy, pandas, dll) |

### Runtime Storage Growth

| Data | Growth Rate | Estimasi |
|---|---|---|
| SQLite scan_history | ~5–10 KB per scan | ~3.6 MB/tahun (1 scan/hari) |
| Log files (`proxy/logs/`) | ~2–5 KB per scan | ~1.8 MB/tahun |
| Payload usage logs | ~1 KB per scan | ~365 KB/tahun |
| **Total runtime growth** | | **~6 MB/tahun** |

## A.3 Memory (RAM) Usage

| Proses | RAM Estimasi |
|---|---|
| FastAPI + Uvicorn (idle) | ~50–80 MB |
| scikit-learn models loaded | ~100–150 MB |
| **Proxy total (running)** | **~150–230 MB** |
| Moodle PHP-FPM | ~100–500 MB |
| MySQL/MariaDB | ~200–500 MB |
| Apache2/Nginx | ~20–50 MB |
| **Total sistem** | **~500 MB–1.3 GB** |

**Catatan:** FP Reducer model (172.8 KB on disk) expands to ~5–15 MB in memory karena tree structures di-deserialize menjadi objek Python (100 RF trees + 75 GB trees + CalibratedClassifierCV wrappers).

## A.4 CPU Usage

| Operasi | CPU Pattern |
|---|---|
| Proxy idle | <1% (event-driven ASGI) |
| Feature extraction (14 fitur) | Burst ~5% selama <1ms |
| ML prediction (per finding) | Burst ~10–15% selama ~2–5ms |
| Scanner crawling | ~15–30% sustained selama crawl |
| Payload injection (concurrent) | ~20–40% per active request |
| Full scan pipeline | ~30–60% selama 2–5 menit |
| Model training (retrain) | ~80–100% selama 5–10 detik |

## A.5 Network/Latency Configuration (Verified dari Code)

| Komponen | Timeout | Sumber |
|---|---|---|
| Web Crawler per page | 10.0 s | `web_crawler.py:155` |
| Payload Injector per request | **30.0 s** | `payload_injector.py:743` |
| Auth client (login) | 30.0 s | `app.py:1533` |
| Proxy-to-Moodle forwarding | 30.0 s | `app.py:320` |
| Scanner per endpoint | 10.0 s | `app.py:522` |
| Slack notifications | 10.0 s | `slack_notifier.py:23` |
| GPT/LLM API calls | 15.0 s | `recommendation_engine.py:381` |
| ZAP integration | 30.0 s | `zap_payload_enhancer.py:126` |

### Port Configuration

| Service | Port | Config Source |
|---|---|---|
| Moodle (Apache) | **8998** | `config.py:13` — `MOODLE_BASE_URL` |
| Proxy (FastAPI) | **8999** | `config.py:16` — `PROXY_LISTEN_PORT` |

---

# BAGIAN B: PERHITUNGAN MEKANIS SETIAP SKENARIO

## B.1 Skenario 1: Single Page Scan (Manual Trigger)

**Alur:** Admin scan 1 halaman (e.g., `/course/view.php?id=1`)

### Tahap 1 — HTTP Request dari Plugin ke Proxy
```
Latency: ~5–20 ms (localhost)
Data: POST body ~200 bytes (URL + credentials)
```

### Tahap 2 — Native Authentication (Login ke Moodle)
```
1 HTTP POST ke /login/index.php
Latency: 100–500 ms
Cookies diperoleh: MoodleSession
```

### Tahap 3 — Crawl Target Page
```
1 halaman di-crawl
Latency: 200–500 ms
Output: endpoints discovered, forms extracted
Typical: 1 endpoint + 0–2 forms = 1–3 scan targets
```

### Tahap 4 — Scanner Engine (per target)
```
Per scan target, 4 scanner dijalankan:
├── SQLi Scanner: pattern matching (< 1 ms)
├── XSS Scanner: pattern matching (< 1 ms)
├── CSRF Validator: token checking (< 1 ms)
└── Path Traversal: pattern matching (< 1 ms)
Subtotal passive scan: ~5 ms per target
```

### Tahap 5 — Payload Injection (per target)
```
Per scan target, payloads diinjeksikan:
├── SQLi payloads: 20 static + N smart (~25 total)
├── XSS payloads: 16 static + N smart (~20 total)
└── CSRF payloads: N smart (~5 total)
Total: ~50 payloads per target

Per payload: 1 HTTP request → Moodle
├── Normal response: 100–500 ms
├── Time-based SQLi (SLEEP): up to 30 s timeout
└── Average: ~300 ms

Payload injection per target:
= 50 payloads × 300 ms avg
= 15,000 ms = 15 detik per target

Untuk 1–3 targets:
= 15–45 detik total payload injection
```

### Tahap 6 — ML Filtering (per finding)
```
Typical raw findings: 5–15 per page

Per finding:
├── Feature extraction: 14 fitur → numpy array: ~0.1 ms
├── StandardScaler.transform: ~0.05 ms
├── CalibratedClassifierCV.predict:
│   ├── VotingClassifier:
│   │   ├── RF (100 trees, depth 8): ~100 × 8 comparisons = ~1 ms
│   │   └── GB (75 trees, depth 4): ~75 × 4 comparisons = ~0.5 ms
│   └── Probability calibration (sigmoid): ~0.05 ms
└── Total per finding: ~2–5 ms

Untuk 10 findings: 10 × 3 ms = 30 ms
```

### Tahap 7 — Rule-based Heuristic (remaining findings)
```
4 pattern checks per finding: ~0.01 ms each
Untuk 10 findings: 10 × 0.04 ms = 0.4 ms (negligible)
```

### Tahap 8 — Response ke Plugin
```
JSON serialization + HTTP response: ~5–10 ms
```

### **Total Skenario 1 (Single Page):**
```
Auth login:        ~300 ms
Crawl (1 page):    ~400 ms
Passive scan:      ~5 ms
Payload injection: ~15–45 s
ML filtering:      ~30 ms
Response:          ~10 ms
─────────────────────────
TOTAL: ~16–46 detik
Typical: ~25 detik
```

---

## B.2 Skenario 2: Full Authenticated Scan (Production)

**Alur:** Admin trigger full scan → crawl + scan semua endpoint

### Tahap 1–2 — Auth Login (sama dengan Skenario 1)
```
~300 ms
```

### Tahap 3 — Full Crawl
```
Crawler config: max_depth=3, max_pages=100
Start URL: /my/ (authenticated dashboard)

Typical Moodle crawl result: 8 halaman visited
Per page: ~200–500 ms
Total: 8 × 350 ms avg = 2.8 detik

Output: ~7 unique endpoints + forms
```

### Tahap 4 — Scanner Engine (7 endpoints)
```
Passive scanning (pattern matching):
7 endpoints × 5 ms = 35 ms (negligible)
```

### Tahap 5 — Payload Injection (7 endpoints)
```
Per endpoint: ~50 payloads × 300 ms = 15 s
7 endpoints: 7 × 15 s = 105 detik

Limit: max 50 endpoints (app.py:519)
Worst case (50 endpoints): 50 × 15 s = 750 s = 12.5 menit
```

### Tahap 6 — ML Filtering
```
Raw findings: ~29 (production actual)
29 × 3 ms = 87 ms

Pipeline result:
├── ML filtered: 25 findings (86.2%)
├── Rule-based filtered: 3 findings (10.3%)
└── Remaining: 1 finding (3.4%)
```

### **Total Skenario 2 (Full Scan — Production Actual):**
```
Auth login:        ~300 ms
Crawl (8 pages):   ~2.8 s
Passive scan:      ~35 ms
Payload injection: ~105 s (7 endpoints)
ML filtering:      ~87 ms
CVSS scoring:      ~5 ms
Response:          ~10 ms
─────────────────────────────
TOTAL: ~108 detik ≈ 1 menit 48 detik
```

### **Worst Case (50 endpoints):**
```
~753 detik ≈ 12.5 menit
```

---

## B.3 Skenario 3: ML Prediction Only (Real-time Filtering)

**Alur:** Existing ZAP results di-filter via `/ml/post-process-zap`

```
Input: N findings dari ZAP (JSON array)

Per finding processing:
├── Feature extraction:     0.1 ms
├── Scaler transform:       0.05 ms
├── Model predict:          2–5 ms
├── Heuristic fallback:     0.01 ms
└── Result formatting:      0.05 ms
Total per finding: ~3 ms

For N findings:
├── N=10:   30 ms
├── N=50:   150 ms
├── N=100:  300 ms
├── N=500:  1.5 s
└── N=1000: 3.0 s

Throughput: ~333 findings/detik
```

---

## B.4 Skenario 4: Model Retraining (Online Learning)

**Alur:** Feedback terakumulasi 50 samples → auto retrain

```
Data preparation: 50 samples × feature extraction
= 50 × 0.1 ms = 5 ms

Train/test split (75/25 stratified):
Train: 37 samples, Test: 13 samples

Model training:
├── StandardScaler.fit_transform: ~1 ms
├── RandomForest.fit(100 trees, depth 8, 37 samples):
│   = 100 trees × O(n × log(n) × features)
│   = 100 × O(37 × 5.2 × 14)
│   ≈ 200–500 ms
├── GradientBoosting.fit(75 trees, depth 4, 37 samples):
│   = 75 iterations × O(n × features)
│   ≈ 100–300 ms
├── VotingClassifier aggregation: ~50 ms
├── CalibratedClassifierCV (3-fold sigmoid): ~500 ms
├── Baseline models (LR + DT + SVM): ~200 ms
└── Model serialization (joblib.dump): ~50 ms

TOTAL RETRAINING: ~1.5–3 detik
CPU: ~80–100% burst
```

---

## B.5 Skenario 5: Dashboard Page Load

**Alur:** Admin buka index.php (Security Dashboard)

```
PHP → GET /ml/dashboard/recent-scans (proxy):
├── SQLite query: ~5–20 ms
├── JSON response: ~5 ms
└── Network: ~5 ms
Subtotal API call: ~15–30 ms

PHP → GET /health (proxy):
├── Status check: ~1 ms
└── Network: ~5 ms
Subtotal: ~6 ms

PHP SVG chart generation (vulnerability trends):
├── Data processing (10 bars): ~1 ms
├── SVG string building: ~2 ms
└── No CDN/JavaScript required
Subtotal: ~3 ms

Moodle page rendering (header/footer/CSS):
~100–300 ms

TOTAL PAGE LOAD: ~150–350 ms
```

---

## B.6 Skenario 6: ML Dashboard + PR Curve

```
PHP → GET /ml/status (proxy):
├── Model info query: ~1 ms
├── Network: ~5 ms
Subtotal: ~6 ms

PHP SVG PR Curve generation:
├── 13 data points calculation: ~0.5 ms
├── SVG polyline + circles: ~1 ms
├── Legend + axes: ~0.5 ms
Subtotal: ~2 ms

Metric cards rendering: ~5 ms
Moodle page: ~100–300 ms

TOTAL PAGE LOAD: ~120–320 ms
```

---

## B.7 Tabel Ringkasan Latency Semua Skenario

| Skenario | Typical | Worst Case | Bottleneck |
|---|---|---|---|
| Single page scan | **~25 s** | ~46 s | Payload injection |
| Full scan (7 endpoints) | **~108 s** | ~180 s | Payload injection |
| Full scan (50 endpoints) | **~750 s** | ~1500 s | Payload injection |
| ML filtering only (29 findings) | **~87 ms** | ~150 ms | Model predict |
| ML filtering (1000 findings) | **~3 s** | ~5 s | Model predict |
| Model retraining (50 samples) | **~2 s** | ~3 s | RF/GB training |
| Dashboard page load | **~200 ms** | ~350 ms | Moodle render |
| ML Dashboard page load | **~180 ms** | ~320 ms | Moodle render |

## B.8 Throughput & Scalability

| Metrik | Nilai |
|---|---|
| ML prediction throughput | ~333 findings/detik |
| Payload injection throughput | ~3.3 payloads/detik (sequential per endpoint) |
| Crawler throughput | ~2.5 pages/detik |
| Concurrent scan support | 1 (single-threaded scan pipeline) |
| Max endpoints per scan | 50 (hardcoded limit, `app.py:519`) |
| Max crawl pages | 100 (configurable, `web_crawler.py:22`) |
| Max crawl depth | 3 (configurable, `web_crawler.py:21`) |

## B.9 Bottleneck Analysis

```
Waktu scan end-to-end breakdown (Skenario 2):

Payload Injection: ████████████████████████████████████ 97.2%  (105 s)
Crawling:          █                                     2.6%  (2.8 s)
Auth Login:        ░                                     0.3%  (0.3 s)
ML Filtering:      ░                                    <0.1%  (87 ms)
Other:             ░                                    <0.1%
```

**Kesimpulan:** Payload injection mendominasi >97% waktu scan. ML filtering sangat cepat (<100ms untuk 29 findings) dan bukan bottleneck. Optimisasi scan time harus fokus pada concurrent payload injection (asyncio gather) dan smart payload selection.
