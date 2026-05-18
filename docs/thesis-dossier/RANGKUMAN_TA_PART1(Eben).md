# RANGKUMAN TEKNIS MOODLESEC — PART 1 (BAB 1–3)
## Untuk Referensi Penulisan Paper TA — Calvin Institute of Technology (CIT)

> **Proyek:** MoodleSec — Adaptive Security Monitoring System for Moodle LMS
> **Institusi:** Calvin Institute of Technology (CIT), Jakarta — Prodi IBDA
> **Anggota:** Krisopras (FP Reducer, Scanner Engine, Plugin) & Nathanael (Anomaly Detector, CVSS Engine)
> **Repo:** https://github.com/ebenhaezer19/MoodleSec

---

# BAB 1 — PENDAHULUAN (F-100)

## 1.1 Latar Belakang

Moodle Learning Management System (LMS) merupakan platform e-learning open source yang digunakan oleh lebih dari 300 juta pengguna di seluruh dunia pada lebih dari 240 negara (Moodle HQ, 2024). Sebagai platform yang menangani data sensitif mahasiswa dan proses akademik, keamanan Moodle menjadi aspek kritis yang tidak dapat diabaikan. Data dari CVE (Common Vulnerabilities and Exposures) menunjukkan bahwa Moodle secara konsisten menerima laporan kerentanan keamanan setiap tahun, mencakup kategori SQL Injection, Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), dan berbagai jenis vulnerability lainnya.

Permasalahan utama dalam implementasi vulnerability scanning pada lingkungan Moodle adalah tingginya tingkat **false positive** yang dihasilkan oleh scanner konvensional. Scanner seperti OWASP ZAP menghasilkan banyak alert yang bukan merupakan kerentanan sesungguhnya, melainkan artefak dari arsitektur Moodle yang kompleks (misalnya: inline JavaScript yang sah terdeteksi sebagai XSS, atau missing security headers yang bersifat informasional). Fenomena ini membuang waktu administrator keamanan dan menurunkan kepercayaan terhadap hasil scanning.

Selain itu, administrator Moodle pada umumnya tidak memiliki tool vulnerability assessment yang terintegrasi langsung ke dalam dashboard Moodle. Tools yang ada bersifat eksternal (standalone), memerlukan konfigurasi terpisah, dan tidak menyajikan hasil dalam konteks spesifik Moodle.

Berdasarkan permasalahan tersebut, proyek ini mengembangkan **MoodleSec**, sebuah sistem monitoring keamanan adaptif yang terintegrasi langsung sebagai Moodle plugin. MoodleSec mengombinasikan custom vulnerability scanner dengan machine learning-based false positive reducer, sehingga menghasilkan alert keamanan yang lebih akurat dan actionable bagi administrator.

## 1.2 Rumusan Masalah

1. **RM-1:** Bagaimana membangun arsitektur proxy service yang dapat mengintegrasikan multi-scanner dengan Moodle LMS?
2. **RM-2:** Bagaimana ML pipeline dapat mereduksi false positive dari hasil vulnerability scanner?
3. **RM-3:** Bagaimana sistem CVSS scoring dapat disesuaikan dengan konteks lingkungan Moodle?
4. **RM-4:** Bagaimana sistem memberikan rekomendasi mitigasi yang kontekstual kepada administrator?

## 1.3 Maksud dan Tujuan

**Maksud:** Mengembangkan sistem monitoring keamanan adaptif untuk Moodle LMS yang menggabungkan vulnerability scanning dengan machine learning untuk mereduksi false positive.

**Tujuan:**
1. Membangun arsitektur FastAPI proxy service yang mengorkestrasi multi-scanner (SQLi, XSS, CSRF, Path Traversal) dan terintegrasi dengan Moodle melalui plugin PHP.
2. Mengembangkan ML pipeline (RF+GB Ensemble) yang mampu mereduksi false positive dari hasil scanner dengan CV accuracy ≥ 90%.
3. Mengimplementasikan CVSS v3.1 scoring engine yang dikontekstualisasi untuk lingkungan Moodle.
4. Menyediakan rekomendasi mitigasi kontekstual berdasarkan kategori kerentanan dan skor CVSS.

[GAMBAR 1: Diagram Use Case — Admin interaksi dengan Security Dashboard Moodle]

---

# BAB 2 — METODOLOGI / TINJAUAN PUSTAKA (F-200)

## 2.1 Metode Penelitian

Pengembangan MoodleSec menggunakan pendekatan **iteratif-inkremental** dengan 5 fase pengembangan ML pipeline dan pengembangan paralel antara komponen scanner, ML, dan plugin. Setiap fase didokumentasikan dengan masalah yang ditemukan, perbaikan yang dilakukan, dan metrik evaluasi yang dihasilkan.

**Tahapan pengembangan:**
1. **Fase Eksplorasi** — Studi literatur, analisis kerentanan Moodle, pemilihan teknologi
2. **Fase Arsitektur** — Perancangan sistem 4-layer (Plugin → Proxy → ML → Scanner)
3. **Fase Implementasi Iteratif** — 5 fase ML pipeline + pengembangan scanner + plugin
4. **Fase Integrasi** — Penggabungan seluruh komponen end-to-end
5. **Fase Evaluasi** — Pengujian dengan 5-fold CV, holdout test, dan production scan

## 2.2 Tinjauan Pustaka

### 2.2.1 Moodle LMS dan Aspek Keamanannya
Moodle adalah platform LMS open source berbasis PHP yang menggunakan arsitektur plugin modular. Moodle memiliki mekanisme keamanan bawaan seperti sesskey (CSRF token), parameterized queries, dan output encoding, namun konfigurasi yang tidak tepat atau plugin pihak ketiga dapat membuka celah keamanan.

### 2.2.2 OWASP Top 10 dan Vulnerability Scanning
OWASP Top 10 (2021) mengidentifikasi kerentanan web yang paling kritis, termasuk Injection (A03), Cross-Site Scripting (A07), dan Security Misconfiguration (A05). Dynamic Application Security Testing (DAST) tools seperti OWASP ZAP melakukan scanning dengan mengirimkan payload berbahaya dan menganalisis respons.

### 2.2.3 False Positive dalam Security Scanning
False positive (FP) adalah alert yang salah mengidentifikasi kondisi aman sebagai kerentanan. Penelitian menunjukkan bahwa scanner konvensional menghasilkan FP rate 30–80% tergantung pada kompleksitas aplikasi (Holm et al., 2011). FP yang tinggi menyebabkan *alert fatigue* dan menurunkan efektivitas security operations.

### 2.2.4 Machine Learning untuk Klasifikasi Kerentanan
Pendekatan ML untuk klasifikasi kerentanan menggunakan fitur yang diekstrak dari finding scanner (severity, category, evidence text, URL pattern) untuk membedakan true positive dari false positive. Algoritma ensemble seperti Random Forest dan Gradient Boosting menunjukkan performa baik pada task klasifikasi biner dengan dataset kecil.

### 2.2.5 CVSS v3.1 (Common Vulnerability Scoring System)
CVSS v3.1 adalah standar industri untuk menilai keparahan kerentanan. Skor CVSS terdiri dari Base Score, Temporal Score, dan Environmental Score, dengan range 0.0–10.0 dan klasifikasi None/Low/Medium/High/Critical.

### 2.2.6 FastAPI sebagai Middleware Service
FastAPI adalah framework Python modern berbasis ASGI yang mendukung asynchronous processing, auto-generated API documentation (OpenAPI), dan validasi input dengan Pydantic. FastAPI dipilih karena performa tinggi dan kemudahan integrasi dengan ML libraries (scikit-learn, joblib).

## 2.3 Alternatif Solusi dan Alasan Pemilihan

### Alternatif 1: Menggunakan OWASP ZAP secara standalone
- **Kelebihan:** Mature tool, komunitas besar, banyak plugin
- **Kekurangan:** Tidak terintegrasi ke Moodle dashboard, FP rate tinggi, tidak ada ML filtering, memerlukan konfigurasi terpisah
- **Alasan tidak dipilih:** Tidak menyelesaikan masalah utama (FP tinggi dan kurangnya integrasi)

### Alternatif 2: Menggunakan Acunetix / Burp Suite (komersial)
- **Kelebihan:** Akurasi scanning tinggi, fitur lengkap
- **Kekurangan:** Lisensi mahal, closed source, tidak dapat di-customize untuk konteks Moodle, tidak open source
- **Alasan tidak dipilih:** Biaya lisensi tidak sesuai untuk konteks institusi pendidikan, dan tidak mendukung kustomisasi ML pipeline

### Alternatif 3: Custom Scanner + ML Pipeline (MoodleSec) — **DIPILIH**
- **Kelebihan:** Terintegrasi langsung ke Moodle sebagai plugin native, ML-based FP reduction, fully customizable, open source, kontekstualisasi CVSS untuk Moodle
- **Kekurangan:** Memerlukan pengembangan dari nol, dataset masih terbatas
- **Alasan dipilih:** Menyelesaikan semua masalah yang diidentifikasi — FP reduction, integrasi dashboard, dan kontekstualisasi Moodle. Hybrid approach (ML + rule-based) memberikan robustness.

### Tabel Perbandingan Solusi

| Kriteria | OWASP ZAP | Acunetix | **MoodleSec** |
|---|---|---|---|
| Integrasi Moodle | ❌ Tidak | ❌ Tidak | ✅ Plugin native |
| ML FP Reduction | ❌ Tidak | ❌ Tidak | ✅ RF+GB Ensemble |
| CVSS Kontekstual | ❌ Generik | ⚠️ Partial | ✅ Moodle-specific |
| Biaya | Gratis | Mahal | Gratis (Open Source) |
| Kustomisasi | ⚠️ Limited | ❌ Closed | ✅ Full |
| Kemudahan Admin | ⚠️ Terpisah | ⚠️ Terpisah | ✅ Dalam dashboard |

## 2.4 Teknologi yang Digunakan

| Komponen | Teknologi | Versi |
|---|---|---|
| LMS Platform | Moodle | 4.x |
| Plugin Language | PHP | 7.4+ |
| Proxy Framework | FastAPI (Python) | - |
| ASGI Server | Uvicorn | - |
| ML Library | scikit-learn | - |
| ML Algorithms | RandomForest, GradientBoosting, CalibratedClassifierCV | - |
| Model Persistence | joblib | - |
| Plugin Database | MySQL/MariaDB (Moodle native) | - |
| Proxy Database | SQLite | - |
| HTTP Client | httpx | - |
| Frontend | HTML, CSS, JavaScript, jQuery/AJAX | - |
| Version Control | Git + GitHub | - |

---

# BAB 3 — DESAIN (F-300)

## 3.1 Arsitektur Sistem

MoodleSec menggunakan arsitektur **4-layer** yang memisahkan concern antara presentasi, orkestrasi, machine learning, dan scanning:

```
┌──────────────────────────────────────────────────────┐
│  LAYER 1: Moodle Plugin (PHP)                        │
│  /local/security_dashboard/                          │
│  ├── index.php (Dashboard + Vulnerability Trends)    │
│  ├── scan.php (Trigger Scan)                         │
│  ├── ml_dashboard.php (ML Metrics + PR Curve)        │
│  ├── zap_results.php (Scan Results + ML Banner)      │
│  ├── native_auth_scan.php (Authenticated Scan)       │
│  ├── lib.php (Core functions + ml_filter_findings)   │
│  └── classes/api_client.php (Proxy API calls)        │
├──────────────────────────────────────────────────────┤
│  LAYER 2: FastAPI Proxy Service (Python)             │
│  Port: 8999 (Proxy) → Moodle: Port 8998             │
│  ├── app.py (2603 lines — API endpoints)             │
│  ├── routers/ (payload_router, scanner_router)       │
│  ├── database/ (scan_history, payload_repository)    │
│  └── integrations/ (ml_pipeline_integration)         │
├──────────────────────────────────────────────────────┤
│  LAYER 3: ML Pipeline                                │
│  ├── ml/false_positive_reducer.py (646 lines)        │
│  │   └── RF+GB Ensemble, 14 features (Clean-14)      │
│  ├── ml/ml_manager.py (ML orchestration)             │
│  ├── ml/models/fp_reducer.pkl (trained model)        │
│  └── evaluate_model.py (full evaluation script)      │
├──────────────────────────────────────────────────────┤
│  LAYER 4: Custom Scanner Engine                      │
│  ├── scanners/scanner_engine.py (orchestrator)       │
│  ├── scanners/sql_injection.py (27 patterns, 20 payloads) │
│  ├── scanners/xss_detector.py (7 HTML patterns, 16 payloads) │
│  ├── scanners/csrf_validator.py (16 token patterns)  │
│  ├── scanners/path_traversal.py                      │
│  ├── scanners/payload_injector.py (POST+GET support) │
│  └── scanners/recommendation_engine.py (L2-L7)      │
└──────────────────────────────────────────────────────┘
```

[GAMBAR 2: Diagram Arsitektur 4-Layer MoodleSec]

## 3.2 Alur Data End-to-End

```
Admin klik "Trigger Scan" di Moodle Dashboard (scan.php)
    │
    ▼
Moodle Plugin (PHP) → POST request ke FastAPI proxy (port 8999)
    │  endpoint: /api/scan-native-auth
    ▼
FastAPI: Native Authentication → Login ke Moodle dengan kredensial
    │
    ▼
Web Crawler: Crawl halaman target, discover endpoints dan forms
    │  (detect form method: GET/POST, extract input fields)
    ▼
Scanner Engine: Orkestrasi 4 scanner secara paralel
    │  ├── SQL Injection Scanner (27 error patterns, 20 payloads)
    │  ├── XSS Scanner (7 HTML patterns, 16 payloads)
    │  ├── CSRF Validator (16 token patterns)
    │  └── Path Traversal Scanner
    ▼
Payload Injector: Inject payloads ke setiap parameter endpoint
    │  (POST body injection + GET query injection)
    ▼
Raw Findings dikumpulkan (~29 findings pada production scan)
    │
    ▼
ML FP Reducer: Klasifikasi setiap finding (TP atau FP)
    │  ├── Extract 14 features (Clean-14)
    │  ├── Scale features (StandardScaler)
    │  ├── Predict via CalibratedClassifierCV(VotingClassifier(RF+GB))
    │  └── Filter findings dengan confidence > 60%
    │  Hasil: 25 findings difilter sebagai FP (86.2%)
    ▼
Rule-based Filter (Heuristic Backup)
    │  ├── Pattern: Info severity + short evidence → FP
    │  ├── Pattern: "missing" + "header" → FP
    │  ├── Pattern: Educational context without exploit markers → FP
    │  └── Hasil: 3 findings tambahan difilter (10.3%)
    ▼
CVSS v3.1 Scoring: Hitung skor untuk remaining findings
    │  (Kontekstualisasi: /admin/* mendapat multiplier lebih tinggi)
    ▼
Recommendation Engine: Generate rekomendasi mitigasi per finding
    │
    ▼
Simpan ke SQLite database (scan_history)
    │
    ▼
Response ke Moodle Plugin → Tampil di Dashboard
    Final: 1 confirmed Critical SQL Injection finding
    FP Reduction Rate: 28/29 = 96.6%
```

[GAMBAR 3: Sequence Diagram Alur Scan End-to-End]

## 3.3 Desain ML Pipeline — False Positive Reducer

### 3.3.1 Perjalanan Pengembangan (5 Fase Iteratif)

| Fase | Dataset | Samples | CV Accuracy | Masalah Kritis | Status |
|---|---|---|---|---|---|
| Phase 0 | Synthetic | 186 | 99.3% ±1.3% | CVSS data leakage (d=5.23) | ❌ Tidak valid |
| Phase 2 | Real HAR imbalanced | 46 | 72% / 47.3% balanced | Class imbalance 82:18 | ❌ Underpowered |
| Phase 3 buggy | Real HAR balanced | 76 | 100% ±0% | 5 extraction bugs | ❌ Artefak |
| Phase 3 fixed | Real HAR balanced | 76 | 89.3% ±8.4% | has_post_data artifact | ⚠️ Caveat |
| **Phase 5 Clean-14** | **Finding-level** | **86** | **92.9% ±6.9%** | Borderline keywords | **✅ Valid** |

### 3.3.2 Arsitektur Model Final (Phase 5 Clean-14)

```
Input: Security Finding (dict)
    │
    ▼
Feature Extraction (14 fitur Clean-14)
    │
    ▼
StandardScaler (normalisasi)
    │
    ▼
CalibratedClassifierCV (method='sigmoid', cv=3)
    └── VotingClassifier (voting='soft', weights=[2, 1])
        ├── RandomForestClassifier
        │   n_estimators=100, max_depth=8
        │   min_samples_split=6, min_samples_leaf=3
        │   max_features='sqrt', class_weight='balanced'
        │
        └── GradientBoostingClassifier
            n_estimators=75, max_depth=4
            learning_rate=0.05, subsample=0.8
            min_samples_split=6, min_samples_leaf=3
    │
    ▼
Output: (is_false_positive: bool, confidence: float)
```

### 3.3.3 Fitur yang Digunakan (Clean-14)

| # | Nama Fitur | Tipe | Sumber | Deskripsi |
|---|---|---|---|---|
| 1 | severity | Encoded (1–5) | Finding | Info=1, Low=2, Medium=3, High=4, Critical=5 |
| 2 | category | Encoded (1–19) | Finding | SQLi=1, XSS=2, CSRF=3, dst (19 kategori) |
| 3 | evidence_length | Float (0–10) | Finding | len(evidence)/100, capped at 10 |
| 4 | description_length | Float (0–10) | Finding | len(description)/100, capped at 10 |
| 5 | url_complexity | Int (0–10) | Finding | Jumlah segmen '/' pada URL |
| 6 | has_params | Binary (0/1) | Finding | 1 jika URL mengandung '?' |
| 7 | cvss_score | Float | Finding | Dinolkan (=0.0) untuk anti-leakage |
| 8 | risk_score | Float | Finding | Dinolkan (=0.0) untuk anti-leakage |
| 9 | fp_keyword_count | Int | Description | Jumlah FP pattern words: "missing", "header", dst. |
| 10 | tp_keyword_count | Int | Description | Jumlah TP pattern words: "injection", "xss", dst. |
| 11 | keyword_ratio | Float (0–1) | Derived | fp_count / (fp_count + tp_count) |
| 12 | is_informational | Binary (0/1) | Derived | 1 jika severity ∈ {info,low} AND tp_count=0 |
| 13 | status_code | Int | Context | HTTP response code (200, 302, 500, dst.) |
| 14 | response_time | Float | Context | Response time dalam milliseconds |

**Fitur yang DIHAPUS (shortcut prevention):**
- `occurrence_count`: Dihapus karena single-feature accuracy 95.3% → shortcut
- `days_since_first_seen`: Dihapus karena berkorelasi dengan occurrence_count (d=1.53)

### 3.3.4 FP/TP Keyword Patterns (Domain Knowledge)

**FP Keywords** (10 kata — indikator informasional/best-practice):
`missing`, `not implemented`, `not set`, `header`, `best practice`, `recommendation`, `information`, `disclosure`, `version`, `banner`

**TP Keywords** (11 kata — indikator kerentanan eksploitabel):
`injection`, `xss`, `csrf`, `bypass`, `exploit`, `vulnerability`, `attack`, `malicious`, `unauthorized`, `exposed`, `sensitive`

Sumber: OWASP Top 10, CVE Common Patterns, SANS Security Guidelines — bukan turunan dari training labels.

## 3.4 Desain Custom Scanner Engine

### 3.4.1 SQL Injection Scanner
- **27 error patterns** dari 5 RDBMS: MySQL/MariaDB (7), PostgreSQL (4), MSSQL (6), Oracle (5), Generic (5)
- **20 static payloads** + smart payloads dari PayloadRepository
- Kategori payload: Basic (6), Union-based (2), Time-based blind (2), Boolean-based blind (2), Comment (4), Stacked (1), Special chars (3)
- Request timeout 30 detik untuk mendukung time-based blind SQLi

### 3.4.2 XSS Scanner
- **7 HTML context patterns** (script, iframe, object, embed, applet, javascript:, event handlers)
- **16 static payloads** + smart payloads dari repository
- **10 dangerous HTML tags** terdeteksi
- **23 event handlers** yang dapat mengeksekusi JavaScript
- Mendukung deteksi: Reflected XSS, DOM-based XSS, filter bypass, template injection

### 3.4.3 CSRF Validator
- **16 token parameter names** yang dikenali (termasuk Moodle-specific: `sesskey`)
- Validasi pada state-changing methods: POST, PUT, DELETE, PATCH
- Deteksi missing token, weak token, dan expired token

### 3.4.4 Payload Injector
- Mendukung injeksi pada **GET query parameters** dan **POST body**
- Auto-detect form method dari HTML response
- Deduplication findings via MD5 hash
- Tracking statistik penggunaan payload via `record_usage()`

## 3.5 Desain Moodle Plugin

### 3.5.1 Struktur Plugin
```
/local/security_dashboard/
├── index.php          ← Main dashboard + vulnerability trends (SVG)
├── scan.php           ← Manual trigger scan (path + query string support)
├── ml_dashboard.php   ← ML metrics + Precision-Recall curve (SVG)
├── native_auth_scan.php ← Authenticated scan
├── fullscan.php       ← Full scan mode
├── zap_results.php    ← Scan results + ML stats banner
├── reports.php        ← PDF report generation
├── lib.php            ← Core functions (ml_filter_findings, health check)
├── settings.php       ← Admin settings
├── styles.css         ← Dashboard styling
├── classes/
│   └── api_client.php ← FastAPI proxy communication
├── lib/
│   └── zap_integration.php ← ZAP API integration
└── db/
    ├── install.xml    ← Database schema
    ├── events.php     ← Event observers (cleared — anomaly detector handles)
    └── tasks.php      ← Cron tasks (cleared — anomaly detector handles)
```

### 3.5.2 Komunikasi Plugin ↔ Proxy

| Endpoint FastAPI | Method | Fungsi |
|---|---|---|
| `/api/scan-native-auth` | POST | Memulai authenticated scan |
| `/ml/post-process-zap` | POST | Filter ZAP results dengan ML real-time |
| `/health` | GET | Health check proxy + CVSS engine |
| `/ml/status` | GET | Status model ML (trained/not) |
| `/ml/dashboard/recent-scans` | GET | Data untuk dashboard trends |
| `/api/payloads/reload` | POST | Reload scanner payloads |

### 3.5.3 Desain Dashboard

**Fitur visual dashboard:**
- Service health status banner (proxy online/offline)
- Vulnerability Trends chart (pure PHP SVG — stacked bar, no external CDN)
- Color-coded severity badges (Critical=merah tua, High=oranye, Medium=kuning, Low=hijau)
- ML Stats Banner: "Raw: N | FPs removed: M | Final: K"
- Scan history table dengan ML filtering statistics
- Precision-Recall curve di ML Dashboard (pure PHP SVG)
- GPT/LLM recommendation settings panel

## 3.6 Desain Database

### 3.6.1 SQLite (Proxy Side)
- `scan_history`: Menyimpan semua scan results dan findings
- `payload_repository`: Menyimpan payload database dengan statistik keberhasilan
- `payload_usage_log`: Log penggunaan setiap payload (success/fail tracking)

### 3.6.2 MySQL/MariaDB (Moodle Side)
- Menggunakan Moodle database API (XMLDB) untuk tabel plugin-specific
- Schema didefinisikan di `db/install.xml`

[GAMBAR 4: Entity Relationship Diagram (ERD) MoodleSec]

## 3.7 Desain CVSS Engine (Nathanael)

- Implementasi CVSS v3.1 dengan Base Score, Temporal Score, Environmental Score
- Kontekstualisasi Moodle: endpoint `/admin/*` mendapat environmental multiplier lebih tinggi
- Output: skor numerik (0.0–10.0) + klasifikasi (None/Low/Medium/High/Critical)
- Integrasi: dipanggil setelah ML filtering untuk scoring remaining findings

## 3.8 Desain Anomaly Detector (Nathanael)

- Algoritma: IsolationForest (unsupervised)
- Input: 17 features termasuk temporal patterns
- Training data: 306 normal behaviour samples
- Output: anomaly score untuk deteksi zero-day attack patterns
- Runtime controls: configurable di `config.py` (threshold, block mode, lookback window)
