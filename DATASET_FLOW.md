# 🔬 Alur Dataset MoodleSec — Dari Awal Hingga Output Saat Ini

> Dokumen ini menjelaskan secara lengkap bagaimana seluruh data mengalir — mulai dari pengumpulan mentah, labeling, training, hingga inferensi real-time di dalam sistem MoodleSec.

---

## 📌 Gambaran Besar (Big Picture)

```
┌─────────────────────────────────────────────────────────────┐
│               SUMBER DATA MENTAH                            │
│  ZAP Reports · Acunetix Reports · HAR Files · Scan Lokal   │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│           PREPROCESSING & LABELING (5 Phase)                │
│  Auto-label → Manual Review → Balancing → Cleaning         │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│           TRAINING PIPELINE                                 │
│  FP Reducer (Phase 5 Clean-14) · Anomaly Detector           │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│           SAVED MODELS (.pkl)                               │
│  fp_reducer.pkl · anomaly_detector.pkl                      │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│           RUNTIME INFERENCE (app.py)                        │
│  Scan L2-L7 → ML Pipeline → Dashboard / PDF Report         │
└─────────────────────────────────────────────────────────────┘
```

---

## 🗂️ FASE 1 — Pengumpulan Data Mentah

### 1.1 Sumber Data Eksternal

| Sumber | Format | Lokasi | Isi |
|--------|--------|--------|-----|
| **OWASP ZAP** | JSON | `proxy/data/` & `proxy/ml/training_data/OWASP_ZAP_Data/` | Hasil scan Moodle publik (capacitacion100.milaulas.com, richardsedu, dll) |
| **Acunetix** | JSON | `proxy/ml/training_data/Acunnetix_Data/` | Hasil scan target Moodle cloud (12+ instance) |
| **Scan Lokal** | JSON | `proxy/data/20251124_JSON_http_localhost_8998.json` | Hasil ZAP scan di Moodle lokal port 8998 |
| **Sandbox Moodle** | JSON | `proxy/data/20251201_JSON_https_sandbox_moodledemo_net.json` | Moodle demo publik |

> Total raw data ZAP terbesar: **548 MB** per file (profesoresopp.moodlecloud.com)

### 1.2 Sumber Data Internal (Moodle Scanner sendiri)

Sistem MoodleSec melakukan scan L2–L7 ke `localhost:8998` dan hasilnya disimpan ke:
- `proxy/data/scan_history.db` — database SQLite semua hasil scan
- `proxy/data/payload_repository.db` — payload yang sudah pernah dicoba

---

## 🧹 FASE 2 — Preprocessing & Labeling

### 2.1 Auto-Labeling

Script memproses JSON ZAP/Acunetix dan memberi label otomatis:
- **Label 0 (True Positive / Nyata Berbahaya)** — pattern SQL Injection, XSS, CSRF dengan evidence kuat
- **Label 1 (False Positive / Palsu)** — temuan informatif, missing headers, version disclosure

Hasil disimpan di:
```
proxy/ml/training_data/backup/
  auto_labeled_20251209_*.json
  auto_labeled_20251219_*.json
```

### 2.2 Manual Review

Setelah auto-label, tim mereview secara manual ambiguous cases:
```
proxy/ml/training_data/backup/
  manually_labeled_20251219_031657.json
  needs_review_20251209_*.json
```

### 2.3 Merge & Normalisasi

Semua labeled data di-merge menjadi satu training set:
```
proxy/ml/training_data/merged/
  hybrid_balanced_20260127_200506.json    (207 KB)
  normalized_training_data_20260127_*.json
```

Data real dari scanning aktif (bukan ZAP) juga diproses:
```
proxy/ml/training_data/real_data/
  processed_findings_20260129_121146.json (368 KB — data terbesar/terbaru)
  tp_candidates.json
```

---

## 📊 FASE 3 — Dataset Phase 3 Final (Balanced CSV)

### File Kunci: `phase3_balanced_dataset_FINAL.csv`

Ini adalah **master dataset** yang dipakai untuk training FP Reducer:

| Properti | Nilai |
|----------|-------|
| Format | CSV (16 kolom features) |
| Label | 0 = True Positive, 1 = False Positive |
| Balancing | 38 TP : 38 FP (balanced, no shortcuts) |
| Fitur awal | 16 (ALL_FEATURES) |

**16 Fitur Awal:**
```
severity, category, evidence_length, description_length,
url_complexity, has_params, cvss_score, risk_score,
fp_keyword_count, tp_keyword_count, keyword_ratio,
is_informational, status_code, response_time,
occurrence_count, days_since_first_seen
```

### Masalah yang Ditemukan (Phase 0 — Data Leakage)

Fitur `occurrence_count` dan `days_since_first_seen` mengalami **data leakage**:
- Nilainya terlalu berbeda antara training set vs production (scanner baru = selalu 1 dan 0)
- Menyebabkan model "curang" → akurasi palsu tinggi

---

## 🏋️ FASE 4 — Training Pipeline FP Reducer (Phase 5 Clean-14)

### Script: `proxy/deploy_clean14.py`

```python
ALL_FEATURES = [16 features]
NEUTRALIZED  = ['cvss_score', 'risk_score',        # dinetralkan (di-zero)
                 'occurrence_count', 'days_since_first_seen']  # dihapus
CLEAN_FEATURES = 14 features  # setelah buang 2 leaking features
```

### Pipeline Training

```
Phase3 CSV (76 balanced samples real)
         │
         ├── 40 sampel TP synthetic (augmentation)
         │   → dari TP_TEMPLATES: SQLi, XSS, CSRF patterns
         │
         └── 8 sampel FP synthetic
             → dari FP_TEMPLATES: missing header, info disclosure
         │
         ▼
Total training: 124 samples (76 real + 40 TP aug + 8 FP aug)
+ 22-sample holdout untuk test akhir
         │
         ▼
Model: RF + GB Ensemble (VotingClassifier)
         + CalibratedClassifierCV (probabilitas terkalibrasi)
         │
         ▼
Evaluation:
  - 5-Fold CV Accuracy: 92.9% ± 6.9%
  - Test Accuracy (22-sample holdout): 86.4%
```

### Hyperparameter

```python
RandomForestClassifier(n_estimators=200, max_depth=6, min_samples_leaf=2,
                       class_weight='balanced', random_state=42)
GradientBoostingClassifier(n_estimators=150, learning_rate=0.05,
                           max_depth=3, subsample=0.8)
VotingClassifier(voting='soft')  # soft voting probabilitas
CalibratedClassifierCV(cv=5, method='isotonic')
```

---

## 🤖 FASE 5 — Training Anomaly Detector (Teman — branch main)

> Dikerjakan di branch `origin/main` oleh teman (Nathanael)

### Data: `proxy/ml/training_data/data/anomaly_training.json`

| Properti | Nilai |
|----------|-------|
| Samples | 4073 (scan aktual Moodle normal) |
| Algoritma | Isolation Forest |
| Contamination | 10% |
| Features | 17 (request-level features) |
| Meta-classifier | Random Forest (sebagai lapisan kedua) |

### Features Anomaly Detector (17 fitur):
```
response_time, status_code, url_length, has_params, param_count,
method, body_size, header_count, has_user_agent, has_referer,
hour_of_day, day_of_week, request_rate_1min, request_rate_1hr,
finding_count, is_authenticated, endpoint_sensitivity
```

### Hasil Training:
```
Normal samples:   ~180 (train) + meta-classifier 140 train / 35 val
Anomaly detected: ~20 anomalies per 200 samples
Meta-classifier:  Random Forest, threshold=0.2, target_recall=0.9
Detection Rate:   ~90%
```

---

## 💾 FASE 6 — Saved Models

### `proxy/ml/models/fp_reducer.pkl`

```
Version   : v3.0-clean14
Timestamp : 2026-05-01T09:30:38Z
Features  : 14 (tanpa occurrence_count & days_since_first_seen)
Algorithm : RF + GB Ensemble + CalibratedClassifierCV
CV Acc    : 92.9% ± 6.9%
Test Acc  : 86.4% (22-sample holdout)
```

### `proxy/ml/models/anomaly_detector.pkl`

```
Algorithm   : Isolation Forest + Meta Random Forest
Samples     : 4073 normal behaviour
Contamination: 10%
Features    : 17 (inferred schema — feature_names not in file)
Detection   : ~90% rate
```

---

## 🔄 FASE 7 — Runtime Inference (saat scan berjalan)

### Flow Saat User Klik "Start Scan"

```
Browser (localhost:8998)
    │ POST via proxy_api.php
    ▼
proxy/app.py (localhost:8999)
    │
    ├── ScannerEngine.run_scan()
    │       ├── L2: Header Scanner (passive)
    │       ├── L3: Auth Scanner (login bruteforce attempt)
    │       ├── L4: SQLi Scanner (PayloadInjector → 2 payloads dari DB)
    │       ├── L5: XSS Scanner (0 payloads dari DB → static fallback)
    │       ├── L6: CSRF Scanner (9 payloads dari DB)
    │       └── L7: Config/Behavior Scanner
    │
    ├── ML Pipeline (FalsePositiveReducer.predict_batch)
    │       ├── Extract 14 features dari setiap finding
    │       ├── FP Reducer predict → probabilitas FP (0.0–1.0)
    │       ├── Threshold: prob_fp > 0.5 → filtered as FP
    │       └── ml_stats: {fp_count, tp_count, filtered_findings}
    │
    ├── AnomalyDetector.score_request()
    │       ├── Extract 17 request features
    │       ├── IsolationForest.score_samples() → anomaly score
    │       └── Flag jika score < threshold
    │
    ├── RiskScorer + CVSS Calculator
    │       └── Assign cvss_score dan priority ke setiap finding
    │
    ├── RecommendationEngine.get_recommendation()
    │       ├── Jika ada LLM key → Groq/OpenAI API call
    │       └── Fallback → static template per kategori
    │
    └── ScanHistory.save_scan()
            ├── Simpan ke scan_history.db
            ├── metadata JSON (termasuk ml_stats untuk FP display)
            └── Findings dengan hash deduplication
```

### Output Akhir yang Terlihat User

| Output | Lokasi | Isi |
|--------|--------|-----|
| **Dashboard** | `/local/security_dashboard/` | Recent scans, FP count, severity breakdown |
| **Scan Findings** | `scan_findings.php` | Detail temuan + verify-fix button |
| **ML Dashboard** | `ml_dashboard.php` | FP Reducer 92.9%, Anomaly Detector status, LLM key |
| **PDF Report** | `download_report.php` | Full PDF dengan CVSS, PoC, rekomendasi |
| **Trends** | `trends.php` | Grafik tren temuan per waktu |

---

## 📐 Ringkasan Angka Kritis

| Metrik | Nilai |
|--------|-------|
| Total raw ZAP data | ~1.3 GB (12+ Moodle instances) |
| Dataset Phase 3 Final (real balanced) | 76 samples (38 TP + 38 FP) |
| + Synthetic augmentation | +48 samples |
| Total training FP Reducer | **124 samples** |
| Holdout test FP Reducer | **22 samples** |
| FP Reducer CV Accuracy | **92.9% ± 6.9%** |
| FP Reducer Test Accuracy | **86.4%** |
| Anomaly Detector samples | **4073 normal requests** |
| Anomaly Detection Rate | **~90%** |
| Active scan features (FP) | **14 clean features** |
| Active scan features (Anomaly) | **17 request features** |

---

## ⚠️ Keputusan Desain Penting

| Keputusan | Alasan |
|-----------|--------|
| Hapus `occurrence_count` & `days_since_first_seen` | Data leakage — scanner baru selalu nilai 0/1 |
| Netralkan `cvss_score` & `risk_score` | Nilai dihitung oleh sistem sendiri → circular dependency risiko |
| Augmentasi TP synthetic (+40) | Dataset awal TP sangat sedikit → perlu balancing |
| Soft voting ensemble (RF+GB) | Lebih stabil dari single classifier pada dataset kecil |
| CalibratedClassifierCV | Probabilitas lebih reliabel untuk threshold tuning |
| Threshold FP = 0.5 | Default, bisa diubah untuk trade-off precision/recall |
| Groq sebagai pengganti OpenAI | OpenAI tidak ada free tier lagi; Groq gratis |

---

*Dokumen dibuat: 2026-05-11 | Tidak di-push ke GitHub*
