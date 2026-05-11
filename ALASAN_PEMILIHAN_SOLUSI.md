# Sub-bab: Alasan Pemilihan Solusi (Bab 3 / Bab 2 Tinjauan Pustaka Lanjutan)

> Dokumen ini berisi konten siap pakai untuk sub-bab "Alasan Pemilihan Teknologi dan Metode"
> pada skripsi MoodleSec. Tidak di-push ke GitHub.

---

## 3.X Alasan Pemilihan Solusi

Pemilihan teknologi dan metode pada sistem MoodleSec didasarkan pada evaluasi
komparatif terhadap alternatif yang tersedia, dengan mempertimbangkan kebutuhan
spesifik keamanan Moodle, keterbatasan dataset yang tersedia, dan kebutuhan
integrasi yang non-intrusif terhadap instalasi Moodle yang sudah berjalan.

---

### 3.X.1 Pemilihan Algoritma Machine Learning — RF + GB Ensemble

#### Tabel Perbandingan Algoritma Klasifikasi untuk FP Reduction

| Algoritma | Kelebihan | Kekurangan | Sesuai untuk Dataset Kecil? | Interpretabilitas |
|-----------|-----------|------------|----------------------------|-------------------|
| **Random Forest** | Robust terhadap overfitting, feature importance built-in, handles imbalanced data | Tidak menghasilkan probabilitas terkalibrasi secara alami | ✅ Ya (bekerja baik dengan n<200) | ✅ Tinggi |
| **Gradient Boosting** | Akurasi tinggi, memperbaiki kesalahan RF secara iteratif | Lebih lambat, rentan overfitting tanpa regularisasi | ✅ Ya (dengan subsample) | ✅ Sedang |
| **RF + GB Ensemble (dipilih)** | Menggabungkan kekuatan keduanya, variance lebih rendah, soft voting meningkatkan kalibrasi | Lebih kompleks, waktu training lebih lama | ✅ Optimal untuk n=86-124 | ✅ Tinggi |
| Logistic Regression | Sederhana, cepat, probabilitas terkalibrasi secara alami | Tidak mampu menangkap pola non-linear antar fitur | ⚠️ Ya, tapi performa rendah | ✅ Sangat Tinggi |
| SVM | Efektif di ruang dimensi tinggi | Tidak menghasilkan probabilitas langsung, butuh kalibrasi eksternal | ⚠️ Ya, tapi slow untuk CV | ❌ Rendah |
| Deep Learning / MLP | Sangat fleksibel, pola kompleks | Butuh data besar (n>1000), interpretasi sulit, overkill untuk 14 fitur | ❌ Tidak cocok (overfitting) | ❌ Black box |
| XGBoost | Performa tinggi di kompetisi ML | Banyak hyperparameter, sulit diinterpretasi, butuh tuning | ⚠️ Bisa, tapi proposal awal menggunakannya | ❌ Sedang |
| Decision Tree tunggal | Sangat mudah diinterpretasi | Overfitting parah pada data kecil | ❌ Tidak cocok | ✅ Sangat Tinggi |

#### Alasan Pemilihan RF + GB Ensemble

1. **Dataset kecil (n=86 real samples):** Tree-based ensemble terbukti robust pada dataset kecil
   tanpa membutuhkan normalisasi dan tidak sensitif terhadap scale fitur (Breiman, 2001).

2. **Fitur heterogen:** Dataset memiliki campuran fitur numerik kontinu (response_time, evidence_length)
   dan fitur kategorikal ter-encode (severity, category). RF dan GB keduanya robust terhadap tipe
   fitur seperti ini tanpa perlu preprocessing khusus.

3. **Robustness terhadap data leakage:** Pada Phase 0 teridentifikasi bahwa fitur `cvss_score`
   dan `occurrence_count` menciptakan shortcut learning. RF+GB dengan feature importance
   memungkinkan deteksi dan eliminasi fitur-fitur bermasalah ini secara eksplisit.

4. **Probability calibration:** `CalibratedClassifierCV` (isotonic regression, cv=5) diterapkan
   di atas ensemble untuk menghasilkan skor kepercayaan yang reliabel — diperlukan untuk
   threshold-based FP filtering di runtime.

5. **Alternatif yang ditolak:**
   - XGBoost ditolak karena kompleksitas hyperparameter yang tidak proporsional untuk n=86
   - Neural network ditolak karena overfitting pada data kecil (minimum n>500 direkomendasikan
     untuk MLP dengan hidden layers)
   - Logistic Regression ditolak karena tidak mampu menangkap interaksi non-linear antara
     `fp_keyword_count`, `severity`, dan `evidence_length`

---

### 3.X.2 Pemilihan Framework Backend — Python FastAPI

#### Tabel Perbandingan Framework Web untuk Proxy Service

| Framework | Bahasa | Async? | Performa | Ekosistem ML | Integrasi Mudah? | Alasan Ditolak |
|-----------|--------|--------|----------|--------------|------------------|----------------|
| **FastAPI (dipilih)** | Python | ✅ Native async | ⭐⭐⭐⭐⭐ | ✅ NumPy, sklearn, joblib langsung | ✅ | — |
| Flask | Python | ❌ (butuh ekstensi) | ⭐⭐⭐ | ✅ | ✅ | Tidak async, tidak ada OpenAPI auto-docs |
| Django | Python | ❌ (partial di 4.x) | ⭐⭐ | ✅ | ❌ Terlalu heavy, ORM tidak dibutuhkan | Overhead besar untuk proxy sederhana |
| Express.js | JavaScript | ✅ | ⭐⭐⭐⭐ | ❌ sklearn tidak tersedia di Node | ⚠️ | ML model harus di-port ke TensorFlow.js |
| Spring Boot | Java | ✅ | ⭐⭐⭐⭐⭐ | ❌ Butuh Jython atau API terpisah | ❌ | Bahasa berbeda dari ML pipeline |
| Go (Gin/Fiber) | Go | ✅ | ⭐⭐⭐⭐⭐ | ❌ Tidak ada ekosistem ML natif | ❌ | ML model harus dijalankan via subprocess |
| PHP | PHP | ❌ | ⭐⭐ | ❌ | ✅ | Tidak bisa langsung load sklearn model |

#### Alasan Pemilihan FastAPI

1. **Bahasa yang sama dengan ML pipeline:** Seluruh ML pipeline (training, inference, feature
   extraction) ditulis dalam Python. FastAPI memungkinkan inference langsung tanpa overhead
   serialisasi model ke format lain (ONNX, TensorFlow SavedModel, dll).

2. **Performa async tinggi:** FastAPI berbasis ASGI (Asynchronous Server Gateway Interface)
   menggunakan Uvicorn, mendukung concurrent request handling yang penting saat proxy menerima
   multiple simultaneous scan requests.

3. **Auto-generated OpenAPI documentation:** FastAPI secara otomatis menghasilkan dokumentasi
   API (Swagger UI di `/docs`), memudahkan debugging dan integrasi antara proxy service dan
   Moodle plugin tanpa dokumentasi manual.

4. **Type hints dan Pydantic validation:** Memastikan data integrity antara Moodle plugin (PHP)
   dan proxy service (Python) melalui skema JSON yang tervalidasi secara otomatis.

5. **Deployment sederhana:** Single command (`uvicorn app:app --host 0.0.0.0 --port 8999`)
   dengan dukungan systemd service (`moodlesec-proxy.service`) untuk production deployment.

---

### 3.X.3 Pemilihan Arsitektur Integrasi — Moodle Plugin (Admin Tool)

#### Tabel Perbandingan Pendekatan Integrasi dengan Moodle

| Pendekatan | Deskripsi | Kelebihan | Kekurangan | Alasan Ditolak |
|------------|-----------|-----------|------------|----------------|
| **Moodle Plugin Admin Tool (dipilih)** | Plugin PHP native Moodle dengan halaman admin terintegrasi | Auth Moodle built-in, capability check, UI konsisten, tidak perlu login terpisah | Perlu update saat Moodle update major | — |
| Standalone Web App terpisah | Aplikasi web mandiri (React/Vue) | Fleksibel, tidak terikat Moodle versi | Perlu autentikasi terpisah, tidak terintegrasi UI Moodle | Admin harus kelola 2 sistem terpisah |
| Browser Extension | Extension Chrome/Firefox | Bisa scan dari sisi klien | Tidak ada akses ke server-side data, sulit deploy untuk semua admin | Tidak sesuai untuk server-side security scanning |
| Modifikasi Core Moodle | Edit langsung file Moodle | Sangat terintegrasi | Tidak upgradeable, melanggar Moodle guidelines | Tidak maintainable |
| CLI Tool | Script command line | Sederhana | Tidak ada UI, tidak bisa diakses non-technical admin | Tidak user-friendly |
| Reverse Proxy (Nginx module) | Tambahkan ML di level reverse proxy | Transparan untuk Moodle | Kompleksitas deployment sangat tinggi, tidak ada konteks Moodle | Overkill untuk scope penelitian |

#### Alasan Pemilihan Moodle Plugin

1. **Non-intrusif:** Plugin tidak memodifikasi core Moodle, sehingga kompatibel dengan semua
   versi Moodle 4.x dan dapat di-uninstall tanpa merusak instalasi Moodle yang ada.

2. **Autentikasi terintegrasi:** Menggunakan sistem autentikasi Moodle (`require_login()`,
   `require_capability()`) sehingga tidak diperlukan manajemen user terpisah. Hanya admin
   dengan capability `local/security_dashboard:scan` yang dapat mengakses fitur scanning.

3. **UI konsisten:** Menggunakan Moodle Bootstrap theme yang sama dengan halaman admin Moodle
   lainnya, meningkatkan familiarity bagi administrator Moodle.

4. **Capability-based access control:** Moodle capability system memungkinkan kontrol granular
   (misal: admin bisa scan, teacher hanya bisa lihat laporan) tanpa implementasi RBAC dari nol.

5. **Distribusi mudah:** Plugin dapat didistribusikan sebagai file ZIP dan diinstall melalui
   Moodle Plugin Manager, sesuai dengan standar distribusi plugin Moodle resmi.

---

### 3.X.4 Pemilihan Metode Proxy — Separate Python Service vs WAF

#### Tabel Perbandingan Pendekatan Keamanan

| Pendekatan | Contoh Tool | Real-time? | ML Integration | Moodle-Specific? | Deployment |
|------------|-------------|------------|----------------|------------------|------------|
| **Separate Proxy Service (dipilih)** | FastAPI di port 8999 | ✅ | ✅ Native Python | ✅ Bisa dikustomasi | ⭐⭐⭐ |
| Web Application Firewall (WAF) | ModSecurity, Nginx WAF | ✅ | ❌ Rule-based saja | ❌ Generic | ⭐⭐ |
| SAST Tool | SonarQube, Semgrep | ❌ Batch scan | ❌ | ❌ Code analysis | ⭐⭐ |
| DAST Tool (standalone) | OWASP ZAP, Acunetix | ✅ | ❌ | ❌ Generic | ⭐⭐⭐ |
| DAST + Custom ML Pipeline | **MoodleSec (ini)** | ✅ | ✅ RF+GB+Isolation Forest | ✅ Moodle context-aware | ⭐⭐⭐⭐ |
| Cloud Security Service | AWS GuardDuty, Cloudflare | ✅ | ✅ | ❌ | ⭐ (butuh cloud) |

#### Alasan Pemilihan Separate Proxy Service

1. **Separation of concerns:** Proxy service berjalan independen dari Moodle, sehingga:
   - Bug di proxy tidak mengakibatkan Moodle down
   - Proxy dapat di-restart tanpa mengganggu Moodle
   - Dapat di-deploy di server berbeda jika diperlukan

2. **ML model lifecycle management:** Model dapat diperbarui (retrain + redeploy) tanpa
   memerlukan Moodle maintenance window atau plugin update.

3. **CORS bypass melalui PHP proxy:** JavaScript di Moodle plugin tidak langsung berkomunikasi
   dengan proxy (menghindari CORS issue browser), melainkan melalui `proxy_api.php` yang
   berjalan di sisi server PHP Moodle — memastikan keamanan credential dan API key.

4. **Port isolation:** Proxy berjalan di port 8999 (tidak exposed ke internet dalam deployment
   production), hanya dapat diakses dari server Moodle itu sendiri (localhost).

---

### 3.X.5 Ringkasan Keputusan Teknologi

| Komponen | Pilihan | Alternatif Ditolak | Alasan Utama |
|----------|---------|-------------------|--------------|
| ML Algoritma FP | RF + GB Ensemble + CalibratedClassifierCV | XGBoost, Neural Network, SVM | Optimal untuk dataset kecil (n=86), interpretable, no overfitting |
| ML Algoritma Anomaly | Isolation Forest (unsupervised) | Autoencoder, One-class SVM, LSTM | Tidak butuh label, efektif untuk novelty detection, efisien |
| Backend Proxy | Python FastAPI + Uvicorn | Flask, Express.js, Go | Ekosistem ML native Python, async, auto-docs |
| Integrasi Moodle | Admin Tool Plugin PHP | Standalone App, Browser Extension | Non-intrusif, auth terintegrasi, capability-based |
| Database | SQLite (scan_history.db) | PostgreSQL, MySQL, MongoDB | Deployment sederhana, tidak butuh DB server terpisah |
| LLM Rekomendasi | Groq API (compound-beta-mini) / OpenAI GPT-4o-mini | Llama lokal, Claude API | Groq gratis, latensi rendah; OpenAI sebagai fallback berbayar |
| Report Format | PDF (ReportLab) | HTML report, CSV | Standar dokumentasi formal, mudah diarsipkan |

---

*Dokumen ini tidak dipush ke GitHub. Gunakan sebagai referensi untuk penulisan Bab 3 skripsi.*
*Dibuat: 2026-05-11*
