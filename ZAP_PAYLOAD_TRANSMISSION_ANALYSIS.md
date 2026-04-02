# 🔍 ZAP OWASP Report Transmission Analysis

**Analysis Date:** April 2, 2026  
**Status:** INVESTIGASI SELESAI

---

## 📊 FINDINGS SUMMARY

### 1. **Actual Architecture di Sistem Anda**

Hasil investigasi menunjukkan sistem menggunakan **CUSTOM SCANNER**, bukan ZAP secara langsung:

```
┌─────────────────────────────────────────────────────────────┐
│  CURRENT DATA FLOW IN YOUR SYSTEM                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Moodle Dashboard                                           │
│       ↓                                                     │
│  lib.php → curl ke proxy /ml/dashboard/recent-scans        │
│       ↓                                                     │
│  Proxy Service (app.py)                                    │
│       ├─ /api/scan-native-auth → Custom Scanner Engine    │
│       │   ├─ XSS Detector      (xss_detector.py)          │
│       │   ├─ SQL Injection     (sql_injection.py)         │
│       │   ├─ CSRF Detector     (csrf_detector.py)         │
│       │   └─ Path Traversal    (path_traversal.py)        │
│       │                                                    │
│       └─ Database (SQLite)                                 │
│           └─ findings dengan EVIDENCE FIELD                │
│                                                             │
│  ZAP Integration (ml/zap_integration/) - TERSEDIA NAMUN    │
│  TIDAK DIGUNAKAN DALAM AUTHENTICATION SCAN                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 2. **Apa yang Ditemukan di Evidence Field**

Evidence yang ada BUKAN dari ZAP payload, tetapi dari custom scanner:

**Contoh dari database:**
```json
CSRF: "POST request to http://localhost:8998/login/index.php does not include CSRF token"
XSS:  "Parameter value \"\" appears unescaped in response"
```

**Ini adalah OUTPUT dari custom scanner kita**, bukan payload mentah.

---

## 🔌 ZAP Connection Model

### Current Implementation:

ZAP integration yang ada menggunakan model **PULL** (API Query):

```python
# Dari zap_ascan_manager.py:
response = self.client.request("GET", "core/view/alerts", params=params)
alerts_list = response if isinstance(response, list) else response.get("alerts", [])
```

**ZAP API Endpoint:** 
```
GET http://localhost:8080/JSON/core/view/alerts
```

**Response Format from ZAP:**
```json
{
  "alerts": [
    {
      "id": "number",
      "alert": "Vulnerability Type",
      "risk": "High/Medium/Low",
      "confidence": "High/Medium/Low",
      "url": "http://...",
      "description": "...",
      "evidence": "HTML snippet atau payload yang ditemukan",
      "otherInfo": "",
      "solution": "...",
      "reference": "",
      "pluginId": 12345
    }
  ]
}
```

### Status Sekarang:
- ✅ ZAP Running (v2.17.0)
- ✅ ZAP API Accessible pada port 8080
- ❌ **No active alerts** (tidak ada scan yang berjalan)
- ❌ **ZAP integration tidak digunakan** dalam authentication scans

---

## 📝 Apa yang TIDAK Terjadi (Misconceptions)

### ❌ ZAP GUI → Report File → Proxy
**TIDAK ADA** webhooks atau file uploads dari ZAP GUI ke proxy secara otomatis.

### ❌ Payloads Disimpan di Database
Database Anda MENYIMPAN **evidence text description**, BUKAN payload mentah:
- ✗ Database tidak punya field khusus "payloads"
- ✗ Evidence adalah teks deskriptif dari scanner

### ❌ ZAP Report dengan Seluruh Payloads
ZAP mengembalikan data mentah di evidence field TETAPI:
- Untuk XSS: HTML snippet yang dicoba
- Untuk SQL Injection: Query pattern atau error message
- Untuk CSRF: Deskripsi token yang hilang

---

## ✅ Bagaimana Sistem Benar-Benar Bekerja

### Flow untuk "Authenticated Scan":

```
1. Moodle Dashboard 
   └─ User click "Scan Now"
      ↓
2. Proxy menerima POST /api/scan-native-auth
   ├─ Username: admin
   ├─ Password: ***
   ├─ Max depth: 2
   └─ Max pages: 50
      ↓
3. Scanner melakukan:
   a) Login ke Moodle (set session cookie)
   b) Crawl authenticated pages (follow links)
   c) Untuk setiap URL yang ditemukan:
      - Scan dengan XSS detector
      - Scan dengan SQL Injection detector
      - Scan dengan CSRF detector
      - Scan dengan Path Traversal detector
      ↓
4. Setiap Finding:
   - severity: "High"
   - category: "XSS"
   - description: "Potential reflected XSS in parameter..."
   - evidence: "Parameter value \"\" appears unescaped" ← TEXT, bukan payload
   ↓
5. Hash untuk deduplication:
   MD5(category:description:url:evidence) ← Semua 4 field
   ↓
6. Save ke database findings table
   ↓
7. ML Filtering:
   - Tier 1: Rule-based (informational removal)
   - Tier 2: Rarity calculation
   - Tier 3: ML prediction (optional)
   ↓
8. Display di Moodle dashboard
```

---

## 🎯 PAYLOAD SITUATION DIJELASKAN

### Dari ZAP API Response:

```json
{
  "evidence": "<img src=\"x\" onerror=\"alert('xss')\">"
}
```

Ini adalah HTML/JavaScript yang ZAP COBA INJECT. Sistem Anda:
1. Menerima ini dari ZAP API
2. **TIDAK menyimpan payload mentah**
3. Menyimpan deskripsi: "Evidence: <img... (truncated)"

### Dari Custom Scanner (Sekarang):

```python
# Di xss_detector.py:
evidence = f'Parameter value "{param_value[:100]}" appears unescaped in response'
```

Ini adalah deskripsi, bukan payload aktual.

---

## 📊 Database Schema

```sql
CREATE TABLE findings (
    id INTEGER PRIMARY KEY,
    scan_id TEXT,
    finding_hash TEXT,           -- MD5(category:description:url:evidence)
    category TEXT,               -- "XSS", "SQL Injection", dll
    description TEXT,            -- Human readable description
    evidence TEXT,               -- ← TEKS DESKRIPSI, bukan payload
    url TEXT,
    severity TEXT,
    cvss_score FLOAT,
    ...
);
```

Evidence field Anda saat ini:
```
evidence: "Parameter value \"\" appears unescaped in response"
evidence: "POST request... does not include CSRF token"
```

**BUKAN payload payload mentah seperti:**
```
evidence: "<img src=x onerror=alert('xss')>"  ← ZAP would send this
```

---

## 🔗 CONNECTION BETWEEN ZAP AND YOUR PROXY

### Tidak Ada Direct Connection untuk Report Reception!

**ZAP Integration ada tapi:**
- ✅ Proxy BISA **query** ZAP API (pull model)
- ❌ ZAP GUI **tidak** automatically push reports ke proxy
- ❌ Tidak ada webhook endpoint `POST /zap-report` yang menerima dari ZAP GUI

**Cara sebenarnya:**
```python
# Di ZAPActiveScanManager:
response = self.client.request("GET", "core/view/alerts")
# Ini adalah PULL, bukan PUSH
```

---

## 💡 KESIMPULAN DAN REKOMENDASI

### Apa yang Ada:
1. ✅ Custom scanner bekerja dengan 35 findings yang tersimpan
2. ✅ Evidence field berisi deskripsi, bukan payload
3. ✅ ZAP API accessible tapi tidak digunakan dalam auth scans
4. ✅ Database menyimpan ALL data dengan deduplication berbasis evidence

### Apa yang Tidak Ada:
1. ❌ Direct payload storage (mencadangkan payload yang digunakan)
2. ❌ ZAP report webhook receiver
3. ❌ Payload reuse mechanism (untuk testing dengan payload yang sama di scan berikutnya)

### Untuk Reuse ZAP Payloads (Sesuai Pertanyaan Awal):

**Opsi 1: Extract dari ZAP Report**
```python
# Jika ZAP scan dijalankan manual dari GUI dan export report:
# Baca XML/JSON → Extract payloads dari evidence field
# Simpan di payload database
# Gunakan untuk testing berikutnya
```

**Opsi 2: Enable ZAP Integration**
```python
# Uncomment ZAP manager initialization
manager = ZAPIntegrationManager(host="localhost", port=8080)
# Scan akan pull dari ZAP API dan menggunakan evidence ZAP
```

**Opsi 3: Record Payloads dari Custom Scanner**
```python
# Tambah field:
# - payload_used: payload aktual yang diinject
# - payload_response: response yang diterima
# Untuk setiap finding, simpan payload yang berhasil
```

---

## 📋 REKOMENDASI NEXT STEPS

1. **Clarify Architecture:**
   - Apakah ingin terus pakai custom scanner atau switch ke ZAP?
   - Custom: Lebih kontrol, bisa custom payload
   - ZAP: Enterprise tool, lebih banyak payloads built-in

2. **Payload Recording:**
   - Jika ingin reuse payloads, perlu add database schema:
     ```
     payloads table: (id, category, type, payload_text, success_rate)
     ```

3. **ZAP Integration:**
   - Jika ingin ZAP, aktifkan di `/api/scan-native-auth`
   - Konfigurasi: `Moodle authentication untuk ZAP`
   - Enable API query ke ZAP untuk get findings

---

**END OF ANALYSIS**
