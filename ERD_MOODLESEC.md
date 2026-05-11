# ERD MoodleSec — Berdasarkan Kode Aktual

> Dibuat berdasarkan: `proxy/database/scan_history.py`, `moodle-plugin/db/install.xml`, `moodle-plugin/db/install_login_monitor.xml`
> Tidak di-push ke GitHub.

---

## ERD Lengkap (Mermaid)

```mermaid
erDiagram
    %% ══════════════════════════════════════
    %% PROXY SERVICE — SQLite Database
    %% ══════════════════════════════════════

    scans {
        int id PK
        text scan_id UK
        text scan_type
        text target_url
        datetime timestamp
        int endpoints_discovered
        int endpoints_scanned
        int total_findings
        int critical_count
        int high_count
        int medium_count
        int low_count
        int info_count
        real scan_duration
        text metadata
    }

    findings {
        int id PK
        text scan_id FK
        text finding_hash
        text severity
        text category
        text description
        text evidence
        text url
        real cvss_score
        real risk_score
        int priority
        datetime first_seen
        datetime last_seen
        text status
        datetime fixed_date
        text metadata
    }

    %% ══════════════════════════════════════
    %% MOODLE — MySQL / PostgreSQL Database
    %% ══════════════════════════════════════

    mdl_user {
        int id PK
        text username
        text email
        text firstname
        text lastname
    }

    local_security_scans {
        int id PK
        text scan_id UK
        text target_url
        text scan_path
        text scan_method
        text scan_type
        text status
        int total_findings
        int critical_count
        int high_count
        int medium_count
        int low_count
        int info_count
        int scan_duration
        int triggered_by FK
        int timecreated
        int timemodified
    }

    local_security_findings {
        int id PK
        int scan_id FK
        text severity
        text category
        text title
        text description
        text evidence
        real cvss_score
        text cvss_vector
        text cwe_id
        text remediation
        text status
        int false_positive
        int timecreated
        int timemodified
    }

    local_security_logs {
        int id PK
        int scan_id FK
        text log_type
        text log_level
        text message
        text data
        int user_id FK
        int timecreated
    }

    local_security_schedules {
        int id PK
        text name
        text scan_path
        text scan_method
        text scan_type
        text frequency
        text schedule_time
        int is_enabled
        int last_run
        int next_run
        int created_by FK
        int timecreated
        int timemodified
    }

    local_security_login_log {
        int id PK
        int userid FK
        text username
        int success
        text ip_address
        text user_agent
        text country
        text city
        text region
        text isp
        real latitude
        real longitude
        int is_suspicious
        int risk_score
        text fail_reason
        text session_id
        int timecreated
    }

    local_security_ip_blocklist {
        int id PK
        text ip_address UK
        text reason
        text block_type
        int fail_count
        int first_seen
        int last_seen
        int blocked_by FK
        int expires
        int is_active
        int timecreated
        int timemodified
    }

    local_security_phishing {
        int id PK
        text content_type
        int content_id
        text content_url
        int user_id FK
        text risk_level
        real risk_score
        text suspicious_url
        text indicators
        text status
        int detected_by FK
        int resolved_by FK
        int timecreated
        int timemodified
    }

    local_security_config {
        int id PK
        text name UK
        text value
        text description
        text config_type
        int is_active
        int timecreated
        int timemodified
    }

    %% ══════════════════════════════════════
    %% RELASI — Proxy SQLite (internal)
    %% ══════════════════════════════════════
    scans ||--o{ findings : "scan_id (text FK)"

    %% ══════════════════════════════════════
    %% RELASI — Moodle DB (internal)
    %% ══════════════════════════════════════
    mdl_user ||--o{ local_security_scans : "triggered_by"
    local_security_scans ||--o{ local_security_findings : "scan_id"
    local_security_scans ||--o{ local_security_logs : "scan_id"
    mdl_user ||--o{ local_security_logs : "user_id"
    mdl_user ||--o{ local_security_schedules : "created_by"
    mdl_user ||--o{ local_security_login_log : "userid (nullable)"
    mdl_user ||--o{ local_security_phishing : "user_id"
    mdl_user ||--o{ local_security_phishing : "detected_by"
    mdl_user ||--o{ local_security_ip_blocklist : "blocked_by"
```

---

## Catatan Arsitektur Penting

### Relasi Lintas Database (LOGIS, bukan FK fisik)

```
Proxy SQLite              Moodle MySQL/PostgreSQL
─────────────             ──────────────────────
scans.scan_id  ←──────────→  local_security_scans.scan_id
(text, UUID)   (logical      (text, UK index)
               matching,
               NO physical
               FK constraint)
```

> **Mengapa tidak ada FK fisik?**
> SQLite dan MySQL/PostgreSQL adalah dua database terpisah yang berjalan di proses berbeda.
> Foreign key constraint tidak bisa lintas database engine.
> Sinkronisasi dilakukan melalui API: Moodle plugin mengirim `scan_id` ke proxy,
> proxy menyimpan hasilnya dengan `scan_id` yang sama.

---

## ERD Ringkas untuk Paper (Fokus Entitas Utama)

```mermaid
erDiagram
    mdl_user {
        int id PK
        text username
        text email
    }

    scans_sqlite["scans (SQLite)"] {
        int id PK
        text scan_id UK
        text scan_type
        text target_url
        datetime timestamp
        int total_findings
        text metadata
    }

    findings_sqlite["findings (SQLite)"] {
        int id PK
        text scan_id FK
        text severity
        text category
        real cvss_score
        real risk_score
        text status
        text metadata
    }

    local_security_scans {
        int id PK
        text scan_id UK
        text scan_type
        text status
        int total_findings
        int triggered_by FK
        int timecreated
    }

    local_security_findings {
        int id PK
        int scan_id FK
        text severity
        text category
        real cvss_score
        int false_positive
    }

    local_security_login_log {
        int id PK
        int userid FK
        text ip_address
        text country
        int is_suspicious
        int risk_score
    }

    scans_sqlite ||--o{ findings_sqlite : "scan_id"
    mdl_user ||--o{ local_security_scans : "triggered_by"
    local_security_scans ||--o{ local_security_findings : "scan_id"
    mdl_user ||--o{ local_security_login_log : "userid"
    scans_sqlite }|--|{ local_security_scans : "scan_id (logical)"
```

---

## Tabel Ringkasan Entitas

| Entitas | Database | Tujuan | Baris Kunci |
|---------|----------|--------|-------------|
| `scans` | Proxy SQLite | Riwayat semua scan + statistik | `scan_id`, `metadata` (ml_stats) |
| `findings` | Proxy SQLite | Detail temuan per scan | `finding_hash` (deduplication), `metadata` (ml confidence) |
| `local_security_scans` | Moodle MySQL | Sinkronisasi scan ke Moodle | `scan_id`, `triggered_by` |
| `local_security_findings` | Moodle MySQL | Temuan yang ditampilkan di UI | `false_positive`, `cvss_score` |
| `local_security_logs` | Moodle MySQL | Audit trail aktivitas | `log_type`, `log_level` |
| `local_security_schedules` | Moodle MySQL | Jadwal scan otomatis | `frequency`, `next_run` |
| `local_security_login_log` | Moodle MySQL | Monitor login mencurigakan | `is_suspicious`, `risk_score`, `ip_address` |
| `local_security_ip_blocklist` | Moodle MySQL | Blokir IP berbahaya | `block_type`, `is_active` |
| `local_security_phishing` | Moodle MySQL | Deteksi konten phishing | `risk_level`, `suspicious_url` |
| `local_security_config` | Moodle MySQL | Konfigurasi plugin | `name` (UK), `config_type` |

*Dokumen ini tidak di-push ke GitHub. Dibuat: 2026-05-11*
