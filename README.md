
# MoodleSec

Project ini adalah kumpulan alat dan plugin untuk analisis keamanan, integrasi scanning, dan komponen pendukung untuk instalasi Moodle yang aman. Repo mencakup plugin Moodle, proxy untuk pemrosesan hasil scan / machine learning, serta modul CVSS untuk perhitungan skor kerawanan.

**Intinya:** repo ini menggabungkan skrip, layanan, dan plugin yang digunakan untuk menjalankan pemindaian keamanan, memproses hasil, dan menampilkan laporan pada instalasi Moodle.

**Direktori utama**

- `moodle-plugin/`: plugin PHP yang di-deploy ke Moodle untuk integrasi hasil scan, dashboard, dan fitur terkait.
- `proxy/`: layanan Python untuk memproses hasil scan, menyiapkan data training ML, auto-labeling, dan API untuk integrasi.
- `cvss-engine/`: implementasi kalkulator CVSS (Common Vulnerability Scoring System) dan API terkait.
- `docs/`, `db/`, dan file panduan lain: dokumentasi instalasi, konfigurasi, dan pengujian.

**Fitur utama**

- Pengumpulan dan pemrosesan output scanner (ZAP, Acunetix, dll.).
- Auto-labeling dan pipeline data training untuk model ML yang digunakan dalam penilaian temuan.
- Plugin Moodle untuk menampilkan laporan, tren, dan integrasi manajemen temuan.
- Engine CVSS untuk menghitung skor risiko berdasarkan temuan.

Prasyarat

- Docker & Docker Compose (direkomendasikan untuk environment terpadu)
- Python 3.8+ (untuk `proxy/` dan `cvss-engine/`)
- PHP & Moodle (untuk `moodle-plugin/`)

Quick start (menggunakan Docker Compose)

1. Pastikan Docker berjalan di mesin Anda.
2. Jalankan Compose (jika konfigurasi tersedia untuk layanan yang ingin dijalankan):

```powershell
docker-compose up --build
```

Instalasi manual (komponen Python)

1. Buat virtual environment dan install requirements untuk `proxy`:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r proxy\requirements.txt
```

2. Untuk `cvss-engine`:

```powershell
python -m venv .venv-cvss
.\.venv-cvss\Scripts\Activate.ps1
pip install -r cvss-engine\requirements.txt
```

Menjalankan test singkat

- Repo berisi beberapa skrip uji dan helper. Untuk menjalankan skrip pengujian yang cepat:

```powershell
python test_all.py
```

Catatan khusus untuk `moodle-plugin`

- Folder `moodle-plugin/` berisi plugin PHP yang perlu dipasang ke direktori plugin Moodle Anda (mis. `local/moodlesec` atau sesuai struktur plugin).
- Ikuti `moodle-plugin/DATABASE_DOCUMENTATION.md` dan `moodle-plugin/README.md` (jika ada) untuk langkah instalasi di lingkungan Moodle.

Kontribusi dan pengembangan

- Mohon buka issue atau PR untuk perubahan fitur, bugfix, atau dokumentasi.
- Untuk pekerjaan ML atau data, lihat `proxy/IMPROVE_CONFIDENCE.md` dan panduan auto-labeling di folder yang sama.

Kontak dan dukungan

- Untuk pertanyaan lebih lanjut, buka issue di repository ini atau hubungi maintainer proyek.

Lisensi

- Periksa file lisensi jika tersedia di root repository (tidak disertakan otomatis di repo ini). Jika Anda menambahkan kode pihak ketiga, sertakan atribusi sesuai lisensi masing-masing.

----

Jika Anda ingin, saya bisa:

- Menyempurnakan README dalam bahasa Inggris juga.
- Menambahkan contoh konfigurasi `docker-compose.yml` untuk skenario lokal.
- Membuat panduan singkat untuk memasang `moodle-plugin` ke instance Moodle.

Beritahu opsi mana yang Anda mau saya kerjakan selanjutnya.
