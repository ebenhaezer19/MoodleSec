#!/usr/bin/env python3
"""
Explain Opsi 1 dan Check ZAP Payloads
"""

import sys
from pathlib import Path
import httpx

# Add modules to path
sys.path.insert(0, str(Path(__file__).parent / "integrations"))
sys.path.insert(0, str(Path(__file__).parent / "database"))

from zap_payload_enhancer import ZAPPayloadEnhancer
from payload_repository import PayloadRepositoryManager

def explain_opsi1():
    """Jelaskan Opsi 1 dengan visual"""
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                    OPSI 1: INTELLIGENT PAYLOAD REUSE                       ║
║                     (Native Scan → Accumulate Payloads)                    ║
╚════════════════════════════════════════════════════════════════════════════╝

ALUR KERJA:
───────────

1️⃣ SCAN 1 (HARI 1):
   ├─ Login as Admin
   ├─ Crawl Moodle (50 endpoints)
   ├─ Test scan mereka, menemukan:
   │  ├─ XSS di parameter "q" → Extract payload: ' alert(1) '
   │  ├─ SQLi di parameter "id" → Extract payload: ' OR 1=1 --
   │  └─ CSRF missing token → Extract payload pattern
   └─ Payloads stored di database
      DATABASE SEKARANG: 3 payloads

2️⃣ SCAN 2 (HARI 1, 30 menit kemudian):
   ├─ Login as Teacher (role berbeda)
   ├─ Crawl Moodle (7 endpoints - teacher role lebih limited)
   ├─ Scanner SMART: "Saya tahu ada XSS di 'q' dari scan sebelumnya"
   │  ├─ Load 5 top XSS payloads dari database (dari Scan 1)
   │  ├─ Test mereka langsung ke parameter XSS yang pernah vulnerable
   │  ├─ CEK LAGI! Update effectiveness score
   │  └─ Menemukan 12 payloads BARU
   └─ Payloads stored di database
      DATABASE SEKARANG: 3 + 12 = 15 payloads

3️⃣ SCAN 3 (HARI 2):
   ├─ Developer runs scan di environment baru
   ├─ Scanner SMART: "Database sudah punya 15 payloads"
   │  ├─ Focus test di yang paling effective (success rate tinggi)
   │  ├─ Scanning lebih EFFICIENT, lebih CEPAT
   │  └─ Menemukan 8 payloads BARU
   └─ Payloads stored di database
      DATABASE SEKARANG: 15 + 8 = 23 payloads

═══════════════════════════════════════════════════════════════════════════

VISUALIZATION DATABASE:

Scan 1 Result:
┌─────────────────────────────────────────────────┐
│ PAYLOAD REPOSITORY                              │
├─ XSS: ' alert(1) '         │ effectiveness: 0.6 │
├─ SQLi: ' OR 1=1 --          │ effectiveness: 0.5 │
└─ CSRF: token missing        │ effectiveness: 0.4 │
└─────────────────────────────────────────────────┘
                    ↓
            Learn & Improve
                    ↓
Scan 2 Result:
┌─────────────────────────────────────────────────┐
│ PAYLOAD REPOSITORY (UPDATED)                    │
├─ XSS: ' alert(1) '         │ effectiveness: 0.8 │ ← IMPROVED!
├─ XSS: "<img onerror>        │ effectiveness: 0.7 │
├─ XSS: "><script>            │ effectiveness: 0.6 │
├─ SQLi: ' OR 1=1 --          │ effectiveness: 0.5 │
├─ SQLi: 1' UNION SELECT      │ effectiveness: 0.4 │
└─ ... 10 more payloads
└─────────────────────────────────────────────────┘

═══════════════════════════════════════════════════════════════════════════

KEUNTUNGAN OPSI 1:

✅ Knowledge accumulation     → Setiap scan menambah library
✅ Adaptive testing           → Scan berikutnya lebih smart
✅ Self-improving system      → Effectiveness score terus meningkat
✅ No external dependency     → Tidak perlu ZAP running
✅ Fast scanning              → Prioritas test payload yg paling efektif
✅ ML integration ready       → Data bagus untuk training model anomaly

KEKURANGAN OPSI 1:

❌ Slow start                 → Scan pertama tanpa payload prior knowledge
❌ Limited payload diversity  → Hanya dari findings sendiri
❌ Takes time to mature       → Butuh beberapa scan sebelum optimal

═══════════════════════════════════════════════════════════════════════════
    """)

async def check_zap_payloads():
    """Check berapa payload/alerts di ZAP sekarang"""
    print("\n\n╔════════════════════════════════════════════════════════════════╗")
    print("║         CHECKING ZAP OWASP PAYLOADS & ALERTS                  ║")
    print("╚════════════════════════════════════════════════════════════════╝\n")
    
    # Check ZAP connection
    enhancer = ZAPPayloadEnhancer(zap_host="localhost", zap_port=8080)
    
    print("[1] Checking ZAP Connection...")
    if enhancer.check_zap_connection():
        print("    ✓ ZAP is accessible at http://localhost:8080\n")
    else:
        print("    ✗ ZAP NOT accessible at http://localhost:8080")
        print("    Note: ZAP tidak running atau ada masalah koneksi\n")
        print("    Untuk check ZAP payloads, perlu:")
        print("    - ZAP running di /opt/zapproxy")
        print("    - Jalankan: sudo /opt/zapproxy/ZAP_2.14.0/zap.sh")
        print("    - Atau akses: http://localhost:8080\n")
        return
    
    # Get ZAP alerts
    print("[2] Fetching ZAP Alerts...")
    try:
        alerts = await enhancer.get_zap_alerts(count=200)
        
        if alerts:
            print(f"    ✓ Found {len(alerts)} alerts in ZAP\n")
            
            # Categorize alerts
            categories = {}
            for alert in alerts:
                alert_type = alert.get('alert', 'Unknown')
                if alert_type not in categories:
                    categories[alert_type] = []
                categories[alert_type].append(alert)
            
            print("[3] Alert Breakdown by Category:")
            print("─" * 60)
            for category, items in sorted(categories.items(), 
                                         key=lambda x: len(x[1]), 
                                         reverse=True):
                print(f"    {category:<40} : {len(items):>3} alerts")
            print("─" * 60)
            print(f"    TOTAL                                : {len(alerts):>3} alerts\n")
            
            # Sample payloads from evidence
            print("[4] Sample Evidence from ZAP Alerts:")
            print("─" * 60)
            payload_count = 0
            for alert in alerts[:5]:  # First 5 only
                evidence = alert.get('evidence', '')
                if evidence:
                    payload_count += 1
                    print(f"\n    Alert #{payload_count}: {alert.get('alert', 'Unknown')}")
                    print(f"    Evidence: {evidence[:100]}...")
            
            print("\n" + "─" * 60)
            print("\n[5] Payload Import Status:")
            print(f"    Total payloads available dari ZAP: {len(alerts)}")
            print(f"    Status: READY untuk extract & import\n")
        else:
            print("    ✗ No alerts found in ZAP")
            print("    Reason: No scans completed yet atau alerts cleared\n")
    
    except Exception as e:
        print(f"    ✗ Error fetching alerts: {e}\n")

def check_local_repository():
    """Check berapa payload di local repository"""
    print("╔════════════════════════════════════════════════════════════════╗")
    print("║       LOCAL PAYLOAD REPOSITORY STATUS                         ║")
    print("╚════════════════════════════════════════════════════════════════╝\n")
    
    try:
        repo = PayloadRepositoryManager("data/payload_repository.db")
        stats = repo.get_stats()
        
        print(f"[1] Local Database Status:")
        print(f"    ✓ Total payloads: {stats['total_payloads']}")
        print(f"    ✓ Vulnerable payloads: {stats['vulnerable_payloads']}\n")
        
        print(f"[2] Payloads by Category:")
        print("─" * 60)
        for category, data in sorted(stats['by_category'].items()):
            count = data['count']
            avg_rate = data['avg_rate']
            print(f"    {category:<40} : {count:>3} payloads (avg rate: {avg_rate:.1f}%)")
        print("─" * 60 + "\n")
        
    except Exception as e:
        print(f"Error reading repository: {e}\n")

if __name__ == "__main__":
    import asyncio
    
    # Explain Opsi 1
    explain_opsi1()
    
    # Check local repository
    check_local_repository()
    
    # Check ZAP
    asyncio.run(check_zap_payloads())
