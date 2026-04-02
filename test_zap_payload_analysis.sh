#!/bin/bash

# Test ZAP Report Structure and Payload Inclusion
# Cek apa yang sebenarnya dikirim ZAP ke sistem

echo "=== ZAP PAYLOAD ANALYSIS TEST ==="
echo ""

# 1. Cek struktur data di proxy/scan_history.db
echo "1️⃣  CHECKING DATABASE STRUCTURE - Recent findings with evidence:"
wsl bash << 'EOF'
cd /home/krisopras1913/TA/adaptive-moodle-security/MoodleSec

python3 << 'PYEOF'
import sqlite3
import json

db_path = "proxy/data/scan_history.db"
conn = sqlite3.connect(db_path)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

# Get latest scan
cursor.execute("""
    SELECT scan_id, reported_findings, actual_findings 
    FROM scan_history 
    ORDER BY created_at DESC 
    LIMIT 1
""")
latest = cursor.fetchone()

if latest:
    scan_id = latest['scan_id']
    print(f"\n[DB] Latest Scan: {scan_id}")
    print(f"[DB] Reported: {latest['reported_findings']}, Actual: {latest['actual_findings']}")
    
    # Get sample findings with evidence
    cursor.execute("""
        SELECT id, category, description, url, severity, evidence 
        FROM findings 
        WHERE scan_id = ? 
        LIMIT 5
    """, (scan_id,))
    
    print(f"\n[DB] Sample findings (showing evidence field):")
    for row in cursor.fetchall():
        print(f"\n  ID: {row['id']}")
        print(f"  Category: {row['category']}")
        print(f"  Description: {row['description'][:80]}...")
        print(f"  URL: {row['url']}")
        print(f"  Severity: {row['severity']}")
        print(f"  Evidence: {row['evidence'][:200] if row['evidence'] else '[EMPTY]'}...")

conn.close()
PYEOF
EOF

echo ""
echo "2️⃣  CHECKING API RESPONSE - What proxy returns:"
curl -s http://localhost:8999/ml/dashboard/recent-scans?limit=1 | python3 -m json.tool | head -100

echo ""
echo "3️⃣  CHECKING ZAP API DIRECTLY - Raw alerts structure:"
echo "   Connecting to ZAP at localhost:8080..."
curl -s "http://localhost:8080/JSON/core/view/alerts" | python3 -m json.tool | head -150

echo ""
echo "4️⃣  CHECKING ZAP CONFIGURATION:"
wsl bash << 'EOF'
echo "   ZAP Version:"
curl -s "http://localhost:8080/JSON/core/view/version" | python3 -m json.tool

echo ""
echo "   ZAP Home Directory:"
ls -la ~/.ZAP/ 2>/dev/null | head -20

echo ""
echo "   ZAP Options (includes report settings):"
curl -s "http://localhost:8080/JSON/core/view/optionParamNames" | python3 -m json.tool | grep -i "report\|payload" | head -20
EOF

echo ""
echo "5️⃣  CHECKING IF ZAP HAS WEBHOOK CAPABILITY:"
wsl curl -s "http://localhost:8080/JSON/core/action/setOptionBoolValue?optionName=ext.extender.webhooks.enabled&optionValue=true" 2>/dev/null | python3 -m json.tool

echo ""
echo "✅ Test complete - Check output above for evidence field content"
