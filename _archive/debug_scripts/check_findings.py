import sqlite3
import json

conn = sqlite3.connect('data/scan_history.db')
cursor = conn.cursor()

print("Checking findings with PoC data:")
print("-" * 80)

# Get latest auth scan
cursor.execute('SELECT scan_id FROM scans WHERE scan_type = "authentication" ORDER BY id DESC LIMIT 1')
scan_id = cursor.fetchone()

if scan_id:
    scan_id = scan_id[0]
    print(f"Latest auth scan: {scan_id}\n")
    
    # Get findings for this scan
    cursor.execute('SELECT id, category, severity, description, evidence, metadata FROM findings WHERE scan_id = ?', (scan_id,))
    findings = cursor.fetchall()
    
    print(f"Found {len(findings)} findings:\n")
    
    for finding in findings:
        finding_id, category, severity, desc, evidence, metadata = finding
        print(f"Finding ID: {finding_id}")
        print(f"  Category: {category}")
        print(f"  Severity: {severity}")
        print(f"  Description: {desc}")
        print(f"  Evidence: {evidence[:100]}...")
        print(f"  Metadata: {metadata[:200] if metadata else 'None'}...")
        
        # Try to parse metadata as JSON
        if metadata:
            try:
                meta_dict = json.loads(metadata)
                if 'poc' in meta_dict:
                    print(f"  ✅ HAS PoC DATA!")
                else:
                    print(f"  ❌ NO PoC in metadata")
            except:
                print(f"  ⚠️ Metadata not JSON")
        print()
else:
    print("No auth scans found")

conn.close()
