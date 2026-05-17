import sqlite3
import json

conn = sqlite3.connect('data/scan_history.db')
cursor = conn.cursor()

print("All findings in database:")
print("-" * 80)

# Get all findings
cursor.execute('SELECT id, scan_id, category, severity, metadata FROM findings ORDER BY id DESC LIMIT 10')
findings = cursor.fetchall()

print(f"Latest {len(findings)} findings:\n")

for finding in findings:
    finding_id, scan_id, category, severity, metadata = finding
    print(f"ID: {finding_id} | Scan: {scan_id}")
    print(f"  Category: {category} | Severity: {severity}")
    
    if metadata:
        try:
            meta_dict = json.loads(metadata)
            if 'poc' in meta_dict:
                print(f"  ✅ HAS PoC DATA!")
                print(f"     PoC keys: {list(meta_dict['poc'].keys())}")
            else:
                print(f"  ❌ NO PoC in metadata")
                print(f"     Metadata keys: {list(meta_dict.keys())}")
        except Exception as e:
            print(f"  ⚠️ Error parsing metadata: {e}")
    else:
        print(f"  ❌ Metadata is empty")
    print()

conn.close()
