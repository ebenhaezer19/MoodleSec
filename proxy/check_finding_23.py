import sqlite3
import json

conn = sqlite3.connect('data/scan_history.db')
cursor = conn.cursor()

print("Checking Finding ID 23 (Session Management):")
print("-" * 80)

cursor.execute('SELECT id, scan_id, category, severity, metadata FROM findings WHERE id = 23')
finding = cursor.fetchone()

if finding:
    finding_id, scan_id, category, severity, metadata = finding
    print(f"ID: {finding_id}")
    print(f"Scan: {scan_id}")
    print(f"Category: {category}")
    print(f"Severity: {severity}")
    print(f"\nMetadata (raw): {metadata[:500]}...")
    
    if metadata:
        try:
            meta_dict = json.loads(metadata)
            print(f"\nMetadata parsed successfully!")
            print(f"Keys: {list(meta_dict.keys())}")
            
            if 'poc' in meta_dict:
                print(f"\n✅ HAS PoC DATA!")
                poc = meta_dict['poc']
                print(f"PoC keys: {list(poc.keys())}")
                if 'request' in poc:
                    print(f"  Request URL: {poc['request'].get('url', 'N/A')}")
                if 'steps' in poc:
                    print(f"  Steps count: {len(poc['steps'])}")
            else:
                print(f"\n❌ NO PoC in metadata")
        except Exception as e:
            print(f"\n⚠️ Error parsing metadata: {e}")
    else:
        print(f"\n❌ Metadata is empty")
else:
    print("Finding ID 23 not found")

conn.close()
