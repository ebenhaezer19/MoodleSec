from database.scan_history import ScanHistoryDB

db = ScanHistoryDB()

print("Testing get_scan_with_findings:")
print("-" * 80)

scan_data = db.get_scan_with_findings('auth_scan_20251118_193606')

if scan_data:
    print(f"Scan ID: {scan_data['scan_id']}")
    print(f"Total findings: {len(scan_data['findings'])}")
    
    for finding in scan_data['findings']:
        print(f"\nFinding: {finding['category']}")
        print(f"  Severity: {finding['severity']}")
        
        if 'poc' in finding:
            print(f"  ✅ HAS PoC!")
            print(f"     PoC keys: {list(finding['poc'].keys())}")
        else:
            print(f"  ❌ NO PoC")
            print(f"     Finding keys: {list(finding.keys())}")
else:
    print("Scan not found")
