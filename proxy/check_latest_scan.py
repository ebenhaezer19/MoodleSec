#!/usr/bin/env python3
from database.scan_history import ScanHistoryDB

db = ScanHistoryDB()
scan = db.get_scan_with_findings('auth_scan_20251122_070417')

if scan and scan.get('findings'):
    finding = scan['findings'][0]
    print(f"Scan ID: {scan['scan_id']}")
    print(f"Finding: {finding.get('category')}")
    print(f"Risk Score: {finding.get('risk_score', 'NOT FOUND')}")
    print(f"CVSS Score: {finding.get('cvss_score', 'NOT FOUND')}")
    print(f"Priority: {finding.get('priority', 'NOT FOUND')}")
else:
    print("No findings found")
