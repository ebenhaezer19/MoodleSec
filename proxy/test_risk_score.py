#!/usr/bin/env python3
"""Test if risk scores are being added to findings"""

from database.scan_history import ScanHistoryDB

db = ScanHistoryDB()

# Get latest auth scan
print("=" * 80)
print("CHECKING LATEST AUTH SCAN")
print("=" * 80)

scans = db.get_scan_history(limit=20)
auth_scans = [s for s in scans if s['scan_type'] == 'authentication']

if auth_scans:
    latest_auth = auth_scans[0]
    print(f"\nLatest Auth Scan: {latest_auth['scan_id']}")
    print(f"Timestamp: {latest_auth['timestamp']}")
    print(f"Total Findings: {latest_auth['total_findings']}")
    
    # Get full scan with findings
    scan_data = db.get_scan_with_findings(latest_auth['scan_id'])
    
    if scan_data and scan_data.get('findings'):
        print(f"\nFindings Analysis:")
        for i, finding in enumerate(scan_data['findings'], 1):
            print(f"\nFinding #{i}:")
            print(f"  Category: {finding.get('category')}")
            print(f"  Severity: {finding.get('severity')}")
            print(f"  Risk Score: {finding.get('risk_score', 'MISSING!')}")
            print(f"  CVSS Score: {finding.get('cvss_score', 'MISSING!')}")
            print(f"  Priority: {finding.get('priority', 'MISSING!')}")
    else:
        print("No findings found")
else:
    print("No auth scans found")

# Get latest API scan
print("\n" + "=" * 80)
print("CHECKING LATEST API SCAN")
print("=" * 80)

api_scans = [s for s in scans if s['scan_type'] == 'api']

if api_scans:
    latest_api = api_scans[0]
    print(f"\nLatest API Scan: {latest_api['scan_id']}")
    print(f"Timestamp: {latest_api['timestamp']}")
    print(f"Total Findings: {latest_api['total_findings']}")
    
    # Get full scan with findings
    scan_data = db.get_scan_with_findings(latest_api['scan_id'])
    
    if scan_data and scan_data.get('findings'):
        print(f"\nFindings Analysis (showing first 5):")
        for i, finding in enumerate(scan_data['findings'][:5], 1):
            print(f"\nFinding #{i}:")
            print(f"  Category: {finding.get('category')}")
            print(f"  Severity: {finding.get('severity')}")
            print(f"  Risk Score: {finding.get('risk_score', 'MISSING!')}")
            print(f"  CVSS Score: {finding.get('cvss_score', 'MISSING!')}")
            print(f"  Priority: {finding.get('priority', 'MISSING!')}")
    else:
        print("No findings found")
else:
    print("No API scans found")
