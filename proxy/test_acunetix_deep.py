#!/usr/bin/env python3
import json
from pathlib import Path

acunetix_dir = Path("data/raw/acunetix")
json_file = list(acunetix_dir.glob("*.json"))[0]

print(f"[*] Testing: {json_file.name}\n")

with open(json_file, 'r') as f:
    data = json.load(f)

export = data.get('export', {})
print(f"Export keys: {list(export.keys())}")

scans = export.get('scans', [])
print(f"Scans count: {len(scans)}")

if scans:
    scan = scans[0]
    print(f"\nFirst scan keys: {list(scan.keys())[:10]}")
    print(f"Has 'vulnerability_types': {'vulnerability_types' in scan}")
    
    vuln_types = scan.get('vulnerability_types', [])
    print(f"Vulnerability types count: {len(vuln_types)}")
    
    if vuln_types:
        first_vt = vuln_types[0]
        print(f"\nFirst vuln_type keys: {list(first_vt.keys())}")
        print(f"Name: {first_vt.get('name', 'N/A')}")
        print(f"Has 'vulnerabilities': {'vulnerabilities' in first_vt}")
        
        vulns = first_vt.get('vulnerabilities', [])
        print(f"Vulnerabilities count: {len(vulns)}")
