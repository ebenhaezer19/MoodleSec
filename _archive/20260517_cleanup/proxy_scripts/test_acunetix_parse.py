#!/usr/bin/env python3
import json
from pathlib import Path

acunetix_dir = Path("data/raw/acunetix")
for json_file in acunetix_dir.glob("*.json"):
    print(f"\n[*] Testing: {json_file.name}")
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        print(f"    Keys: {list(data.keys())[:5]}")
        print(f"    Has 'vulnerability_types': {'vulnerability_types' in data}")
        print(f"    Has 'export': {'export' in data}")
        
        if 'vulnerability_types' in data:
            print(f"    Vuln types count: {len(data['vulnerability_types'])}")
            if data['vulnerability_types']:
                first = data['vulnerability_types'][0]
                print(f"    First vuln: {first.get('name', 'N/A')}")
        
        if 'export' in data:
            print(f"    Export format detected")
            
    except Exception as e:
        print(f"    Error: {e}")
