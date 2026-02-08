#!/usr/bin/env python3
"""Count Real Findings from OWASP ZAP and Acunetix Source Files"""

import json
from pathlib import Path
from collections import Counter

def count_findings_in_file(filepath):
    """Count findings in a JSON file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Handle different JSON structures
        if isinstance(data, list):
            return len(data)
        elif isinstance(data, dict):
            # Acunetix format: export.scans[].vulnerabilities
            if 'export' in data and 'scans' in data['export']:
                total = 0
                scans = data['export']['scans']
                for scan in scans:
                    vulns = scan.get('vulnerabilities', [])
                    total += len(vulns)
                return total
            # OWASP ZAP format might have 'site' key with alerts
            elif 'site' in data:
                sites = data['site'] if isinstance(data['site'], list) else [data['site']]
                total = 0
                for site in sites:
                    if 'alerts' in site:
                        total += len(site['alerts'])
                return total
            # Or direct findings
            elif 'findings' in data:
                return len(data['findings'])
            # Or vulnerabilities
            elif 'vulnerabilities' in data:
                return len(data['vulnerabilities'])
            else:
                return 1  # Single finding
        return 0
    except Exception as e:
        print(f"   Error reading {filepath.name}: {e}")
        return 0

def main():
    print('='*80)
    print('COUNT REAL FINDINGS FROM SOURCE FILES')
    print('='*80)
    print()
    
    # OWASP ZAP files
    zap_dir = Path('ml/training_data/OWASP_ZAP_Data')
    print('📊 OWASP ZAP Data:')
    print('-' * 80)
    
    zap_files = list(zap_dir.glob('*.json'))
    zap_total = 0
    
    for zap_file in sorted(zap_files):
        count = count_findings_in_file(zap_file)
        zap_total += count
        print(f'   {zap_file.name[:60]:60s}: {count:4d} findings')
    
    print(f'\n   Total OWASP ZAP: {zap_total} findings from {len(zap_files)} files')
    print()
    
    # Acunetix files
    acunetix_dir = Path('ml/training_data/Acunnetix_Data')
    print('📊 Acunetix Data:')
    print('-' * 80)
    
    acunetix_files = list(acunetix_dir.glob('*.json'))
    acunetix_total = 0
    
    for acunetix_file in sorted(acunetix_files):
        count = count_findings_in_file(acunetix_file)
        acunetix_total += count
        print(f'   {acunetix_file.name[:60]:60s}: {count:4d} findings')
    
    print(f'\n   Total Acunetix: {acunetix_total} findings from {len(acunetix_files)} files')
    print()
    
    # Summary
    print('='*80)
    print('SUMMARY')
    print('='*80)
    print()
    print(f'📊 Total Real Findings:')
    print(f'   OWASP ZAP:     {zap_total:4d} findings ({len(zap_files)} files)')
    print(f'   Acunetix:      {acunetix_total:4d} findings ({len(acunetix_files)} files)')
    print(f'   TOTAL:         {zap_total + acunetix_total:4d} findings')
    print()
    print(f'📈 Note: These are RAW findings before:')
    print(f'   - Deduplication')
    print(f'   - Filtering')
    print(f'   - Labeling (TP/FP)')
    print()

if __name__ == '__main__':
    main()
