#!/usr/bin/env python3
"""
Analyze Scan Targets

Count unique websites/targets in OWASP ZAP and Acunetix scan data.
"""

import json
from pathlib import Path
from collections import defaultdict
from urllib.parse import urlparse

def extract_domain(url):
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc or parsed.path.split('/')[0]
    except:
        return url

def analyze_owasp_targets():
    """Analyze OWASP ZAP scan targets."""
    owasp_dir = Path('ml/training_data/OWASP_ZAP_Data')
    
    if not owasp_dir.exists():
        print("⚠️  OWASP ZAP data directory not found")
        return {}
    
    files = list(owasp_dir.glob('*.json'))
    targets = defaultdict(lambda: {'files': [], 'findings': 0})
    
    print(f"\n📂 OWASP ZAP Data: {len(files)} files")
    print("=" * 80)
    
    for file in files:
        try:
            with open(file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract target from filename or data
            filename = file.name
            
            # Try to get target from data
            if 'site' in data and isinstance(data['site'], list) and len(data['site']) > 0:
                site = data['site'][0]
                target_url = site.get('@name', '')
                if target_url:
                    domain = extract_domain(target_url)
                else:
                    # Fallback to filename
                    domain = filename.replace('2025-12-05-ZAP-Report-', '').replace('.json', '')
            else:
                # Fallback to filename
                domain = filename.replace('2025-12-05-ZAP-Report-', '').replace('.json', '')
            
            # Count findings
            finding_count = 0
            if 'site' in data and isinstance(data['site'], list):
                for site in data['site']:
                    if 'alerts' in site and isinstance(site['alerts'], list):
                        finding_count += len(site['alerts'])
            
            targets[domain]['files'].append(filename)
            targets[domain]['findings'] += finding_count
            
        except Exception as e:
            print(f"⚠️  Error reading {file.name}: {e}")
    
    # Display results
    for domain, info in sorted(targets.items()):
        print(f"\n🌐 {domain}")
        print(f"   Files: {len(info['files'])}")
        print(f"   Findings: {info['findings']}")
        for fname in info['files']:
            print(f"   - {fname}")
    
    return targets

def analyze_acunetix_targets():
    """Analyze Acunetix scan targets."""
    acunetix_dir = Path('ml/training_data/Acunnetix_Data')
    
    if not acunetix_dir.exists():
        print("⚠️  Acunetix data directory not found")
        return {}
    
    files = list(acunetix_dir.glob('*.json'))
    targets = defaultdict(lambda: {'files': [], 'findings': 0})
    
    print(f"\n\n📂 Acunetix Data: {len(files)} files")
    print("=" * 80)
    
    for file in files:
        try:
            with open(file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Extract target from data
            domain = "Unknown"
            finding_count = 0
            
            if 'export' in data and 'scans' in data['export']:
                scans = data['export']['scans']
                if isinstance(scans, list) and len(scans) > 0:
                    scan = scans[0]
                    
                    # Get target URL
                    target_url = scan.get('target', {}).get('url', '')
                    if target_url:
                        domain = extract_domain(target_url)
                    
                    # Count vulnerabilities
                    if 'vulnerabilities' in scan:
                        finding_count = len(scan['vulnerabilities'])
            
            # If still unknown, use filename
            if domain == "Unknown":
                filename = file.name
                domain = filename.replace('acunetix_scan_', '').replace('.json', '')
            
            targets[domain]['files'].append(file.name)
            targets[domain]['findings'] += finding_count
            
        except Exception as e:
            print(f"⚠️  Error reading {file.name}: {e}")
    
    # Display results
    for domain, info in sorted(targets.items()):
        print(f"\n🌐 {domain}")
        print(f"   Files: {len(info['files'])}")
        print(f"   Findings: {info['findings']}")
        for fname in info['files'][:5]:  # Limit to first 5 files
            print(f"   - {fname}")
        if len(info['files']) > 5:
            print(f"   ... and {len(info['files']) - 5} more files")
    
    return targets

def main():
    """Main analysis function."""
    print("=" * 80)
    print("SCAN TARGET ANALYSIS")
    print("=" * 80)
    print("\nAnalyzing unique websites/targets in scan data...")
    
    # Analyze both sources
    owasp_targets = analyze_owasp_targets()
    acunetix_targets = analyze_acunetix_targets()
    
    # Summary
    print("\n\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    
    print(f"\n📊 OWASP ZAP:")
    print(f"   Unique targets: {len(owasp_targets)}")
    print(f"   Total files: {sum(len(t['files']) for t in owasp_targets.values())}")
    print(f"   Total findings: {sum(t['findings'] for t in owasp_targets.values())}")
    
    print(f"\n📊 Acunetix:")
    print(f"   Unique targets: {len(acunetix_targets)}")
    print(f"   Total files: {sum(len(t['files']) for t in acunetix_targets.values())}")
    print(f"   Total findings: {sum(t['findings'] for t in acunetix_targets.values())}")
    
    # Combined unique targets
    all_targets = set(owasp_targets.keys()) | set(acunetix_targets.keys())
    
    print(f"\n🌐 TOTAL UNIQUE WEBSITES: {len(all_targets)}")
    print("\nAll targets:")
    for i, target in enumerate(sorted(all_targets), 1):
        owasp_count = owasp_targets[target]['findings'] if target in owasp_targets else 0
        acunetix_count = acunetix_targets[target]['findings'] if target in acunetix_targets else 0
        total_findings = owasp_count + acunetix_count
        
        sources = []
        if target in owasp_targets:
            sources.append("OWASP")
        if target in acunetix_targets:
            sources.append("Acunetix")
        
        print(f"   {i}. {target}")
        print(f"      Sources: {', '.join(sources)}")
        print(f"      Findings: OWASP={owasp_count}, Acunetix={acunetix_count}, Total={total_findings}")
    
    print("\n" + "=" * 80)

if __name__ == '__main__':
    main()
