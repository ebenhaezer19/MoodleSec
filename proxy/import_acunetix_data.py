#!/usr/bin/env python3
"""
Import Acunetix Scan Results for ML Training

This script converts Acunetix scan results to the format
needed for ML model training.
"""

import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
import hashlib

# Paths
OUTPUT_DIR = "ml/training_data/acunetix_data"
OUTPUT_FILE = f"{OUTPUT_DIR}/acunetix_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

def parse_acunetix_xml(xml_file):
    """Parse Acunetix XML export."""
    print(f"Parsing Acunetix XML: {xml_file}")
    
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    findings = []
    
    # Acunetix XML structure: <ScanGroup><Scan><ReportItems><ReportItem>
    for report_item in root.findall('.//ReportItem'):
        finding = {
            'category': report_item.findtext('Name', 'Unknown'),
            'severity': map_acunetix_severity(report_item.findtext('Severity', '0')),
            'description': report_item.findtext('Description', ''),
            'url': report_item.findtext('Affects', ''),
            'evidence': report_item.findtext('Details', ''),
            'cvss_score': float(report_item.findtext('CVSS', '0') or 0),
            'recommendation': report_item.findtext('Recommendation', ''),
            'source': 'acunetix',
            'scan_timestamp': datetime.now().isoformat()
        }
        
        # Add PoC if exists
        poc = report_item.findtext('TechnicalDetails/Request')
        if poc:
            finding['proof_of_concept'] = poc
        
        findings.append(finding)
    
    print(f"Extracted {len(findings)} findings from XML")
    return findings

def parse_acunetix_json(json_file):
    """Parse Acunetix JSON export."""
    print(f"Parsing Acunetix JSON: {json_file}")
    
    with open(json_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    findings = []
    
    # Check for Acunetix export format
    if 'export' in data and 'scans' in data['export']:
        # New Acunetix format (24.x)
        for scan in data['export']['scans']:
            vuln_types = scan.get('vulnerability_types', [])
            
            for vt in vuln_types:
                # Create a finding for each vulnerability type
                finding = {
                    'category': vt.get('name', 'Unknown'),
                    'severity': map_acunetix_severity(vt.get('severity', 0)),
                    'description': vt.get('description', ''),
                    'url': scan.get('info', {}).get('start_url', ''),
                    'evidence': vt.get('details_template', ''),
                    'cvss_score': float(vt.get('cvss_score', 0) or 0),
                    'recommendation': vt.get('recommendation', ''),
                    'source': 'acunetix',
                    'scan_timestamp': scan.get('info', {}).get('start_date', datetime.now().isoformat()),
                    'impact': vt.get('impact', ''),
                    'tags': vt.get('tags', []),
                    'vuln_count': vt.get('vuln_count', 1)
                }
                
                findings.append(finding)
    
    # Try other common structures
    elif 'vulnerabilities' in data:
        vulnerabilities = data.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            finding = {
                'category': vuln.get('name', vuln.get('title', 'Unknown')),
                'severity': map_acunetix_severity(vuln.get('severity', '0')),
                'description': vuln.get('description', ''),
                'url': vuln.get('url', vuln.get('affects', '')),
                'evidence': vuln.get('details', vuln.get('evidence', '')),
                'cvss_score': float(vuln.get('cvss', vuln.get('cvss_score', 0)) or 0),
                'recommendation': vuln.get('recommendation', vuln.get('remediation', '')),
                'source': 'acunetix',
                'scan_timestamp': datetime.now().isoformat()
            }
            
            # Add PoC if exists
            if 'request' in vuln:
                finding['proof_of_concept'] = vuln['request']
            elif 'http_request' in vuln:
                finding['proof_of_concept'] = vuln['http_request']
            
            findings.append(finding)
    
    elif 'results' in data:
        vulnerabilities = data.get('results', [])
        for vuln in vulnerabilities:
            finding = {
                'category': vuln.get('name', vuln.get('title', 'Unknown')),
                'severity': map_acunetix_severity(vuln.get('severity', '0')),
                'description': vuln.get('description', ''),
                'url': vuln.get('url', vuln.get('affects', '')),
                'evidence': vuln.get('details', vuln.get('evidence', '')),
                'cvss_score': float(vuln.get('cvss', vuln.get('cvss_score', 0)) or 0),
                'recommendation': vuln.get('recommendation', vuln.get('remediation', '')),
                'source': 'acunetix',
                'scan_timestamp': datetime.now().isoformat()
            }
            findings.append(finding)
    
    print(f"Extracted {len(findings)} findings from JSON")
    return findings

def map_acunetix_severity(severity):
    """Map Acunetix severity to standard format."""
    severity_map = {
        '4': 'Critical',
        '3': 'High',
        '2': 'Medium',
        '1': 'Low',
        '0': 'Info',
        'critical': 'Critical',
        'high': 'High',
        'medium': 'Medium',
        'low': 'Low',
        'informational': 'Info',
        'info': 'Info'
    }
    
    severity_str = str(severity).lower()
    return severity_map.get(severity_str, 'Medium')

def auto_label_acunetix_findings(findings):
    """Auto-label Acunetix findings based on patterns."""
    labeled_data = []
    
    # Known false positive patterns in Acunetix
    fp_patterns = {
        'xss_in_error_page': {
            'pattern': lambda f: (
                'xss' in f.get('category', '').lower() and
                any(p in f.get('url', '').lower() for p in ['error', '404', '500'])
            ),
            'label': 1,
            'reason': 'XSS in error pages (usually FP)'
        },
        'xss_dangerous_tag_moodle': {
            'pattern': lambda f: (
                'xss' in f.get('category', '').lower() and
                any(tag in f.get('evidence', '').lower() for tag in [
                    'jquery', 'bootstrap', 'moodle', 'yui', 'requirejs'
                ])
            ),
            'label': 1,
            'reason': 'XSS in Moodle legitimate libraries'
        },
        'sql_in_token': {
            'pattern': lambda f: (
                'sql' in f.get('category', '').lower() and
                any(p in f.get('url', '').lower() for p in ['token', 'sesskey', 'wstoken'])
            ),
            'label': 1,
            'reason': 'SQL keywords in tokens (FP)'
        },
        'missing_headers': {
            'pattern': lambda f: (
                f.get('severity', '').lower() in ['low', 'info'] and
                any(h in f.get('category', '').lower() for h in [
                    'header', 'hsts', 'csp', 'x-frame', 'x-content', 'permissions-policy'
                ])
            ),
            'label': 1,
            'reason': 'Missing security headers (best practice, not vulnerability)'
        },
        'credentials_over_http': {
            'pattern': lambda f: (
                'credentials' in f.get('category', '').lower() and
                'clear text' in f.get('category', '').lower() and
                f.get('severity', '').lower() in ['medium', 'high']
            ),
            'label': 0,
            'reason': 'Credentials sent over HTTP (TRUE POSITIVE - security risk)'
        },
        'apache_server_status': {
            'pattern': lambda f: (
                'apache' in f.get('category', '').lower() and
                'server-status' in f.get('category', '').lower() and
                f.get('severity', '').lower() in ['medium', 'high']
            ),
            'label': 0,
            'reason': 'Apache server-status exposed (TRUE POSITIVE - info disclosure)'
        },
        'csrf_confirmed': {
            'pattern': lambda f: (
                'csrf' in f.get('category', '').lower() and
                f.get('severity', '').lower() in ['high', 'critical'] and
                'proof_of_concept' in f
            ),
            'label': 0,
            'reason': 'CSRF with PoC (TRUE POSITIVE)'
        },
        'sql_injection_confirmed': {
            'pattern': lambda f: (
                'sql' in f.get('category', '').lower() and
                f.get('severity', '').lower() in ['high', 'critical'] and
                any(e in f.get('evidence', '').lower() for e in [
                    'sql error', 'mysql', 'postgresql', 'syntax error'
                ])
            ),
            'label': 0,
            'reason': 'SQL Injection with error (TRUE POSITIVE)'
        },
        'xss_reflected_confirmed': {
            'pattern': lambda f: (
                'xss' in f.get('category', '').lower() and
                f.get('severity', '').lower() in ['high', 'critical'] and
                'proof_of_concept' in f and
                'jquery' not in f.get('evidence', '').lower()
            ),
            'label': 0,
            'reason': 'Reflected XSS with PoC (TRUE POSITIVE)'
        }
    }
    
    categorized = 0
    uncategorized = 0
    
    for finding in findings:
        labeled = False
        
        for pattern_name, pattern_info in fp_patterns.items():
            if pattern_info['pattern'](finding):
                labeled_data.append({
                    'finding': finding,
                    'label': pattern_info['label'],
                    'label_name': 'FALSE_POSITIVE' if pattern_info['label'] == 1 else 'TRUE_POSITIVE',
                    'reason': pattern_info['reason'],
                    'pattern': pattern_name,
                    'confidence': 1.0
                })
                categorized += 1
                labeled = True
                break
        
        if not labeled:
            labeled_data.append({
                'finding': finding,
                'label': None,
                'label_name': 'NEEDS_REVIEW',
                'reason': 'No automatic pattern match',
                'pattern': None,
                'confidence': 0.0
            })
            uncategorized += 1
    
    print(f"Auto-categorized: {categorized}")
    print(f"Needs manual review: {uncategorized}")
    
    return labeled_data

def save_training_data(labeled_data):
    """Save labeled data for training."""
    Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
    
    # Separate into auto-labeled and needs-review
    auto_labeled = [d for d in labeled_data if d['label'] is not None]
    needs_review = [d for d in labeled_data if d['label'] is None]
    
    # Save auto-labeled data
    auto_file = OUTPUT_FILE.replace('.json', '_auto_labeled.json')
    with open(auto_file, 'w') as f:
        json.dump(auto_labeled, f, indent=2)
    print(f"Saved {len(auto_labeled)} auto-labeled findings to {auto_file}")
    
    # Save needs-review data
    if needs_review:
        review_file = OUTPUT_FILE.replace('.json', '_needs_review.json')
        with open(review_file, 'w') as f:
            json.dump(needs_review, f, indent=2)
        print(f"Saved {len(needs_review)} findings needing review to {review_file}")
    
    # Generate summary
    summary = {
        'total_findings': len(labeled_data),
        'auto_labeled': len(auto_labeled),
        'needs_review': len(needs_review),
        'true_positives': sum(1 for d in auto_labeled if d['label'] == 0),
        'false_positives': sum(1 for d in auto_labeled if d['label'] == 1),
        'source': 'acunetix',
        'timestamp': datetime.now().isoformat(),
        'categories': {}
    }
    
    # Count by category
    for item in auto_labeled:
        category = item['finding'].get('category', 'unknown')
        if category not in summary['categories']:
            summary['categories'][category] = {'tp': 0, 'fp': 0}
        
        if item['label'] == 0:
            summary['categories'][category]['tp'] += 1
        else:
            summary['categories'][category]['fp'] += 1
    
    summary_file = OUTPUT_FILE.replace('.json', '_summary.json')
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"Saved summary to {summary_file}")
    
    return summary

def main():
    """Main function."""
    import sys
    
    print("=" * 60)
    print("IMPORT ACUNETIX SCAN RESULTS")
    print("=" * 60)
    print()
    
    if len(sys.argv) < 2:
        print("Usage: python import_acunetix_data.py <acunetix_file.xml|json>")
        print()
        print("Steps:")
        print("1. Run Acunetix scan on Moodle")
        print("2. Export results as XML or JSON")
        print("3. Run this script: python import_acunetix_data.py scan_results.xml")
        print("4. Review and label findings: python label_findings.py")
        print("5. Merge with existing data")
        print("6. Retrain models: python retrain_models.py")
        return
    
    input_file = sys.argv[1]
    
    if not Path(input_file).exists():
        print(f"Error: File not found: {input_file}")
        return
    
    # Step 1: Parse Acunetix file
    print("Step 1: Parsing Acunetix results...")
    
    if input_file.endswith('.xml'):
        findings = parse_acunetix_xml(input_file)
    elif input_file.endswith('.json'):
        findings = parse_acunetix_json(input_file)
    else:
        print("Error: Unsupported file format. Use .xml or .json")
        return
    
    if not findings:
        print("No findings found in file!")
        return
    
    print()
    
    # Step 2: Auto-label findings
    print("Step 2: Auto-labeling findings...")
    labeled_data = auto_label_acunetix_findings(findings)
    print()
    
    # Step 3: Save training data
    print("Step 3: Saving training data...")
    summary = save_training_data(labeled_data)
    print()
    
    # Step 4: Print summary
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total Findings: {summary['total_findings']}")
    print(f"Auto-labeled: {summary['auto_labeled']}")
    print(f"  - True Positives: {summary['true_positives']}")
    print(f"  - False Positives: {summary['false_positives']}")
    print(f"Needs Review: {summary['needs_review']}")
    print()
    print("Breakdown by Category:")
    for category, counts in summary['categories'].items():
        print(f"  {category}:")
        print(f"    TP: {counts['tp']}, FP: {counts['fp']}")
    print()
    print("Next Steps:")
    print("1. Review findings: python label_findings.py")
    print("2. Merge with existing data (see merge_training_data.py)")
    print("3. Retrain models: python retrain_models.py")
    print()

if __name__ == "__main__":
    main()
