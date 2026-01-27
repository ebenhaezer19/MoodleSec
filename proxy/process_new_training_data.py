#!/usr/bin/env python3
"""
Process New Training Data from OWASP ZAP and Acunetix
- Load all JSON files from OWASP_ZAP_Data and Acunnetix_Data folders
- Normalize format to match system
- Remove duplicates
- Auto-label findings
- Merge with existing real data
- Generate training report
"""

import json
import os
import hashlib
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Any, Set

# Auto-labeling patterns
AUTO_LABEL_PATTERNS = {
    'FALSE_POSITIVE': {
        # Header/Cookie findings (typically FP in development)
        'patterns': [
            r'X-Frame-Options',
            r'X-Content-Type-Options',
            r'Content-Security-Policy.*Not Set',
            r'Strict-Transport-Security.*Not Set',
            r'Cookie.*Secure',
            r'Cookie.*HttpOnly',
            r'Cookie.*SameSite',
            r'Server.*Version',
            r'Timestamp Disclosure',
            r'Information Disclosure.*Suspicious Comments',
        ],
        'severity': ['Low', 'Informational', 'Info'],
        'confidence': 0.85
    },
    'TRUE_POSITIVE': {
        # Critical vulnerabilities (likely TP)
        'patterns': [
            r'SQL Injection.*exploitable',
            r'Remote Code Execution',
            r'Path Traversal',
            r'Authentication Bypass',
            r'Privilege Escalation',
            r'File Upload',
            r'Command Injection',
        ],
        'severity': ['Critical', 'High'],
        'confidence': 0.95
    },
    'NEEDS_REVIEW': {
        # Medium severity - needs manual review
        'patterns': [
            r'XSS.*(?!error)',
            r'CSRF',
            r'Clickjacking',
        ],
        'severity': ['Medium', 'High'],
        'confidence': 0.5
    }
}

def calculate_hash(finding: Dict[str, Any]) -> str:
    """Calculate unique hash for a finding to detect duplicates."""
    # Use category, severity, and URL as unique identifier
    key_fields = [
        finding.get('category', ''),
        finding.get('severity', ''),
        finding.get('url', ''),
        finding.get('description', '')[:100]  # First 100 chars
    ]
    key_string = '|'.join(str(f) for f in key_fields)
    return hashlib.md5(key_string.encode()).hexdigest()

def auto_label_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Auto-label a finding based on patterns."""
    import re
    
    category = finding.get('category', '')
    severity = finding.get('severity', '')
    description = finding.get('description', '')
    cvss_score = finding.get('cvss_score', 0)
    
    # Check patterns
    for label_type, config in AUTO_LABEL_PATTERNS.items():
        # Check severity match
        if severity in config.get('severity', []):
            # Check pattern match
            for pattern in config.get('patterns', []):
                if re.search(pattern, category, re.IGNORECASE) or \
                   re.search(pattern, description, re.IGNORECASE):
                    
                    label = 1 if label_type == 'FALSE_POSITIVE' else 0
                    confidence = config.get('confidence', 0.5)
                    
                    return {
                        'label': label,
                        'label_name': label_type,
                        'confidence': confidence,
                        'reason': f"Pattern matched: {pattern}",
                        'strategy': 'auto_pattern'
                    }
    
    # CVSS-based labeling
    if cvss_score == 0 or cvss_score < 4.0:
        return {
            'label': 1,
            'label_name': 'FALSE_POSITIVE',
            'confidence': 0.7,
            'reason': f"Low CVSS score ({cvss_score})",
            'strategy': 'cvss_threshold'
        }
    
    # Default: needs review
    return {
        'label': -1,
        'label_name': 'NEEDS_REVIEW',
        'confidence': 0.5,
        'reason': "No clear pattern match",
        'strategy': 'default'
    }

def normalize_owasp_finding(raw_finding: Dict[str, Any], scan_id: str) -> Dict[str, Any]:
    """Normalize OWASP ZAP finding to system format."""
    finding = {
        'scan_id': scan_id,
        'severity': raw_finding.get('severity', raw_finding.get('risk', 'Medium')),
        'category': raw_finding.get('name', raw_finding.get('alert', 'Unknown')),
        'description': raw_finding.get('description', raw_finding.get('desc', '')),
        'evidence': raw_finding.get('solution', raw_finding.get('solution', '')),
        'url': raw_finding.get('url', ''),
        'cvss_score': float(raw_finding.get('cweid', 0)),
        'risk_score': 0,
        'priority': 3,
        'first_seen': datetime.now().isoformat(),
        'last_seen': datetime.now().isoformat(),
        'status': 'open',
        'scan_type': 'zap',
        'scan_timestamp': datetime.now().isoformat() + 'Z',
        'metadata': {
            'recommendation': raw_finding.get('solution', ''),
            'reference': raw_finding.get('reference', ''),
            'cwe_id': raw_finding.get('cweid', ''),
            'wasc_id': raw_finding.get('wascid', '')
        }
    }
    
    return finding

def normalize_acunetix_finding(raw_finding: Dict[str, Any], scan_id: str) -> Dict[str, Any]:
    """Normalize Acunetix finding to system format."""
    finding = {
        'scan_id': scan_id,
        'severity': raw_finding.get('Severity', raw_finding.get('severity', 'Medium')),
        'category': raw_finding.get('Name', raw_finding.get('name', 'Unknown')),
        'description': raw_finding.get('Description', raw_finding.get('description', '')),
        'evidence': raw_finding.get('Recommendation', raw_finding.get('recommendation', '')),
        'url': raw_finding.get('AffectedUrl', raw_finding.get('url', '')),
        'cvss_score': float(raw_finding.get('Cvss31Score', raw_finding.get('cvss_score', 0))),
        'risk_score': 0,
        'priority': 3,
        'first_seen': datetime.now().isoformat(),
        'last_seen': datetime.now().isoformat(),
        'status': 'open',
        'scan_type': 'acunetix',
        'scan_timestamp': datetime.now().isoformat() + 'Z',
        'metadata': {
            'recommendation': raw_finding.get('Recommendation', ''),
            'details': raw_finding.get('Details', ''),
            'type': raw_finding.get('Type', ''),
            'confirmed': raw_finding.get('Confirmed', False)
        }
    }
    
    return finding

def process_all_data():
    """Process all data from OWASP and Acunetix folders."""
    base_path = Path('ml/training_data')
    owasp_path = base_path / 'real_data' / 'OWASP_ZAP_Data'
    acunetix_path = base_path / 'real_data' / 'Acunnetix_Data'
    
    all_findings = []
    seen_hashes: Set[str] = set()
    duplicates_removed = 0
    stats = {
        'owasp_files': 0,
        'acunetix_files': 0,
        'total_findings': 0,
        'unique_findings': 0,
        'duplicates': 0,
        'auto_labeled_tp': 0,
        'auto_labeled_fp': 0,
        'needs_review': 0
    }
    
    print("="*80)
    print("PROCESSING NEW TRAINING DATA")
    print("="*80)
    print()
    
    # Process OWASP ZAP data
    print("📂 Processing OWASP ZAP Data...")
    if owasp_path.exists():
        for json_file in owasp_path.glob('*.json'):
            stats['owasp_files'] += 1
            print(f"   Loading: {json_file.name}")
            
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                scan_id = f"zap_{json_file.stem}"
                
                # Handle different OWASP ZAP formats
                if isinstance(data, dict):
                    alerts = data.get('site', [{}])[0].get('alerts', []) if 'site' in data else data.get('alerts', [])
                elif isinstance(data, list):
                    alerts = data
                else:
                    alerts = []
                
                for alert in alerts:
                    finding = normalize_owasp_finding(alert, scan_id)
                    finding_hash = calculate_hash(finding)
                    
                    if finding_hash not in seen_hashes:
                        seen_hashes.add(finding_hash)
                        
                        # Auto-label
                        label_info = auto_label_finding(finding)
                        
                        labeled_finding = {
                            'finding': finding,
                            **label_info
                        }
                        
                        all_findings.append(labeled_finding)
                        stats['total_findings'] += 1
                        
                        if label_info['label'] == 0:
                            stats['auto_labeled_tp'] += 1
                        elif label_info['label'] == 1:
                            stats['auto_labeled_fp'] += 1
                        else:
                            stats['needs_review'] += 1
                    else:
                        stats['duplicates'] += 1
                        
            except Exception as e:
                print(f"   ⚠️  Error loading {json_file.name}: {e}")
    
    print(f"   ✅ Processed {stats['owasp_files']} OWASP ZAP files")
    print()
    
    # Process Acunetix data
    print("📂 Processing Acunetix Data...")
    if acunetix_path.exists():
        for json_file in acunetix_path.glob('*.json'):
            stats['acunetix_files'] += 1
            print(f"   Loading: {json_file.name}")
            
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                scan_id = f"acunetix_{json_file.stem}"
                
                # Handle different Acunetix formats
                vulnerabilities = data.get('Vulnerabilities', data.get('vulnerabilities', []))
                
                for vuln in vulnerabilities:
                    finding = normalize_acunetix_finding(vuln, scan_id)
                    finding_hash = calculate_hash(finding)
                    
                    if finding_hash not in seen_hashes:
                        seen_hashes.add(finding_hash)
                        
                        # Auto-label
                        label_info = auto_label_finding(finding)
                        
                        labeled_finding = {
                            'finding': finding,
                            **label_info
                        }
                        
                        all_findings.append(labeled_finding)
                        stats['total_findings'] += 1
                        
                        if label_info['label'] == 0:
                            stats['auto_labeled_tp'] += 1
                        elif label_info['label'] == 1:
                            stats['auto_labeled_fp'] += 1
                        else:
                            stats['needs_review'] += 1
                    else:
                        stats['duplicates'] += 1
                        
            except Exception as e:
                print(f"   ⚠️  Error loading {json_file.name}: {e}")
    
    print(f"   ✅ Processed {stats['acunetix_files']} Acunetix files")
    print()
    
    stats['unique_findings'] = len(all_findings)
    
    # Save processed data
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = base_path / 'real_data' / f'processed_findings_{timestamp}.json'
    
    print("="*80)
    print("STATISTICS")
    print("="*80)
    print(f"📊 OWASP ZAP Files: {stats['owasp_files']}")
    print(f"📊 Acunetix Files: {stats['acunetix_files']}")
    print(f"📊 Total Findings Processed: {stats['total_findings']}")
    print(f"📊 Unique Findings: {stats['unique_findings']}")
    print(f"📊 Duplicates Removed: {stats['duplicates']}")
    print(f"✅ Auto-labeled TP: {stats['auto_labeled_tp']}")
    print(f"❌ Auto-labeled FP: {stats['auto_labeled_fp']}")
    print(f"⚠️  Needs Review: {stats['needs_review']}")
    print()
    
    # Save to file
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(all_findings, f, indent=2, ensure_ascii=False)
    
    print(f"💾 Saved to: {output_file}")
    print()
    
    # Save summary
    summary_file = base_path / 'real_data' / f'processed_summary_{timestamp}.json'
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=2)
    
    print(f"💾 Summary saved to: {summary_file}")
    print()
    
    print("="*80)
    print("✅ PROCESSING COMPLETE!")
    print("="*80)
    print()
    print("Next steps:")
    print(f"1. Review needs_review findings: {stats['needs_review']} items")
    print(f"2. Merge with existing data:")
    print(f"   python merge_training_data.py")
    print(f"3. Retrain model:")
    print(f"   python retrain_models.py --data ml/training_data/real_data/processed_findings_{timestamp}.json")
    print()
    
    return all_findings, stats

if __name__ == '__main__':
    process_all_data()
