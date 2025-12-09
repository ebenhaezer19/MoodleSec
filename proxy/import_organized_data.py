#!/usr/bin/env python3
"""
Import Organized Scan Data to Database and Auto-Label for ML Training

This script:
1. Reads organized JSON files from data/raw/
2. Imports findings to database
3. Auto-labels findings using enhanced patterns
4. Prepares data for ML training
"""

import json
import sqlite3
from pathlib import Path
from datetime import datetime
import sys

# Import auto-labeling logic
sys.path.append(str(Path(__file__).parent))
from enhanced_auto_label import EnhancedAutoLabeler

DB_PATH = "data/scan_history.db"
ACUNETIX_DIR = Path("data/raw/acunetix")
ZAP_DIR = Path("data/raw/owasp_zap")
OUTPUT_DIR = Path("ml/training_data")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

def init_database():
    """Initialize database if not exists."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id TEXT PRIMARY KEY,
            scan_type TEXT,
            target_url TEXT,
            timestamp TEXT,
            status TEXT,
            findings_count INTEGER,
            metadata TEXT
        )
    """)
    
    # Create findings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            severity TEXT,
            category TEXT,
            description TEXT,
            evidence TEXT,
            url TEXT,
            cvss_score REAL,
            risk_score REAL,
            priority TEXT,
            first_seen TEXT,
            last_seen TEXT,
            status TEXT,
            metadata TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
        )
    """)
    
    conn.commit()
    conn.close()
    print("[+] Database initialized")

def parse_acunetix_file(file_path):
    """Parse Acunetix JSON file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    findings = []
    scan_id = f"acunetix_{file_path.stem}"
    target_url = 'unknown'
    
    # Try to get target URL from locations
    if 'locations' in data and data['locations']:
        target_url = data['locations'][0].get('root_url', 'unknown')
    
    # Parse Acunetix export format (old format)
    if 'export' in data and 'scans' in data['export']:
        for scan in data['export']['scans']:
            target_url = scan.get('target', {}).get('url', target_url)
            
            for vuln_type in scan.get('vulnerability_types', []):
                for vuln in vuln_type.get('vulnerabilities', []):
                    finding = {
                        'scan_id': scan_id,
                        'severity': vuln.get('severity', 'unknown'),
                        'category': vuln_type.get('name', 'unknown'),
                        'description': vuln.get('details', {}).get('description', ''),
                        'evidence': vuln.get('details', {}).get('proof', ''),
                        'url': vuln.get('affects_url', target_url),
                        'cvss_score': vuln.get('cvss_score', 0.0),
                        'timestamp': scan.get('start_date', datetime.now().isoformat())
                    }
                    findings.append(finding)
    
    # Parse Acunetix new format (vulnerability_types at root)
    elif 'vulnerability_types' in data:
        for vuln_type in data['vulnerability_types']:
            # Map severity number to string
            severity_map = {0: 'info', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
            severity = severity_map.get(vuln_type.get('severity', 0), 'unknown')
            
            finding = {
                'scan_id': scan_id,
                'severity': severity,
                'category': vuln_type.get('name', 'unknown'),
                'description': vuln_type.get('description', ''),
                'evidence': vuln_type.get('recommendation', ''),
                'url': target_url,
                'cvss_score': vuln_type.get('cvss_score', 0.0),
                'timestamp': datetime.now().isoformat()
            }
            findings.append(finding)
    
    return scan_id, findings

def parse_zap_file(file_path):
    """Parse OWASP ZAP JSON file."""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    findings = []
    scan_id = f"zap_{file_path.stem}"
    
    # Parse ZAP format
    for site in data.get('site', []):
        site_url = site.get('@name', 'unknown')
        
        for alert in site.get('alerts', []):
            finding = {
                'scan_id': scan_id,
                'severity': alert.get('riskdesc', 'unknown').split()[0],  # "High (Medium)" -> "High"
                'category': alert.get('name', 'unknown'),
                'description': alert.get('desc', ''),
                'evidence': alert.get('solution', ''),
                'url': alert.get('instances', [{}])[0].get('uri', site_url) if alert.get('instances') else site_url,
                'cvss_score': 0.0,  # ZAP doesn't provide CVSS by default
                'timestamp': datetime.now().isoformat()
            }
            findings.append(finding)
    
    return scan_id, findings

def import_to_database(scan_id, findings, scan_type):
    """Import findings to database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Insert scan record
    cursor.execute("""
        INSERT OR REPLACE INTO scans (scan_id, scan_type, target_url, timestamp, status, findings_count, metadata)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        scan_type,
        findings[0]['url'] if findings else 'unknown',
        findings[0]['timestamp'] if findings else datetime.now().isoformat(),
        'completed',
        len(findings),
        json.dumps({})
    ))
    
    # Insert findings
    for finding in findings:
        cursor.execute("""
            INSERT INTO findings (
                scan_id, severity, category, description, evidence, url,
                cvss_score, risk_score, priority, first_seen, last_seen, status, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding['scan_id'],
            finding['severity'],
            finding['category'],
            finding['description'],
            finding['evidence'],
            finding['url'],
            finding.get('cvss_score', 0.0),
            0.0,  # Will be calculated later
            'medium',
            finding['timestamp'],
            finding['timestamp'],
            'open',
            json.dumps({})
        ))
    
    conn.commit()
    conn.close()
    print(f"  [+] Imported {len(findings)} findings from {scan_id}")

def auto_label_and_export():
    """Auto-label findings and export for ML training."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM findings")
    all_findings = cursor.fetchall()
    
    auto_labeled = []
    needs_review = []
    
    print(f"\n[*] Auto-labeling {len(all_findings)} findings...")
    
    # Initialize auto-labeler
    labeler = EnhancedAutoLabeler()
    
    for row in all_findings:
        finding = {
            'severity': row['severity'],
            'category': row['category'],
            'description': row['description'],
            'evidence': row['evidence'],
            'url': row['url'],
            'cvss_score': row['cvss_score']
        }
        
        # Auto-label using enhanced patterns
        label, confidence, reason, strategy = labeler.label_finding(finding)
        
        labeled_finding = {
            **finding,
            'label': label if label is not None else -1,  # -1 for needs review
            'confidence': confidence,
            'reason': reason,
            'strategy': strategy,
            'scan_id': row['scan_id']
        }
        
        if label is not None and confidence >= 0.8:
            auto_labeled.append(labeled_finding)
        else:
            needs_review.append(labeled_finding)
    
    # Export to JSON files
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    auto_labeled_file = OUTPUT_DIR / f"auto_labeled_{timestamp}.json"
    with open(auto_labeled_file, 'w') as f:
        json.dump(auto_labeled, f, indent=2)
    
    needs_review_file = OUTPUT_DIR / f"needs_review_{timestamp}.json"
    with open(needs_review_file, 'w') as f:
        json.dump(needs_review, f, indent=2)
    
    conn.close()
    
    return auto_labeled, needs_review, auto_labeled_file, needs_review_file

def main():
    print("=" * 60)
    print("IMPORT ORGANIZED DATA & AUTO-LABEL FOR ML TRAINING")
    print("=" * 60)
    
    # Initialize database
    init_database()
    
    # Import Acunetix files
    print("\n[*] Importing Acunetix files...")
    acunetix_count = 0
    if ACUNETIX_DIR.exists():
        for json_file in ACUNETIX_DIR.glob("*.json"):
            try:
                scan_id, findings = parse_acunetix_file(json_file)
                if findings:
                    import_to_database(scan_id, findings, 'acunetix')
                    acunetix_count += len(findings)
            except Exception as e:
                print(f"  [!] Error processing {json_file.name}: {e}")
    
    # Import ZAP files
    print("\n[*] Importing OWASP ZAP files...")
    zap_count = 0
    if ZAP_DIR.exists():
        for json_file in ZAP_DIR.glob("*.json"):
            try:
                # Skip very large files (>100MB)
                if json_file.stat().st_size > 100 * 1024 * 1024:
                    print(f"  [!] Skipping large file: {json_file.name}")
                    continue
                
                scan_id, findings = parse_zap_file(json_file)
                if findings:
                    import_to_database(scan_id, findings, 'owasp_zap')
                    zap_count += len(findings)
            except Exception as e:
                print(f"  [!] Error processing {json_file.name}: {e}")
    
    print("\n" + "=" * 60)
    print(f"[+] Import Summary:")
    print(f"    Acunetix findings: {acunetix_count}")
    print(f"    OWASP ZAP findings: {zap_count}")
    print(f"    Total: {acunetix_count + zap_count}")
    print("=" * 60)
    
    # Auto-label findings
    auto_labeled, needs_review, auto_file, review_file = auto_label_and_export()
    
    print("\n" + "=" * 60)
    print("[+] Auto-Labeling Summary:")
    print(f"    Auto-labeled (high confidence): {len(auto_labeled)}")
    print(f"    Needs review (low confidence): {len(needs_review)}")
    print(f"\n[+] Exported to:")
    print(f"    {auto_file}")
    print(f"    {review_file}")
    print("=" * 60)
    
    # Check if ready for training
    if len(auto_labeled) >= 200:
        print("\n✅ Ready for ML training! Run: python retrain_models.py")
    else:
        print(f"\n⚠️  Need {200 - len(auto_labeled)} more labeled findings for optimal training")
        print("   You can:")
        print("   1. Manually review and label findings in needs_review file")
        print("   2. Scan more websites to collect more data")

if __name__ == "__main__":
    main()
