#!/usr/bin/env python3
"""
Collect Real Training Data from Scan History

This script extracts findings from your scan history database
and creates a labeled dataset for retraining the ML models.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path

# Paths
DB_PATH = "data/scan_history.db"
OUTPUT_DIR = "ml/training_data/real_data"
OUTPUT_FILE = f"{OUTPUT_DIR}/real_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

def collect_findings_from_db():
    """Extract all findings from scan history database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Get all findings from findings table
    cursor.execute("""
        SELECT 
            f.scan_id,
            f.severity,
            f.category,
            f.description,
            f.evidence,
            f.url,
            f.cvss_score,
            f.risk_score,
            f.priority,
            f.first_seen,
            f.last_seen,
            f.status,
            f.metadata,
            s.scan_type,
            s.timestamp as scan_timestamp
        FROM findings f
        JOIN scans s ON f.scan_id = s.scan_id
        ORDER BY f.last_seen DESC
    """)
    
    all_findings = []
    
    for row in cursor.fetchall():
        # Convert Row to dict
        finding = {
            'scan_id': row['scan_id'],
            'severity': row['severity'],
            'category': row['category'],
            'description': row['description'],
            'evidence': row['evidence'],
            'url': row['url'],
            'cvss_score': row['cvss_score'],
            'risk_score': row['risk_score'],
            'priority': row['priority'],
            'first_seen': row['first_seen'],
            'last_seen': row['last_seen'],
            'status': row['status'],
            'scan_type': row['scan_type'],
            'scan_timestamp': row['scan_timestamp']
        }
        
        # Parse metadata if exists
        if row['metadata']:
            try:
                metadata = json.loads(row['metadata'])
                finding['metadata'] = metadata
                # Add PoC if exists in metadata
                if 'proof_of_concept' in metadata:
                    finding['proof_of_concept'] = metadata['proof_of_concept']
            except json.JSONDecodeError:
                pass
        
        all_findings.append(finding)
    
    conn.close()
    
    # Count unique scans
    scan_ids = set(f['scan_id'] for f in all_findings)
    
    print(f"Collected {len(all_findings)} findings from {len(scan_ids)} scans")
    return all_findings

def categorize_findings(findings):
    """Automatically categorize findings as TP or FP based on patterns."""
    labeled_data = []
    
    fp_patterns = {
        'xss_dangerous_tag': {
            'pattern': lambda f: (
                f.get('category') == 'Cross-Site Scripting (XSS)' and
                'dangerous HTML tag' in f.get('description', '').lower()
            ),
            'label': 1,  # False Positive
            'reason': 'XSS dangerous tag in Moodle legitimate HTML'
        },
        'sql_in_button': {
            'pattern': lambda f: (
                f.get('category') == 'SQL Injection' and
                'submitbutton' in f.get('description', '').lower()
            ),
            'label': 1,  # False Positive
            'reason': 'SQL keyword in button text, not SQL query'
        },
        'csrf_missing_token': {
            'pattern': lambda f: (
                f.get('category') == 'Cross-Site Request Forgery (CSRF)' and
                'missing' in f.get('description', '').lower()
            ),
            'label': 0,  # True Positive
            'reason': 'Real CSRF vulnerability'
        },
        'xss_with_poc': {
            'pattern': lambda f: (
                f.get('category') == 'Cross-Site Scripting (XSS)' and
                f.get('proof_of_concept') is not None and
                'dangerous HTML tag' not in f.get('description', '').lower()
            ),
            'label': 0,  # True Positive
            'reason': 'Real XSS with PoC'
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
                    'confidence': 1.0  # High confidence in automatic labeling
                })
                categorized += 1
                labeled = True
                break
        
        if not labeled:
            # Mark for manual review
            labeled_data.append({
                'finding': finding,
                'label': None,  # Needs manual labeling
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
    print("=" * 60)
    print("COLLECTING REAL TRAINING DATA FROM SCAN HISTORY")
    print("=" * 60)
    print()
    
    # Step 1: Collect findings
    print("Step 1: Extracting findings from database...")
    findings = collect_findings_from_db()
    print()
    
    if not findings:
        print("No findings found in database!")
        return
    
    # Step 2: Categorize findings
    print("Step 2: Auto-categorizing findings...")
    labeled_data = categorize_findings(findings)
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
    print("1. Review findings in *_needs_review.json")
    print("2. Run: python retrain_models.py")
    print("3. New models will have higher confidence!")
    print()

if __name__ == "__main__":
    main()
