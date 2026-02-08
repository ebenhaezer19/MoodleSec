#!/usr/bin/env python3
"""
Find Potential True Positive Samples

Analyze existing findings to identify candidates for TP labeling.
Focuses on high-severity, exploitable vulnerabilities.
"""

import json
from pathlib import Path
from collections import Counter

def analyze_potential_tp():
    """Find high-severity findings that could be True Positives."""
    
    data_file = Path('ml/training_data/real_data/processed_findings_20260129_121146.json')
    
    print("=" * 80)
    print("POTENTIAL TRUE POSITIVE CANDIDATES")
    print("=" * 80)
    print("\nAnalyzing findings for exploitable vulnerabilities...")
    
    with open(data_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    # Exploitable keywords (from OWASP Top 10, CVE patterns)
    exploitable_keywords = [
        'sql injection', 'sqli', 'injection',
        'xss', 'cross-site scripting', 'script injection',
        'csrf', 'cross-site request forgery',
        'rce', 'remote code execution', 'command injection',
        'file upload', 'unrestricted upload',
        'path traversal', 'directory traversal',
        'authentication bypass', 'authorization bypass',
        'session fixation', 'session hijacking',
        'xxe', 'xml external entity',
        'ssrf', 'server-side request forgery',
        'deserialization', 'insecure deserialization',
        'ldap injection', 'xml injection',
        'open redirect', 'unvalidated redirect'
    ]
    
    # Analyze findings
    high_severity = []
    medium_with_exploitable = []
    current_tp = []
    current_fp = []
    unlabeled = []
    
    for item in data:
        finding = item.get('finding', item)
        label = item.get('label', -1)
        
        category = finding.get('category', '').lower()
        description = finding.get('description', '').lower()
        severity = finding.get('severity', '').lower()
        
        # Check for exploitable keywords
        has_exploitable = any(kw in category or kw in description for kw in exploitable_keywords)
        
        # Categorize
        if label == 0:
            current_tp.append(item)
        elif label == 1:
            current_fp.append(item)
        else:
            unlabeled.append(item)
        
        # High severity findings
        if severity in ['high', 'critical']:
            high_severity.append({
                'item': item,
                'category': finding.get('category', 'Unknown'),
                'severity': severity,
                'has_exploitable': has_exploitable,
                'label': label
            })
        
        # Medium severity with exploitable keywords
        elif severity == 'medium' and has_exploitable:
            medium_with_exploitable.append({
                'item': item,
                'category': finding.get('category', 'Unknown'),
                'severity': severity,
                'label': label
            })
    
    # Report current state
    print(f"\n📊 Current Dataset State:")
    print(f"   Total findings: {len(data)}")
    print(f"   True Positives (TP): {len(current_tp)}")
    print(f"   False Positives (FP): {len(current_fp)}")
    print(f"   Unlabeled: {len(unlabeled)}")
    print(f"   Imbalance ratio: {len(current_fp)/len(current_tp) if current_tp else 'N/A'}:1")
    
    # High severity candidates
    print(f"\n🔴 HIGH/CRITICAL SEVERITY FINDINGS: {len(high_severity)}")
    print("-" * 80)
    
    unlabeled_high = [f for f in high_severity if f['label'] == -1]
    labeled_high = [f for f in high_severity if f['label'] != -1]
    
    print(f"   Unlabeled: {len(unlabeled_high)}")
    print(f"   Already labeled: {len(labeled_high)}")
    
    if unlabeled_high:
        print("\n   Top candidates for TP labeling:")
        for i, finding in enumerate(unlabeled_high[:10], 1):
            exploit_flag = "⚠️ EXPLOITABLE" if finding['has_exploitable'] else ""
            print(f"   {i}. [{finding['severity'].upper()}] {finding['category'][:60]} {exploit_flag}")
    
    # Medium with exploitable
    print(f"\n🟡 MEDIUM SEVERITY WITH EXPLOITABLE KEYWORDS: {len(medium_with_exploitable)}")
    print("-" * 80)
    
    unlabeled_medium = [f for f in medium_with_exploitable if f['label'] == -1]
    labeled_medium = [f for f in medium_with_exploitable if f['label'] != -1]
    
    print(f"   Unlabeled: {len(unlabeled_medium)}")
    print(f"   Already labeled: {len(labeled_medium)}")
    
    if unlabeled_medium:
        print("\n   Top candidates for TP labeling:")
        for i, finding in enumerate(unlabeled_medium[:10], 1):
            print(f"   {i}. [MEDIUM] {finding['category'][:60]}")
    
    # Category analysis
    print(f"\n📂 EXPLOITABLE CATEGORIES (by frequency):")
    print("-" * 80)
    
    all_exploitable = high_severity + medium_with_exploitable
    category_counts = Counter([f['category'] for f in all_exploitable])
    
    for category, count in category_counts.most_common(15):
        unlabeled_count = sum(1 for f in all_exploitable if f['category'] == category and f['label'] == -1)
        print(f"   {category[:60]:<60} | Total: {count:2d} | Unlabeled: {unlabeled_count:2d}")
    
    # Recommendations
    print(f"\n💡 RECOMMENDATIONS:")
    print("-" * 80)
    print(f"   1. Review {len(unlabeled_high)} HIGH/CRITICAL unlabeled findings")
    print(f"   2. Review {len(unlabeled_medium)} MEDIUM exploitable unlabeled findings")
    print(f"   3. Target: Label at least 30 TP samples (currently: {len(current_tp)})")
    print(f"   4. Focus on Moodle-specific categories (auth, session, file upload)")
    
    # Save candidates to file
    output_file = Path('ml/training_data/real_data/tp_candidates.json')
    candidates = {
        'high_severity_unlabeled': [f['item'] for f in unlabeled_high],
        'medium_exploitable_unlabeled': [f['item'] for f in unlabeled_medium],
        'summary': {
            'total_candidates': len(unlabeled_high) + len(unlabeled_medium),
            'high_severity': len(unlabeled_high),
            'medium_exploitable': len(unlabeled_medium),
            'current_tp_count': len(current_tp),
            'target_tp_count': 30
        }
    }
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(candidates, f, indent=2, ensure_ascii=False)
    
    print(f"\n💾 Candidates saved to: {output_file}")
    print("\n" + "=" * 80)

if __name__ == '__main__':
    analyze_potential_tp()
