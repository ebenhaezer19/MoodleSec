#!/usr/bin/env python3
"""
Interactive script untuk review dan label findings yang needs review.
"""

import json
import os
from datetime import datetime

def load_needs_review():
    """Load needs review findings."""
    filepath = 'ml/training_data/needs_review_20251219_030244.json'
    with open(filepath, 'r') as f:
        return json.load(f)

def save_labeled(labeled_findings):
    """Save labeled findings."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filepath = f'ml/training_data/manually_labeled_{timestamp}.json'
    with open(filepath, 'w') as f:
        json.dump(labeled_findings, f, indent=2)
    print(f'\n✅ Saved to: {filepath}')
    return filepath

def display_finding(finding, index, total):
    """Display finding details."""
    print('\n' + '=' * 70)
    print(f'FINDING {index}/{total}')
    print('=' * 70)
    
    print(f'\n📋 Category: {finding.get("category", "Unknown")}')
    print(f'⚠️  Severity: {finding.get("severity", "Unknown").upper()}')
    
    # Show scan source
    scan_id = finding.get("scan_id", "Unknown")
    if scan_id != "Unknown":
        # Extract meaningful info from scan_id
        if "localhost" in scan_id:
            print(f'🌐 Source: localhost:8998 (Test Instance)')
        else:
            # Extract domain from scan_id
            parts = scan_id.replace("acunetix_", "").replace("zap_", "").split("_")
            domain = " ".join(parts[2:5]) if len(parts) > 2 else scan_id
            print(f'🌐 Source: {domain[:50]}')
    
    # Show URL if available and not "unknown"
    url = finding.get("url", "")
    if url and url != "unknown":
        print(f'🔗 URL: {url[:60]}...' if len(url) > 60 else f'🔗 URL: {url}')
    
    if 'description' in finding:
        desc = finding['description']
        print(f'\n📝 Description:')
        # Clean up description
        desc_clean = desc.replace('<br/>', ' ').replace('<br>', ' ')
        desc_clean = desc_clean.replace('&quot;', '"').replace('&lt;', '<').replace('&gt;', '>')
        print(f'   {desc_clean[:250]}...' if len(desc_clean) > 250 else f'   {desc_clean}')
    
    if 'evidence' in finding:
        evidence = finding['evidence']
        print(f'\n🔍 Evidence/Recommendation:')
        evidence_clean = evidence.replace('\n', ' ').strip()
        print(f'   {evidence_clean[:200]}...' if len(evidence_clean) > 200 else f'   {evidence_clean}')
    
    if 'cvss_score' in finding:
        cvss = finding.get("cvss_score", 0)
        risk = "CRITICAL" if cvss >= 9.0 else "HIGH" if cvss >= 7.0 else "MEDIUM" if cvss >= 4.0 else "LOW"
        print(f'\n💯 CVSS Score: {cvss} ({risk})')
    
    # Show current auto-label info if available
    if 'confidence' in finding and finding.get('confidence', 0) > 0:
        conf = finding.get('confidence', 0) * 100
        reason = finding.get('reason', 'Unknown')
        print(f'\n🤖 Auto-label: Confidence {conf:.1f}% - {reason[:60]}')

def get_label():
    """Get label from user."""
    print('\n' + '-' * 70)
    print('LABEL OPTIONS:')
    print('  [0] TRUE POSITIVE  - Real vulnerability, needs fixing')
    print('  [1] FALSE POSITIVE - Not a real vulnerability')
    print('  [s] SKIP - Review later')
    print('  [q] QUIT - Save and exit')
    print('-' * 70)
    
    while True:
        choice = input('\nYour choice [0/1/s/q]: ').strip().lower()
        
        if choice == 'q':
            return 'quit'
        elif choice == 's':
            return 'skip'
        elif choice == '0':
            return 0
        elif choice == '1':
            return 1
        else:
            print('❌ Invalid choice. Please enter 0, 1, s, or q.')

def main():
    """Main review loop."""
    print('=' * 70)
    print('INTERACTIVE FINDINGS REVIEW')
    print('=' * 70)
    print('\nLoading findings that need review...')
    
    findings = load_needs_review()
    total = len(findings)
    
    print(f'\n✅ Loaded {total} findings')
    print('\nInstructions:')
    print('  - Review each finding carefully')
    print('  - Label as TRUE POSITIVE (0) or FALSE POSITIVE (1)')
    print('  - Skip (s) if unsure - can review later')
    print('  - Quit (q) anytime to save progress')
    
    input('\nPress ENTER to start...')
    
    labeled = []
    skipped = []
    
    for i, finding in enumerate(findings, 1):
        display_finding(finding, i, total)
        
        label = get_label()
        
        if label == 'quit':
            print('\n⚠️  Quitting...')
            break
        elif label == 'skip':
            print('⏭️  Skipped')
            skipped.append(finding)
            continue
        else:
            finding['label'] = label
            finding['manually_labeled'] = True
            finding['labeled_at'] = datetime.now().isoformat()
            labeled.append(finding)
            
            label_text = 'TRUE POSITIVE' if label == 0 else 'FALSE POSITIVE'
            print(f'✅ Labeled as: {label_text}')
    
    # Summary
    print('\n' + '=' * 70)
    print('REVIEW SUMMARY')
    print('=' * 70)
    print(f'\n✅ Labeled: {len(labeled)}')
    print(f'   - True Positives: {sum(1 for f in labeled if f["label"] == 0)}')
    print(f'   - False Positives: {sum(1 for f in labeled if f["label"] == 1)}')
    print(f'⏭️  Skipped: {len(skipped)}')
    print(f'📊 Progress: {len(labeled)}/{total} ({len(labeled)/total*100:.1f}%)')
    
    if labeled:
        filepath = save_labeled(labeled)
        print(f'\n✅ {len(labeled)} findings saved!')
        print(f'\nNext steps:')
        print(f'  1. Merge with training data:')
        print(f'     python3 merge_training_data.py')
        print(f'  2. Retrain model:')
        print(f'     python3 retrain_models.py')
    
    if skipped:
        print(f'\n⚠️  {len(skipped)} findings skipped - review later')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\n\n⚠️  Interrupted by user')
    except Exception as e:
        print(f'\n❌ Error: {e}')
        import traceback
        traceback.print_exc()
