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
    print(f'⚠️  Severity: {finding.get("severity", "Unknown")}')
    print(f'🔗 URL: {finding.get("url", "Unknown")[:60]}...')
    
    if 'description' in finding:
        desc = finding['description']
        print(f'\n📝 Description:')
        print(f'   {desc[:200]}...' if len(desc) > 200 else f'   {desc}')
    
    if 'evidence' in finding:
        evidence = finding['evidence']
        print(f'\n🔍 Evidence:')
        print(f'   {evidence[:150]}...' if len(evidence) > 150 else f'   {evidence}')
    
    if 'cvss_score' in finding:
        print(f'\n💯 CVSS Score: {finding.get("cvss_score", "N/A")}')
    
    if 'recommendation' in finding:
        rec = finding['recommendation']
        print(f'\n💡 Recommendation:')
        print(f'   {rec[:150]}...' if len(rec) > 150 else f'   {rec}')

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
