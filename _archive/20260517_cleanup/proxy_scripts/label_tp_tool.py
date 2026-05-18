#!/usr/bin/env python3
"""
Quick Label Tool for TP Candidates

Allows manual review and labeling of potential TP findings.
"""

import json
from pathlib import Path

def label_candidates():
    """Interactive labeling tool for TP candidates."""
    
    candidates_file = Path('ml/training_data/real_data/tp_candidates.json')
    data_file = Path('ml/training_data/real_data/processed_findings_20260129_121146.json')
    
    print("=" * 80)
    print("MANUAL TP LABELING TOOL")
    print("=" * 80)
    
    # Load candidates
    with open(candidates_file, 'r', encoding='utf-8') as f:
        candidates = json.load(f)
    
    # Load full dataset
    with open(data_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    high_candidates = candidates['high_severity_unlabeled']
    medium_candidates = candidates['medium_exploitable_unlabeled']
    
    print(f"\n📊 Found {len(high_candidates)} HIGH/CRITICAL candidates")
    print(f"📊 Found {len(medium_candidates)} MEDIUM exploitable candidates")
    print(f"\nTotal to review: {len(high_candidates) + len(medium_candidates)}")
    
    # Review HIGH severity first
    print("\n" + "=" * 80)
    print("REVIEWING HIGH/CRITICAL SEVERITY FINDINGS")
    print("=" * 80)
    
    labeled_count = 0
    
    for i, candidate in enumerate(high_candidates, 1):
        finding = candidate.get('finding', candidate)
        
        print(f"\n[{i}/{len(high_candidates)}] HIGH SEVERITY FINDING:")
        print("-" * 80)
        print(f"Category: {finding.get('category', 'Unknown')}")
        print(f"Severity: {finding.get('severity', 'Unknown').upper()}")
        print(f"URL: {finding.get('url', 'N/A')[:80]}")
        print(f"Description: {finding.get('description', 'N/A')[:200]}...")
        print(f"Evidence: {finding.get('evidence', 'N/A')[:150]}...")
        
        # SQL Injection auto-recommendation
        category_lower = finding.get('category', '').lower()
        if 'sql injection' in category_lower or 'sqli' in category_lower:
            print("\n💡 RECOMMENDATION: TP (SQL Injection is exploitable vulnerability)")
        
        print("\nLabel as:")
        print("  [T] True Positive (exploitable vulnerability)")
        print("  [F] False Positive (not exploitable/informational)")
        print("  [S] Skip (review later)")
        print("  [Q] Quit")
        
        choice = input("\nYour choice (T/F/S/Q): ").strip().upper()
        
        if choice == 'Q':
            print("\n⚠️  Quitting labeling session...")
            break
        elif choice == 'S':
            print("Skipped.")
            continue
        elif choice == 'T':
            # Find and update in original dataset
            for item in data:
                item_finding = item.get('finding', item)
                if (item_finding.get('category') == finding.get('category') and
                    item_finding.get('url') == finding.get('url')):
                    item['label'] = 0  # TP
                    item['label_name'] = 'TRUE_POSITIVE'
                    item['label_source'] = 'manual_review'
                    item['label_confidence'] = 1.0
                    labeled_count += 1
                    print("✅ Labeled as TRUE POSITIVE")
                    break
        elif choice == 'F':
            # Find and update in original dataset
            for item in data:
                item_finding = item.get('finding', item)
                if (item_finding.get('category') == finding.get('category') and
                    item_finding.get('url') == finding.get('url')):
                    item['label'] = 1  # FP
                    item['label_name'] = 'FALSE_POSITIVE'
                    item['label_source'] = 'manual_review'
                    item['label_confidence'] = 1.0
                    print("✅ Labeled as FALSE POSITIVE")
                    break
    
    # Review MEDIUM exploitable
    if medium_candidates:
        print("\n" + "=" * 80)
        print("REVIEWING MEDIUM EXPLOITABLE FINDINGS")
        print("=" * 80)
        
        for i, candidate in enumerate(medium_candidates, 1):
            finding = candidate.get('finding', candidate)
            
            print(f"\n[{i}/{len(medium_candidates)}] MEDIUM EXPLOITABLE FINDING:")
            print("-" * 80)
            print(f"Category: {finding.get('category', 'Unknown')}")
            print(f"URL: {finding.get('url', 'N/A')[:80]}")
            print(f"Description: {finding.get('description', 'N/A')[:200]}...")
            
            print("\nLabel as (T/F/S/Q): ", end='')
            choice = input().strip().upper()
            
            if choice == 'Q':
                break
            elif choice == 'S':
                continue
            elif choice == 'T':
                for item in data:
                    item_finding = item.get('finding', item)
                    if (item_finding.get('category') == finding.get('category') and
                        item_finding.get('url') == finding.get('url')):
                        item['label'] = 0
                        item['label_name'] = 'TRUE_POSITIVE'
                        item['label_source'] = 'manual_review'
                        item['label_confidence'] = 1.0
                        labeled_count += 1
                        print("✅ Labeled as TRUE POSITIVE")
                        break
            elif choice == 'F':
                for item in data:
                    item_finding = item.get('finding', item)
                    if (item_finding.get('category') == finding.get('category') and
                        item_finding.get('url') == finding.get('url')):
                        item['label'] = 1
                        item['label_name'] = 'FALSE_POSITIVE'
                        item['label_source'] = 'manual_review'
                        item['label_confidence'] = 1.0
                        print("✅ Labeled as FALSE POSITIVE")
                        break
    
    # Save updated dataset
    if labeled_count > 0:
        backup_file = data_file.parent / f"{data_file.stem}_backup.json"
        import shutil
        shutil.copy(data_file, backup_file)
        print(f"\n💾 Backup created: {backup_file}")
        
        with open(data_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"💾 Updated dataset saved: {data_file}")
        
        # Count new state
        tp_count = sum(1 for item in data if item.get('label') == 0)
        fp_count = sum(1 for item in data if item.get('label') == 1)
        unlabeled_count = sum(1 for item in data if item.get('label', -1) == -1)
        
        print("\n" + "=" * 80)
        print("LABELING SUMMARY")
        print("=" * 80)
        print(f"Newly labeled: {labeled_count}")
        print(f"\nUpdated dataset state:")
        print(f"  True Positives: {tp_count}")
        print(f"  False Positives: {fp_count}")
        print(f"  Unlabeled: {unlabeled_count}")
        print(f"  Imbalance ratio: {fp_count/tp_count if tp_count else 'N/A'}:1")
        
        if tp_count >= 30:
            print("\n🎉 Target achieved! You have 30+ TP samples.")
        else:
            print(f"\n📌 Still need {30 - tp_count} more TP samples to reach target.")
    else:
        print("\n⚠️  No items were labeled.")
    
    print("\n" + "=" * 80)

if __name__ == '__main__':
    try:
        label_candidates()
    except KeyboardInterrupt:
        print("\n\n⚠️  Labeling interrupted by user.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
