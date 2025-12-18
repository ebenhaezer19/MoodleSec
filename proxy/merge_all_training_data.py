#!/usr/bin/env python3
"""
Merge all training data sources into single dataset for model training.
"""

import json
from pathlib import Path
from datetime import datetime
from collections import Counter

def load_all_training_files():
    """Load all training data files."""
    training_dir = Path("ml/training_data")
    all_findings = []
    
    print("=" * 70)
    print("MERGING ALL TRAINING DATA")
    print("=" * 70)
    
    # Load auto-labeled files
    print("\n📂 Loading auto-labeled files...")
    auto_labeled_files = list(training_dir.glob("auto_labeled_*.json"))
    for file in auto_labeled_files:
        print(f"  - {file.name}")
        with open(file, 'r') as f:
            data = json.load(f)
            for item in data:
                item['source_file'] = file.name
            all_findings.extend(data)
    
    # Load manually labeled files
    print("\n📂 Loading manually labeled files...")
    manually_labeled_files = list(training_dir.glob("manually_labeled_*.json"))
    for file in manually_labeled_files:
        print(f"  - {file.name}")
        with open(file, 'r') as f:
            data = json.load(f)
            for item in data:
                item['source_file'] = file.name
                item['manually_reviewed'] = True
            all_findings.extend(data)
    
    # Load merged files (old ones)
    print("\n📂 Loading previous merged files...")
    merged_files = list(training_dir.glob("merged_training_data_*.json"))
    for file in merged_files:
        print(f"  - {file.name}")
        with open(file, 'r') as f:
            data = json.load(f)
            for item in data:
                if 'source_file' not in item:
                    item['source_file'] = file.name
            all_findings.extend(data)
    
    print(f"\n✅ Total findings loaded: {len(all_findings)}")
    return all_findings

def deduplicate_findings(findings):
    """Remove duplicates based on category + severity + scan_id."""
    print("\n🔍 Deduplicating findings...")
    
    seen = set()
    unique = []
    duplicates = 0
    
    for finding in findings:
        # Create unique key
        key = (
            finding.get('category', ''),
            finding.get('severity', ''),
            finding.get('scan_id', ''),
            finding.get('description', '')[:100]  # First 100 chars of description
        )
        
        if key not in seen:
            seen.add(key)
            unique.append(finding)
        else:
            duplicates += 1
    
    print(f"  Removed {duplicates} duplicates")
    print(f"  Unique findings: {len(unique)}")
    return unique

def filter_valid_labels(findings, min_confidence=0.6):
    """Filter findings with valid labels (0 or 1) and minimum confidence."""
    print(f"\n🔍 Filtering valid labels (confidence >= {min_confidence})...")
    
    valid = []
    invalid = 0
    low_confidence = 0
    
    for finding in findings:
        label = finding.get('label', -1)
        confidence = finding.get('confidence', finding.get('auto_label_confidence', 0))
        
        # Must have valid label
        if label not in [0, 1]:
            invalid += 1
            continue
        
        # Must have minimum confidence OR be manually reviewed
        if confidence >= min_confidence or finding.get('manually_reviewed', False):
            valid.append(finding)
        else:
            low_confidence += 1
    
    print(f"  Valid labels: {len(valid)}")
    print(f"  Invalid/unlabeled: {invalid}")
    print(f"  Low confidence (filtered): {low_confidence}")
    return valid

def analyze_dataset(findings):
    """Analyze the merged dataset."""
    print("\n" + "=" * 70)
    print("DATASET ANALYSIS")
    print("=" * 70)
    
    # Count by label
    labels = Counter(f.get('label', -1) for f in findings)
    tp_count = labels.get(0, 0)
    fp_count = labels.get(1, 0)
    
    print(f"\n📊 Label Distribution:")
    print(f"  True Positives (0):  {tp_count} ({tp_count/len(findings)*100:.1f}%)")
    print(f"  False Positives (1): {fp_count} ({fp_count/len(findings)*100:.1f}%)")
    print(f"  Imbalance Ratio: 1:{fp_count/tp_count:.1f}" if tp_count > 0 else "  Imbalance Ratio: N/A")
    
    # Count by severity
    print(f"\n📊 Severity Distribution:")
    severities = Counter(f.get('severity', 'Unknown') for f in findings)
    for sev, count in severities.most_common():
        print(f"  {sev}: {count}")
    
    # Count by source
    print(f"\n📊 Source Distribution:")
    sources = Counter(f.get('source_file', 'Unknown') for f in findings)
    for src, count in sources.most_common(5):
        print(f"  {src[:40]}: {count}")
    
    # Manually reviewed count
    manual_count = sum(1 for f in findings if f.get('manually_reviewed', False))
    print(f"\n📊 Manual Review:")
    print(f"  Manually reviewed: {manual_count}")
    print(f"  Auto-labeled: {len(findings) - manual_count}")
    
    return {
        'total': len(findings),
        'true_positives': tp_count,
        'false_positives': fp_count,
        'manually_reviewed': manual_count
    }

def save_merged_data(findings):
    """Save merged dataset."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filepath = f'ml/training_data/merged_training_data_{timestamp}.json'
    
    with open(filepath, 'w') as f:
        json.dump(findings, f, indent=2)
    
    print(f"\n✅ Saved merged dataset to: {filepath}")
    return filepath

def main():
    """Main merge process."""
    # Load all data
    all_findings = load_all_training_files()
    
    if not all_findings:
        print("\n❌ No training data found!")
        return
    
    # Deduplicate
    unique_findings = deduplicate_findings(all_findings)
    
    # Filter valid labels with confidence threshold
    valid_findings = filter_valid_labels(unique_findings, min_confidence=0.65)
    
    if not valid_findings:
        print("\n❌ No valid labeled findings!")
        return
    
    # Analyze
    stats = analyze_dataset(valid_findings)
    
    # Save
    filepath = save_merged_data(valid_findings)
    
    # Summary
    print("\n" + "=" * 70)
    print("MERGE COMPLETE!")
    print("=" * 70)
    print(f"\n✅ Total training samples: {stats['total']}")
    print(f"✅ Ready for model training!")
    print(f"\n📋 Next step:")
    print(f"   python3 retrain_models.py")
    print("\n" + "=" * 70)

if __name__ == '__main__':
    main()
