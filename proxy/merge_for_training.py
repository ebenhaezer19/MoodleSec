#!/usr/bin/env python3
"""
Merge Auto-Labeled and Needs-Review Data for Training

This script merges high-confidence auto-labeled findings with
medium-confidence findings from needs_review to create a larger
training dataset.
"""

import json
from pathlib import Path
from datetime import datetime

def merge_training_data(min_confidence=0.6):
    """Merge auto-labeled and needs-review data with confidence threshold."""
    
    training_dir = Path("ml/training_data")
    
    # Find latest files
    auto_labeled_files = sorted(training_dir.glob("auto_labeled_*.json"), reverse=True)
    needs_review_files = sorted(training_dir.glob("needs_review_*.json"), reverse=True)
    
    if not auto_labeled_files or not needs_review_files:
        print("[!] Error: Training data files not found!")
        return
    
    auto_labeled_file = auto_labeled_files[0]
    needs_review_file = needs_review_files[0]
    
    print(f"[*] Loading data...")
    print(f"    Auto-labeled: {auto_labeled_file.name}")
    print(f"    Needs review: {needs_review_file.name}")
    
    with open(auto_labeled_file, 'r') as f:
        auto_labeled = json.load(f)
    
    with open(needs_review_file, 'r') as f:
        needs_review = json.load(f)
    
    print(f"\n[*] Initial counts:")
    print(f"    Auto-labeled (high confidence): {len(auto_labeled)}")
    print(f"    Needs review: {len(needs_review)}")
    
    # Filter needs_review by confidence threshold
    medium_confidence = [
        item for item in needs_review
        if item.get('confidence', 0) >= min_confidence
    ]
    
    print(f"\n[*] After filtering (confidence >= {min_confidence}):")
    print(f"    Medium confidence: {len(medium_confidence)}")
    
    # Merge datasets
    merged_data = auto_labeled + medium_confidence
    
    # Count labels
    tp_count = sum(1 for item in merged_data if item.get('label') == 0)
    fp_count = sum(1 for item in merged_data if item.get('label') == 1)
    
    print(f"\n[*] Merged dataset:")
    print(f"    Total findings: {len(merged_data)}")
    print(f"    True Positives (label=0): {tp_count}")
    print(f"    False Positives (label=1): {fp_count}")
    
    # Save merged data
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = training_dir / f"merged_training_data_{timestamp}.json"
    
    with open(output_file, 'w') as f:
        json.dump(merged_data, f, indent=2)
    
    print(f"\n[+] Saved to: {output_file}")
    
    # Check if ready for training
    if len(merged_data) >= 50:
        print(f"\n✅ Ready for training! ({len(merged_data)} findings)")
        print("   Run: python retrain_models.py")
    else:
        print(f"\n⚠️  Warning: Only {len(merged_data)} findings")
        print("   Recommended minimum: 50 findings")
        print("   Consider lowering confidence threshold or scanning more sites")
    
    return merged_data, output_file

if __name__ == "__main__":
    import sys
    
    # Allow custom confidence threshold
    min_confidence = float(sys.argv[1]) if len(sys.argv) > 1 else 0.6
    
    print("=" * 60)
    print("MERGE TRAINING DATA")
    print("=" * 60)
    print(f"Minimum confidence threshold: {min_confidence}")
    print("=" * 60)
    
    merge_training_data(min_confidence)
