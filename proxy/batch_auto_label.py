#!/usr/bin/env python3
"""
Batch Auto-Labeling Script
Process all needs_review files automatically
"""

import json
from pathlib import Path
from datetime import datetime
from enhanced_auto_label import EnhancedAutoLabeler

def find_needs_review_files(base_dir='ml/training_data'):
    """Find all *needs_review.json files"""
    base_path = Path(base_dir)
    return list(base_path.rglob('*needs_review*.json'))

def process_all_needs_review():
    """Process all needs_review files"""
    
    print("="*60)
    print("BATCH AUTO-LABELING - Processing All Needs Review Files")
    print("="*60)
    
    # Find all needs_review files
    files = find_needs_review_files()
    
    if not files:
        print("\n[!] No needs_review files found!")
        print("    Looking in: ml/training_data/")
        return
    
    print(f"\n[+] Found {len(files)} needs_review files:")
    for f in files:
        print(f"    - {f}")
    
    # Initialize labeler
    labeler = EnhancedAutoLabeler()
    
    # Process each file
    total_stats = {
        'total_findings': 0,
        'auto_labeled': 0,
        'still_needs_review': 0,
        'true_positives': 0,
        'false_positives': 0
    }
    
    for file_path in files:
        print(f"\n{'='*60}")
        print(f"Processing: {file_path.name}")
        print(f"{'='*60}")
        
        # Load findings
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        findings = [item['finding'] for item in data]
        print(f"[+] Loaded {len(findings)} findings")
        
        # Process
        auto_labeled, needs_review, stats = labeler.process_findings(findings, min_confidence=0.60)
        
        # Update total stats
        total_stats['total_findings'] += stats['total']
        total_stats['auto_labeled'] += stats['auto_labeled']
        total_stats['still_needs_review'] += stats['needs_review']
        total_stats['true_positives'] += stats['true_positives']
        total_stats['false_positives'] += stats['false_positives']
        
        # Print file stats
        print(f"\nResults:")
        print(f"  Auto-labeled:       {stats['auto_labeled']} ({stats['auto_labeled']/stats['total']*100:.1f}%)")
        print(f"  Still needs review: {stats['needs_review']} ({stats['needs_review']/stats['total']*100:.1f}%)")
        
        # Save results
        output_dir = file_path.parent
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if auto_labeled:
            # Append to existing auto_labeled file or create new
            auto_file = output_dir / f"enhanced_auto_labeled_{timestamp}.json"
            with open(auto_file, 'w', encoding='utf-8') as f:
                json.dump(auto_labeled, f, indent=2)
            print(f"  [+] Saved to: {auto_file.name}")
        
        if needs_review:
            review_file = output_dir / f"still_needs_review_{timestamp}.json"
            with open(review_file, 'w', encoding='utf-8') as f:
                json.dump(needs_review, f, indent=2)
            print(f"  [+] Remaining: {review_file.name}")
    
    # Print total summary
    print("\n" + "="*60)
    print("BATCH PROCESSING COMPLETE - TOTAL SUMMARY")
    print("="*60)
    print(f"Total findings processed:  {total_stats['total_findings']}")
    print(f"Auto-labeled:              {total_stats['auto_labeled']} ({total_stats['auto_labeled']/total_stats['total_findings']*100:.1f}%)")
    print(f"  ├── True Positives:      {total_stats['true_positives']}")
    print(f"  └── False Positives:     {total_stats['false_positives']}")
    print(f"Still needs review:        {total_stats['still_needs_review']} ({total_stats['still_needs_review']/total_stats['total_findings']*100:.1f}%)")
    
    reduction = (1 - total_stats['still_needs_review']/total_stats['total_findings']) * 100
    print(f"\n🎉 SUCCESS! Reduced manual review by {reduction:.1f}%")
    print(f"   From {total_stats['total_findings']} to {total_stats['still_needs_review']} findings!")
    print("="*60)


if __name__ == '__main__':
    process_all_needs_review()
