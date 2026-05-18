#!/usr/bin/env python3
"""
Interactive Labeling Tool for Findings

This script helps you manually label findings that couldn't be auto-categorized.
"""

import json
from pathlib import Path
from datetime import datetime

def load_needs_review():
    """Load findings that need manual review."""
    data_dir = Path("ml/training_data/real_data")
    
    # Find latest needs_review file
    review_files = sorted(data_dir.glob("*_needs_review.json"), reverse=True)
    
    if not review_files:
        print("No findings need review!")
        return None, None
    
    latest_file = review_files[0]
    print(f"Loading: {latest_file}")
    
    with open(latest_file, 'r') as f:
        data = json.load(f)
    
    return data, latest_file

def display_finding(finding, index, total):
    """Display finding details for labeling."""
    print("\n" + "=" * 70)
    print(f"FINDING {index}/{total}")
    print("=" * 70)
    print(f"Category: {finding['finding'].get('category', 'Unknown')}")
    print(f"Severity: {finding['finding'].get('severity', 'Unknown')}")
    print(f"URL: {finding['finding'].get('url', 'N/A')}")
    print(f"\nDescription:")
    print(f"  {finding['finding'].get('description', 'N/A')[:200]}...")
    print(f"\nEvidence:")
    print(f"  {finding['finding'].get('evidence', 'N/A')[:200]}...")
    print()

def get_label():
    """Get label from user."""
    while True:
        response = input("Is this a FALSE POSITIVE? (y/n/s=skip/q=quit): ").lower().strip()
        
        if response == 'y':
            return 1, "User labeled as False Positive"
        elif response == 'n':
            return 0, "User labeled as True Positive"
        elif response == 's':
            return None, "Skipped by user"
        elif response == 'q':
            return 'quit', None
        else:
            print("Invalid input. Please enter y, n, s, or q.")

def save_labeled_data(data, original_file):
    """Save labeled data."""
    # Separate labeled and still needs review
    labeled = [d for d in data if d['label'] is not None]
    still_needs_review = [d for d in data if d['label'] is None]
    
    # Update auto-labeled file
    auto_file = str(original_file).replace('_needs_review.json', '_auto_labeled.json')
    
    if Path(auto_file).exists():
        try:
            with open(auto_file, 'r') as f:
                existing_labeled = json.load(f)
            labeled = existing_labeled + labeled
        except json.JSONDecodeError as e:
            print(f"\n⚠️  Warning: Existing auto_labeled file is corrupt: {e}")
            print(f"   Backing up corrupt file and creating new one...")
            backup_file = str(auto_file) + '.backup'
            Path(auto_file).rename(backup_file)
            print(f"   Backup saved to: {backup_file}")
    
    with open(auto_file, 'w') as f:
        json.dump(labeled, f, indent=2)
    
    print(f"\nSaved {len(labeled)} labeled findings to {auto_file}")
    
    # Update needs_review file
    if still_needs_review:
        with open(original_file, 'w') as f:
            json.dump(still_needs_review, f, indent=2)
        print(f"Saved {len(still_needs_review)} findings still needing review to {original_file}")
    else:
        # Delete needs_review file if empty
        Path(original_file).unlink()
        print("All findings labeled! Deleted needs_review file.")
    
    # Update summary
    summary_file = str(original_file).replace('_needs_review.json', '_summary.json')
    with open(summary_file, 'r') as f:
        summary = json.load(f)
    
    summary['auto_labeled'] = len(labeled)
    summary['needs_review'] = len(still_needs_review)
    summary['true_positives'] = sum(1 for d in labeled if d['label'] == 0)
    summary['false_positives'] = sum(1 for d in labeled if d['label'] == 1)
    summary['last_updated'] = datetime.now().isoformat()
    
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"Updated summary in {summary_file}")

def main():
    """Main function."""
    print("=" * 70)
    print("INTERACTIVE FINDING LABELING TOOL")
    print("=" * 70)
    print()
    print("This tool helps you label findings as True Positive or False Positive.")
    print("Commands:")
    print("  y = False Positive (FP)")
    print("  n = True Positive (TP)")
    print("  s = Skip this finding")
    print("  q = Quit and save")
    print()
    
    # Load data
    data, original_file = load_needs_review()
    
    if data is None:
        return
    
    print(f"\nFound {len(data)} findings needing review")
    input("Press Enter to start labeling...")
    
    # Label each finding
    labeled_count = 0
    
    for i, item in enumerate(data, 1):
        display_finding(item, i, len(data))
        
        label, reason = get_label()
        
        if label == 'quit':
            print("\nQuitting...")
            break
        
        if label is not None:
            item['label'] = label
            item['label_name'] = 'FALSE_POSITIVE' if label == 1 else 'TRUE_POSITIVE'
            item['reason'] = reason
            item['confidence'] = 1.0
            labeled_count += 1
            print(f"✓ Labeled as {'FP' if label == 1 else 'TP'}")
    
    # Save results
    if labeled_count > 0:
        print("\n" + "=" * 70)
        print(f"SAVING RESULTS ({labeled_count} findings labeled)")
        print("=" * 70)
        save_labeled_data(data, original_file)
    else:
        print("\nNo findings labeled.")
    
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total reviewed: {len(data)}")
    print(f"Labeled: {labeled_count}")
    print(f"Skipped: {len(data) - labeled_count}")
    print()
    
    if labeled_count > 0:
        tp_count = sum(1 for d in data if d.get('label') == 0)
        fp_count = sum(1 for d in data if d.get('label') == 1)
        print(f"True Positives: {tp_count}")
        print(f"False Positives: {fp_count}")
        print()
        print("Next step: Run python retrain_models.py")
    
    print()

if __name__ == "__main__":
    main()
