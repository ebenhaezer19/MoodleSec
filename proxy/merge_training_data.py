#!/usr/bin/env python3
"""
Merge Training Data from Multiple Sources

Combines findings from:
- Your scanner (32 findings)
- Acunetix (200-500 findings)
- Other sources

Into a single training dataset.
"""

import json
from pathlib import Path
from datetime import datetime

def load_all_training_data():
    """Load training data from all sources."""
    all_data = []
    
    # Source 1: Your scanner data
    real_data_dir = Path("ml/training_data/real_data")
    if real_data_dir.exists():
        for file in real_data_dir.glob("*_auto_labeled.json"):
            print(f"Loading: {file}")
            with open(file, 'r') as f:
                data = json.load(f)
                for item in data:
                    item['source'] = 'your_scanner'
                all_data.extend(data)
    
    # Source 2: Acunetix data
    acunetix_dir = Path("ml/training_data/acunetix_data")
    if acunetix_dir.exists():
        for file in acunetix_dir.glob("*_auto_labeled.json"):
            print(f"Loading: {file}")
            with open(file, 'r') as f:
                data = json.load(f)
                for item in data:
                    item['source'] = 'acunetix'
                all_data.extend(data)
    
    print(f"\nTotal findings loaded: {len(all_data)}")
    return all_data

def deduplicate_findings(findings):
    """Remove duplicate findings."""
    seen = set()
    unique = []
    
    for item in findings:
        finding = item['finding']
        # Create hash based on category + url + description
        key = f"{finding.get('category', '')}_{finding.get('url', '')}_{finding.get('description', '')[:100]}"
        
        if key not in seen:
            seen.add(key)
            unique.append(item)
    
    print(f"Removed {len(findings) - len(unique)} duplicates")
    return unique

def save_merged_data(merged_data):
    """Save merged training data."""
    output_dir = Path("ml/training_data/merged")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    output_file = output_dir / f"merged_training_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    with open(output_file, 'w') as f:
        json.dump(merged_data, f, indent=2)
    
    print(f"\nSaved merged data to: {output_file}")
    
    # Generate summary
    summary = {
        'total_findings': len(merged_data),
        'true_positives': sum(1 for d in merged_data if d['label'] == 0),
        'false_positives': sum(1 for d in merged_data if d['label'] == 1),
        'sources': {},
        'categories': {},
        'timestamp': datetime.now().isoformat()
    }
    
    # Count by source
    for item in merged_data:
        source = item.get('source', 'unknown')
        if source not in summary['sources']:
            summary['sources'][source] = 0
        summary['sources'][source] += 1
        
        # Count by category
        category = item['finding'].get('category', 'unknown')
        if category not in summary['categories']:
            summary['categories'][category] = {'tp': 0, 'fp': 0}
        
        if item['label'] == 0:
            summary['categories'][category]['tp'] += 1
        else:
            summary['categories'][category]['fp'] += 1
    
    summary_file = output_dir / f"merged_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"Saved summary to: {summary_file}")
    
    return summary, output_file

def main():
    """Main function."""
    print("=" * 60)
    print("MERGE TRAINING DATA FROM MULTIPLE SOURCES")
    print("=" * 60)
    print()
    
    # Step 1: Load all data
    print("Step 1: Loading training data from all sources...")
    all_data = load_all_training_data()
    
    if not all_data:
        print("No training data found!")
        print("\nMake sure you have:")
        print("1. Your scanner data in: ml/training_data/real_data/")
        print("2. Acunetix data in: ml/training_data/acunetix_data/")
        return
    
    print()
    
    # Step 2: Deduplicate
    print("Step 2: Removing duplicates...")
    unique_data = deduplicate_findings(all_data)
    print()
    
    # Step 3: Save merged data
    print("Step 3: Saving merged data...")
    summary, output_file = save_merged_data(unique_data)
    print()
    
    # Step 4: Print summary
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total Findings: {summary['total_findings']}")
    print(f"  True Positives: {summary['true_positives']}")
    print(f"  False Positives: {summary['false_positives']}")
    print()
    print("Sources:")
    for source, count in summary['sources'].items():
        print(f"  {source}: {count} findings")
    print()
    print("Top 10 Categories:")
    sorted_categories = sorted(
        summary['categories'].items(),
        key=lambda x: x[1]['tp'] + x[1]['fp'],
        reverse=True
    )
    for category, counts in sorted_categories[:10]:
        total = counts['tp'] + counts['fp']
        print(f"  {category}: {total} (TP: {counts['tp']}, FP: {counts['fp']})")
    print()
    print("Next Steps:")
    print(f"1. Review merged data: {output_file}")
    print("2. Retrain models: python retrain_models.py")
    print(f"3. Expected accuracy: ~{min(95, 70 + (summary['total_findings'] / 10))}%")
    print()
    
    # Estimate ML performance
    if summary['total_findings'] >= 100:
        print("✅ Dataset size is GOOD for ML training!")
        print(f"   {summary['total_findings']} samples should give 85-95% accuracy")
    elif summary['total_findings'] >= 50:
        print("⚠️  Dataset size is MARGINAL for ML training")
        print(f"   {summary['total_findings']} samples should give 70-85% accuracy")
    else:
        print("❌ Dataset size is TOO SMALL for reliable ML")
        print(f"   {summary['total_findings']} samples may give <70% accuracy")
        print("   Recommendation: Collect more data (target: 100+ samples)")
    print()

if __name__ == "__main__":
    main()
