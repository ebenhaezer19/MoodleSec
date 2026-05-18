#!/usr/bin/env python3
"""
Merge Real + Synthetic Training Data

This script merges real scan findings with synthetic training data
to create a larger, more balanced dataset for ML model training.

Usage:
    python merge_with_synthetic.py
"""

import json
from pathlib import Path
from datetime import datetime
from collections import Counter

def normalize_finding(item):
    """
    Normalize finding to consistent format.
    
    Args:
        item: Finding dictionary (can be nested or flat)
        
    Returns:
        Normalized finding dictionary
    """
    # Check if nested format
    if 'finding' in item:
        finding = item['finding']
    else:
        finding = item
    
    # Ensure required fields with defaults
    normalized = {
        'severity': finding.get('severity', 'unknown').lower(),
        'category': finding.get('category', 'unknown'),
        'description': finding.get('description', ''),
        'evidence': finding.get('evidence', ''),
        'url': finding.get('url', 'unknown'),
        'cvss_score': float(finding.get('cvss_score', 0.0)),
        'label': int(item.get('label', -1))
    }
    
    # Optional fields
    optional_fields = ['risk_score', 'scan_id', 'priority', 'confidence', 'reason']
    for field in optional_fields:
        if field in finding:
            normalized[field] = finding[field]
        elif field in item:
            normalized[field] = item[field]
    
    return normalized

def load_real_data():
    """
    Load real training data from latest merged file.
    
    Returns:
        List of real findings
    """
    print("\n📂 Loading Real Data...")
    print("-" * 70)
    
    # Find latest merged file
    merged_dir = Path('ml/training_data/merged')
    if not merged_dir.exists():
        print("   ⚠️  No merged directory found")
        return []
    
    # Get all normalized files
    merged_files = list(merged_dir.glob('normalized_training_data_*.json'))
    merged_files.extend(merged_dir.glob('hybrid_training_data_*.json'))
    
    if not merged_files:
        print("   ⚠️  No merged files found")
        return []
    
    # Get latest file
    latest_file = max(merged_files, key=lambda p: p.stat().st_mtime)
    
    print(f"📄 Loading: {latest_file.name}")
    
    try:
        with open(latest_file, 'r') as f:
            data = json.load(f)
        
        print(f"   ✅ Loaded: {len(data)} real samples")
        return data
    
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return []

def load_synthetic_data():
    """
    Load synthetic training data from ml/data/ directory.
    
    Returns:
        List of synthetic findings
    """
    print("\n📂 Loading Synthetic Data...")
    print("-" * 70)
    
    synthetic_file = Path('ml/data/false_positive_training.json')
    
    if not synthetic_file.exists():
        print(f"   ⚠️  File not found: {synthetic_file}")
        print("   Run: python generate_training_data.py")
        return []
    
    print(f"📄 Loading: {synthetic_file.name}")
    
    try:
        with open(synthetic_file, 'r') as f:
            synthetic_raw = json.load(f)
        
        synthetic_data = []
        
        # Check format
        if isinstance(synthetic_raw, dict):
            if 'data' in synthetic_raw and 'labels' in synthetic_raw:
                # Format: {'data': [...], 'labels': [...]}
                samples = synthetic_raw['data']
                labels = synthetic_raw['labels']
                
                for sample, label in zip(samples, labels):
                    # Normalize
                    normalized = normalize_finding({'finding': sample.get('finding', sample), 'label': label})
                    synthetic_data.append(normalized)
            else:
                print(f"   ⚠️  Unknown dict format")
                return []
        
        elif isinstance(synthetic_raw, list):
            # Format: [{...}, {...}]
            for item in synthetic_raw:
                normalized = normalize_finding(item)
                synthetic_data.append(normalized)
        
        else:
            print(f"   ⚠️  Unknown format: {type(synthetic_raw)}")
            return []
        
        print(f"   ✅ Loaded: {len(synthetic_data)} synthetic samples")
        return synthetic_data
    
    except Exception as e:
        print(f"   ❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return []

def deduplicate(findings):
    """
    Remove duplicate findings.
    
    Args:
        findings: List of finding dictionaries
        
    Returns:
        List of unique findings
    """
    print("\n🔍 Deduplicating findings...")
    print("-" * 70)
    
    seen = set()
    unique = []
    duplicates = 0
    
    for finding in findings:
        # Create unique key
        key = (
            finding.get('category', '').lower(),
            finding.get('severity', '').lower(),
            finding.get('description', '')[:100]  # First 100 chars
        )
        
        if key not in seen:
            seen.add(key)
            unique.append(finding)
        else:
            duplicates += 1
    
    print(f"   Original findings: {len(findings)}")
    print(f"   Duplicates removed: {duplicates}")
    print(f"   Unique findings: {len(unique)}")
    
    return unique

def calculate_statistics(findings):
    """
    Calculate and display dataset statistics.
    
    Args:
        findings: List of finding dictionaries
    """
    print("\n📊 Dataset Statistics:")
    print("-" * 70)
    
    # Label distribution
    tp_count = sum(1 for f in findings if f.get('label') == 0)
    fp_count = sum(1 for f in findings if f.get('label') == 1)
    
    total = len(findings)
    
    print(f"\n🏷️  Label Distribution:")
    print(f"   True Positives (label=0):  {tp_count:3d} ({tp_count/total*100:5.1f}%)")
    print(f"   False Positives (label=1): {fp_count:3d} ({fp_count/total*100:5.1f}%)")
    
    # Severity distribution
    severities = [f.get('severity', 'unknown') for f in findings]
    severity_counts = Counter(severities)
    
    print(f"\n⚠️  Severity Distribution:")
    for severity, count in severity_counts.most_common():
        print(f"   {severity.capitalize():12s}: {count:3d} ({count/total*100:5.1f}%)")
    
    # Category distribution (top 10)
    categories = [f.get('category', 'unknown') for f in findings]
    category_counts = Counter(categories)
    
    print(f"\n📋 Top 10 Categories:")
    for category, count in category_counts.most_common(10):
        cat_display = category[:45] + '...' if len(category) > 45 else category
        print(f"   {cat_display:48s}: {count:3d}")
    
    # CVSS scores
    cvss_scores = [f.get('cvss_score', 0) for f in findings if f.get('cvss_score', 0) > 0]
    if cvss_scores:
        avg_cvss = sum(cvss_scores) / len(cvss_scores)
        print(f"\n📊 CVSS Scores:")
        print(f"   Average: {avg_cvss:.2f}")
        print(f"   Min: {min(cvss_scores):.1f}")
        print(f"   Max: {max(cvss_scores):.1f}")

def save_merged_data(findings):
    """
    Save merged dataset to file.
    
    Args:
        findings: List of normalized findings
        
    Returns:
        Path to saved file
    """
    print("\n💾 Saving merged data...")
    print("-" * 70)
    
    # Create output directory
    output_dir = Path('ml/training_data/merged')
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = output_dir / f'hybrid_training_data_{timestamp}.json'
    
    # Save JSON
    with open(output_file, 'w') as f:
        json.dump(findings, f, indent=2)
    
    file_size = output_file.stat().st_size / 1024  # KB
    
    print(f"   ✅ Saved to: {output_file}")
    print(f"   📦 File size: {file_size:.1f} KB")
    
    return output_file

def main():
    """Main function."""
    print("=" * 70)
    print("MERGE REAL + SYNTHETIC TRAINING DATA")
    print("=" * 70)
    print("\nThis script will:")
    print("  1. Load real findings from latest merged file")
    print("  2. Load synthetic data from ml/data/")
    print("  3. Merge and deduplicate")
    print("  4. Save hybrid dataset")
    
    try:
        # Step 1: Load real data
        real_data = load_real_data()
        
        # Step 2: Load synthetic data
        synthetic_data = load_synthetic_data()
        
        # Check if we have data
        if not real_data and not synthetic_data:
            print("\n❌ ERROR: No training data found!")
            print("\nMake sure you have:")
            print("  - Real data: ml/training_data/merged/*.json")
            print("  - Synthetic data: ml/data/false_positive_training.json")
            return 1
        
        # Step 3: Combine
        print("\n📦 Combining datasets...")
        print("-" * 70)
        all_data = real_data + synthetic_data
        print(f"   Real samples: {len(real_data)}")
        print(f"   Synthetic samples: {len(synthetic_data)}")
        print(f"   Total (before dedup): {len(all_data)}")
        
        # Step 4: Deduplicate
        unique_data = deduplicate(all_data)
        
        # Step 5: Calculate statistics
        calculate_statistics(unique_data)
        
        # Step 6: Save
        output_file = save_merged_data(unique_data)
        
        # Final summary
        print("\n" + "=" * 70)
        print("✅ MERGE COMPLETE!")
        print("=" * 70)
        
        tp_count = sum(1 for f in unique_data if f.get('label') == 0)
        fp_count = sum(1 for f in unique_data if f.get('label') == 1)
        
        print(f"\n📊 Final Dataset:")
        print(f"   Total findings: {len(unique_data)}")
        print(f"   True Positives: {tp_count}")
        print(f"   False Positives: {fp_count}")
        
        print(f"\n📁 Output file:")
        print(f"   {output_file}")
        
        print("\n" + "=" * 70)
        print("NEXT STEPS")
        print("=" * 70)
        print(f"\n1. Delete old model:")
        print(f"   rm ml/models/fp_reducer.pkl")
        print(f"\n2. Retrain with hybrid data:")
        print(f"   python retrain_models.py --data {output_file}")
        print(f"\n3. Verify feature importance:")
        print(f"   python get_feature_importance.py")
        print()
        
        return 0
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    import sys
    sys.exit(main())

