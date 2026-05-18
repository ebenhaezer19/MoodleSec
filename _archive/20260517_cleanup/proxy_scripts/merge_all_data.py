#!/usr/bin/env python3
"""
Quick merge: Real data + Synthetic data
"""

import json
from pathlib import Path
from datetime import datetime

print("="*70)
print("MERGE REAL + SYNTHETIC DATA")
print("="*70)

all_data = []

# 1. Load real data
real_file = Path('ml/training_data/merged/normalized_training_data_20260127_142929.json')
print(f"\n📄 Loading real data: {real_file.name}")

with open(real_file, 'r') as f:
    real_data = json.load(f)

print(f"   ✅ Real samples: {len(real_data)}")
all_data.extend(real_data)

# 2. Load synthetic data
synthetic_file = Path('ml/data/false_positive_training.json')
print(f"\n📄 Loading synthetic data: {synthetic_file.name}")

with open(synthetic_file, 'r') as f:
    synthetic_raw = json.load(f)

# Convert synthetic format
synthetic_data = []
if 'data' in synthetic_raw and 'labels' in synthetic_raw:
    for sample, label in zip(synthetic_raw['data'], synthetic_raw['labels']):
        if 'finding' in sample:
            finding = sample['finding']
        else:
            finding = sample
        
        finding['label'] = label
        synthetic_data.append(finding)

print(f"   ✅ Synthetic samples: {len(synthetic_data)}")
all_data.extend(synthetic_data)

# 3. Deduplicate
print(f"\n🔍 Deduplicating...")
seen = set()
unique = []

for item in all_data:
    key = (
        item.get('category', '').lower(),
        item.get('severity', '').lower(),
        item.get('description', '')[:100]
    )
    
    if key not in seen:
        seen.add(key)
        unique.append(item)

print(f"   Original: {len(all_data)}")
print(f"   Duplicates removed: {len(all_data) - len(unique)}")
print(f"   Unique: {len(unique)}")

# 4. Calculate stats
tp_count = sum(1 for d in unique if d.get('label') == 0)
fp_count = sum(1 for d in unique if d.get('label') == 1)

print(f"\n📊 Final Dataset:")
print(f"   Total: {len(unique)}")
print(f"   True Positives: {tp_count} ({tp_count/len(unique)*100:.1f}%)")
print(f"   False Positives: {fp_count} ({fp_count/len(unique)*100:.1f}%)")

# 5. Save
output_dir = Path('ml/training_data/merged')
output_dir.mkdir(exist_ok=True)

timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
output_file = output_dir / f'hybrid_training_data_{timestamp}.json'

with open(output_file, 'w') as f:
    json.dump(unique, f, indent=2)

print(f"\n💾 Saved to: {output_file}")

print("\n" + "="*70)
print("✅ MERGE COMPLETE!")
print("="*70)
print(f"\nNext step:")
print(f"   python retrain_models.py --data {output_file}")
print()
