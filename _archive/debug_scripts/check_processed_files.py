#!/usr/bin/env python3
"""Check processed real data files"""

import json
from pathlib import Path

files_to_check = [
    'ml/training_data/real_data/processed_findings_20260127_200411.json',
    'ml/training_data/real_data/merged_real_data_20260127_200432.json',
    'ml/training_data/real_data/real_findings_20260127_133041_auto_labeled.json'
]

print('='*80)
print('CHECK PROCESSED REAL DATA FILES')
print('='*80)
print()

for filepath in files_to_check:
    try:
        data = json.load(open(filepath))
        filename = Path(filepath).name
        
        print(f'📄 {filename}')
        print(f'   Total samples: {len(data)}')
        
        # Count labeled
        labeled = sum(1 for d in data if d.get('label') not in [-1, None])
        tp = sum(1 for d in data if d.get('label') == 0)
        fp = sum(1 for d in data if d.get('label') == 1)
        unlabeled = sum(1 for d in data if d.get('label') == -1 or d.get('label') is None)
        
        print(f'   Labeled: {labeled}')
        print(f'     TP: {tp}')
        print(f'     FP: {fp}')
        print(f'   Unlabeled: {unlabeled}')
        print()
        
    except Exception as e:
        print(f'❌ {filepath}: {e}')
        print()

print('='*80)
print('Check merged_training_data_20251219_033523.json')
print('='*80)
print()

try:
    data = json.load(open('ml/training_data/merged_training_data_20251219_033523.json'))
    print(f'Total: {len(data)}')
    labeled = sum(1 for d in data if d.get('label') not in [-1, None])
    tp = sum(1 for d in data if d.get('label') == 0)
    fp = sum(1 for d in data if d.get('label') == 1)
    unlabeled = sum(1 for d in data if d.get('label') == -1 or d.get('label') is None)
    
    print(f'Labeled: {labeled}')
    print(f'  TP: {tp}')
    print(f'  FP: {fp}')
    print(f'Unlabeled: {unlabeled}')
except Exception as e:
    print(f'Error: {e}')
