#!/usr/bin/env python3
"""
Inspect model pickle contents.
"""

import pickle
import json

with open('ml/models/fp_reducer.pkl', 'rb') as f:
    model_data = pickle.load(f)

print("="*70)
print("MODEL PICKLE CONTENTS")
print("="*70)

print(f"\nType: {type(model_data)}")

if isinstance(model_data, dict):
    print("\n📋 Dictionary Keys:")
    for key in model_data.keys():
        print(f"   - {key}")
    
    print("\n📊 Key Details:")
    for key, value in model_data.items():
        print(f"\n   {key}:")
        print(f"      Type: {type(value)}")
        
        if isinstance(value, (int, float, str, bool)):
            print(f"      Value: {value}")
        elif isinstance(value, (list, tuple)):
            print(f"      Length: {len(value)}")
            if len(value) > 0:
                print(f"      First item type: {type(value[0])}")
        elif isinstance(value, dict):
            print(f"      Keys: {list(value.keys())[:5]}")
        elif hasattr(value, '__class__'):
            print(f"      Class: {value.__class__.__name__}")
            if hasattr(value, 'n_estimators'):
                print(f"      Estimators: {value.n_estimators}")
            if hasattr(value, 'feature_importances_'):
                print(f"      Has feature_importances: Yes")

print("\n" + "="*70)
