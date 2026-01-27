#!/usr/bin/env python3
"""
Test feature extraction from training data.
"""

import json
import numpy as np
from ml.false_positive_reducer import FalsePositiveReducer

# Load one sample
with open('ml/training_data/merged/normalized_training_data_20260127_141514.json', 'r') as f:
    data = json.load(f)

sample = data[0]

print("="*70)
print("TESTING FEATURE EXTRACTION")
print("="*70)

print("\n📋 Sample Finding:")
print(f"   Category: {sample.get('category')}")
print(f"   Severity: {sample.get('severity')}")
print(f"   Description: {sample.get('description', '')[:100]}...")
print(f"   Evidence: {sample.get('evidence', '')[:100]}...")
print(f"   URL: {sample.get('url', 'N/A')}")
print(f"   CVSS: {sample.get('cvss_score', 0)}")
print(f"   Label: {sample.get('label')}")

print("\n🔧 Extracting Features...")

# Initialize FP Reducer
fp_reducer = FalsePositiveReducer()

# Extract features
try:
    features = fp_reducer.extract_features(sample, context={})
    
    print(f"\n✅ Features Extracted:")
    print(f"   Shape: {features.shape}")
    print(f"   Values: {features}")
    print(f"   Non-zero count: {np.count_nonzero(features)}")
    
    # Check if all zeros
    if np.all(features == 0):
        print("\n⚠️  WARNING: All features are zero!")
        print("   This means feature extraction is failing.")
    else:
        print("\n✅ Feature extraction working!")
        
except Exception as e:
    print(f"\n❌ ERROR: {e}")
    import traceback
    traceback.print_exc()

print("\n"+"="*70)
