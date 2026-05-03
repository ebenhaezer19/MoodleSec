#!/usr/bin/env python3
"""
Deep diagnosis of training process.
"""

import json
import numpy as np
from ml.anomaly_false_positive_reducer import FalsePositiveReducer

# Load data
with open('ml/training_data/merged/hybrid_training_data_20260127_143448.json', 'r') as f:
    data = json.load(f)

print("="*70)
print("TRAINING PROCESS DIAGNOSIS")
print("="*70)

print(f"\n📊 Dataset Info:")
print(f"   Total samples: {len(data)}")
print(f"   TP: {sum(1 for d in data if d.get('label') == 0)}")
print(f"   FP: {sum(1 for d in data if d.get('label') == 1)}")

# Check feature extraction on samples
print(f"\n🔧 Testing Feature Extraction:")

fp_reducer = FalsePositiveReducer()

# Extract features from first 5 samples
for i, sample in enumerate(data[:5], 1):
    print(f"\n   Sample {i}:")
    print(f"      Category: {sample.get('category', 'N/A')}")
    print(f"      Severity: {sample.get('severity', 'N/A')}")
    print(f"      Label: {sample.get('label', -1)}")
    
    # Extract features
    features = fp_reducer.extract_features(sample, context={})
    print(f"      Features shape: {features.shape}")
    print(f"      Non-zero features: {np.count_nonzero(features)}")
    print(f"      Feature values: {features[0][:8]}")  # First 8 features

# Check if all samples have same features
print(f"\n🔍 Checking Feature Variance:")

all_features = []
for sample in data[:50]:
    features = fp_reducer.extract_features(sample, context={})
    all_features.append(features[0])

all_features = np.array(all_features)
feature_variance = np.var(all_features, axis=0)

print(f"   Feature variances:")
feature_names = [
    'severity', 'category', 'evidence_length', 'description_length',
    'url_complexity', 'has_params', 'cvss_score', 'risk_score'
]

for i, (name, var) in enumerate(zip(feature_names, feature_variance[:8])):
    print(f"      {name:20s}: {var:.6f}")

if np.all(feature_variance < 0.001):
    print(f"\n   ⚠️  WARNING: All features have near-zero variance!")
    print(f"   This means all samples look the same to the model.")

# Check label distribution in training
print(f"\n🎯 Training Split Check:")
from sklearn.model_selection import train_test_split

labels = [d.get('label', -1) for d in data]
X_train, X_test, y_train, y_test = train_test_split(
    data, labels, test_size=0.2, random_state=42, stratify=labels
)

print(f"   Train set: {len(X_train)} samples")
print(f"      TP: {sum(1 for y in y_train if y == 0)}")
print(f"      FP: {sum(1 for y in y_train if y == 1)}")
print(f"   Test set: {len(X_test)} samples")
print(f"      TP: {sum(1 for y in y_test if y == 0)}")
print(f"      FP: {sum(1 for y in y_test if y == 1)}")

print("\n" + "="*70)
