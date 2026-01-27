#!/usr/bin/env python3
"""
Test if model is just predicting majority class.
"""

import json
from ml.false_positive_reducer import FalsePositiveReducer

# Load data
with open('ml/training_data/merged/normalized_training_data_20260127_141514.json', 'r') as f:
    data = json.load(f)

fp_reducer = FalsePositiveReducer()

print("="*70)
print("TESTING MODEL PREDICTIONS")
print("="*70)

# Test on all samples
predictions = []
true_labels = []

for sample in data[:20]:  # Test first 20
    is_fp, conf = fp_reducer.predict(sample, context={})
    pred_label = 1 if is_fp else 0
    true_label = sample.get('label', -1)
    
    predictions.append(pred_label)
    true_labels.append(true_label)

print(f"\n📊 Prediction Analysis (first 20 samples):")
print(f"   Predicted FP: {predictions.count(1)}")
print(f"   Predicted TP: {predictions.count(0)}")
print(f"   True FP: {true_labels.count(1)}")
print(f"   True TP: {true_labels.count(0)}")

# Check if model ALWAYS predicts same class
if len(set(predictions)) == 1:
    print(f"\n⚠️  WARNING: Model ALWAYS predicts class {predictions[0]}!")
    print(f"   This means model is NOT learning - just predicting majority class.")
else:
    print(f"\n✅ Model predicts different classes: {set(predictions)}")

# Check unique confidences
unique_confs = []
for sample in data[:20]:
    _, conf = fp_reducer.predict(sample, context={})
    unique_confs.append(round(conf, 4))

unique_confs = set(unique_confs)
print(f"\n🎯 Unique Confidence Values: {len(unique_confs)}")
if len(unique_confs) == 1:
    print(f"   ⚠️  WARNING: All predictions have SAME confidence: {list(unique_confs)[0]}")
    print(f"   This confirms model is using constant prediction!")
else:
    print(f"   ✅ Varying confidences: {sorted(unique_confs)[:5]}")

print("\n" + "="*70)
