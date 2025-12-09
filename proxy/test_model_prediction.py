#!/usr/bin/env python3
"""Test model prediction directly"""

import json
from pathlib import Path
from ml.false_positive_reducer import FalsePositiveReducer

# Load training data
training_file = sorted(Path("ml/training_data").glob("merged_training_data_*.json"), reverse=True)[0]
print(f"[*] Loading: {training_file.name}\n")

with open(training_file, 'r') as f:
    data = json.load(f)

# Initialize model
fp_reducer = FalsePositiveReducer()

print(f"Model trained: {fp_reducer.is_trained}")
print(f"Model exists: {fp_reducer.model is not None}")
print()

# Test first finding
finding = data[0]
print(f"Testing finding: {finding.get('category', 'N/A')}")
print(f"True label: {finding.get('label', -1)} ({'TP' if finding.get('label')==0 else 'FP'})")
print()

# Try prediction
try:
    is_fp, confidence = fp_reducer.predict(finding)
    print(f"Predicted: {'FP' if is_fp else 'TP'}")
    print(f"Confidence: {confidence:.2%}")
    print(f"Using model: {fp_reducer.is_trained}")
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
