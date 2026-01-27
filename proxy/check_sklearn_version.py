#!/usr/bin/env python3
"""Check sklearn version and calibrator structure."""

import sklearn
import pickle

print(f"Sklearn version: {sklearn.__version__}")

# Load model
with open('ml/models/fp_reducer.pkl', 'rb') as f:
    model_data = pickle.load(f)

model = model_data['model']
calibrator = model.calibrated_classifiers_[0]

print(f"\nCalibrator type: {type(calibrator)}")
print(f"\nCalibrator attributes:")
for attr in dir(calibrator):
    if not attr.startswith('_'):
        print(f"  - {attr}")
