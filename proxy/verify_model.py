#!/usr/bin/env python3
"""
Verify trained model status and feature importance.
"""

import pickle
import numpy as np
from pathlib import Path

print("="*70)
print("MODEL VERIFICATION")
print("="*70)

# Load model
model_path = Path('ml/models/fp_reducer.pkl')

if not model_path.exists():
    print("\n❌ Model file not found!")
    exit(1)

with open(model_path, 'rb') as f:
    model_data = pickle.load(f)

print(f"\n📦 Model File: {model_path}")
print(f"   File size: {model_path.stat().st_size / 1024:.1f} KB")
print(f"   Last modified: {model_path.stat().st_mtime}")

# Check model type
print(f"\n🔍 Model Structure:")
print(f"   Type: {type(model_data)}")

# If it's CalibratedClassifierCV
if hasattr(model_data, 'calibrated_classifiers_'):
    print(f"   Calibrated: Yes")
    print(f"   Calibrators: {len(model_data.calibrated_classifiers_)}")
    
    # Get base estimator
    base = model_data.calibrated_classifiers_[0].base_estimator
    print(f"\n🌳 Base Estimator:")
    print(f"   Type: {type(base)}")
    
    # If VotingClassifier
    if hasattr(base, 'estimators_'):
        print(f"   Voting Classifier: Yes")
        print(f"   Estimators: {len(base.estimators_)}")
        
        # Check each estimator
        for i, est in enumerate(base.estimators_):
            print(f"\n   Estimator {i+1}: {type(est).__name__}")
            
            if hasattr(est, 'feature_importances_'):
                importances = est.feature_importances_
                print(f"      Features: {len(importances)}")
                print(f"      Max importance: {np.max(importances):.6f}")
                print(f"      Min importance: {np.min(importances):.6f}")
                print(f"      Sum: {np.sum(importances):.6f}")
                
                # Top 5 features
                indices = np.argsort(importances)[::-1]
                print(f"\n      Top 5 Features by Index:")
                for idx in indices[:5]:
                    print(f"         Feature {idx:2d}: {importances[idx]:.6f}")
    
    # Check if model has n_features_in_
    if hasattr(model_data, 'n_features_in_'):
        print(f"\n📊 Input Features: {model_data.n_features_in_}")
else:
    print(f"   Calibrated: No")
    
    if hasattr(model_data, 'feature_importances_'):
        importances = model_data.feature_importances_
        print(f"\n📊 Feature Importances:")
        print(f"   Features: {len(importances)}")
        
        indices = np.argsort(importances)[::-1]
        for i, idx in enumerate(indices[:10], 1):
            print(f"   {i:2d}. Feature {idx:2d}: {importances[idx]:.6f}")

print("\n" + "="*70)
