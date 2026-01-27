#!/usr/bin/env python3
"""
Extract feature importance from CalibratedClassifierCV model.
(Compatible with sklearn 1.0+)
"""

import pickle
import numpy as np

print("="*70)
print("EXTRACT FEATURE IMPORTANCE")
print("="*70)

# Load model
with open('ml/models/fp_reducer.pkl', 'rb') as f:
    model_data = pickle.load(f)

model = model_data['model']

print(f"\n📦 Model Type: {type(model).__name__}")

# Extract from CalibratedClassifierCV
if hasattr(model, 'calibrated_classifiers_'):
    print(f"   Calibrators: {len(model.calibrated_classifiers_)}")
    
    # Get first calibrator
    calibrator = model.calibrated_classifiers_[0]
    
    # Try different attribute names (sklearn version compatibility)
    base_estimator = None
    
    # sklearn 1.0+: estimator
    if hasattr(calibrator, 'estimator'):
        base_estimator = calibrator.estimator
        print(f"   ✅ Found via 'estimator' attribute (sklearn 1.0+)")
    # sklearn <1.0: base_estimator
    elif hasattr(calibrator, 'base_estimator'):
        base_estimator = calibrator.base_estimator
        print(f"   ✅ Found via 'base_estimator' attribute (sklearn <1.0)")
    else:
        print(f"   ❌ Could not find base estimator")
        print(f"   Available attributes: {dir(calibrator)[:10]}")
        exit(1)
    
    print(f"\n🌳 Base Estimator: {type(base_estimator).__name__}")
    
    # Check if VotingClassifier (ensemble)
    if hasattr(base_estimator, 'estimators_'):
        print(f"   Type: Ensemble (VotingClassifier)")
        print(f"   Estimators: {len(base_estimator.estimators_)}")
        
        # Get feature importance from each estimator
        all_importances = []
        
        for i, estimator in enumerate(base_estimator.estimators_):
            print(f"\n   📊 Estimator {i+1}: {type(estimator).__name__}")
            
            if hasattr(estimator, 'feature_importances_'):
                importances = estimator.feature_importances_
                all_importances.append(importances)
                
                print(f"      Features: {len(importances)}")
                print(f"      Sum: {np.sum(importances):.6f}")
                print(f"      Max: {np.max(importances):.6f}")
                print(f"      Non-zero: {np.count_nonzero(importances > 0.001)}")
        
        # Average feature importance across estimators
        if all_importances:
            avg_importances = np.mean(all_importances, axis=0)
            
            print(f"\n" + "="*70)
            print("AVERAGED FEATURE IMPORTANCE")
            print("="*70)
            
            # Feature names (from FalsePositiveReducer)
            feature_names = [
                'severity',
                'category', 
                'evidence_length',
                'description_length',
                'url_complexity',
                'has_params',
                'cvss_score',
                'risk_score',
                'fp_keyword_count',
                'tp_keyword_count',
                'keyword_ratio',
                'is_informational',
                'status_code',
                'response_time',
                'occurrence_count',
                'days_since_first'
            ]
            
            # Sort by importance
            indices = np.argsort(avg_importances)[::-1]
            
            print(f"\n🏆 Top 10 Features:")
            for i, idx in enumerate(indices[:10], 1):
                if idx < len(feature_names):
                    fname = feature_names[idx]
                else:
                    fname = f"feature_{idx}"
                importance_pct = avg_importances[idx] * 100
                print(f"   {i:2d}. {fname:20s}: {avg_importances[idx]:.6f} ({importance_pct:.3f}%)")
            
            print(f"\n📊 All Features:")
            for idx in indices:
                if idx < len(feature_names):
                    fname = feature_names[idx]
                else:
                    fname = f"feature_{idx}"
                importance_pct = avg_importances[idx] * 100
                if avg_importances[idx] > 0.001:  # Only show non-trivial
                    print(f"      {fname:20s}: {avg_importances[idx]:.6f} ({importance_pct:.3f}%)")
            
            # Save for future reference
            import json
            importance_dict = {
                'features': {
                    feature_names[i]: float(avg_importances[i]) 
                    for i in range(min(len(feature_names), len(avg_importances)))
                },
                'top_5': [
                    {
                        'name': feature_names[indices[i]] if indices[i] < len(feature_names) else f"feature_{indices[i]}",
                        'importance': float(avg_importances[indices[i]]),
                        'percentage': float(avg_importances[indices[i]] * 100)
                    }
                    for i in range(min(5, len(indices)))
                ]
            }
            
            with open('ml/models/feature_importance.json', 'w') as f:
                json.dump(importance_dict, f, indent=2)
            
            print(f"\n💾 Saved to: ml/models/feature_importance.json")
        else:
            print("\n⚠️  No estimators with feature_importances_ found")
    
    elif hasattr(base_estimator, 'feature_importances_'):
        # Single estimator
        importances = base_estimator.feature_importances_
        
        print(f"\n📊 Feature Importances:")
        print(f"   Features: {len(importances)}")
        
        feature_names = [
            'severity', 'category', 'evidence_length', 'description_length',
            'url_complexity', 'has_params', 'cvss_score', 'risk_score',
            'fp_keyword_count', 'tp_keyword_count', 'keyword_ratio',
            'is_informational', 'status_code', 'response_time',
            'occurrence_count', 'days_since_first'
        ]
        
        indices = np.argsort(importances)[::-1]
        
        print(f"\n🏆 Top 10 Features:")
        for i, idx in enumerate(indices[:10], 1):
            if idx < len(feature_names):
                fname = feature_names[idx]
            else:
                fname = f"feature_{idx}"
            importance_pct = importances[idx] * 100
            print(f"   {i:2d}. {fname:20s}: {importances[idx]:.6f} ({importance_pct:.3f}%)")
    
    else:
        print(f"\n⚠️  Base estimator doesn't have feature_importances_")
        print(f"   Type: {type(base_estimator)}")
        print(f"   Attributes: {[a for a in dir(base_estimator) if not a.startswith('_')][:20]}")

else:
    print("\n⚠️  Model doesn't have calibrated_classifiers_ attribute")

print("\n" + "="*70)
