#!/usr/bin/env python3
"""
Train FP Reducer with Balanced ZAP Dataset (524 samples: 262 TP + 262 FP)

This script trains the False Positive Reducer model using:
- Input: 2026-04-14-ZAP-Report-localhost_labeled_balanced_524.json
- 262 True Positives (label=0)
- 262 False Positives (label=1)
- Perfect class balance for unbiased baseline training
"""

import json
import sys
import os
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from proxy.ml.false_positive_reducer import FalsePositiveReducer


def load_balanced_data(json_path: str):
    """Load balanced training dataset."""
    print(f"\n[LOAD] Loading balanced dataset: {json_path}")
    
    if not os.path.exists(json_path):
        print(f"[ERROR] File not found: {json_path}")
        return None, None
    
    with open(json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    print(f"[OK] Loaded {len(data)} records")
    
    # Extract findings and labels
    findings = []
    labels = []
    
    label_counts = {'TP': 0, 'FP': 0, 'Potential': 0}
    
    for record in data:
        # Get label: string or int
        label_name = record.get('label_name', '')
        label_int = record.get('label', -1)
        
        # Determine label
        if label_name == 'TP' or label_int == 0:
            labels.append(0)
            label_counts['TP'] += 1
        elif label_name == 'FP' or label_int == 1:
            labels.append(1)
            label_counts['FP'] += 1
        elif label_name == 'Potential':
            label_counts['Potential'] += 1
            continue  # Skip Potential records
        else:
            print(f"[WARN] Unknown label: {label_name}/{label_int}, skipping")
            continue
        
        # Create finding object
        finding = {
            'severity': record.get('severity', 'medium'),
            'category': record.get('category', 'Unknown'),
            'description': record.get('description', ''),
            'evidence': record.get('evidence', ''),
            'cvss_score': float(record.get('cvss_score', 0) or 0),
            'risk_score': float(record.get('cvss_score', 0) or 0),
            'url': record.get('url', 'http://localhost/')
        }
        
        findings.append(finding)
    
    # Print summary
    print(f"\n[DATA] Dataset Summary:")
    print(f"   True Positives (TP, label=0): {label_counts['TP']}")
    print(f"   False Positives (FP, label=1): {label_counts['FP']}")
    if label_counts['Potential'] > 0:
        print(f"   Potential (skipped): {label_counts['Potential']}")
    print(f"   Total used: {len(findings)}")
    
    if len(findings) < 10:
        print("[ERROR] Not enough data to train (minimum 10 samples required)")
        return None, None
    
    return findings, labels


def train_model(findings, labels):
    """Train the FP Reducer model."""
    print("\n" + "="*80)
    print("TRAINING FALSE POSITIVE REDUCER")
    print("="*80)
    
    reducer = FalsePositiveReducer()
    
    print(f"\n[TRAIN] Training on {len(findings)} samples...")
    print(f"   - Ensemble: Random Forest + Gradient Boosting")
    print(f"   - Features: 16 semantic + structural features")
    print(f"   - Class Balance: {labels.count(0)} TP vs {labels.count(1)} FP")
    print(f"   - Anti-overfitting: class_weight='balanced', regularization, stratified split")
    
    # Train
    result = reducer.train(findings, labels)
    
    # Check success
    if 'error' in result:
        print(f"\n[ERROR] Training failed: {result.get('error')}")
        return None
    
    if not result.get('success', False):
        print(f"\n[ERROR] Training failed: {result.get('message', 'Unknown error')}")
        return None
    
    # Print results
    print(f"\n[OK] Training successful!\n")
    print(f"[METRICS] Model Metrics:")
    print(f"   Test Accuracy: {result.get('test_accuracy', 0):.1%}")
    print(f"   Test Precision: {result.get('test_precision', 0):.1%}")
    print(f"   Test Recall: {result.get('test_recall', 0):.1%}")
    print(f"   Test F1: {result.get('test_f1', 0):.3f}")
    print(f"   Training Time: {result.get('training_time', 0):.2f}s")
    
    # Feature importance
    if result.get('feature_importance'):
        print(f"\n[FEATURES] Top 10 Features (by importance):")
        features = result['feature_importance']
        sorted_features = sorted(features.items(), key=lambda x: x[1], reverse=True)[:10]
        for i, (name, importance) in enumerate(sorted_features, 1):
            bar = "█" * int(importance * 20)
            print(f"   {i:2d}. {name:25s} {bar} {importance:.1%}")
    
    # Train/Test split ratios
    if 'train_count' in result and 'test_count' in result:
        print(f"\n[SPLIT] Data Split:")
        print(f"   Train: {result['train_count']} samples (75%)")
        print(f"   Test: {result['test_count']} samples (25%)")
    
    # GPU status
    if result.get('gpu_used'):
        print(f"\n[GPU] GPU Used: {result.get('gpu_used')}")
    else:
        print(f"\n[CPU] Using CPU")
    
    return reducer


def test_model(reducer):
    """Run semantic tests on trained model."""
    if reducer is None:
        return False
    
    # Debug: Print model state
    print(f"\n[DEBUG] Model Debug Info:")
    print(f"   is_trained: {reducer.is_trained}")
    print(f"   model object: {type(reducer.model)}")
    print(f"   scaler object: {type(reducer.scaler)}")
    
    # Test a simple feature extraction
    test_finding = {
        'severity': 'high',
        'category': 'SQL Injection',
        'description': 'SQL injection found',
        'evidence': 'Union-based SQL injection detected',
        'cvss_score': 9.0,
        'risk_score': 9.0,
        'url': 'http://localhost/test.php?id=1'
    }
    
    try:
        features = reducer.extract_features(test_finding)
        print(f"\n[DEBUG] Feature extraction works:")
        print(f"   Feature vector length: {len(features.flatten())}")
        print(f"   Feature values: {features.flatten()[:5]}...")  # Show first 5
    except Exception as e:
        print(f"\n[ERROR] Feature extraction failed: {e}")
    
    print("\n" + "="*80)
    print("SEMANTIC TESTS")
    print("="*80)
    
    test_cases = [
        {
            'name': 'SQL Injection (Expected: TP)',
            'finding': {
                'severity': 'critical',
                'category': 'SQL Injection',
                'description': 'SQL injection in login form',
                'evidence': 'Union-based SQL injection detected in parameter id',
                'cvss_score': 9.8,
                'risk_score': 9.5,
                'url': 'http://localhost/user.php?id=1'
            },
            'expected': 0  # TP
        },
        {
            'name': 'HSTS Missing (Expected: FP)',
            'finding': {
                'severity': 'info',
                'category': 'Security Misconfiguration',
                'description': 'HSTS header not set',
                'evidence': 'Missing Strict-Transport-Security header',
                'cvss_score': 0.0,
                'risk_score': 0.0,
                'url': 'http://localhost/index.php'
            },
            'expected': 1  # FP
        },
        {
            'name': 'XSS Reflected (Expected: TP)',
            'finding': {
                'severity': 'high',
                'category': 'Cross-site Scripting',
                'description': 'Reflected XSS in search parameter',
                'evidence': 'Script tag <script>alert(1)</script> not filtered in response',
                'cvss_score': 7.5,
                'risk_score': 7.0,
                'url': 'http://localhost/search.php?q=test'
            },
            'expected': 0  # TP
        },
        {
            'name': 'X-Powered-By Header (Expected: FP)',
            'finding': {
                'severity': 'medium',
                'category': 'Information Disclosure',
                'description': 'Server technology disclosed',
                'evidence': 'X-Powered-By: Apache/2.4.41 header present',
                'cvss_score': 0.0,
                'risk_score': 0.0,
                'url': 'http://localhost/'
            },
            'expected': 1  # FP
        },
        {
            'name': 'Authentication Bypass (Expected: TP)',
            'finding': {
                'severity': 'high',
                'category': 'Authentication',
                'description': 'Authentication bypass vulnerability',
                'evidence': 'Can access admin panel without login credentials',
                'cvss_score': 8.5,
                'risk_score': 8.0,
                'url': 'http://localhost/admin/dashboard.php'
            },
            'expected': 0  # TP
        }
    ]
    
    passed = 0
    results = []
    
    for test_case in test_cases:
        is_fp, confidence = reducer.predict(test_case['finding'])
        predicted = 1 if is_fp else 0
        correct = predicted == test_case['expected']
        
        if correct:
            passed += 1
            status = "[PASS]"
        else:
            status = "[FAIL]"
        
        print(f"\n{test_case['name']}")
        print(f"   Expected: {'FP' if test_case['expected'] == 1 else 'TP'}, "
              f"Got: {'FP' if predicted == 1 else 'TP'} "
              f"(confidence: {confidence:.1%})")
        print(f"   {status}")
        
        results.append({
            'test': test_case['name'],
            'expected': test_case['expected'],
            'predicted': predicted,
            'confidence': confidence,
            'passed': correct
        })
    
    print(f"\n{'='*80}")
    print(f"Semantic Tests: {passed}/{len(test_cases)} passed")
    print(f"{'='*80}\n")
    
    return passed == len(test_cases)


def main():
    """Main execution."""
    print("\n" + "="*80)
    print("TRAINING FP REDUCER WITH BALANCED DATASET (524 samples)")
    print("="*80)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Load data
    data_path = 'proxy/ml/training_data/2026-04-14-ZAP-Report-localhost_labeled_balanced_524.json'
    findings, labels = load_balanced_data(data_path)
    
    if findings is None:
        print("\n[ERROR] Failed to load data. Exiting.")
        return False
    
    # Train model
    reducer = train_model(findings, labels)
    
    if reducer is None:
        print("\n[ERROR] Training failed. Exiting.")
        return False
    
    # Run semantic tests
    test_passed = test_model(reducer)
    
    # Finalize
    print("\n" + "="*80)
    print("TRAINING COMPLETE")
    print("="*80)
    print(f"\n[SAVED] Model saved to: ml/models/fp_reducer.pkl")
    print(f"[OK] Ready for deployment/integration\n")
    
    return test_passed


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
