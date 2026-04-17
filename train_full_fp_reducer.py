#!/usr/bin/env python3
"""
Train FP Reducer with FULL ZAP Dataset (1799 samples: 1308 TP + 262 FP + 229 Potential)

This script trains using the UNBALANCED but more representative data:
- Input: 2026-04-14-ZAP-Report-localhost_labeled.json
- 1308 True Positives (label=0) - includes headers, auth, cookies, etc.
- 262 False Positives (label=1) - scanner metadata
- Potential items removed
- class_weight='balanced' in RF handles 5:1 imbalance automatically
"""

import json
import sys
import os
from pathlib import Path
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from proxy.ml.false_positive_reducer import FalsePositiveReducer


def load_full_data(json_path: str):
    """Load full (unbalanced) training dataset."""
    print(f"\n[LOAD] Loading full labeled dataset: {json_path}")
    
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
            continue  # Skip Potential records for this training
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
    print(f"\n[DATA] Dataset Summary (Imbalanced - Less Bias):")
    print(f"   True Positives (TP, label=0): {label_counts['TP']}")
    print(f"   False Positives (FP, label=1): {label_counts['FP']}")
    print(f"   Potential (skipped): {label_counts['Potential']}")
    print(f"   Total used: {len(findings)}")
    print(f"   Imbalance ratio: {label_counts['TP'] / label_counts['FP']:.1f}:1 (TP:FP)")
    
    if len(findings) < 10:
        print("[ERROR] Not enough data to train (minimum 10 samples required)")
        return None, None
    
    return findings, labels


def train_model_unbalanced(findings, labels):
    """Train the FP Reducer model with imbalanced data."""
    print("\n" + "="*80)
    print("TRAINING FALSE POSITIVE REDUCER (FULL UNBALANCED DATA)")
    print("="*80)
    
    reducer = FalsePositiveReducer()
    
    print(f"\n[TRAIN] Training on {len(findings)} samples...")
    print(f"   - Class imbalance: {labels.count(0)} TP vs {labels.count(1)} FP (5:1 ratio)")
    print(f"   - Ensemble: Random Forest + Gradient Boosting")
    print(f"   - Imbalance handling: class_weight='balanced' in RandomForest")
    print(f"   - Features: 16 semantic + structural features")
    print(f"   - Train/test split: 75/25 stratified")
    
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
    print(f"[METRICS] Model Performance:")
    print(f"   Train Accuracy: {result.get('train_accuracy', 0):.1%}")
    print(f"   Test Accuracy:  {result.get('test_accuracy', 0):.1%}")
    print(f"   Test Precision: {result.get('precision', 0):.1%}")
    print(f"   Test Recall:    {result.get('recall', 0):.1%}")
    print(f"   Test F1:        {result.get('f1', 0):.3f}")
    print(f"   Training Time:  {result.get('training_time', 0):.2f}s")
    
    # Train/Test split
    if 'samples_trained' in result and 'samples_tested' in result:
        train_count = result['samples_trained']
        test_count = result['samples_tested']
        print(f"\n[SPLIT] Data Split (75/25):")
        print(f"   Train: {train_count} samples (75%)")
        print(f"   Test:  {test_count} samples (25%)")
    
    # Feature importance
    if result.get('feature_importance'):
        print(f"\n[FEATURES] Top 10 Most Important Features:")
        features = result['feature_importance']
        sorted_features = sorted(features.items(), key=lambda x: x[1], reverse=True)[:10]
        for i, (name, importance) in enumerate(sorted_features, 1):
            bar = "█" * int(importance * 20)
            print(f"   {i:2d}. {name:25s} {bar} {importance:.1%}")
    
    # Benchmark comparison
    if result.get('benchmark_results'):
        print(f"\n[BENCHMARK] Comparison with Other Classifiers (Test Accuracy):")
        benchmarks = result['benchmark_results']
        for name, metrics in sorted(benchmarks.items(), key=lambda x: x[1]['accuracy'], reverse=True):
            acc = metrics['accuracy']
            print(f"   {name:30s}: {acc:.1%}")
    
    return reducer


def test_model(reducer):
    """Run semantic tests on trained model."""
    if reducer is None:
        return False
    
    print("\n" + "="*80)
    print("SEMANTIC VALIDATION TESTS")
    print("="*80)
    
    test_cases = [
        {
            'name': 'SQL Injection (Real Vulnerability)',
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
            'name': 'HSTS Missing (Info Disclosure)',
            'finding': {
                'severity': 'info',
                'category': 'Security Misconfiguration',
                'description': 'HSTS header not set',
                'evidence': 'Missing Strict-Transport-Security header',
                'cvss_score': 0.0,
                'risk_score': 0.0,
                'url': 'http://localhost/index.php'
            },
            'expected': 0  # This SHOULD be TP - it's evidence-based info disclosure
        },
        {
            'name': 'XSS Reflected (Real Vulnerability)',
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
            'name': 'Authentication Detected (Scanner Artifact)',
            'finding': {
                'severity': 'medium',
                'category': 'Authentication Request Identified',
                'description': 'The given request has been identified as an authentication request',
                'evidence': 'Authentication Request Identified',
                'cvss_score': 0.0,
                'risk_score': 0.0,
                'url': 'http://localhost/login.php'
            },
            'expected': 1  # FP - scanner metadata
        },
        {
            'name': 'Authentication Bypass (Real Vulnerability)',
            'finding': {
                'severity': 'high',
                'category': 'Authentication',
                'description': 'Authentication bypass vulnerability allows access without login',
                'evidence': 'Can access admin panel without login credentials via direct URL',
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
        
        exp_label = "FP" if test_case['expected'] == 1 else "TP"
        pred_label = "FP" if predicted == 1 else "TP"
        
        print(f"\n{test_case['name']}")
        print(f"   Expected: {exp_label}, Got: {pred_label} (confidence: {confidence:.1%})")
        print(f"   {status}")
        
        results.append({
            'test': test_case['name'],
            'expected': test_case['expected'],
            'predicted': predicted,
            'confidence': confidence,
            'passed': correct
        })
    
    print(f"\n{'='*80}")
    print(f"Semantic Validation: {passed}/{len(test_cases)} passed")
    print(f"{'='*80}\n")
    
    return passed >= 3  # Need at least 3/5 to consider OK


def main():
    """Main execution."""
    print("\n" + "="*80)
    print("TRAINING FP REDUCER WITH FULL UNBALANCED DATASET (1570 samples)")
    print("="*80)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Remove old model
    old_model = "ml/models/fp_reducer.pkl"
    if os.path.exists(old_model):
        os.remove(old_model)
        print(f"[CLEANUP] Removed old model: {old_model}")
    
    # Load data
    data_path = 'proxy/ml/training_data/2026-04-14-ZAP-Report-localhost_labeled.json'
    findings, labels = load_full_data(data_path)
    
    if findings is None:
        print("\n[ERROR] Failed to load data. Exiting.")
        return False
    
    # Train model
    reducer = train_model_unbalanced(findings, labels)
    
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
    if test_passed:
        print(f"[OK] Semantic validation passed - model is ready for use!")
    else:
        print(f"[WARN] Some semantic tests failed - model may need tuning")
    print()
    
    return test_passed


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
