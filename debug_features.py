#!/usr/bin/env python3
"""
Debug script to check feature extraction and simple model behavior
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from proxy.ml.false_positive_reducer import FalsePositiveReducer

# Create a fresh reducer without loading any saved model
reducer = FalsePositiveReducer("ml/models/fp_reducer_debug.pkl")

print("[DEBUG] Testing feature extraction and keyword detection\n")

test_cases = [
    {
        'name': 'SQL Injection',
        'finding': {
            'severity': 'critical',
            'category': 'SQL Injection',
            'description': 'SQL injection in login form',
            'evidence': 'Union-based SQL injection detected in parameter id',
            'cvss_score': 9.8,
            'risk_score': 9.5,
            'url': 'http://localhost/user.php?id=1'
        }
    },
    {
        'name': 'HSTS Missing',
        'finding': {
            'severity': 'info',
            'category': 'Security Misconfiguration',
            'description': 'HSTS header not set',
            'evidence': 'Missing Strict-Transport-Security header',
            'cvss_score': 0.0,
            'risk_score': 0.0,
            'url': 'http://localhost/index.php'
        }
    }
]

for test_case in test_cases:
    finding = test_case['finding']
    print(f"\n{'='*80}")
    print(f"Test Case: {test_case['name']}")
    print(f"{'='*80}")
    
    # Extract features
    features = reducer.extract_features(finding)
    print(f"\nFeatures extracted: {features.shape}")
    
    # Get keyword information
    desc_lower = finding['description'].lower()
    print(f"\nKeyword analysis:")
    print(f"  Description: {finding['description']}")
    
    # Check FP keywords
    fp_keywords_found = [kw for kw in reducer.fp_keywords if kw in desc_lower]
    tp_keywords_found = [kw for kw in reducer.tp_keywords if kw in desc_lower]
    
    print(f"  FP keywords found: {fp_keywords_found}")
    print(f"  TP keywords found: {tp_keywords_found}")
    
    # Feature values (indices)
    print(f"\nFeatured values (detailed):")
    feature_names = [
        'severity', 'category', 'evidence_length', 'description_length',
        'url_complexity', 'has_params', 'cvss_score', 'risk_score',
        'fp_keyword_count', 'tp_keyword_count', 'keyword_ratio'
    ]
    
    for i, (name, value) in enumerate(zip(feature_names, features.flatten()[:11])):
        print(f"  {i}: {name:25s} = {value:8.2f}")

print(f"\n{'='*80}")
print("Model Training Status:")
print(f"{'='*80}")
print(f"is_trained: {reducer.is_trained}")
print(f"model: {reducer.model}")
