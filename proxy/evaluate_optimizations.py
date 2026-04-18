#!/usr/bin/env python3
"""
Evaluate optimized anomaly detector improvements.

Tests the following optimizations:
1. Enhanced feature scaling with per-feature normalization hints
2. Improved score normalization using learned distribution parameters
3. Meta-classifier calibration optimized for FP reduction with recall preservation
4. Better threshold selection with weighted objective function

Generates comparison metrics and recommendations.
"""

import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ML_DIR = os.path.join(CURRENT_DIR, "ml")
if ML_DIR not in sys.path:
    sys.path.insert(0, ML_DIR)

from anomaly_detector import AnomalyDetector


def generate_synthetic_samples(count: int = 100, anomalous: bool = False) -> List[Dict[str, Any]]:
    """Generate synthetic test samples for evaluation."""
    samples = []
    
    for i in range(count):
        if anomalous:
            # Anomalous sample with suspicious patterns
            sample = {
                'request': {
                    'url': f'http://localhost/admin?id={i}&payload=<script>alert(1)</script>',
                    'headers': {
                        'User-Agent': 'sqlmap/1.5.0' if i % 3 == 0 else 'Mozilla/5.0',
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    'body': "username=admin' OR '1'=1' --&password=anything" if i % 2 == 0 else 'id=1 UNION SELECT * FROM users',
                },
                'response': {
                    'status_code': 500 if i % 4 == 0 else 200,
                    'size': 5000 + i * 100,
                    'time': 3000 if i % 5 == 0 else 500,
                    'headers': {
                        'Server': 'Apache',
                    }
                },
                'finding': {
                    'severity': 'critical' if i % 3 == 0 else 'high',
                    'risk_score': 8 + (i % 3),
                    'cvss_score': 7.5 + (i % 2),
                } if i % 2 == 0 else {},
                'request_count_last_minute': 50 + i % 100,
                'unique_ips_last_minute': i % 50,
                'error_rate_last_minute': 0.1 + (i % 10) * 0.05,
            }
        else:
            # Normal sample
            sample = {
                'request': {
                    'url': f'http://localhost/api/users/{i}',
                    'headers': {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                        'Content-Type': 'application/json',
                    },
                    'body': json.dumps({'id': i}) if i % 3 == 0 else '',
                },
                'response': {
                    'status_code': 200,
                    'size': 1000 + (i % 1000),
                    'time': 100 + (i % 200),
                    'headers': {
                        'Content-Type': 'application/json',
                        'X-Frame-Options': 'DENY',
                        'Content-Security-Policy': "default-src 'self'",
                    }
                },
                'finding': {
                    'severity': 'info',
                    'risk_score': 1 + (i % 2),
                    'cvss_score': 0,
                } if i % 5 == 0 else {},
                'request_count_last_minute': 5 + (i % 20),
                'unique_ips_last_minute': 1 + (i % 5),
                'error_rate_last_minute': 0.01 * (i % 5),
            }
        
        samples.append(sample)
    
    return samples


def evaluate_detector(detector: AnomalyDetector, 
                      normal_samples: List[Dict[str, Any]], 
                      anomalous_samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Evaluate detector performance on test samples."""
    
    results = {
        'normal': {'detected': 0, 'total': len(normal_samples), 'scores': []},
        'anomalous': {'detected': 0, 'total': len(anomalous_samples), 'scores': []},
        'details': []
    }
    
    # Test normal samples
    for sample in normal_samples:
        is_anom, score, reason = detector.detect(sample)
        results['normal']['scores'].append(score)
        if is_anom:
            results['normal']['detected'] += 1
        results['details'].append({
            'type': 'normal',
            'is_anomaly': is_anom,
            'score': score,
            'reason': reason
        })
    
    # Test anomalous samples
    for sample in anomalous_samples:
        is_anom, score, reason = detector.detect(sample)
        results['anomalous']['scores'].append(score)
        if is_anom:
            results['anomalous']['detected'] += 1
        results['details'].append({
            'type': 'anomaly',
            'is_anomaly': is_anom,
            'score': score,
            'reason': reason
        })
    
    # Calculate metrics
    tp = results['anomalous']['detected']
    fp = results['normal']['detected']
    tn = results['normal']['total'] - fp
    fn = results['anomalous']['total'] - tp
    
    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0
    fn_rate = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    results['metrics'] = {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'fp_rate': fp_rate,
        'fn_rate': fn_rate,
        'tp': tp,
        'fp': fp,
        'tn': tn,
        'fn': fn,
    }
    
    return results


def print_evaluation_report(results: Dict[str, Any]) -> None:
    """Print formatted evaluation report."""
    
    metrics = results['metrics']
    
    print("\n" + "="*70)
    print("ANOMALY DETECTOR OPTIMIZATION EVALUATION REPORT")
    print("="*70)
    
    print("\n📊 PERFORMANCE METRICS")
    print("-" * 70)
    print(f"Accuracy:     {metrics['accuracy']:.2%}")
    print(f"Precision:    {metrics['precision']:.2%}")
    print(f"Recall:       {metrics['recall']:.2%}")
    print(f"F1 Score:     {metrics['f1']:.4f}")
    print(f"FP Rate:      {metrics['fp_rate']:.2%}")
    print(f"FN Rate:      {metrics['fn_rate']:.2%}")
    
    print("\n📈 CONFUSION MATRIX")
    print("-" * 70)
    print(f"True Positives:   {metrics['tp']:4d} (Correctly identified anomalies)")
    print(f"False Positives:  {metrics['fp']:4d} (Normal flagged as anomaly)")
    print(f"True Negatives:   {metrics['tn']:4d} (Correctly identified normal)")
    print(f"False Negatives:  {metrics['fn']:4d} (Anomaly not detected)")
    
    print("\n🎯 OPTIMIZATION RESULTS")
    print("-" * 70)
    
    # Analyze score distributions
    normal_scores = results['normal']['scores']
    anomalous_scores = results['anomalous']['scores']
    
    if normal_scores and anomalous_scores:
        import numpy as np
        normal_mean = np.mean(normal_scores)
        normal_std = np.std(normal_scores)
        anomalous_mean = np.mean(anomalous_scores)
        anomalous_std = np.std(anomalous_scores)
        
        print(f"Normal samples distribution:    mean={normal_mean:.3f}, std={normal_std:.3f}")
        print(f"Anomalous samples distribution: mean={anomalous_mean:.3f}, std={anomalous_std:.3f}")
        print(f"Score separation:               {abs(anomalous_mean - normal_mean):.3f}")
    
    print("\n✅ OPTIMIZATION BENEFITS")
    print("-" * 70)
    print("✓ Enhanced feature scaling:")
    print("  - Per-feature normalization hints for better range handling")
    print("  - StandardScaler + RobustScaler for outlier resilience")
    print("  - MinMaxScaler available for bounded features")
    
    print("\n✓ Improved score normalization:")
    print("  - Learned distribution parameters (mean/std) from training data")
    print("  - Z-score normalization with sigmoid calibration")
    print("  - Better handling of extreme values")
    
    print("\n✓ Meta-classifier calibration:")
    print("  - Weighted objective: prioritize FP reduction over FN")
    print("  - Fine-grained threshold sweep (141 candidates, 0.005 step)")
    print("  - Minimum recall preservation (90% default)")
    print("  - 2x penalty weight on FP to drive reduction")
    
    print("\n📋 RECOMMENDATIONS")
    print("-" * 70)
    
    if metrics['fp_rate'] > 0.15:
        print("⚠️  HIGH FALSE POSITIVE RATE")
        print("   Action: Lower the meta-classifier threshold (default 0.5)")
        print("   Impact: Reduce FP while potentially increasing FN")
    
    if metrics['recall'] < 0.85:
        print("⚠️  LOW RECALL RATE")
        print("   Action: Increase minimum recall target (default 0.90)")
        print("   Impact: More anomalies detected but more FP expected")
    
    if metrics['accuracy'] < 0.80:
        print("⚠️  LOW OVERALL ACCURACY")
        print("   Action: Review feature engineering and heuristic rules")
        print("   Impact: Better feature representation = better decisions")
    
    if metrics['fp_rate'] <= 0.10 and metrics['recall'] >= 0.90:
        print("✅ EXCELLENT BALANCE ACHIEVED")
        print("   FP reduction successful while maintaining recall")
        print("   Current threshold is well-calibrated")
    
    print("\n" + "="*70)


def main():
    """Run evaluation of optimized anomaly detector."""
    
    print("🔍 Initializing optimized anomaly detector...")
    detector = AnomalyDetector()
    
    # Generate test data
    print("📊 Generating synthetic test data...")
    normal_train = generate_synthetic_samples(count=200, anomalous=False)
    anomalous_train = generate_synthetic_samples(count=150, anomalous=True)
    
    normal_test = generate_synthetic_samples(count=100, anomalous=False)
    anomalous_test = generate_synthetic_samples(count=100, anomalous=True)
    
    # Train on normal data
    print("🎓 Training anomaly detector on normal behavior...")
    train_result = detector.train(normal_train, contamination=0.10)
    
    if 'error' in train_result:
        print(f"❌ Training failed: {train_result['error']}")
        return
    
    print(f"✅ Training successful: {train_result['samples_trained']} samples")
    print(f"   Baseline stats: {json.dumps(train_result['baseline_stats'], indent=2)}")
    
    # Train meta-classifier for FP reduction
    print("\n🔧 Training meta-classifier for FP reduction...")
    meta_result = detector.train_meta_classifier(
        normal_data=normal_train[-100:],  # Use last 100 for meta training
        anomaly_data=anomalous_train[-75:],  # Use last 75 anomalies
        model_type='random_forest',
        target_recall=0.90,  # Preserve 90% recall minimum
        fp_penalty_weight=2.0,  # 2x penalty on false positives
    )
    
    if 'error' in meta_result:
        print(f"⚠️  Meta-classifier training: {meta_result['error']}")
    else:
        print(f"✅ Meta-classifier trained successfully")
        print(f"   Threshold: {meta_result['meta_threshold']:.3f}")
        print(f"   Validation metrics: {json.dumps(meta_result['validation_metrics'], indent=2)}")
    
    # Evaluate on test data
    print("\n📈 Evaluating on test data...")
    results = evaluate_detector(detector, normal_test, anomalous_test)
    
    # Print report
    print_evaluation_report(results)
    
    # Save detailed results
    output_file = os.path.join(CURRENT_DIR, 'optimization_eval_results.json')
    with open(output_file, 'w') as f:
        json.dump({
            'timestamp': datetime.utcnow().isoformat(),
            'training_result': train_result,
            'meta_result': meta_result,
            'evaluation': results,
        }, f, indent=2, default=str)
    
    print(f"\n💾 Detailed results saved to: {output_file}")


if __name__ == '__main__':
    main()
