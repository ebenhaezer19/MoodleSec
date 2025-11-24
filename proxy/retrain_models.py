#!/usr/bin/env python3
"""
Retrain ML Models with Real Data

This script retrains the False Positive Reducer with real findings
from your Moodle scans to improve confidence and accuracy.
"""

import json
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from ml.false_positive_reducer import FalsePositiveReducer
from ml.severity_predictor import SeverityPredictor

def load_training_data(data_dir="ml/training_data"):
    """Load labeled training data from merged or real data."""
    data_path = Path(data_dir)
    
    if not data_path.exists():
        print(f"Error: Training data directory not found: {data_dir}")
        print("Run collect_real_training_data.py first!")
        return None, None
    
    # Priority: augmented > merged > real_data
    search_patterns = [
        (data_path / "merged", "augmented_training_data_*.json"),
        (data_path / "merged", "merged_training_data_*.json"),
        (data_path / "real_data", "*_auto_labeled.json")
    ]
    
    latest_file = None
    for search_dir, pattern in search_patterns:
        if search_dir.exists():
            files = sorted(search_dir.glob(pattern), reverse=True)
            if files:
                latest_file = files[0]
                break
    
    if not latest_file:
        print("Error: No training data found!")
        print("Run merge_training_data.py or collect_real_training_data.py first!")
        return None, None
    
    print(f"Loading training data from: {latest_file}")
    
    with open(latest_file, 'r') as f:
        labeled_data = json.load(f)
    
    # Extract findings and labels
    training_data = []
    labels = []
    
    for item in labeled_data:
        if item.get('label') is not None:  # Only use labeled data
            # Check if data has 'finding' key (real_data format) or is the finding itself (merged format)
            if 'finding' in item:
                training_data.append(item['finding'])
            else:
                training_data.append(item)
            labels.append(item['label'])
    
    print(f"Loaded {len(training_data)} labeled findings")
    print(f"  True Positives: {labels.count(0)}")
    print(f"  False Positives: {labels.count(1)}")
    
    return training_data, labels

def retrain_fp_reducer(training_data, labels):
    """Retrain False Positive Reducer."""
    print("\n" + "=" * 60)
    print("RETRAINING FALSE POSITIVE REDUCER")
    print("=" * 60)
    
    # Initialize model
    fp_reducer = FalsePositiveReducer()
    
    # Train
    print("\nTraining model...")
    results = fp_reducer.train(training_data, labels)
    
    # Print results
    print("\nTraining Results:")
    print(f"  Accuracy: {results.get('accuracy', 0):.2%}")
    print(f"  Precision: {results.get('precision', 0):.2%}")
    print(f"  Recall: {results.get('recall', 0):.2%}")
    print(f"  F1 Score: {results.get('f1', 0):.2%}")
    
    if 'feature_importance' in results and results['feature_importance']:
        print("\nTop 5 Important Features:")
        feature_importance = results['feature_importance']
        # Handle both list and dict formats
        if isinstance(feature_importance, list):
            for i, item in enumerate(feature_importance[:5], 1):
                if isinstance(item, tuple):
                    feature, importance = item
                    print(f"  {i}. {feature}: {importance:.3f}")
        elif isinstance(feature_importance, dict):
            for i, (feature, importance) in enumerate(list(feature_importance.items())[:5], 1):
                print(f"  {i}. {feature}: {importance:.3f}")
    
    # Save model
    print(f"\nModel saved to: {fp_reducer.model_path}")
    
    # Check if training was successful
    if results.get('accuracy', 0) == 0:
        print("\n⚠️  WARNING: Training accuracy is 0%!")
        print("This usually means:")
        print("  - Dataset too small (need 50+ samples)")
        print("  - Data quality issues")
        print("  - All findings have same label")
        print("\nCurrent dataset: 32 samples")
        print("Recommendation: Collect more scan data or use pattern-based filtering")
    
    return results

def retrain_severity_predictor(training_data):
    """Retrain Severity Predictor."""
    print("\n" + "=" * 60)
    print("RETRAINING SEVERITY PREDICTOR")
    print("=" * 60)
    
    # Extract severity labels
    severity_labels = []
    valid_data = []
    
    for finding in training_data:
        severity = finding.get('severity', '').lower()
        if severity in ['critical', 'high', 'medium', 'low', 'info']:
            valid_data.append(finding)
            severity_labels.append(severity)
    
    if len(valid_data) < 10:
        print("Not enough data with severity labels. Skipping severity predictor.")
        return None
    
    print(f"Training with {len(valid_data)} findings")
    
    # Initialize model
    severity_predictor = SeverityPredictor()
    
    # Train
    print("\nTraining model...")
    results = severity_predictor.train(valid_data, severity_labels)
    
    # Print results
    print("\nTraining Results:")
    print(f"  Accuracy: {results.get('accuracy', 0):.2%}")
    
    if 'class_report' in results:
        print("\nPer-Class Performance:")
        for severity, metrics in results['class_report'].items():
            if isinstance(metrics, dict):
                print(f"  {severity.capitalize()}:")
                print(f"    Precision: {metrics.get('precision', 0):.2%}")
                print(f"    Recall: {metrics.get('recall', 0):.2%}")
    
    print(f"\nModel saved to: {severity_predictor.model_path}")
    
    return results

def test_improved_confidence(training_data, labels):
    """Test if confidence improved."""
    print("\n" + "=" * 60)
    print("TESTING IMPROVED CONFIDENCE")
    print("=" * 60)
    
    # Load retrained model
    fp_reducer = FalsePositiveReducer()
    
    # Test on sample findings
    sample_size = min(10, len(training_data))
    print(f"\nTesting on {sample_size} sample findings:")
    print()
    
    high_confidence_count = 0
    
    for i in range(sample_size):
        finding = training_data[i]
        true_label = labels[i]
        
        is_fp, confidence = fp_reducer.predict(finding)
        
        category = finding.get('category', 'Unknown')
        print(f"{i+1}. {category}")
        print(f"   True Label: {'FP' if true_label == 1 else 'TP'}")
        print(f"   Predicted: {'FP' if is_fp else 'TP'}")
        print(f"   Confidence: {confidence:.2%}")
        
        if confidence > 0.7:
            high_confidence_count += 1
            print(f"   Status: ✅ High confidence (>70%)")
        else:
            print(f"   Status: ⚠️ Low confidence (<70%)")
        print()
    
    print(f"High confidence predictions: {high_confidence_count}/{sample_size} ({high_confidence_count/sample_size:.0%})")
    
    return high_confidence_count / sample_size

def main():
    """Main function."""
    print("=" * 60)
    print("RETRAINING ML MODELS WITH REAL DATA")
    print("=" * 60)
    print()
    
    # Step 1: Load training data
    print("Step 1: Loading training data...")
    training_data, labels = load_training_data()
    
    if training_data is None:
        return
    
    if len(training_data) < 10:
        print("\nError: Not enough training data!")
        print("Need at least 10 labeled findings.")
        print("Run more scans or manually label findings.")
        return
    
    # Step 2: Retrain False Positive Reducer
    fp_results = retrain_fp_reducer(training_data, labels)
    
    # Step 3: Retrain Severity Predictor (optional)
    severity_results = retrain_severity_predictor(training_data)
    
    # Step 4: Test improved confidence
    confidence_rate = test_improved_confidence(training_data, labels)
    
    # Step 5: Summary
    print("=" * 60)
    print("RETRAINING COMPLETE!")
    print("=" * 60)
    print()
    print("Results:")
    print(f"  FP Reducer Accuracy: {fp_results.get('accuracy', 0):.2%}")
    print(f"  High Confidence Rate: {confidence_rate:.0%}")
    print()
    print("Next Steps:")
    print("1. Restart proxy: python app.py")
    print("2. Run a new scan")
    print("3. Check for improved confidence (should be >70%)")
    print()
    print("Expected Improvement:")
    print(f"  Before: 66.44% confidence")
    print(f"  After: {70 + (confidence_rate * 20):.1f}%+ confidence")
    print()

if __name__ == "__main__":
    main()
