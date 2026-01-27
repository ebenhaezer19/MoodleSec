#!/usr/bin/env python3
"""
Retrain ML Models with Real Data

This script retrains the ML models using real scan data
that has been labeled (either auto-labeled or manually).

Usage:
    python retrain_models.py
    python retrain_models.py --data path/to/training_data.json
"""

import json
import sys
import argparse
from pathlib import Path
from ml.false_positive_reducer import FalsePositiveReducer
from ml.severity_predictor import SeverityPredictor

def load_training_data(filepath):
    """
    Load and normalize training data from JSON file.
    
    Handles both old and new formats:
    - Old: {severity, category, ...}
    - New: {finding: {severity, category, ...}}
    
    Args:
        filepath: Path to training data JSON file
        
    Returns:
        Tuple of (training_data, labels)
    """
    print(f"Loading training data from: {filepath}")
    
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    training_data = []
    labels = []
    skipped = 0
    
    for item in data:
        label = item.get('label')
        
        # Skip unlabeled data
        if label is None or label == -1:
            skipped += 1
            continue
        
        # ✅ NORMALIZE FORMAT
        # Check if data has nested 'finding' key (new format)
        if 'finding' in item:
            finding = item['finding']
        else:
            # Old format: direct fields
            finding = item
        
        # Ensure finding has minimum required fields
        if not finding.get('category') or not finding.get('severity'):
            skipped += 1
            continue
        
        training_data.append(finding)
        labels.append(label)
    
    print(f"Loaded {len(training_data)} labeled findings")
    if skipped > 0:
        print(f"Skipped {skipped} unlabeled/invalid findings")
    print(f"  True Positives (label=0): {labels.count(0)}")
    print(f"  False Positives (label=1): {labels.count(1)}")
    
    return training_data, labels

def retrain_fp_reducer(training_data, labels):
    """
    Retrain False Positive Reducer.
    
    Args:
        training_data: List of finding dictionaries
        labels: List of labels (0=TP, 1=FP)
        
    Returns:
        Training results dictionary
    """
    print("\n" + "=" * 60)
    print("RETRAINING FALSE POSITIVE REDUCER")
    print("=" * 60)
    
    # Initialize model
    fp_reducer = FalsePositiveReducer()
    
    # Train
    print("\nTraining model...")
    results = fp_reducer.train(training_data, labels)
    
    # Print results
    print("\n📊 Training Results:")
    print(f"   Accuracy:  {results.get('accuracy', 0):.2%}")
    print(f"   Precision: {results.get('precision', 0):.2%}")
    print(f"   Recall:    {results.get('recall', 0):.2%}")
    print(f"   F1 Score:  {results.get('f1', 0):.2%}")
    
    # Feature importance
    if 'feature_importance' in results and results['feature_importance']:
        print("\n🔍 Top 5 Important Features:")
        feature_importance = results['feature_importance']
        
        # Handle both list and dict formats
        if isinstance(feature_importance, list):
            for i, item in enumerate(feature_importance[:5], 1):
                if isinstance(item, tuple):
                    feature, importance = item
                    print(f"   {i}. {feature:20s}: {importance:.8f}")
        elif isinstance(feature_importance, dict):
            sorted_features = sorted(
                feature_importance.items(), 
                key=lambda x: x[1], 
                reverse=True
            )
            for i, (feature, importance) in enumerate(sorted_features[:5], 1):
                print(f"   {i}. {feature:20s}: {importance:.8f}")
    
    # ✅ Save feature importance to JSON file
    if 'feature_importance' in results and results['feature_importance']:
        feature_importance_path = Path('ml/models/feature_importance.json')
        feature_importance = results['feature_importance']
        
        # Sort features by importance
        sorted_features = sorted(
            feature_importance.items(), 
            key=lambda x: x[1], 
            reverse=True
        )
        
        # Prepare JSON data
        feature_importance_data = {
            "features": feature_importance,
            "top_5": [
                {
                    "name": feature,
                    "importance": float(importance),
                    "percentage": float(importance * 100)
                }
                for feature, importance in sorted_features[:5]
            ],
            "timestamp": results.get('timestamp', ''),
            "accuracy": results.get('accuracy', 0)
        }
        
        # Save to file
        with open(feature_importance_path, 'w') as f:
            json.dump(feature_importance_data, f, indent=2)
        
        print(f"\n💾 Feature importance saved to: {feature_importance_path}")
    
    # Save model
    print(f"💾 Model saved to: {fp_reducer.model_path}")
    
    # Check if training was successful
    if results.get('accuracy', 0) < 0.60:
        print("\n⚠️  WARNING: Training accuracy is low!")
        print("   Possible causes:")
        print("   - Dataset too small (need 50+ samples)")
        print("   - Data quality issues")
        print("   - Imbalanced classes")
        print(f"\n   Current dataset: {len(training_data)} samples")
        print("   Recommendation: Collect more scan data")
    elif results.get('accuracy', 0) > 0.95:
        print("\n⚠️  WARNING: Training accuracy very high (>95%)!")
        print("   Possible data leakage - check for:")
        print("   - Duplicate samples")
        print("   - Perfect correlation between features and labels")
    else:
        print("\n✅ Training successful!")
    
    return results

def retrain_severity_predictor(training_data):
    """
    Retrain Severity Predictor.
    
    Args:
        training_data: List of finding dictionaries
        
    Returns:
        Training results dictionary or None
    """
    print("\n" + "=" * 60)
    print("RETRAINING SEVERITY PREDICTOR")
    print("=" * 60)
    
    # Extract severity labels
    severity_labels = []
    valid_data = []
    
    valid_severities = ['critical', 'high', 'medium', 'low', 'info']
    
    for finding in training_data:
        severity = finding.get('severity', '').lower()
        if severity in valid_severities:
            valid_data.append(finding)
            severity_labels.append(severity)
    
    if len(valid_data) < 10:
        print(f"⚠️  Not enough data with valid severity labels: {len(valid_data)}")
        print("   Minimum required: 10 samples")
        print("   Skipping severity predictor training.")
        return None
    
    print(f"Training with {len(valid_data)} findings")
    
    # Count severity distribution
    from collections import Counter
    severity_dist = Counter(severity_labels)
    print(f"\n📊 Severity Distribution:")
    for severity in valid_severities:
        count = severity_dist.get(severity, 0)
        pct = count / len(valid_data) * 100 if valid_data else 0
        print(f"   {severity.capitalize():10s}: {count:3d} ({pct:5.1f}%)")
    
    # Initialize model
    severity_predictor = SeverityPredictor()
    
    # Train
    print("\nTraining model...")
    try:
        results = severity_predictor.train(valid_data, severity_labels)
        
        # Print results
        print("\n📊 Training Results:")
        print(f"   Accuracy: {results.get('accuracy', 0):.2%}")
        
        # Save model
        print(f"\n💾 Model saved to: {severity_predictor.model_path}")
        
        if results.get('accuracy', 0) < 0.50:
            print("\n⚠️  WARNING: Severity predictor accuracy is low!")
            print("   This is normal if severity distribution is imbalanced.")
        else:
            print("\n✅ Training successful!")
        
        return results
        
    except Exception as e:
        print(f"\n❌ Error training severity predictor: {e}")
        return None

def test_improved_confidence(training_data):
    """
    Test if model confidence improved.
    
    Args:
        training_data: List of finding dictionaries
    """
    print("\n" + "=" * 60)
    print("TESTING IMPROVED CONFIDENCE")
    print("=" * 60)
    
    # Load trained model
    fp_reducer = FalsePositiveReducer()
    
    print("\n📊 Model Status:")
    print(f"   Trained: {fp_reducer.is_trained}")
    
    if hasattr(fp_reducer, 'model') and fp_reducer.model:
        if hasattr(fp_reducer.model, 'n_features_in_'):
            print(f"   Features: {fp_reducer.model.n_features_in_}")
        if hasattr(fp_reducer.model, 'n_estimators'):
            print(f"   Estimators: {fp_reducer.model.n_estimators}")
    
    # Test on sample findings
    sample_size = min(10, len(training_data))
    print(f"\n🧪 Testing on {sample_size} sample findings:")
    
    correct = 0
    high_confidence = 0
    
    for i, finding in enumerate(training_data[:sample_size], 1):
        true_label = finding.get('label', -1)
        
        # Predict
        is_fp, confidence = fp_reducer.predict(finding, context={})
        predicted_label = 1 if is_fp else 0
        
        # Check accuracy
        is_correct = (predicted_label == true_label)
        if is_correct:
            correct += 1
        
        if confidence > 0.70:
            high_confidence += 1
        
        # Display result
        label_names = {0: 'TP', 1: 'FP'}
        accuracy_icon = '✅' if is_correct else '❌'
        confidence_icon = '✅' if confidence > 0.70 else '⚠️'
        
        print(f"\n{i}. {finding.get('category', 'Unknown')[:50]}")
        print(f"   True Label: {label_names.get(true_label, 'Unknown')}")
        print(f"   Predicted: {label_names.get(predicted_label, 'Unknown')}")
        print(f"   Confidence: {confidence:.2%}")
        print(f"   Accuracy: {accuracy_icon} {'Correct' if is_correct else 'Wrong'}")
        print(f"   Status: {confidence_icon} {'High confidence (>70%)' if confidence > 0.70 else 'Low confidence (<70%)'}")
    
    # Summary
    accuracy = correct / sample_size * 100
    high_conf_pct = high_confidence / sample_size * 100
    
    print(f"\n📊 Test Summary:")
    print(f"   Accuracy: {correct}/{sample_size} ({accuracy:.0f}%)")
    print(f"   High confidence: {high_confidence}/{sample_size} ({high_conf_pct:.0f}%)")

def find_latest_training_data():
    """
    Find the latest training data file.
    
    Returns:
        Path to latest training file or None
    """
    # Check merged directory first
    merged_dir = Path('ml/training_data/merged')
    if merged_dir.exists():
        merged_files = list(merged_dir.glob('normalized_training_data_*.json'))
        if merged_files:
            # Get latest by timestamp in filename
            latest = max(merged_files, key=lambda p: p.stat().st_mtime)
            return latest
    
    # Fallback to old merged file
    old_merged = Path('ml/training_data/merged_training_data_20251219_033523.json')
    if old_merged.exists():
        return old_merged
    
    return None

def main():
    """Main function."""
    # Parse arguments
    parser = argparse.ArgumentParser(
        description='Retrain ML models with real data',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python retrain_models.py
  python retrain_models.py --data ml/training_data/merged/normalized_training_data_20260127.json
        """
    )
    parser.add_argument(
        '--data', 
        type=str,
        help='Path to training data file (default: auto-detect latest)'
    )
    args = parser.parse_args()
    
    print("=" * 60)
    print("RETRAINING ML MODELS WITH REAL DATA")
    print("=" * 60)
    
    # Determine training data file
    if args.data:
        training_file = Path(args.data)
    else:
        print("\n🔍 Auto-detecting latest training data...")
        training_file = find_latest_training_data()
    
    if not training_file or not training_file.exists():
        print("\n❌ ERROR: Training data not found!")
        print("\nPlease:")
        print("  1. Run: python merge_all_data.py")
        print("  2. Or specify file: python retrain_models.py --data <file>")
        return 1
    
    try:
        # Step 1: Load data
        print("\n" + "=" * 60)
        print("STEP 1: LOADING DATA")
        print("=" * 60)
        training_data, labels = load_training_data(training_file)
        
        if len(training_data) < 10:
            print(f"\n❌ ERROR: Not enough training data!")
            print(f"   Found: {len(training_data)} samples")
            print(f"   Minimum required: 10 samples")
            print("\n   Collect more scan data and label findings.")
            return 1
        
        # Step 2: Retrain FP Reducer
        print("\n" + "=" * 60)
        print("STEP 2: FALSE POSITIVE REDUCER")
        print("=" * 60)
        fp_results = retrain_fp_reducer(training_data, labels)
        
        # Step 3: Retrain Severity Predictor
        print("\n" + "=" * 60)
        print("STEP 3: SEVERITY PREDICTOR")
        print("=" * 60)
        severity_results = retrain_severity_predictor(training_data)
        
        # Step 4: Test improved confidence
        print("\n" + "=" * 60)
        print("STEP 4: CONFIDENCE TEST")
        print("=" * 60)
        test_improved_confidence(training_data)
        
        # Final summary
        print("\n" + "=" * 60)
        print("✅ RETRAINING COMPLETE!")
        print("=" * 60)
        
        print(f"\n📊 Results:")
        print(f"   FP Reducer Accuracy: {fp_results.get('accuracy', 0):.2%}")
        if severity_results:
            print(f"   Severity Predictor Accuracy: {severity_results.get('accuracy', 0):.2%}")
        
        print("\n" + "=" * 60)
        print("NEXT STEPS")
        print("=" * 60)
        print("\n1. Restart proxy service:")
        print("   python app.py")
        print("\n2. Run a new scan:")
        print("   curl -X POST http://localhost:8999/scan")
        print("\n3. Check for improved confidence in logs:")
        print("   Should see ML confidence >70%")
        
        print("\n📈 Expected Improvement:")
        print(f"   Before: 66% confidence (synthetic data)")
        print(f"   After: {max(70, fp_results.get('accuracy', 0)*100):.0f}%+ confidence (real data)")
        print()
        
        return 0
        
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
