#!/usr/bin/env python3
"""
Test for Overfitting in FP Reducer Model

Tests multiple scenarios to determine if 100% accuracy is due to overfitting:
1. Learning curves
2. Cross-validation
3. Feature correlation analysis
4. Data leakage detection
5. Model complexity analysis
"""

import json
import numpy as np
from sklearn.model_selection import learning_curve, cross_val_score, KFold
from sklearn.metrics import accuracy_score, confusion_matrix
import matplotlib.pyplot as plt
from pathlib import Path
from ml.anomaly_false_positive_reducer import FalsePositiveReducer

def load_training_data(filepath):
    """Load training data."""
    with open(filepath, 'r', encoding='utf-8-sig') as f:
        data = json.load(f)
    
    training_data = []
    labels = []
    
    for item in data:
        label = item.get('label')
        if label is None or label == -1:
            continue
        
        if 'finding' in item:
            training_data.append(item)
        else:
            training_data.append({'finding': item, 'context': {}})
        
        labels.append(label)
    
    return training_data, labels

def test_cross_validation(training_data, labels):
    """Test with cross-validation to detect overfitting."""
    print("\n" + "="*80)
    print("TEST 1: CROSS-VALIDATION (K-FOLD)")
    print("="*80)
    print("Cross-validation splits data into K folds and tests on each fold.")
    print("If model is overfitting, CV scores will be much lower than training score.")
    print()
    
    fp_reducer = FalsePositiveReducer()
    
    # Extract features
    X = []
    for sample in training_data:
        if 'finding' in sample:
            finding = sample['finding']
            context = sample.get('context', {})
        else:
            finding = sample
            context = {}
        
        features = fp_reducer.extract_features(finding, context)
        X.append(features.flatten())
    
    X = np.array(X)
    y = np.array(labels)
    
    print(f"Dataset size: {len(X)} samples")
    print(f"Features: {X.shape[1]}")
    print()
    
    # 5-Fold Cross Validation
    kfold = KFold(n_splits=5, shuffle=True, random_state=42)
    
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    
    cv_scores = []
    fold = 1
    
    for train_idx, test_idx in kfold.split(X):
        X_train, X_test = X[train_idx], X[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]
        
        # Scale
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train simple RF
        model = RandomForestClassifier(
            n_estimators=150,
            max_depth=12,
            random_state=42,
            class_weight='balanced'
        )
        model.fit(X_train_scaled, y_train)
        
        # Evaluate
        train_score = model.score(X_train_scaled, y_train)
        test_score = model.score(X_test_scaled, y_test)
        cv_scores.append(test_score)
        
        print(f"Fold {fold}:")
        print(f"  Train Accuracy: {train_score:.2%}")
        print(f"  Test Accuracy:  {test_score:.2%}")
        print(f"  Gap: {(train_score - test_score):.2%}")
        
        # Large gap indicates overfitting
        if (train_score - test_score) > 0.15:
            print(f"  ⚠️  OVERFITTING DETECTED! Gap > 15%")
        
        fold += 1
    
    print()
    print(f"📊 Cross-Validation Results:")
    print(f"   Mean CV Score: {np.mean(cv_scores):.2%}")
    print(f"   Std Dev: {np.std(cv_scores):.2%}")
    print(f"   Min: {np.min(cv_scores):.2%}")
    print(f"   Max: {np.max(cv_scores):.2%}")
    print()
    
    # Interpretation
    if np.mean(cv_scores) > 0.95:
        print("🔴 CONCERN: CV score > 95% - Possible overfitting or data leakage!")
    elif np.mean(cv_scores) > 0.85:
        print("🟢 GOOD: CV score 85-95% - Model is performing well!")
    else:
        print("🟡 WARNING: CV score < 85% - Model may need improvement")
    
    return cv_scores

def test_learning_curves(training_data, labels):
    """Generate learning curves to visualize overfitting."""
    print("\n" + "="*80)
    print("TEST 2: LEARNING CURVES")
    print("="*80)
    print("Learning curves show training vs validation score as training size increases.")
    print("Overfitting shows as large gap between train and validation curves.")
    print()
    
    fp_reducer = FalsePositiveReducer()
    
    # Extract features
    X = []
    for sample in training_data:
        if 'finding' in sample:
            finding = sample['finding']
            context = sample.get('context', {})
        else:
            finding = sample
            context = {}
        
        features = fp_reducer.extract_features(finding, context)
        X.append(features.flatten())
    
    X = np.array(X)
    y = np.array(labels)
    
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    
    # Scale
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=12,
        random_state=42,
        class_weight='balanced'
    )
    
    train_sizes = np.linspace(0.1, 1.0, 10)
    train_sizes_abs, train_scores, val_scores = learning_curve(
        model, X_scaled, y,
        train_sizes=train_sizes,
        cv=5,
        scoring='accuracy',
        n_jobs=-1,
        random_state=42
    )
    
    train_mean = np.mean(train_scores, axis=1)
    train_std = np.std(train_scores, axis=1)
    val_mean = np.mean(val_scores, axis=1)
    val_std = np.std(val_scores, axis=1)
    
    print("Training size | Train Acc | Val Acc | Gap")
    print("-" * 50)
    for size, train_acc, val_acc in zip(train_sizes_abs, train_mean, val_mean):
        gap = train_acc - val_acc
        status = "⚠️ " if gap > 0.15 else "✓"
        print(f"{size:12.0f} | {train_acc:9.2%} | {val_acc:7.2%} | {gap:+6.2%} {status}")
    
    print()
    final_gap = train_mean[-1] - val_mean[-1]
    print(f"📊 Final Gap (with full dataset): {final_gap:+.2%}")
    
    if final_gap > 0.15:
        print("🔴 OVERFITTING: Gap > 15% - Model memorizing training data!")
    elif final_gap > 0.05:
        print("🟡 SLIGHT OVERFITTING: Gap 5-15% - Consider regularization")
    else:
        print("🟢 GOOD FIT: Gap < 5% - Model generalizes well!")
    
    return train_mean, val_mean

def test_feature_correlation(training_data, labels):
    """Test for feature correlation with labels - potential data leakage."""
    print("\n" + "="*80)
    print("TEST 3: FEATURE-LABEL CORRELATION")
    print("="*80)
    print("Check if any feature is too correlated with label (> 0.9 = data leakage)")
    print()
    
    fp_reducer = FalsePositiveReducer()
    
    # Extract features
    X = []
    for sample in training_data:
        if 'finding' in sample:
            finding = sample['finding']
            context = sample.get('context', {})
        else:
            finding = sample
            context = {}
        
        features = fp_reducer.extract_features(finding, context)
        X.append(features.flatten())
    
    X = np.array(X)
    y = np.array(labels)
    
    # Feature names (16 features total)
    # Note: Features 9-11 (keyword features) are domain knowledge-based,
    # derived from OWASP/SANS security patterns, not from training labels
    feature_names = [
        'severity', 'category', 'evidence_length', 'description_length',
        'url_complexity', 'has_params', 'cvss_score', 'risk_score',
        'fp_keyword_count', 'tp_keyword_count', 'keyword_ratio',
        'is_informational', 'status_code', 'response_time',
        'occurrence_count', 'days_since_first'
    ]
    
    # Validate feature count matches
    if X.shape[1] != len(feature_names):
        print(f"⚠️ Warning: Expected {len(feature_names)} features, got {X.shape[1]}")
        print(f"   Adjusting feature names...")
        # Truncate or pad feature names
        if X.shape[1] < len(feature_names):
            feature_names = feature_names[:X.shape[1]]
        else:
            feature_names.extend([f'feature_{i}' for i in range(len(feature_names), X.shape[1])])
    
    print("Feature Correlations with Label:")
    print("-" * 60)
    
    from scipy.stats import pearsonr
    
    high_correlation = []
    
    for i, name in enumerate(feature_names):
        corr, p_value = pearsonr(X[:, i], y)
        abs_corr = abs(corr)
        
        if abs_corr > 0.8:
            status = "🔴 CRITICAL"
            high_correlation.append((name, abs_corr))
        elif abs_corr > 0.6:
            status = "🟡 HIGH"
        else:
            status = "✓"
        
        print(f"{name:25s}: {corr:+7.4f}  {status}")
    
    print()
    
    if high_correlation:
        print("🔴 DATA LEAKAGE DETECTED!")
        print("Features with correlation > 0.8:")
        for name, corr in high_correlation:
            print(f"  • {name}: {corr:.4f}")
        print("\nThis means these features are almost perfectly predicting the label!")
        print("Possible causes:")
        print("  - Feature derived from label")
        print("  - Label encoded in feature")
        print("  - Data from future leaking into training")
    else:
        print("✅ No obvious data leakage detected")
        print("All feature correlations are reasonable")
    
    return high_correlation

def test_data_distribution(training_data, labels):
    """Analyze data distribution for homogeneity."""
    print("\n" + "="*80)
    print("TEST 4: DATA DISTRIBUTION ANALYSIS")
    print("="*80)
    print()
    
    from collections import Counter
    
    # Label distribution
    label_counts = Counter(labels)
    print(f"📊 Label Distribution:")
    print(f"   True Positives (0): {label_counts[0]} ({label_counts[0]/len(labels):.1%})")
    print(f"   False Positives (1): {label_counts[1]} ({label_counts[1]/len(labels):.1%})")
    
    # Check for severe imbalance
    ratio = max(label_counts.values()) / min(label_counts.values())
    print(f"   Imbalance Ratio: {ratio:.2f}:1")
    
    if ratio > 3:
        print("   🟡 WARNING: Imbalanced dataset (ratio > 3:1)")
        print("   This can cause model to be biased toward majority class")
    else:
        print("   ✓ Reasonable balance")
    
    print()
    
    # Category distribution
    categories = []
    severities = []
    
    for sample in training_data:
        finding = sample.get('finding', sample)
        categories.append(finding.get('category', 'Unknown'))
        severities.append(finding.get('severity', 'Unknown'))
    
    print(f"📊 Category Diversity:")
    category_counts = Counter(categories)
    print(f"   Unique categories: {len(category_counts)}")
    print(f"   Top 5 categories:")
    for cat, count in category_counts.most_common(5):
        print(f"     • {cat}: {count}")
    
    print()
    print(f"📊 Severity Distribution:")
    severity_counts = Counter(severities)
    for sev, count in sorted(severity_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"   • {sev}: {count}")
    
    # Check for too much homogeneity
    if len(category_counts) < 5:
        print("\n🟡 WARNING: Low category diversity (< 5 unique)")
        print("   Model may overfit to these specific categories")
    
    return category_counts, severity_counts

def main():
    """Run all overfitting tests."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test for overfitting in FP Reducer model')
    parser.add_argument('--data', type=str, help='Path to training data file')
    args = parser.parse_args()
    
    print("="*80)
    print("OVERFITTING DETECTION SUITE")
    print("="*80)
    print("Testing if 100% accuracy is due to overfitting or genuine performance")
    print()
    
    # Load data
    if args.data:
        data_file = Path(args.data)
    else:
        # Try to find latest file
        candidates = [
            Path('ml/training_data/merged_training_data_20260129_112500.json'),
            Path('ml/training_data/merged/hybrid_balanced_20260127_200506.json'),
            Path('ml/training_data/merged_training_data_20251219_033523.json')
        ]
        data_file = None
        for candidate in candidates:
            if candidate.exists():
                data_file = candidate
                break
        
        if not data_file:
            print("❌ No training data file found!")
            return
    
    if not data_file.exists():
        print(f"❌ Data file not found: {data_file}")
        return
    
    print(f"Loading data from: {data_file}")
    training_data, labels = load_training_data(data_file)
    print(f"Loaded {len(training_data)} samples")
    print()
    
    # Run tests
    cv_scores = test_cross_validation(training_data, labels)
    train_curve, val_curve = test_learning_curves(training_data, labels)
    leakage = test_feature_correlation(training_data, labels)
    categories, severities = test_data_distribution(training_data, labels)
    
    # Final verdict
    print("\n" + "="*80)
    print("FINAL VERDICT")
    print("="*80)
    print()
    
    issues = []
    
    # Check CV score
    if np.mean(cv_scores) > 0.95:
        issues.append("Cross-validation score > 95%")
    
    # Check learning curve gap
    final_gap = train_curve[-1] - val_curve[-1]
    if final_gap > 0.15:
        issues.append(f"Large train/val gap ({final_gap:.1%})")
    
    # Check data leakage
    if leakage:
        issues.append(f"High feature-label correlation detected")
    
    # Check diversity
    if len(categories) < 5:
        issues.append("Low category diversity")
    
    if issues:
        print("🔴 OVERFITTING LIKELY PRESENT")
        print("\nIssues detected:")
        for issue in issues:
            print(f"  • {issue}")
        print("\n📋 Recommendations:")
        print("  1. Collect more diverse training data")
        print("  2. Reduce model complexity (fewer trees, lower depth)")
        print("  3. Add more regularization")
        print("  4. Use proper train/val/test split")
        print("  5. Check for data leakage in features")
    else:
        print("🟢 NO OBVIOUS OVERFITTING DETECTED")
        print("\n100% accuracy might be legitimate because:")
        print("  • Cross-validation scores are consistent")
        print("  • No large train/validation gap")
        print("  • No data leakage detected")
        print("  • Reasonable data distribution")
        print("\nHowever, still recommended to:")
        print("  • Test on completely new scan data")
        print("  • Monitor performance in production")
        print("  • Continue collecting more diverse data")
    
    print()
    print("="*80)

if __name__ == '__main__':
    main()
