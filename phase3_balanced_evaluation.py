#!/usr/bin/env python3
"""
PHASE 3: Real Data Balancing & Comprehensive Evaluation
========================================================

Extract normal Moodle browsing sessions from Normal-Moodle-Browser.har
Combine with 38 attack samples from Phase 2
Re-evaluate model with balanced dataset
Compare with Phase 0, Phase 2, Phase 3
"""

import json
import pandas as pd
import numpy as np
from scipy import stats
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import cross_val_score, StratifiedKFold, cross_validate
from sklearn.metrics import (accuracy_score, balanced_accuracy_score, f1_score, 
                            matthews_corrcoef, roc_auc_score, confusion_matrix, 
                            make_scorer)
from sklearn.dummy import DummyClassifier
from sklearn.utils import resample
import warnings
warnings.filterwarnings('ignore')

print("="*80)
print("PHASE 3: REAL DATA BALANCING & COMPREHENSIVE EVALUATION")
print("="*80)
print()

# ============================================================================
# STEP 1: Load existing attack samples (Phase 2)
# ============================================================================
print("[STEP 1] Loading Phase 2 attack samples...")
with open('ml/training_data/real_features_dataset_20260420.csv', 'r') as f:
    phase2_df = pd.read_csv(f)

# Ensure all columns are numeric except label
for col in phase2_df.columns:
    if col != 'label':
        phase2_df[col] = pd.to_numeric(phase2_df[col], errors='coerce')

attack_samples = phase2_df[phase2_df['label'] == 1].copy()
print(f"  ✓ Loaded {len(attack_samples)} attack samples (TP)")
print(f"    Features: {list(phase2_df.columns[:-1])}")
print()

# ============================================================================
# STEP 2: Extract features from normal HAR file
# ============================================================================
print("[STEP 2] Extracting normal samples from Normal-Moodle-Browser.har...")

def extract_features_from_har(har_path, label=0):
    """Extract 14 features from HAR file entries"""
    try:
        with open(har_path, 'r', encoding='utf-8', errors='ignore') as f:
            har_data = json.load(f)
    except Exception as e:
        print(f"  ❌ Error loading HAR: {e}")
        return []
    
    entries = har_data['log']['entries']
    features_list = []
    attack_keywords = ['SELECT', 'INSERT', 'UNION', 'script', '<svg', 'alert(', 'DROP', 'DELETE']
    
    filtered_count = 0
    excluded_count = 0
    
    for entry in entries:
        # Get request and response
        request = entry['request']
        response = entry['response']
        
        # === FILTERING CRITERIA ===
        
        # 1. Check for attack signatures in POST data
        post_data = request.get('postData', {}).get('text', '')
        if any(kw.lower() in post_data.lower() for kw in attack_keywords):
            excluded_count += 1
            continue
        
        # 2. Filter response time > 2000ms (unlikely for normal browsing)
        time_ms = entry.get('time', 0) * 1000 if isinstance(entry.get('time'), float) else 0
        # Skip very high times (may be recording artifacts)
        if time_ms > 30000:  # 30 seconds - unrealistic
            excluded_count += 1
            continue
        
        # 3. Only accept Moodle requests
        url = request['url'].lower()
        method = request['method']
        if 'localhost:8998' not in url:
            excluded_count += 1
            continue
        
        # === FEATURE EXTRACTION ===
        
        # REQUEST features (5)
        method_get = 1 if method == 'GET' else 0
        has_post_data = 1 if 'postData' in request else 0
        payload_length = len(post_data) if has_post_data else 0
        
        # Session cookie check
        headers = {h['name'].lower(): h['value'] for h in request.get('headers', [])}
        has_session_cookie = 1 if any('session' in h.lower() or 'sid' in h.lower() 
                                     for h in headers.keys()) else 0
        request_time_ms = time_ms
        
        # RESPONSE features (5)
        response_status = response['status']
        response_text = response.get('content', {}).get('text', '')
        response_size = len(response_text)
        
        resp_headers = {h['name'].lower(): h['value'] for h in response.get('headers', [])}
        has_xframe_options = 1 if 'x-frame-options' in resp_headers else 0
        has_csp = 1 if 'content-security-policy' in resp_headers else 0
        has_content_type = 1 if 'content-type' in resp_headers else 0
        
        # DERIVED features (4)
        # Check for leaked errors
        error_keywords = ['error', 'exception', 'fatal', 'warning', 'deprecated', 'strict']
        error_leaked = 1 if any(kw in response_text.lower() for kw in error_keywords) else 0
        
        # Database error visible
        db_error_visible = 1 if any(db_err in response_text.lower() 
                                   for db_err in ['sql', 'mysql', 'postgres', 'database', 'query']) else 0
        
        # Payload reflected in response
        if payload_length > 0:
            # Extract simple patterns from payload
            payload_reflected = 1 if any(p in response_text for p in [
                'name', 'value', 'query', 'data'
            ]) else 0
        else:
            payload_reflected = 0
        
        # Response time anomaly (normal Moodle requests should be <2000ms)
        response_time_anomaly = 1 if request_time_ms > 2000 else 0
        
        # Create feature dict
        features = {
            'method': float(method_get),  # Ensure numeric
            'has_post_data': float(has_post_data),
            'payload_length': float(payload_length),
            'has_session_cookie': float(has_session_cookie),
            'request_time_ms': float(request_time_ms),
            'response_status': float(response_status),
            'response_size': float(response_size),
            'has_xframe_options': float(has_xframe_options),
            'has_csp': float(has_csp),
            'has_content_type': float(has_content_type),
            'error_leaked': float(error_leaked),
            'db_error_visible': float(db_error_visible),
            'payload_reflected': float(payload_reflected),
            'response_time_anomaly': float(response_time_anomaly),
            'label': float(label)
        }
        
        features_list.append(features)
        filtered_count += 1
    
    print(f"  ✓ Extracted {filtered_count} normal samples")
    print(f"  - Excluded: {excluded_count} (attack signatures, timeouts, non-Moodle)")
    
    return features_list

# Extract normal samples
normal_features = extract_features_from_har('ml/training_data/Normal-Moodle-Browser.har', label=0)
normal_df = pd.DataFrame(normal_features)
print()

# ============================================================================
# STEP 3: Combine datasets
# ============================================================================
print("[STEP 3] Combining datasets...")

# Make sure columns match
required_cols = ['method', 'has_post_data', 'payload_length', 'has_session_cookie',
                'request_time_ms', 'response_status', 'response_size', 'has_xframe_options',
                'has_csp', 'has_content_type', 'error_leaked', 'db_error_visible',
                'payload_reflected', 'response_time_anomaly', 'label']

attack_df = attack_samples[required_cols].reset_index(drop=True)
normal_df_filtered = normal_df[required_cols].reset_index(drop=True)

# Combine
combined_df = pd.concat([attack_df, normal_df_filtered], ignore_index=True)
print(f"  ✓ Attack samples: {len(attack_df)}")
print(f"  ✓ Normal samples: {len(normal_df_filtered)}")
print(f"  ✓ Combined total: {len(combined_df)}")
print()

# ============================================================================
# STEP 4: Class distribution & Balancing
# ============================================================================
print("[STEP 4] Class distribution analysis & balancing:")

class_dist = combined_df['label'].value_counts().sort_index()
print(f"  Before balancing:")
print(f"    Class 1 (Attack): {class_dist[1]} ({class_dist[1]*100//len(combined_df)}%)")
print(f"    Class 0 (Normal): {class_dist[0]} ({class_dist[0]*100//len(combined_df)}%)")
print()

# Balance the dataset: match normal samples to attack count for 50:50
attack_count_init = (combined_df['label'] == 1).sum()
normal_df_balance = combined_df[combined_df['label'] == 0]

# Downsample normal to match attack count (random stratified sampling)
normal_sampled = resample(normal_df_balance, n_samples=attack_count_init, random_state=42)
combined_df = pd.concat([
    combined_df[combined_df['label'] == 1],
    normal_sampled
], ignore_index=True)

combined_df = combined_df.sample(frac=1, random_state=42).reset_index(drop=True)

class_dist = combined_df['label'].value_counts().sort_index()
print(f"  After balancing (50:50):")
print(f"    Class 1 (Attack): {class_dist[1]} ({class_dist[1]*100//len(combined_df):.1f}%)")
print(f"    Class 0 (Normal): {class_dist[0]} ({class_dist[0]*100//len(combined_df):.1f}%)")

# Balance ratio
attack_count = class_dist[1]
normal_count = class_dist[0]
ratio = f"{attack_count}:{normal_count}"
balance = f"{attack_count*100/(attack_count+normal_count):.1f}% attack"
print(f"  Ratio: {ratio} ({balance})")
print()

# Define feature columns (excluding label)
feature_cols = [c for c in required_cols if c != 'label']

# ============================================================================
# STEP 5: Feature comparison
# ============================================================================
print("[STEP 5] Feature statistics comparison:")
print()

print("Mann-Whitney U Tests (Attack vs Normal):")
print("-" * 70)
print(f"{'Feature':<25} {'Attack Mean':<15} {'Normal Mean':<15} {'p-value':<12} {'Sig'}")
print("-" * 70)

significant_features = 0
for feature in feature_cols:
    # Skip string features
    if feature == 'method':
        continue
    
    attack_vals = pd.to_numeric(combined_df[combined_df['label'] == 1][feature], errors='coerce').dropna()
    normal_vals = pd.to_numeric(combined_df[combined_df['label'] == 0][feature], errors='coerce').dropna()
    
    if len(attack_vals) > 0 and len(normal_vals) > 0:
        stat, p_value = stats.mannwhitneyu(attack_vals, normal_vals, alternative='two-sided')
        is_sig = "***" if p_value < 0.05 else "ns"
        
        print(f"{feature:<25} {attack_vals.mean():<15.4f} {normal_vals.mean():<15.4f} "
              f"{p_value:<12.6f} {is_sig}")
        
        if p_value < 0.05:
            significant_features += 1

print("-" * 70)
print(f"Significant features (p < 0.05): {significant_features}/{len(feature_cols)}")
print()

# ============================================================================
# STEP 6: ML Model Training & Evaluation
# ============================================================================
print("[STEP 6] ML Model evaluation on Phase 3 balanced data:")
print()

X = combined_df[feature_cols]
y = combined_df['label']

# Convert all features to numeric
for col in feature_cols:
    X[col] = pd.to_numeric(X[col], errors='coerce')

# Drop rows with NaN values
X = X.fillna(0)
y = y[X.index]

# Cross-validation setup
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

# Scoring metrics
scoring = {
    'accuracy': make_scorer(accuracy_score),
    'balanced_accuracy': make_scorer(balanced_accuracy_score),
    'f1': make_scorer(f1_score),
    'roc_auc': make_scorer(roc_auc_score),
}

# Models
models = {
    'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
    'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
}

# Baseline models
baseline_models = {
    'Always Predict 1 (Attack)': DummyClassifier(strategy='constant', constant=1),
    'Always Predict 0 (Normal)': DummyClassifier(strategy='constant', constant=0),
    'Stratified': DummyClassifier(strategy='stratified'),
}

results = {}

print("Model Performance (5-Fold Cross-Validation):")
print("-" * 90)

for name, model in {**models, **baseline_models}.items():
    cv_results = cross_validate(model, X, y, cv=cv, scoring=scoring)
    
    results[name] = {
        'accuracy': (cv_results['test_accuracy'].mean(), cv_results['test_accuracy'].std()),
        'balanced_accuracy': (cv_results['test_balanced_accuracy'].mean(), 
                            cv_results['test_balanced_accuracy'].std()),
        'f1': (cv_results['test_f1'].mean(), cv_results['test_f1'].std()),
        'roc_auc': (cv_results['test_roc_auc'].mean(), cv_results['test_roc_auc'].std()),
    }
    
    print(f"\n{name}:")
    print(f"  Accuracy:          {results[name]['accuracy'][0]:.1%} ± {results[name]['accuracy'][1]:.1%}")
    print(f"  Balanced Accuracy: {results[name]['balanced_accuracy'][0]:.1%} ± {results[name]['balanced_accuracy'][1]:.1%}")
    print(f"  F1-Score:          {results[name]['f1'][0]:.1%} ± {results[name]['f1'][1]:.1%}")
    print(f"  ROC-AUC:           {results[name]['roc_auc'][0]:.1%} ± {results[name]['roc_auc'][1]:.1%}")

print()

# ============================================================================
# STEP 7: Power Analysis & Effect Size
# ============================================================================
print("[STEP 7] Power analysis:")
print()

# Calculate effect size (Cohen's d)
def cohens_d(group1, group2):
    group1 = group1.astype(float)
    group2 = group2.astype(float)
    n1, n2 = len(group1), len(group2)
    var1, var2 = group1.var(), group2.var()
    pooled_std = np.sqrt(((n1-1)*var1 + (n2-1)*var2) / (n1+n2-2))
    return (group1.mean() - group2.mean()) / pooled_std if pooled_std > 0 else 0

print("Effect sizes (Cohen's d):")
for feature in feature_cols:
    d = cohens_d(attack_df[feature], normal_df_filtered[feature])
    print(f"  {feature:<25} d = {d:7.4f} {'(Large)' if abs(d) > 0.8 else '(Medium)' if abs(d) > 0.5 else '(Small)'}")

print()

# ============================================================================
# STEP 8: Phase Comparison Table
# ============================================================================
print("[STEP 8] Phase comparison:")
print()
print("=" * 100)
print(f"{'Metric':<25} {'Phase 0':<25} {'Phase 2':<25} {'Phase 3':<25}")
print("=" * 100)

# Read Phase 0 and Phase 2 results (if available)
phase0_accuracy = 99.3
phase0_balanced_acc = np.nan
phase2_accuracy = 72.0
phase2_balanced_acc = 47.3
phase3_accuracy = results['Random Forest']['accuracy'][0] * 100
phase3_balanced_acc = results['Random Forest']['balanced_accuracy'][0] * 100

print(f"{'Accuracy':<25} {phase0_accuracy:>6.1f}%{'':<18} {phase2_accuracy:>6.1f}%{'':<18} {phase3_accuracy:>6.1f}%")
print(f"{'Balanced Accuracy':<25} {'N/A':<25} {phase2_balanced_acc:>6.1f}%{'':<18} {phase3_balanced_acc:>6.1f}%")
print(f"{'Data Distribution':<25} {'Synthetic (186)':<25} {'Real (46, 82:18)':<25} {'Mixed ({}, {}:{})'.format(len(combined_df), len(attack_df), len(normal_df_filtered)):<25}")
print(f"{'Class Balance':<25} {'Perfect (50:50)':<25} {'Imbalanced (82:18)':<25} {'Balanced ({:.0f}:{:.0f})'.format(attack_count*100/(attack_count+normal_count), normal_count*100/(attack_count+normal_count)):<25}")
print(f"{'Significant Features':<25} {'N/A':<25} {'0/14':<25} {f'{significant_features}/14':<25}")
print("=" * 100)

# ============================================================================
# STEP 9: Save combined dataset
# ============================================================================
print()
print("[STEP 9] Saving combined dataset:")

output_file = f'ml/training_data/phase3_balanced_dataset_{pd.Timestamp.now().strftime("%Y%m%d")}.csv'
combined_df.to_csv(output_file, index=False)
print(f"  ✓ Saved to: {output_file}")
print(f"    - Shape: {combined_df.shape}")
print(f"    - Columns: {list(combined_df.columns)}")
print()

# ============================================================================
# SUMMARY
# ============================================================================
print("="*80)
print("PHASE 3 SUMMARY")
print("="*80)
print()
print(f"✅ Normal samples extracted: {len(normal_df_filtered)}")
print(f"✅ Attack samples reused: {len(attack_df)}")
print(f"✅ Combined dataset: {len(combined_df)} samples")
print(f"✅ Class balance improved: {ratio} ({balance})")
print(f"✅ Significant features: {significant_features}/{len(feature_cols)}")
print(f"✅ Model accuracy: {phase3_accuracy:.1f}% ± {results['Random Forest']['accuracy'][1]*100:.1f}%")
print(f"✅ Balanced accuracy: {phase3_balanced_acc:.1f}% ± {results['Random Forest']['balanced_accuracy'][1]*100:.1f}%")
print()
print("Ready for thesis defense! 🚀")
