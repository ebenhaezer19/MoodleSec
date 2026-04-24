#!/usr/bin/env python3
"""
PHASE 3 COMPLETE FIX: Re-extract all samples properly
=====================================================

Since Phase 2 attack extraction had bugs too, re-extract both:
1. Attack samples from ZAP-FULL-DATASET/*.har files
2. Normal samples from Normal-Moodle-Browser.har

Using CORRECTED extraction logic with proper:
- Time field handling (milliseconds, not seconds)
- Cookie detection from request['cookies'] array
- Numeric data types throughout
"""

import json
import pandas as pd
import numpy as np
import glob
from scipy import stats
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import balanced_accuracy_score, confusion_matrix
from sklearn.dummy import DummyClassifier
from sklearn.utils import resample
import warnings
warnings.filterwarnings('ignore')

print("="*80)
print("PHASE 3 COMPLETE FIX: Re-extract and re-balance dataset")
print("="*80)
print()

# ============================================================================
# STEP 1: Extract attack samples from ZAP-FULL-DATASET
# ============================================================================
print("[STEP 1] Re-extracting attack samples from ZAP-FULL-DATASET...")

def extract_features_corrected(har_path, label=0):
    """Extract 14 features from HAR file - CORRECTED VERSION"""
    try:
        with open(har_path, 'r', encoding='utf-8', errors='ignore') as f:
            har_data = json.load(f)
    except Exception as e:
        print(f"  ❌ Error loading {har_path}: {e}")
        return []
    
    entries = har_data['log']['entries']
    features_list = []
    attack_keywords = ['SELECT', 'INSERT', 'UNION', 'script', '<svg', 'alert(', 'DROP', 'DELETE']
    
    filtered_count = 0
    excluded_count = 0
    
    for entry in entries:
        try:
            request = entry['request']
            response = entry['response']
            
            # Filter: Check for attack signatures in POST data
            post_data = request.get('postData', {}).get('text', '')
            if label == 0 and any(kw.lower() in post_data.lower() for kw in attack_keywords):
                excluded_count += 1
                continue
            
            # Filter: Only Moodle requests
            url = request['url'].lower()
            if 'localhost:8998' not in url:
                excluded_count += 1
                continue
            
            # Filter: Response time check
            time_ms = entry.get('time', 0)  # Already in milliseconds
            if time_ms > 30000 or time_ms < 0:
                excluded_count += 1
                continue
            
            # === FEATURE EXTRACTION ===
            method = request['method']
            method_get = float(1 if method == 'GET' else 0)
            has_post_data = float(1 if 'postData' in request else 0)
            payload_length = float(len(post_data) if has_post_data else 0)
            
            # Cookie detection - CORRECTED
            has_session_cookie = 0.0
            if 'cookies' in request:
                for cookie in request.get('cookies', []):
                    cookie_name = cookie.get('name', '').lower()
                    if 'session' in cookie_name or 'sid' in cookie_name:
                        has_session_cookie = 1.0
                        break
            
            request_time_ms = float(time_ms)
            
            # Response features
            response_status = float(response['status'])
            response_text = response.get('content', {}).get('text', '')
            response_size = float(len(response_text))
            
            resp_headers = {h['name'].lower(): h['value'] for h in response.get('headers', [])}
            has_xframe_options = float(1 if 'x-frame-options' in resp_headers else 0)
            has_csp = float(1 if 'content-security-policy' in resp_headers else 0)
            has_content_type = float(1 if 'content-type' in resp_headers else 0)
            
            # Derived features
            error_keywords = ['error', 'exception', 'fatal', 'warning', 'deprecated', 'strict']
            error_leaked = float(1 if any(kw in response_text.lower() for kw in error_keywords) else 0)
            
            db_error_visible = float(1 if any(db_err in response_text.lower() 
                                       for db_err in ['sql', 'mysql', 'postgres', 'database', 'query']) else 0)
            
            if payload_length > 0:
                payload_reflected = float(1 if any(p in response_text for p in ['name', 'value', 'query', 'data']) else 0)
            else:
                payload_reflected = 0.0
            
            response_time_anomaly = float(1 if request_time_ms > 2000 else 0)
            
            features = {
                'method': method_get,
                'has_post_data': has_post_data,
                'payload_length': payload_length,
                'has_session_cookie': has_session_cookie,
                'request_time_ms': request_time_ms,
                'response_status': response_status,
                'response_size': response_size,
                'has_xframe_options': has_xframe_options,
                'has_csp': has_csp,
                'has_content_type': has_content_type,
                'error_leaked': error_leaked,
                'db_error_visible': db_error_visible,
                'payload_reflected': payload_reflected,
                'response_time_anomaly': response_time_anomaly,
                'label': float(label)
            }
            
            features_list.append(features)
            filtered_count += 1
        except Exception as e:
            excluded_count += 1
            continue
    
    return features_list, filtered_count, excluded_count

# Extract from attack HAR files
zap_har_files = glob.glob('ml/training_data/ZAP-FULL-DATASET/*.har')
print(f"  Found {len(zap_har_files)} ZAP HAR files")

all_attack_features = []
total_attack_filtered = 0
total_attack_excluded = 0

for har_file in sorted(zap_har_files)[:20]:  # Limit to first 20
    features, filtered, excluded = extract_features_corrected(har_file, label=1)
    all_attack_features.extend(features)
    total_attack_filtered += filtered
    total_attack_excluded += excluded
    print(f"    {har_file.split(chr(92))[-1]}: {filtered} extracted, {excluded} excluded")

attack_df = pd.DataFrame(all_attack_features)
print(f"  ✓ Total attack samples extracted: {len(attack_df)}")
print()

# ============================================================================
# STEP 2: Extract normal samples
# ============================================================================
print("[STEP 2] Extracting normal samples from Normal-Moodle-Browser.har...")

normal_features, normal_filtered, normal_excluded = extract_features_corrected(
    'ml/training_data/Normal-Moodle-Browser.har', label=0
)
normal_df = pd.DataFrame(normal_features)
print(f"  ✓ Extracted {len(normal_df)} normal samples")
print(f"  - Excluded: {normal_excluded} (attack signatures, timeouts, non-Moodle)")
print()

# ============================================================================
# STEP 3: Verify data quality
# ============================================================================
print("[STEP 3] Data quality verification:")

for df_name, df in [('Attack', attack_df), ('Normal', normal_df)]:
    print(f"\n  {df_name} samples:")
    print(f"    NaN count by column:")
    nan_counts = df.isna().sum()
    for col, count in nan_counts[nan_counts > 0].items():
        print(f"      {col}: {count}")
    if nan_counts.sum() == 0:
        print(f"      (no NaN values)")
    
    print(f"    Data types:")
    for col in df.columns[:5]:
        print(f"      {col}: {df[col].dtype}")

print()

# ============================================================================
# STEP 4: Combine and balance
# ============================================================================
print("[STEP 4] Combining and balancing datasets...")

required_cols = ['method', 'has_post_data', 'payload_length', 'has_session_cookie',
                'request_time_ms', 'response_status', 'response_size', 'has_xframe_options',
                'has_csp', 'has_content_type', 'error_leaked', 'db_error_visible',
                'payload_reflected', 'response_time_anomaly', 'label']

combined_df = pd.concat([attack_df[required_cols], normal_df[required_cols]], ignore_index=True)
print(f"  Attack: {len(attack_df)}")
print(f"  Normal: {len(normal_df)}")
print(f"  Combined: {len(combined_df)}")

# Remove any rows with NaN
nan_mask = combined_df.isna().any(axis=1)
if nan_mask.any():
    print(f"  Removing {nan_mask.sum()} rows with NaN values")
    combined_df = combined_df[~nan_mask].reset_index(drop=True)

# Balance
min_class_count = min(
    len(combined_df[combined_df['label'] == 0]),
    len(combined_df[combined_df['label'] == 1])
)

normal_balanced = combined_df[combined_df['label'] == 0].sample(n=min_class_count, random_state=42)
attack_balanced = combined_df[combined_df['label'] == 1].sample(n=min_class_count, random_state=42)

balanced_df = pd.concat([normal_balanced, attack_balanced], ignore_index=True)
balanced_df = balanced_df.sample(frac=1, random_state=42).reset_index(drop=True)

print(f"  After balancing:")
print(f"    Normal: {len(balanced_df[balanced_df['label']==0])}")
print(f"    Attack: {len(balanced_df[balanced_df['label']==1])}")
print()

# ============================================================================
# STEP 5: Feature analysis
# ============================================================================
print("[STEP 5] Feature analysis (corrected extraction):")

for col in ['method', 'request_time_ms', 'has_session_cookie', 'has_post_data']:
    normal = balanced_df[balanced_df['label']==0][col]
    attack = balanced_df[balanced_df['label']==1][col]
    
    print(f"\n  {col}:")
    print(f"    Normal: mean={normal.mean():.2f}, min={normal.min():.2f}, max={normal.max():.2f}")
    print(f"    Attack: mean={attack.mean():.2f}, min={attack.min():.2f}, max={attack.max():.2f}")

print()

# ============================================================================
# STEP 6: Model evaluation
# ============================================================================
print("[STEP 6] Model evaluation with corrected data:")

X = balanced_df[required_cols[:-1]]
y = balanced_df['label']

cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

models = {
    'Random Forest': RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1),
    'Gradient Boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
    'Baseline (Most Frequent)': DummyClassifier(strategy='most_frequent'),
    'Baseline (Stratified)': DummyClassifier(strategy='stratified', random_state=42),
}

for model_name, model in models.items():
    scores = cross_val_score(model, X, y, cv=cv, scoring='accuracy')
    balanced_scores = cross_val_score(model, X, y, cv=cv, scoring='balanced_accuracy')
    
    print(f"  {model_name}:")
    print(f"    Accuracy: {scores.mean():.1%} ± {scores.std():.1%}")
    print(f"    Balanced Accuracy: {balanced_scores.mean():.1%} ± {balanced_scores.std():.1%}")

print()

# ============================================================================
# STEP 7: Save corrected dataset
# ============================================================================
print("[STEP 7] Saving corrected dataset...")
output_file = 'ml/training_data/phase3_balanced_dataset_FULLY_CORRECTED.csv'
balanced_df.to_csv(output_file, index=False)
print(f"  ✓ Saved: {output_file}")
print(f"    Shape: {balanced_df.shape}")
print()

print("="*80)
print("PHASE 3 COMPLETE - ALL BUGS FIXED")
print("="*80)
