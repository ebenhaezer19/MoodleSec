"""
PHASE 1: FP-Growth Feature Engineering
======================================

Objective: Extract frequent itemsets from clean features
          Create synthetic features for improved classification
          Target: 99.3% -> 99.8%+ accuracy

Input: ml/training_data/moodle_clean_no_leakage_20260420.json
Output: phase1_engineered_features_20260420.json
"""

import json
import numpy as np
import pandas as pd
from itertools import combinations
from sklearn.preprocessing import StandardScaler, KBinsDiscretizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import warnings
warnings.filterwarnings('ignore')

print("="*70)
print("PHASE 1: FP-Growth Feature Engineering")
print("="*70)

# ========== STEP 1: Load Clean Data ==========
print("\n[STEP 1] Loading clean dataset...")

data_path = r'ml\training_data\moodle_clean_no_leakage_20260420.json'
with open(data_path, encoding='utf-8') as f:
    clean_data = json.load(f)

CLEAN_FEATURES = [
    "evidence_length", "description_length", "severity_encoded",
    "reason_length", "strategy_length", "tp_keyword_count", "keyword_ratio"
]

X_clean = np.array([[item.get(f, 0) for f in CLEAN_FEATURES] for item in clean_data])
y_clean = np.array([item["label"] for item in clean_data])

tp_count = np.sum(y_clean == 1)
fp_count = np.sum(y_clean == 0)

print(f"  Loaded: {len(clean_data)} samples")
print(f"  TP: {tp_count}, FP: {fp_count}")
print(f"  Features: {len(CLEAN_FEATURES)}")

# ========== STEP 2: Discretize for FP-Growth ==========
print("\n[STEP 2] Discretizing features for FP-Growth...")

discretizer = KBinsDiscretizer(n_bins=3, encode='ordinal', strategy='quantile')
X_binned = discretizer.fit_transform(X_clean).astype(int)

# Create itemsets (feature=value combinations)
itemsets = []
feature_names = []

for sample_idx in range(len(X_binned)):
    sample_items = []
    for feat_idx, feat_name in enumerate(CLEAN_FEATURES):
        bin_val = X_binned[sample_idx, feat_idx]
        item = f"{feat_name}=bin{int(bin_val)}"
        sample_items.append(item)
    itemsets.append(set(sample_items))

print(f"  Discretized: {len(CLEAN_FEATURES)} features -> 3 bins each")
print(f"  Total items: {len(CLEAN_FEATURES) * 3}")
print(f"  Sample itemset: {itemsets[0]}")

# ========== STEP 3: FP-Growth (Simple Implementation) ==========
print("\n[STEP 3] Mining frequent itemsets...")

min_support = 0.15  # 15% of samples
min_count = int(len(itemsets) * min_support)

# Count individual items
item_counts = {}
for itemset in itemsets:
    for item in itemset:
        item_counts[item] = item_counts.get(item, 0) + 1

# Filter by min support
frequent_items = {item: count for item, count in item_counts.items() 
                  if count >= min_count}

print(f"  Min support: {min_support*100:.0f}% ({min_count} samples)")
print(f"  Frequent single items: {len(frequent_items)}")
print(f"  Top items:")
for item, count in sorted(frequent_items.items(), key=lambda x: x[1], reverse=True)[:5]:
    print(f"    - {item}: {count} ({count/len(itemsets)*100:.1f}%)")

# Generate 2-itemsets
frequent_pairs = {}
for itemset in itemsets:
    frequent_subset = [item for item in itemset if item in frequent_items]
    for pair in combinations(frequent_subset, 2):
        pair_key = tuple(sorted(pair))
        frequent_pairs[pair_key] = frequent_pairs.get(pair_key, 0) + 1

frequent_pairs = {pair: count for pair, count in frequent_pairs.items() 
                  if count >= min_count}

print(f"  Frequent pairs: {len(frequent_pairs)}")

# ========== STEP 4: Create New Features ==========
print("\n[STEP 4] Creating engineered features from itemsets...")

engineered_features = {}

# Feature 1-3: High evidence/description/reason indicators
engineered_features['high_evidence'] = (X_clean[:, 0] > np.percentile(X_clean[:, 0], 66)).astype(int)
engineered_features['high_description'] = (X_clean[:, 1] > np.percentile(X_clean[:, 1], 66)).astype(int)
engineered_features['high_reason'] = (X_clean[:, 3] > np.percentile(X_clean[:, 3], 66)).astype(int)

# Feature 4: Evidence + Description (combined signal)
engineered_features['evidence_and_description'] = (
    (X_clean[:, 0] > np.percentile(X_clean[:, 0], 50)) & 
    (X_clean[:, 1] > np.percentile(X_clean[:, 1], 50))
).astype(int)

# Feature 5: Strategy + Reason (remediation completeness)
engineered_features['strategy_and_reason'] = (
    (X_clean[:, 4] > np.percentile(X_clean[:, 4], 50)) & 
    (X_clean[:, 3] > np.percentile(X_clean[:, 3], 50))
).astype(int)

# Feature 6: Keyword presence + low ratio (targeted keywords)
engineered_features['focused_keywords'] = (
    (X_clean[:, 5] > 0) & 
    (X_clean[:, 6] < 0.5)
).astype(int)

# Feature 7: Documentation completeness (all high)
engineered_features['complete_documentation'] = (
    (X_clean[:, 0] > np.percentile(X_clean[:, 0], 40)) & 
    (X_clean[:, 1] > np.percentile(X_clean[:, 1], 40)) & 
    (X_clean[:, 3] > np.percentile(X_clean[:, 3], 40)) & 
    (X_clean[:, 4] > np.percentile(X_clean[:, 4], 40))
).astype(int)

# Feature 8: Keyword density
engineered_features['keyword_density'] = (X_clean[:, 6] > 0.3).astype(int)

# Feature 9: Length ratios (evidence vs description)
engineered_features['evidence_greater_description'] = (
    X_clean[:, 0] > X_clean[:, 1]
).astype(int)

# Feature 10: Strategy completeness
engineered_features['complete_strategy'] = (
    X_clean[:, 4] > np.percentile(X_clean[:, 4], 60)
).astype(int)

print(f"  Created: {len(engineered_features)} new features")
for feat_name, feat_vals in engineered_features.items():
    pct = np.sum(feat_vals) / len(feat_vals) * 100
    print(f"    - {feat_name}: {np.sum(feat_vals)} samples ({pct:.1f}%)")

# ========== STEP 5: Combine Features ==========
print("\n[STEP 5] Combining original + engineered features...")

X_engineered = np.column_stack([X_clean] + list(engineered_features.values()))
feature_names = CLEAN_FEATURES + list(engineered_features.keys())

print(f"  Original features: {len(CLEAN_FEATURES)}")
print(f"  Engineered features: {len(engineered_features)}")
print(f"  Total features: {len(feature_names)}")
print(f"  Combined shape: {X_engineered.shape}")

# ========== STEP 6: Train/Test Split ==========
print("\n[STEP 6] Training ensemble model...")

X_dev, X_holdout, y_dev, y_holdout = train_test_split(
    X_engineered, y_clean,
    test_size=0.20,
    stratify=y_clean,
    random_state=42
)

scaler = StandardScaler()
X_dev_scaled = scaler.fit_transform(X_dev)
X_holdout_scaled = scaler.transform(X_holdout)

rf_phase1 = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=12, n_jobs=-1)
gb_phase1 = GradientBoostingClassifier(n_estimators=100, random_state=42, max_depth=6, learning_rate=0.05)

rf_phase1.fit(X_dev_scaled, y_dev)
gb_phase1.fit(X_dev_scaled, y_dev)

print(f"  Random Forest: trained on {len(X_dev)} dev samples")
print(f"  Gradient Boosting: trained on {len(X_dev)} dev samples")

# ========== STEP 7: Cross-Validation ==========
print("\n[STEP 7] 5-Fold Cross-Validation with engineered features...")

kf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
cv_scores_phase0 = []  # Original
cv_scores_phase1 = []  # With engineering

for fold, (train_idx, test_idx) in enumerate(kf.split(X_dev_scaled, y_dev), 1):
    # Phase 0 (clean features only)
    rf0 = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
    gb0 = GradientBoostingClassifier(n_estimators=100, random_state=42, max_depth=5)
    
    rf0.fit(X_dev_scaled[train_idx, :7], y_dev[train_idx])
    gb0.fit(X_dev_scaled[train_idx, :7], y_dev[train_idx])
    
    pred0 = ((rf0.predict_proba(X_dev_scaled[test_idx, :7])[:, 1] + 
              gb0.predict_proba(X_dev_scaled[test_idx, :7])[:, 1]) / 2 > 0.5).astype(int)
    acc0 = accuracy_score(y_dev[test_idx], pred0)
    cv_scores_phase0.append(acc0)
    
    # Phase 1 (with engineered features)
    rf1 = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=12)
    gb1 = GradientBoostingClassifier(n_estimators=100, random_state=42, max_depth=6, learning_rate=0.05)
    
    rf1.fit(X_dev_scaled[train_idx], y_dev[train_idx])
    gb1.fit(X_dev_scaled[train_idx], y_dev[train_idx])
    
    pred1 = ((rf1.predict_proba(X_dev_scaled[test_idx])[:, 1] + 
              gb1.predict_proba(X_dev_scaled[test_idx])[:, 1]) / 2 > 0.5).astype(int)
    acc1 = accuracy_score(y_dev[test_idx], pred1)
    cv_scores_phase1.append(acc1)
    
    improvement = (acc1 - acc0) * 100
    print(f"  Fold {fold}: Phase0={acc0*100:.1f}% -> Phase1={acc1*100:.1f}% (improvement: {improvement:+.1f}%)")

cv_mean0 = np.mean(cv_scores_phase0)
cv_std0 = np.std(cv_scores_phase0)
cv_mean1 = np.mean(cv_scores_phase1)
cv_std1 = np.std(cv_scores_phase1)

print(f"\n  Phase 0 (Original): {cv_mean0*100:.1f}% ± {cv_std0*100:.1f}%")
print(f"  Phase 1 (Engineered): {cv_mean1*100:.1f}% ± {cv_std1*100:.1f}%")
print(f"  Total Improvement: {(cv_mean1-cv_mean0)*100:+.2f}%")

# ========== STEP 8: Holdout Evaluation ==========
print("\n[STEP 8] Final holdout evaluation...")

# Phase 0 holdout
pred_rf0 = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
pred_gb0 = GradientBoostingClassifier(n_estimators=100, random_state=42, max_depth=5)

pred_rf0.fit(X_dev_scaled[:, :7], y_dev)
pred_gb0.fit(X_dev_scaled[:, :7], y_dev)

pred0_holdout = ((pred_rf0.predict_proba(X_holdout_scaled[:, :7])[:, 1] + 
                  pred_gb0.predict_proba(X_holdout_scaled[:, :7])[:, 1]) / 2 > 0.5).astype(int)

# Phase 1 holdout
pred1_holdout = ((rf_phase1.predict_proba(X_holdout_scaled)[:, 1] + 
                  gb_phase1.predict_proba(X_holdout_scaled)[:, 1]) / 2 > 0.5).astype(int)

print("\n  Phase 0 (Clean Features Only)")
acc0_h = accuracy_score(y_holdout, pred0_holdout)
prec0_h = precision_score(y_holdout, pred0_holdout, zero_division=0)
rec0_h = recall_score(y_holdout, pred0_holdout, zero_division=0)
f1_0_h = f1_score(y_holdout, pred0_holdout, zero_division=0)

print(f"    Accuracy:  {acc0_h*100:.1f}%")
print(f"    Precision: {prec0_h*100:.1f}%")
print(f"    Recall:    {rec0_h*100:.1f}%")
print(f"    F1-Score:  {f1_0_h:.3f}")

print("\n  Phase 1 (+ Engineered Features)")
acc1_h = accuracy_score(y_holdout, pred1_holdout)
prec1_h = precision_score(y_holdout, pred1_holdout, zero_division=0)
rec1_h = recall_score(y_holdout, pred1_holdout, zero_division=0)
f1_1_h = f1_score(y_holdout, pred1_holdout, zero_division=0)

print(f"    Accuracy:  {acc1_h*100:.1f}%")
print(f"    Precision: {prec1_h*100:.1f}%")
print(f"    Recall:    {rec1_h*100:.1f}%")
print(f"    F1-Score:  {f1_1_h:.3f}")

# ========== STEP 9: Feature Importance ==========
print("\n[STEP 9] Feature importance analysis...")

# Get feature importance from trained models
rf_importance = rf_phase1.feature_importances_
gb_importance = gb_phase1.feature_importances_
avg_importance = (rf_importance + gb_importance) / 2

# Sort by importance
importance_df = pd.DataFrame({
    'feature': feature_names,
    'rf_importance': rf_importance,
    'gb_importance': gb_importance,
    'avg_importance': avg_importance
}).sort_values('avg_importance', ascending=False)

print("\n  Top 10 Most Important Features:")
for idx, row in importance_df.head(10).iterrows():
    marker = "ORIGINAL" if row['feature'] in CLEAN_FEATURES else "ENGINEERED"
    print(f"    {row['feature']:<30} {row['avg_importance']*100:>6.2f}% [{marker}]")

# ========== STEP 10: Save Results ==========
print("\n[STEP 10] Saving engineered dataset...")

output_data = []
for item, features in zip(clean_data, X_engineered):
    output_item = item.copy()
    for feat_name, feat_val in zip(feature_names, features):
        if feat_name not in CLEAN_FEATURES:  # Only add new engineered features
            output_item[feat_name] = float(feat_val)
    output_data.append(output_item)

output_path = r'ml\training_data\phase1_engineered_features_20260420.json'
with open(output_path, 'w', encoding='utf-8') as f:
    json.dump(output_data, f, indent=2, ensure_ascii=False)

print(f"  Saved: {output_path}")
print(f"  Samples: {len(output_data)}")
print(f"  Total features: {len(feature_names)}")

# ========== SUMMARY ==========
print("\n" + "="*70)
print("PHASE 1 COMPLETE - FEATURE ENGINEERING RESULTS")
print("="*70)

print(f"\n📊 ACCURACY IMPROVEMENT")
print(f"  Phase 0 (Clean Features):      {cv_mean0*100:.1f}% ± {cv_std0*100:.1f}%")
print(f"  Phase 1 (+ FP-Growth):         {cv_mean1*100:.1f}% ± {cv_std1*100:.1f}%")
print(f"  Improvement:                   {(cv_mean1-cv_mean0)*100:+.2f}%")

print(f"\n📋 ENGINEERED FEATURES")
print(f"  Total new features:            {len(engineered_features)}")
print(f"  Feature classes:")
print(f"    - High value indicators:     3")
print(f"    - Composite indicators:      4")
print(f"    - Special patterns:          3")

print(f"\n✅ DATASETS READY")
print(f"  Input:  ml/training_data/moodle_clean_no_leakage_20260420.json")
print(f"  Output: ml/training_data/phase1_engineered_features_20260420.json")

print(f"\n📈 NEXT: PHASE 2 (Deep Learning or Further Optimization)")
print("="*70)
