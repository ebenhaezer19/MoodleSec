# FP Reducer Model Training Report - April 15, 2026

**Status**: v1.0 TRAINED - Ready for Testing  
**Timestamp**: 2026-04-15 11:10:42

---

## Summary

Trained False Positive Reducer model with 1570 samples from ZAP scan report. Model achieves 100% test accuracy on real training data but only passes 2/5 semantic validation tests, indicating potential overfitting and category-based pattern matching rather than true TP/FP logic learning.

---

## Dataset

**Source**: `proxy/ml/training_data/2026-04-14-ZAP-Report-localhost_labeled.json`

| Metric | Value |
|--------|-------|
| Total Samples | 1799 |
| Used (TP+FP) | 1570 |
| True Positives | 1308 (83%) |
| False Positives | 262 (17%) |
| Potential (skipped) | 229 |
| Class Imbalance Ratio | 5:1 (TP:FP) |

### TP Category Distribution
- X-Powered-By header leaks: 94 samples (7.2%)
- X-Content-Type missing: 83 samples (6.3%)
- Server version leaks: 82 samples (6.3%)
- Cookie issues: 2 samples
- **Subtotal (headers/info): 259 samples (19.8%)**
- Other: 1049 samples (80.2%)

### FP Category Distribution
- Authentication Request Identified: 195 samples (74.4%) - Scanner artifact
- Modern Web Application: 36 samples (13.7%)
- User Agent Fuzzer: 24 samples (9.2%)
- Session Management: 6 samples (2.3%)
- ZAP is Out of Date: 1 sample (0.4%)

---

## Model Performance

### Training Results

```
Train Accuracy:   100.0%
Test Accuracy:    100.0%
Test Precision:   100.0%
Test Recall:      100.0%
Test F1:          1.000
Training Time:    <1 second
```

### Data Split

- Train: 1177 samples (75%)
- Test: 393 samples (25%)
- Stratified: Yes (preserves class distribution)

### Benchmark vs Other Classifiers

| Classifier | Test Accuracy | Precision | Recall | F1 |
|------------|---------------|-----------|--------|-----|
| **Ensemble (RF+GB)** | 100.0% | 100.0% | 100.0% | 1.000 |
| Logistic Regression | 100.0% | 100.0% | 100.0% | 1.000 |
| Decision Tree | 100.0% | 100.0% | 100.0% | 1.000 |
| SVM | 100.0% | 100.0% | 100.0% | 1.000 |

**Note**: All classifiers showing identical 100% accuracy is suspicious and indicates potential memorization/overfitting rather than true generalization.

---

## Feature Importance

### Top 10 Features (from Random Forest component)

| Rank | Feature | Importance | Category |
|------|---------|-----------|----------|
| 1 | fp_keyword_count | 29.2% | Content Analysis |
| 2 | category | 23.1% | **Pattern Matching** |
| 3 | keyword_ratio | 18.8% | Content Analysis |
| 4 | has_params | 8.9% | URL Structure |
| 5 | tp_keyword_count | 7.3% | Content Analysis |
| 6 | url_complexity | 6.5% | URL Structure |
| 7 | evidence_length | 4.6% | Content Analysis |
| 8 | description_length | 1.5% | Content Analysis |
| 9 | severity | 0.1% | Metadata |
| 10 | cvss_score | 0.0% | Metadata |

**Key Finding**: `category` feature ranks #2 (23.1%) - model heavily relies on finding category rather than deeper analysis.

---

## Semantic Validation Tests

### Test Results

| Test Name | Expected | Predicted | Status | Confidence | Notes |
|-----------|----------|-----------|--------|-----------|-------|
| SQL Injection (Real) | TP | FP | ❌ FAIL | 85.8% | Category not in training |
| HSTS Missing (Info) | TP | TP | ✅ PASS | 98.8% | Category + keyword match |
| XSS Reflected (Real) | TP | FP | ❌ FAIL | 85.7% | Category not in training |
| Auth Detected (Artifact) | FP | FP | ✅ PASS | 98.1% | Exact match with training |
| Auth Bypass (Real) | TP | FP | ❌ FAIL | 83.3% | Category rare in training |

### Pass Rate: 2/5 (40%)

---

## Analysis

### Why 100% Training Accuracy?

1. **Small feature space** relative to sample size (16 features, 1570 samples = ~98:1 ratio)
2. **High category-based separability**: Most FPs are "Authentication Request" category
3. **Ensemble voting** makes overfitting more likely with simple patterns
4. **Class weighting alone insufficient** for complex imbalance

### Why Semantic Tests Not Better?

1. **SQL Injection**: Zero examples in training data
   - Model never learned "injection" keyword pattern for TP
   - Falls back to FP prediction as default

2. **XSS Reflected**: Zero examples in training data  
   - Similar story as SQL Injection
   - Keyword match not enough without category context

3. **Auth Bypass**: "Authentication" category dominates FP labels (195/262)
   - Model learned: "Authentication" → likely FP
   - Actual "Authentication Bypass" (exploitable) gets confused
   - Category feature too strong

### Root Cause: Imbalanced Training Data

Real ZAP findings from Moodle scan are heavily skewed toward:
- **Info disclosure** (headers, server version) - 1000+ samples
- **Scanner artifacts** (auth detection, fuzzing) - 200+ samples
- **Real exploitable vulns** (SQL, XSS, CSRF) - <50 samples

---

## Recommendations for Next Phase

### Option 1: Data Augmentation (Recommended)
Create synthetic training examples for missing categories:
- SQL Injection variants (10 examples)
- XSS variants (10 examples)  
- Auth Bypass (5 examples)
- CSRF (5 examples)

**Effort**: 1-2 hours  
**Expected Improvement**: Semantic test accuracy to 4-5/5

### Option 2: Feature Weighting Adjustment
- Reduce category feature importance
- Increase keyword-based features
- Add domain-specific TP/FP patterns

**Effort**: 30-60 minutes  
**Expected Improvement**: Modest (3-4/5)

### Option 3: Accept v1.0 Baseline
- Use current model for header/info disclosure TP/FP discrimination
- Plan manual feedback loop for real vulnerabilities
- Collect more diverse ZAP scans on different domains

**Effort**: 0  
**Trade-off**: Lower accuracy on real vulns, but valid baseline

---

## Model Location

**Saved to**: `ml/models/fp_reducer.pkl`

**Deployment ready**: Yes (with caveats)

**Recommended for**: 
- ✅ Header/info disclosure filtering (HSTS, headers, servers)
- ✅ Scanner artifact filtering (auth detection, fuzzing)
- ⚠️ Real vulnerability classification (limited validation)
- ❌ Production use without feedback loop (needs augmentation first)

---

## Next Immediate Steps

1. ✅ **DONE**: Train baseline model
2. ⏳ **TODO**: Augment training data with missing vulnerability types
3. ⏳ **TODO**: Re-train with augmented dataset
4. ⏳ **TODO**: Validate semantic tests again
5. ⏳ **TODO**: Deploy to proxy/scanner integration

---

## Related Files

- Training script: `train_full_fp_reducer.py`
- Balanced dataset: `proxy/ml/training_data/2026-04-14-ZAP-Report-localhost_labeled_balanced_524.json`
- Full dataset: `proxy/ml/training_data/2026-04-14-ZAP-Report-localhost_labeled.json`
- Debug script: `debug_features.py`
- Audit script: `audit_training_data.py`

---

**Report Generated**: 2026-04-15 11:15:00  
**Status**: Ready for next phase (data augmentation recommended)
