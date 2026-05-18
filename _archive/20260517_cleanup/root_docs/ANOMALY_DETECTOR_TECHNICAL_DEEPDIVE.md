# Anomaly Detector Optimization - Technical Deep Dive

## Mathematical Formulations

### 1. Feature Scaling

#### StandardScaler
$$X_{scaled} = \frac{X - \mu}{\sigma}$$

Where:
- $X$ = original feature value
- $\mu$ = feature mean from training data
- $\sigma$ = feature standard deviation

**Properties:**
- Zero mean, unit variance
- Assumes normally distributed features
- Used as primary scaler in implementation

#### RobustScaler (Alternative)
$$X_{robust} = \frac{X - Q_{50}}{Q_{75} - Q_{25}}$$

Where:
- $Q_{50}$ = median (50th percentile)
- $Q_{25}$ = 25th percentile
- $Q_{75}$ = 75th percentile
- Uses IQR (Interquartile Range)

**Properties:**
- Robust to outliers
- Uses median instead of mean
- Available as alternative in implementation

### 2. Isolation Forest Scoring

**Anomaly Score:**
$$\text{score}(X) = 2^{-E(h(X)) / c(n)}$$

Where:
- $h(X)$ = depth of sample in isolation trees
- $E[\cdot]$ = expected value over all trees
- $c(n)$ = normalization constant

**Properties:**
- Normal points have deep paths (lower score)
- Anomalous points have shallow paths (higher score)
- Score range: (-∞, 1]
- Lower score = more anomalous

### 3. Score Normalization (Enhanced)

#### Numerically Stable Sigmoid
$$\sigma(z) = \frac{1}{1 + e^{-z}}$$

With clipping:
$$z_{clipped} = \text{clip}(z, -500, 500)$$
$$\sigma(z_{clipped}) = \frac{1}{1 + e^{-z_{clipped}}}$$

**Properties:**
- Maps $(-\infty, \infty) \rightarrow (0, 1)$
- Monotonically increasing
- Smooth derivative
- Prevents numerical overflow

#### Z-Score Normalization with Calibration
$$z_{norm} = \frac{score - \mu_{score}}{\sigma_{score}}$$

$$p = \sigma(z_{norm}) = \frac{1}{1 + e^{-z_{norm}}}$$

Where:
- $\mu_{score}$ = mean of anomaly scores from training data
- $\sigma_{score}$ = standard deviation of anomaly scores

**Properties:**
- Learned from training data (not hardcoded)
- Adaptive to different datasets
- Centers distribution around 0
- Converts raw scores to probabilities

#### Score Calibration (Optional)
$$p_{calibrated} = \sigma(a \cdot score + b)$$

Where:
- $a$ = scale parameter (self.score_scale)
- $b$ = offset parameter (self.score_offset)

**Purpose:**
- Linear adjustment of Isolation Forest boundary
- Adapts to specific threat model
- Can be learned from validation data

### 4. Meta-Classifier Optimization

#### Weighted Objective Function
$$J(\theta) = w_{fp} \cdot \text{FP_rate} + w_{fn} \cdot \text{FN_rate}$$

Where:
- $w_{fp}$ = false positive weight (default: 2.0)
- $w_{fn}$ = false negative weight (default: 1.0)
- $\text{FP_rate} = \frac{FP}{FP + TN}$
- $\text{FN_rate} = \frac{FN}{FN + TP}$

**Optimization:**
$$\theta^* = \arg\min_{\theta \in \Theta} J(\theta)$$

Where $\Theta$ = set of threshold candidates [0.20, 0.90] with 0.005 step

**With Recall Constraint:**
$$\text{Find } \theta^* \text{ such that:}$$
$$J(\theta^*) \text{ is minimized}$$
$$\text{subject to: } \text{Recall}(\theta^*) \geq r_{min}$$

Where $r_{min}$ = target recall (default: 0.90)

#### Binary Classification Metrics
$$\text{Accuracy} = \frac{TP + TN}{TP + TN + FP + FN}$$

$$\text{Precision} = \frac{TP}{TP + FP}$$

$$\text{Recall} = \frac{TP}{TP + FN}$$

$$F_1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$

$$\text{FP_rate} = \frac{FP}{FP + TN}$$

$$\text{FN_rate} = \frac{FN}{FN + TP}$$

### 5. Three-Stage Detection Decision Function

#### Stage 1: Heuristic Detection
$$h(X) = \begin{cases}
1 & \text{if } S_h(X) > \tau_h \\
0 & \text{otherwise}
\end{cases}$$

Where:
- $S_h(X)$ = heuristic anomaly score (0 to 1)
- $\tau_h$ = heuristic threshold (default: 0.75-0.80)

**Heuristic Score Components:**
$$S_h(X) = \min(\sum_i c_i \cdot p_i(X), 1.0)$$

Where:
- $p_i(X)$ = probability of pattern $i$ in $X$
- $c_i$ = weight for pattern $i$ (0.3 to 0.8)
- Patterns: response time, status codes, request rate, severity, URL patterns, payload patterns, bot detection

#### Stage 2: Isolation Forest
$$s(X) = \text{IsolationForest.score_samples}(X_{scaled})$$

$$p_{if}(X) = \sigma(z_{norm}) = \frac{1}{1 + e^{-\frac{s(X) - \mu_s}{\sigma_s}}}$$

#### Stage 3: Meta-Classifier
$$M = [p_{if}(X), S_h(X), f_1(X), ..., f_9(X)]$$

$$p_{meta}(X) = \text{RandomForest.predict_proba}(M)[1]$$

#### Final Decision
$$d(X) = \begin{cases}
1 & \text{if } p_{meta}(X) > \tau_{meta} \text{ or } (h(X)=1 \text{ and } S_h(X) \geq 0.80) \\
0 & \text{otherwise}
\end{cases}$$

Where $\tau_{meta}$ = learned meta-classifier threshold

---

## Implementation Details

### Feature Vector (26 dimensions)

```
┌─ Original 18 Features ──────────────────────────────────────┐
│
├─ Request Features (5)
│  0: URL length (0-500)
│  1: Path depth (0-20)
│  2: Has parameters (0-1)
│  3: Header count (0-50)
│  4: Body size (0-100000)
│
├─ Response Features (4)
│  5: Status code (200-599)
│  6: Response size (0-1000000)
│  7: Response time (0-10000ms)
│  8: Response headers (0-100)
│
├─ Finding Features (3)
│  9: Severity (1-5)
│ 10: Risk score (0-10)
│ 11: CVSS score (0-10)
│
├─ Temporal Features (2)
│ 12: Hour of day (0-23)
│ 13: Day of week (0-6)
│
├─ Behavioral Features (3)
│ 14: Request count/min (0-1000)
│ 15: Unique IPs/min (0-100)
│ 16: Error rate/min (0-1)
│
└─ Enhanced Features (8) ────────────────────────────────────┘

├─ Payload Analysis (2)
│ 17: Entropy (0-8)
│ 18: Suspicious patterns count (0-10)
│
├─ Bot Detection (1)
│ 19: Is bot/scanner (0-1)
│
├─ Security Headers (1)
│ 20: Missing security headers (0-3)
│
├─ Status Anomaly (1)
│ 21: Status abnormality (0-1)
│
├─ Request Frequency (1)
│ 22: Frequency spike (0-1)
│
├─ Response Time (1)
│ 23: Time deviation (0-1)
│
└─ Risk Aggregation (1)
   24: Normalized risk (0-1)

Total: 26 features
```

### Meta-Classifier Features (9 dimensions)

```
Meta-classifier input combines base model with heuristic signals:

0: Normalized score from Isolation Forest (0-1)
1: Heuristic anomaly score (0-1)
2: Payload suspicion (0-10)
3: Is bot (0-1)
4: Status abnormality (0-1)
5: Frequency spike (0-1)
6: Time deviation (0-1)
7: Request count (0-1000)
8: URL length (0-500)

Purpose: Learn non-linear combinations of signals to reduce FP
```

---

## Threshold Selection Algorithm

### Two-Phase Approach

**Phase 1: Primary Selection (Recall-Constrained)**
```python
best_result = None

for threshold in [0.20, 0.205, ..., 0.90]:  # 141 candidates
    y_pred = (probabilities >= threshold).astype(int)
    metrics = evaluate(y_val, y_pred)
    
    # Check recall constraint
    if metrics['recall'] < target_recall:
        continue  # Skip this threshold
    
    # Calculate weighted objective
    objective = fp_weight * metrics['fp_rate'] + \
                fn_weight * metrics['fn_rate']
    
    # Update best if better
    if objective < best_result.objective:
        best_result = {
            'threshold': threshold,
            'objective': objective,
            'metrics': metrics,
        }

return best_result.threshold  # Best while preserving recall
```

**Phase 2: Fallback (If Phase 1 Fails)**
```python
if best_result is None:
    # No threshold met recall requirement
    # Use highest recall with lowest FP instead
    
    best_result = None
    for threshold in sorted(thresholds):
        y_pred = (probabilities >= threshold).astype(int)
        metrics = evaluate(y_val, y_pred)
        
        if best_result is None or metrics['recall'] > best_result['recall']:
            best_result = {
                'threshold': threshold,
                'metrics': metrics,
            }
    
    return best_result.threshold  # Highest recall fallback
```

---

## Entropy Calculation (Shannon Entropy)

$$H(X) = -\sum_{i=1}^{n} p(x_i) \log_2 p(x_i)$$

Where:
- $n$ = number of unique characters
- $p(x_i)$ = probability of character $x_i$
- High entropy (6-8) = random/encoded (suspicious)
- Low entropy (2-4) = natural language (normal)

**Implementation:**
```python
def _calculate_entropy(text: str) -> float:
    freq = Counter(text)
    entropy = 0
    for count in freq.values():
        p = count / len(text)
        if p > 0:
            entropy -= p * np.log2(p)
    return entropy
```

**Interpretation:**
- Entropy > 6.0 = Likely encoded payload (high suspicion)
- Entropy 4-6 = Possibly encoded or compressible
- Entropy < 4 = Natural language or structured data (low suspicion)

---

## Class Imbalance Handling

### Balanced Subsample Strategy (Random Forest)
```python
RandomForestClassifier(
    class_weight='balanced_subsample',
    # For each tree:
    # - Sample proportional to class weights
    # - Weight = 1/freq_class
    # Prevents majority class domination
)
```

**Effect:**
- Minority class (anomalies) get higher weight
- Each tree bootstrap sample is balanced
- Better recall for rare anomalies

### Balanced Class Weights (Logistic Regression)
```python
LogisticRegression(
    class_weight='balanced',
    # weight_negative = n / (2 * n_negative)
    # weight_positive = n / (2 * n_positive)
)
```

---

## Score Distribution Tracking

### During Training
```python
X_scaled = scaler.fit_transform(X)
scores = model.score_samples(X_scaled)

score_mean = np.mean(scores)    # ~0 for Isolation Forest
score_std = np.std(scores)      # ~1 for normalized features

# Store for later use
baseline_stats['score_mean'] = score_mean
baseline_stats['score_std'] = score_std
```

### During Detection
```python
score = model.score_samples(X_scaled)[0]

# Normalize using learned parameters
z_score = (score - score_mean) / score_std
probability = sigmoid(z_score)  # Converts to [0, 1]
```

---

## Hyperparameter Tuning Grid

### Isolation Forest
```python
IsolationForest(
    n_estimators=100,       # Number of trees
    max_samples='auto',     # Samples per tree (min(256, n))
    contamination=0.10,     # Expected anomaly rate
    random_state=42,        # Reproducibility
    n_jobs=-1,              # Use all CPU cores
)
```

### Random Forest Meta-Classifier
```python
RandomForestClassifier(
    n_estimators=300,                       # More trees = better generalization
    max_depth=15,                           # Prevent overfitting
    min_samples_split=10,                   # Min samples for split
    min_samples_leaf=5,                     # Min samples in leaf node
    max_features='sqrt',                    # Feature subsampling (√26 ≈ 5)
    bootstrap=True,                         # Bootstrap aggregating
    class_weight='balanced_subsample',      # Handle class imbalance
    n_jobs=-1,                              # Parallel
)
```

### Threshold Optimization
```python
threshold_range = [0.20, 0.90]       # Min to max probability
n_candidates = 141                    # Fine-grained (0.005 step)
target_recall = 0.90                 # Minimum recall preserved
fp_penalty_weight = 2.0              # 2x penalty on false positives
```

---

## Performance Characteristics

### Computational Complexity

| Component | Complexity | Time |
|-----------|-----------|------|
| Feature extraction | O(26) | <1ms |
| StandardScaler transform | O(26) | <1ms |
| Isolation Forest predict | O(100 * log n) | ~2-5ms |
| Heuristic detection | O(26) | <1ms |
| Meta-classifier predict | O(9 * 300) | ~1-2ms |
| **Total detect()** | | **<10ms** |

### Memory Usage

| Component | Size |
|-----------|------|
| Isolation Forest (100 trees) | ~50-100 MB |
| StandardScaler | ~1 KB |
| RobustScaler | ~1 KB |
| Random Forest meta-classifier | ~30-50 MB |
| **Total model** | **~80-150 MB** |

---

## Error Handling

### Score Computation Safeguards
```python
# Prevent division by zero
if std == 0:
    return 0.5  # Neutral probability

# Prevent overflow
score = np.clip(score, -500, 500)

# Ensure bounds
probability = np.clip(probability, 0.0, 1.0)
```

### Fallback Strategies
```python
# Heuristic if model not trained
if not self.is_trained:
    return self._heuristic_detection(data)

# Preserve strong heuristic signals
if heuristic_score >= 0.80:
    probability = max(probability, 0.85)

# Two-phase threshold selection
if best_result is None:
    use_fallback_strategy()
```

---

## Validation Metrics Interpretation

### Precision vs Recall Trade-off
```
High Precision (Low FP):
  - Few false alarms ✓
  - May miss some attacks ✗
  - Good for: User-facing systems
  - Use: Higher fp_penalty_weight

High Recall (Low FN):
  - Catch most attacks ✓
  - Many false alarms ✗
  - Good for: Security operations
  - Use: Lower fp_penalty_weight, higher target_recall
```

### F1 Score Balance
$$F_1 = 2 \cdot \frac{\text{Precision} \cdot \text{Recall}}{\text{Precision} + \text{Recall}}$$

- Balances precision and recall
- Useful when classes are imbalanced
- Harmonic mean (not arithmetic mean)
- Range: 0 (worst) to 1 (best)

---

## References

- Isolation Forest: Liu et al., "Isolation Forest" (2008)
- Sigmoid function: https://en.wikipedia.org/wiki/Sigmoid_function
- Standard Scaler: Scikit-learn documentation
- Robust Scaler: Huber, "Robust statistics" (1981)
- Meta-learning: Vilalta & Drissi (2002)

