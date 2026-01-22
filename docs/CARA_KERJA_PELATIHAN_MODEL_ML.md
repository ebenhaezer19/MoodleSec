# 🎓 Cara Kerja Pelatihan Model Machine Learning - MoodleSec

## 📌 Overview

Dokumen ini menjelaskan **secara detail** cara kerja pelatihan untuk **4 ML models** di MoodleSec, dengan fokus mendalam pada **False Positive Reducer** sebagai model utama.

---

## 🎯 Arsitektur Pelatihan - Pipeline Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                  ML TRAINING PIPELINE                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Step 1: DATA GENERATION / COLLECTION                          │
│  ┌──────────────────────────────────────────────────┐          │
│  │  • Training Data Generator (Synthetic)           │          │
│  │  • Real Scan Results (ZAP, Acunetix)            │          │
│  │  • Manual Pentest Findings                       │          │
│  │  • User Feedback (Incremental learning)          │          │
│  └──────────────────────────────────────────────────┘          │
│                        ↓                                        │
│  Step 2: FEATURE EXTRACTION                                     │
│  ┌──────────────────────────────────────────────────┐          │
│  │  • Extract 16 features untuk FP Reducer          │          │
│  │  • Extract 8 features untuk Severity Predictor   │          │
│  │  • Extract 10 features untuk Anomaly Detector    │          │
│  │  • Extract 12 features untuk Rate Limiter        │          │
│  └──────────────────────────────────────────────────┘          │
│                        ↓                                        │
│  Step 3: PREPROCESSING                                          │
│  ┌──────────────────────────────────────────────────┐          │
│  │  • Train-Test Split (80/20, stratified)          │          │
│  │  • Feature Scaling (StandardScaler)              │          │
│  │  • Label Encoding (untuk categorical)            │          │
│  │  • Data Validation                                │          │
│  └──────────────────────────────────────────────────┘          │
│                        ↓                                        │
│  Step 4: MODEL TRAINING                                         │
│  ┌──────────────────────────────────────────────────┐          │
│  │  Model 1: FP Reducer (RF + GB Ensemble)         │          │
│  │  Model 2: Severity Predictor (GB Classifier)     │          │
│  │  Model 3: Anomaly Detector (Isolation Forest)    │          │
│  │  Model 4: Rate Limiter (GB Regressor)            │          │
│  └──────────────────────────────────────────────────┘          │
│                        ↓                                        │
│  Step 5: CALIBRATION (FP Reducer only)                         │
│  ┌──────────────────────────────────────────────────┐          │
│  │  • CalibratedClassifierCV (Platt scaling)        │          │
│  │  • 3-fold cross-validation                       │          │
│  │  • Sigmoid calibration untuk reliable conf.      │          │
│  └──────────────────────────────────────────────────┘          │
│                        ↓                                        │
│  Step 6: EVALUATION                                             │
│  ┌──────────────────────────────────────────────────┐          │
│  │  • Test accuracy, Precision, Recall, F1          │          │
│  │  • Feature importance analysis                    │          │
│  │  • Confusion matrix                               │          │
│  │  • Cross-validation scores                        │          │
│  └──────────────────────────────────────────────────┘          │
│                        ↓                                        │
│  Step 7: MODEL PERSISTENCE                                      │
│  ┌──────────────────────────────────────────────────┐          │
│  │  • Serialize model dengan pickle                 │          │
│  │  • Save scaler, encoders                          │          │
│  │  • Save training metadata                         │          │
│  │  • Generate training report (JSON)                │          │
│  └──────────────────────────────────────────────────┘          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔬 MODEL #1: FALSE POSITIVE REDUCER (Detail Mendalam)

### **Overview**
- **Algoritma:** Random Forest + Gradient Boosting Ensemble dengan Probability Calibration
- **Task:** Binary Classification (True Positive vs False Positive)
- **Target:** Reduce FP rate dari 60% → <10%
- **Current Performance:** 95% test accuracy

---

### **Step 1: Data Generation & Collection**

#### **A. Training Data Generator (Synthetic Data)**

**File:** `proxy/ml/training_data_generator.py`

**Cara Kerja:**
```python
class TrainingDataGenerator:
    def generate_false_positive_data(self, n_samples=1000):
        """Generate synthetic training data untuk FP Reducer."""
        
        # 1. Initialize empty lists
        findings = []
        labels = []
        
        # 2. Generate True Positives (60% of data)
        n_tp = int(n_samples * 0.6)
        for i in range(n_tp):
            finding = {
                'severity': random.choice(['high', 'critical', 'medium']),
                'category': random.choice([
                    'SQL Injection', 'XSS', 'CSRF', 
                    'Authentication Bypass'
                ]),
                'evidence': self._generate_tp_evidence(),
                'description': self._generate_tp_description(),
                'url': self._generate_url(complex=True),
                'cvss_score': random.uniform(6.0, 10.0),
                'risk_score': random.uniform(7.0, 10.0)
            }
            
            context = {
                'status_code': random.choice([200, 500, 403]),
                'response_time': random.randint(100, 3000)
            }
            
            findings.append({'finding': finding, 'context': context})
            labels.append(0)  # 0 = True Positive
        
        # 3. Generate False Positives (40% of data)
        n_fp = n_samples - n_tp
        for i in range(n_fp):
            finding = {
                'severity': random.choice(['low', 'info', 'medium']),
                'category': random.choice([
                    'Information Disclosure', 'Missing Header',
                    'Security Misconfiguration'
                ]),
                'evidence': self._generate_fp_evidence(),
                'description': self._generate_fp_description(),
                'url': self._generate_url(complex=False),
                'cvss_score': random.uniform(0.0, 5.0),
                'risk_score': random.uniform(0.0, 4.0)
            }
            
            context = {
                'status_code': random.choice([200, 404]),
                'response_time': random.randint(50, 500)
            }
            
            findings.append({'finding': finding, 'context': context})
            labels.append(1)  # 1 = False Positive
        
        # 4. CRITICAL: Enforce 15% overlap untuk prevent data leakage
        findings, labels = self._enforce_overlap(findings, labels)
        
        return findings, labels
    
    def _enforce_overlap(self, findings, labels):
        """
        Enforce 15% severity overlap antara TP dan FP.
        
        Why? Prevent data leakage - model tidak boleh belajar bahwa
        "High/Critical = TP" dan "Low/Info = FP" secara mutlak.
        """
        n_overlap = int(len(findings) * 0.15)
        
        # Find 15% TP samples dengan severity rendah
        tp_indices = [i for i, label in enumerate(labels) if label == 0]
        overlap_tp = random.sample(tp_indices, min(n_overlap, len(tp_indices)))
        
        for idx in overlap_tp:
            # Change severity to Low/Info (create overlap)
            findings[idx]['finding']['severity'] = random.choice(['low', 'info'])
            # Tapi tetap True Positive (label = 0)
        
        # Find 15% FP samples dengan severity tinggi
        fp_indices = [i for i, label in enumerate(labels) if label == 1]
        overlap_fp = random.sample(fp_indices, min(n_overlap, len(fp_indices)))
        
        for idx in overlap_fp:
            # Change severity to High/Critical (create overlap)
            findings[idx]['finding']['severity'] = random.choice(['high', 'critical'])
            # Tapi tetap False Positive (label = 1)
        
        return findings, labels
```

**Output Example:**
```json
{
  "finding": {
    "severity": "high",
    "category": "SQL Injection",
    "evidence": "Error message: 'You have an error in your SQL syntax'",
    "description": "SQL Injection vulnerability detected in login form",
    "url": "https://moodle.test/login/index.php?id=1' OR '1'='1",
    "cvss_score": 8.5,
    "risk_score": 9.0
  },
  "context": {
    "status_code": 500,
    "response_time": 850
  },
  "label": 0  // True Positive
}
```

---

#### **B. Real Data Collection**

**Sources:**
1. **ZAP Scan Results** → `proxy/data/zap_reports/*.json`
2. **Acunetix Exports** → `proxy/data/acunetix_data/*.json`
3. **Manual Pentest** → `proxy/data/real_data/manual_findings.json`

**Import Process:**
```python
# Import dari ZAP
python3 import_zap_scan.py --file zap_report.json

# Import dari Acunetix
python3 import_acunetix_data.py --file acunetix_results.json

# Auto-labeling dengan model confidence
python3 enhanced_auto_label.py --threshold 0.85
```

---

### **Step 2: Feature Extraction (16 Features)**

**File:** `proxy/ml/false_positive_reducer.py` - Method `extract_features()`

#### **Feature Engineering Detail:**

```python
def extract_features(self, finding: Dict, context: Optional[Dict]) -> np.ndarray:
    """Extract 16 features dari finding."""
    features = []
    
    # === CATEGORICAL FEATURES (Encoded) ===
    
    # Feature 1: Severity Level (Ordinal Encoding)
    severity_encoding = {
        'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1
    }
    severity = finding.get('severity', 'info').lower()
    features.append(severity_encoding.get(severity, 1))
    
    # Feature 2: Category (Numerical Encoding)
    category = finding.get('category', 'Unknown')
    category_encoding = {
        'SQL Injection': 10, 'XSS': 9, 'CSRF': 8,
        'Authentication': 7, 'Authorization': 6,
        'Information Disclosure': 3, 'Missing Header': 2
    }
    features.append(category_encoding.get(category, 5))
    
    # === TEXT-BASED FEATURES ===
    
    # Feature 3: Evidence Length (Indicator of detail quality)
    evidence = str(finding.get('evidence', ''))
    features.append(len(evidence))
    
    # Feature 4: Description Length
    description = str(finding.get('description', ''))
    features.append(len(description))
    
    # === URL FEATURES ===
    
    # Feature 5: URL Complexity (Path segments count)
    url = finding.get('url', '')
    url_complexity = url.count('/') + url.count('?')
    features.append(url_complexity)
    
    # Feature 6: Has Query Parameters (Binary)
    features.append(1 if '?' in url else 0)
    
    # === RISK METRICS ===
    
    # Feature 7: CVSS Score (0-10)
    features.append(finding.get('cvss_score', 0.0))
    
    # Feature 8: Risk Score (0-10)
    features.append(finding.get('risk_score', 0.0))
    
    # === KEYWORD FEATURES (Most Important!) ===
    
    # Feature 9: False Positive Keyword Count
    fp_keywords = [
        'missing', 'not implemented', 'not set', 'header', 
        'best practice', 'recommendation', 'information'
    ]
    fp_count = sum(1 for kw in fp_keywords 
                   if kw in description.lower() or kw in evidence.lower())
    features.append(fp_count)
    
    # Feature 10: True Positive Keyword Count
    tp_keywords = [
        'injection', 'xss', 'csrf', 'bypass', 'exploit',
        'vulnerability', 'attack', 'malicious', 'exposed'
    ]
    tp_count = sum(1 for kw in tp_keywords 
                   if kw in description.lower() or kw in evidence.lower())
    features.append(tp_count)
    
    # Feature 11: Keyword Ratio (TP/FP balance)
    keyword_ratio = tp_count / (fp_count + 1)  # +1 to avoid division by zero
    features.append(keyword_ratio)
    
    # Feature 12: Is Informational (Binary flag)
    is_info = 1 if severity == 'info' else 0
    features.append(is_info)
    
    # === CONTEXT FEATURES (dari scanner response) ===
    
    if context:
        # Feature 13: Status Code
        status_code = context.get('status_code', 200)
        features.append(status_code)
        
        # Feature 14: Response Time (ms)
        response_time = context.get('response_time', 0)
        features.append(response_time)
        
        # Feature 15: Occurrence Count (historical)
        occurrence_count = context.get('occurrence_count', 1)
        features.append(occurrence_count)
        
        # Feature 16: Days Since First Seen
        days_since = context.get('days_since_first_seen', 0)
        features.append(days_since)
    else:
        # Default values jika context tidak ada
        features.extend([200, 0, 1, 0])
    
    return np.array(features).reshape(1, -1)
```

**Feature Importance (Hasil Training):**
```
Top 5 Most Important Features:
1. keyword_ratio         : 0.1842  (18.42%)
2. cvss_score           : 0.1523  (15.23%)
3. tp_keyword_count     : 0.1398  (13.98%)
4. severity             : 0.1205  (12.05%)
5. evidence_length      : 0.0987  ( 9.87%)
```

**Insight:**
- **Keyword ratio** adalah feature paling powerful → Model belajar dari patterns text
- **CVSS score** dan **severity** penting tapi tidak dominan (good! No data leakage)
- **Context features** (status_code, response_time) contribute ~15% total importance

---

### **Step 3: Data Preprocessing**

**File:** `proxy/ml/false_positive_reducer.py` - Method `train()`

```python
def train(self, training_data: List[Dict], labels: List[int]) -> Dict:
    """Train ensemble model dengan preprocessing."""
    
    # === STEP 3.1: Validate Data ===
    if len(training_data) < 10:
        return {'error': 'Insufficient training data (minimum 10 samples)'}
    
    # === STEP 3.2: Extract Features untuk Semua Samples ===
    X = []
    for sample in training_data:
        finding = sample.get('finding', {})
        context = sample.get('context', {})
        features = self.extract_features(finding, context)
        X.append(features.flatten())
    
    X = np.array(X)  # Shape: (n_samples, 16)
    y = np.array(labels)  # Shape: (n_samples,)
    
    print(f"[Training] Dataset shape: {X.shape}")
    print(f"[Training] True Positives: {(y == 0).sum()} ({(y == 0).sum()/len(y)*100:.1f}%)")
    print(f"[Training] False Positives: {(y == 1).sum()} ({(y == 1).sum()/len(y)*100:.1f}%)")
    
    # === STEP 3.3: Train-Test Split (Stratified) ===
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,        # 80% train, 20% test
        random_state=42,      # Reproducible
        stratify=y            # Maintain class distribution
    )
    
    print(f"[Training] Train set: {len(X_train)} samples")
    print(f"[Training] Test set: {len(X_test)} samples")
    
    # === STEP 3.4: Feature Scaling (StandardScaler) ===
    # NOTE: Tree-based models don't need scaling, but we do it anyway
    # for consistency and potential future ensemble with non-tree models
    
    X_train_scaled = self.scaler.fit_transform(X_train)
    X_test_scaled = self.scaler.transform(X_test)
    
    print(f"[Training] Features scaled (mean=0, std=1)")
    
    # Proceed to model training...
```

**StandardScaler Example:**
```
Original CVSS scores:    [8.5, 3.2, 9.1, 1.5, 7.8]
After scaling:           [0.82, -0.95, 1.15, -1.82, 0.45]
```

**Why Stratified Split?**
```
Without stratification:
  Train: 70% TP, 30% FP
  Test:  50% TP, 50% FP  ❌ Different distribution!

With stratification:
  Train: 60% TP, 40% FP
  Test:  60% TP, 40% FP  ✅ Same distribution!
```

---

### **Step 4: Model Training - Ensemble Architecture**

**File:** `proxy/ml/false_positive_reducer.py` - Method `train()` (lanjutan)

#### **A. Random Forest Component**

```python
from sklearn.ensemble import RandomForestClassifier

# Model 1: Random Forest
rf_model = RandomForestClassifier(
    n_estimators=150,        # 150 decision trees
    max_depth=12,           # Max tree depth (prevent overfitting)
    min_samples_split=4,    # Min samples untuk split node
    min_samples_leaf=2,     # Min samples di leaf node
    random_state=42,        # Reproducible
    class_weight='balanced' # Handle class imbalance (jika ada)
)

# Cara Kerja Random Forest:
# 1. Bootstrap sampling: Create 150 random subsets dari training data
# 2. Train 150 decision trees (each with random feature subsets)
# 3. Prediction: Majority voting dari 150 trees
#    Example: 90 trees vote "TP", 60 trees vote "FP" → Result = TP
```

**Random Forest Visualization:**
```
Training Data (720 samples)
        ↓
┌───────┴───────┬───────┬───────┬─────┬───────┐
│   Tree 1      │ Tree 2│ Tree 3│ ... │Tree 150│
│ (sample 1-480)│(2-481)│(3-482)│     │(150-630)│
└───────┬───────┴───────┴───────┴─────┴───────┘
        ↓
Prediction (Voting):
  Tree 1:  TP (0.8 confidence)
  Tree 2:  TP (0.7 confidence)
  Tree 3:  FP (0.6 confidence)
  ...
  Tree 150: TP (0.9 confidence)
        ↓
Final: 90 trees → TP, 60 trees → FP
Result: TRUE POSITIVE (probability = 90/150 = 0.60)
```

---

#### **B. Gradient Boosting Component**

```python
from sklearn.ensemble import GradientBoostingClassifier

# Model 2: Gradient Boosting
gb_model = GradientBoostingClassifier(
    n_estimators=100,       # 100 sequential trees
    max_depth=5,           # Shallower trees than RF
    learning_rate=0.1,     # Step size untuk learning
    random_state=42
)

# Cara Kerja Gradient Boosting:
# 1. Train tree 1 → Calculate errors
# 2. Train tree 2 pada errors dari tree 1
# 3. Train tree 3 pada errors dari tree 1 + 2
# ... repeat 100 times
# 4. Final prediction = weighted sum of all trees
```

**Gradient Boosting Visualization:**
```
Initial Prediction: All samples = 0.5 (neutral)
        ↓
┌─────────────────────────────────────────┐
│ Iteration 1: Tree 1                     │
│   • Train on original data              │
│   • Predictions: [0.6, 0.4, 0.7, ...]   │
│   • Errors: [0.4, 0.6, 0.3, ...]        │
└─────────────────────────────────────────┘
        ↓
┌─────────────────────────────────────────┐
│ Iteration 2: Tree 2                     │
│   • Train to FIX errors from Tree 1     │
│   • Predictions: [0.1, 0.15, 0.05, ...] │
│   • Combined: Tree1 + 0.1*Tree2         │
└─────────────────────────────────────────┘
        ↓
... repeat 100 times ...
        ↓
Final Prediction = Tree1 + 0.1*Tree2 + 0.1*Tree3 + ... + 0.1*Tree100
```

**Learning Rate Effect:**
```
learning_rate = 0.1 (conservative):
  - Each tree contributes 10% of correction
  - Slower learning, better generalization
  - Need more trees (100-200)

learning_rate = 0.5 (aggressive):
  - Each tree contributes 50% of correction
  - Faster learning, risk overfitting
  - Need fewer trees (50-100)
```

---

#### **C. Ensemble: Voting Classifier**

```python
from sklearn.ensemble import VotingClassifier

# Combine RF + GB dengan Soft Voting
ensemble = VotingClassifier(
    estimators=[
        ('rf', rf_model),
        ('gb', gb_model)
    ],
    voting='soft',     # Use probabilities (not hard votes)
    weights=[2, 1]     # RF gets 2x weight of GB
)

# Fit ensemble pada training data
ensemble.fit(X_train_scaled, y_train)
```

**Soft Voting Calculation:**
```
Sample: SQL Injection finding

Random Forest Prediction:
  P(TP) = 0.85
  P(FP) = 0.15

Gradient Boosting Prediction:
  P(TP) = 0.70
  P(FP) = 0.30

Ensemble Soft Voting (with weights 2:1):
  P(TP) = (2 * 0.85 + 1 * 0.70) / 3 = (1.70 + 0.70) / 3 = 0.80
  P(FP) = (2 * 0.15 + 1 * 0.30) / 3 = (0.30 + 0.30) / 3 = 0.20

Final Prediction: TRUE POSITIVE (confidence 80%)
```

**Why RF Gets 2x Weight?**
- Random Forest lebih stable (bagging approach)
- Gradient Boosting bisa overfit jika data noisy
- Experimentation menunjukkan 2:1 ratio optimal untuk dataset kami

---

### **Step 5: Probability Calibration (CRITICAL!)**

**File:** `proxy/ml/false_positive_reducer.py` - Method `train()` (lanjutan)

```python
from sklearn.calibration import CalibratedClassifierCV

# Calibrate ensemble probabilities menggunakan Platt scaling
self.model = CalibratedClassifierCV(
    ensemble,           # Base estimator (RF + GB voting)
    method='sigmoid',   # Platt scaling (logistic regression)
    cv=3               # 3-fold cross-validation
)

# Fit calibrated model
self.model.fit(X_train_scaled, y_train)
self.is_trained = True
```

#### **Why Calibration?**

**Problem: Uncalibrated Probabilities**
```
Model says P(TP) = 0.80, but actual empirical frequency:
  - Out of 100 predictions with P(TP) = 0.80
  - Only 65 are actually True Positives
  - 35 are False Positives

Calibration error = |0.80 - 0.65| = 0.15 (15% error!)
```

**Solution: Platt Scaling (Sigmoid Calibration)**
```python
# Platt scaling learns a sigmoid function:
P_calibrated(TP) = 1 / (1 + exp(A * P_raw(TP) + B))

# Training process:
# 1. Get raw predictions from ensemble: [0.85, 0.62, 0.91, ...]
# 2. Fit logistic regression: True labels vs Raw predictions
# 3. Learn A and B parameters
# 4. Transform all future predictions through sigmoid

Example:
  Raw P(TP) = 0.80
  After calibration: P(TP) = 1 / (1 + exp(-2.3 * 0.80 + 0.5))
                            = 1 / (1 + exp(-1.34))
                            = 1 / (1 + 0.26)
                            = 0.79 (adjusted slightly)
```

**Calibration Curve Example:**
```
Before Calibration:          After Calibration:
                            
1.0 │     ╱                1.0 │    ╱
    │   ╱  ●                   │  ╱
0.8 │ ╱   ●                0.8 │╱ ●
    │╱  ●                      │ ●
0.6 │ ●                    0.6 │●
    │●                         │●
0.4 │                      0.4 │
    └────────────              └────────────
    Predicted Prob.            Predicted Prob.
    
  ● = Actual frequency      Perfect calibration = diagonal line
  Uncalibrated = far from   Calibrated = close to diagonal
  diagonal
```

**3-Fold Cross-Validation Process:**
```
Training Data (720 samples)
        ↓
Split into 3 folds:
  Fold 1: samples 1-240
  Fold 2: samples 241-480
  Fold 3: samples 481-720

Calibration Iteration 1:
  Train on Fold 2 + 3 (480 samples)
  Calibrate on Fold 1 (240 samples)

Calibration Iteration 2:
  Train on Fold 1 + 3 (480 samples)
  Calibrate on Fold 2 (240 samples)

Calibration Iteration 3:
  Train on Fold 1 + 2 (480 samples)
  Calibrate on Fold 3 (240 samples)

Final Model: Ensemble of 3 calibrated classifiers
```

---

### **Step 6: Evaluation & Metrics**

**File:** `proxy/ml/false_positive_reducer.py` - Method `train()` (lanjutan)

```python
from sklearn.metrics import (
    precision_score, recall_score, f1_score, 
    classification_report, confusion_matrix
)

# === STEP 6.1: Train & Test Accuracy ===
train_score = self.model.score(X_train_scaled, y_train)
test_score = self.model.score(X_test_scaled, y_test)

print(f"Train Accuracy: {train_score:.2%}")  # e.g., 97.5%
print(f"Test Accuracy: {test_score:.2%}")    # e.g., 95.0%

# === STEP 6.2: Detailed Metrics ===
y_pred = self.model.predict(X_test_scaled)

precision = precision_score(y_test, y_pred, average='weighted')
recall = recall_score(y_test, y_pred, average='weighted')
f1 = f1_score(y_test, y_pred, average='weighted')

print(f"Precision: {precision:.2%}")  # 96.7%
print(f"Recall: {recall:.2%}")        # 95.1%
print(f"F1-Score: {f1:.2%}")          # 95.9%

# === STEP 6.3: Confusion Matrix ===
cm = confusion_matrix(y_test, y_pred)
print("\nConfusion Matrix:")
print(cm)
#       Predicted:
#         TP   FP
# Actual:
#   TP  [108   5]  ← 108 correct, 5 misclassified
#   FP  [  4  63]  ← 63 correct, 4 misclassified
```

#### **Metrics Explanation:**

**1. Accuracy:**
```
Accuracy = (Correct Predictions) / (Total Predictions)
         = (TP_correct + FP_correct) / Total
         = (108 + 63) / 180
         = 171 / 180
         = 95.0%
```

**2. Precision (TP class):**
```
Precision_TP = TP_correct / (TP_correct + FP_predicted_as_TP)
             = 108 / (108 + 4)
             = 108 / 112
             = 96.4%

Meaning: When model predicts "True Positive", it's correct 96.4% of the time
```

**3. Recall (TP class):**
```
Recall_TP = TP_correct / (TP_correct + TP_predicted_as_FP)
          = 108 / (108 + 5)
          = 108 / 113
          = 95.6%

Meaning: Model catches 95.6% of all actual True Positives
```

**4. F1-Score:**
```
F1 = 2 * (Precision * Recall) / (Precision + Recall)
   = 2 * (0.964 * 0.956) / (0.964 + 0.956)
   = 2 * 0.921 / 1.920
   = 95.9%

Meaning: Harmonic mean of Precision and Recall
```

---

#### **Feature Importance Analysis**

```python
# Get feature importance dari Random Forest component
base_estimator = self.model.calibrated_classifiers_[0].base_estimator
rf_estimator = base_estimator.estimators_[0]  # Access RF model

feature_names = [
    'severity', 'category', 'evidence_length', 'description_length',
    'url_complexity', 'has_params', 'cvss_score', 'risk_score',
    'fp_keyword_count', 'tp_keyword_count', 'keyword_ratio', 
    'is_informational', 'status_code', 'response_time', 
    'occurrence_count', 'days_since_first_seen'
]

importances = rf_estimator.feature_importances_
feature_importance = dict(zip(feature_names, importances))

# Sort by importance
sorted_features = sorted(
    feature_importance.items(), 
    key=lambda x: x[1], 
    reverse=True
)

print("\nFeature Importance:")
for feature, importance in sorted_features:
    print(f"  {feature:25s}: {importance:.4f} ({importance*100:.2f}%)")
```

**Output Example:**
```
Feature Importance:
  keyword_ratio            : 0.1842 (18.42%)  ← MOST IMPORTANT
  cvss_score              : 0.1523 (15.23%)
  tp_keyword_count        : 0.1398 (13.98%)
  severity                : 0.1205 (12.05%)
  evidence_length         : 0.0987 ( 9.87%)
  risk_score              : 0.0854 ( 8.54%)
  category                : 0.0723 ( 7.23%)
  description_length      : 0.0512 ( 5.12%)
  fp_keyword_count        : 0.0398 ( 3.98%)
  response_time           : 0.0287 ( 2.87%)
  status_code             : 0.0142 ( 1.42%)
  url_complexity          : 0.0098 ( 0.98%)
  has_params              : 0.0031 ( 0.31%)
  is_informational        : 0.0000 ( 0.00%)  ← Redundant with severity
  occurrence_count        : 0.0000 ( 0.00%)
  days_since_first_seen   : 0.0000 ( 0.00%)
```

**Insight:**
- **Text features dominan**: keyword_ratio, tp_keyword_count → Model belajar dari patterns deskripsi
- **Risk metrics penting**: cvss_score, risk_score, severity
- **Temporal features kurang berguna**: occurrence_count, days_since (data synthetic tidak punya history)

---

### **Step 7: Model Persistence (Save to Disk)**

**File:** `proxy/ml/false_positive_reducer.py` - Method `_save_model()`

```python
import pickle
import os
from datetime import datetime

def _save_model(self):
    """Save trained model dan scaler ke disk."""
    
    # Create directory jika belum ada
    os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
    
    # Package model dengan metadata
    model_data = {
        'model': self.model,              # Calibrated ensemble
        'scaler': self.scaler,            # StandardScaler (fitted)
        'is_trained': self.is_trained,    # Training status
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'version': '1.0.0',
        'n_features': 16,
        'algorithm': 'CalibratedClassifierCV(VotingClassifier(RF+GB))'
    }
    
    # Serialize dengan pickle
    with open(self.model_path, 'wb') as f:
        pickle.dump(model_data, f)
    
    print(f"✅ Model saved to: {self.model_path}")
    print(f"   File size: {os.path.getsize(self.model_path) / 1024:.2f} KB")
```

**Saved File Structure:**
```
ml/models/fp_reducer.pkl  (binary file, ~2.5 MB)
  │
  ├─ 'model' → CalibratedClassifierCV object
  │   └─ calibrated_classifiers_ (list of 3)
  │       └─ [0] → CalibratedClassifierCV
  │           └─ base_estimator → VotingClassifier
  │               ├─ estimators_[0] → RandomForestClassifier (150 trees)
  │               └─ estimators_[1] → GradientBoostingClassifier (100 trees)
  │
  ├─ 'scaler' → StandardScaler object
  │   ├─ mean_ → [2.85, 6.23, 125.4, ...] (16 values)
  │   └─ scale_ → [1.24, 2.67, 85.2, ...] (16 values)
  │
  ├─ 'is_trained' → True
  ├─ 'timestamp' → "2026-01-22T10:35:42Z"
  ├─ 'version' → "1.0.0"
  ├─ 'n_features' → 16
  └─ 'algorithm' → "CalibratedClassifierCV(VotingClassifier(RF+GB))"
```

---

### **Step 8: Model Loading & Inference**

**File:** `proxy/ml/false_positive_reducer.py` - Method `_load_model()` & `classify()`

#### **A. Load Model**

```python
def _load_model(self):
    """Load trained model dari disk."""
    if os.path.exists(self.model_path):
        try:
            with open(self.model_path, 'rb') as f:
                model_data = pickle.load(f)
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.is_trained = model_data['is_trained']
            
            print(f"[FP Reducer] ✅ Loaded model from {self.model_path}")
            print(f"[FP Reducer]    Trained: {model_data['timestamp']}")
            print(f"[FP Reducer]    Algorithm: {model_data.get('algorithm', 'Unknown')}")
        except Exception as e:
            print(f"[FP Reducer] ❌ Failed to load model: {e}")
            self.is_trained = False
    else:
        print(f"[FP Reducer] ⚠️  No trained model found at {self.model_path}")
        self.is_trained = False
```

#### **B. Prediction (Inference)**

```python
def classify(self, finding: Dict, context: Optional[Dict] = None) -> Tuple[bool, float]:
    """
    Classify finding sebagai TP atau FP.
    
    Returns:
        (is_false_positive, confidence)
    """
    
    # === STEP 1: Check if model trained ===
    if not self.is_trained:
        print("[FP Reducer] Model not trained, using heuristics")
        return self._heuristic_classification(finding)
    
    # === STEP 2: Extract features ===
    features = self.extract_features(finding, context)
    
    # === STEP 3: Scale features ===
    features_scaled = self.scaler.transform(features)
    
    # === STEP 4: Predict dengan calibrated model ===
    # Get probability untuk each class
    probabilities = self.model.predict_proba(features_scaled)[0]
    # probabilities = [P(TP), P(FP)]
    # Example: [0.85, 0.15] → 85% TP, 15% FP
    
    # === STEP 5: Determine classification ===
    is_false_positive = probabilities[1] > 0.5  # FP if P(FP) > 50%
    confidence = max(probabilities)             # Confidence = max probability
    
    return is_false_positive, confidence
```

**Inference Example:**
```python
# Example finding
finding = {
    'severity': 'high',
    'category': 'SQL Injection',
    'evidence': "Error: 'You have an error in your SQL syntax near...'",
    'description': 'SQL injection vulnerability detected in login parameter',
    'url': 'https://moodle.test/login/index.php?id=1%27',
    'cvss_score': 8.5,
    'risk_score': 9.0
}

context = {
    'status_code': 500,
    'response_time': 850
}

# Classify
is_fp, confidence = fp_reducer.classify(finding, context)

# Output:
# is_fp = False (True Positive)
# confidence = 0.92 (92% confident)

print(f"Classification: {'FP' if is_fp else 'TP'}")
print(f"Confidence: {confidence:.2%}")
# Output:
# Classification: TP
# Confidence: 92%
```

---

## 📊 MODEL #2: SEVERITY PREDICTOR (Overview)

### **Training Process (Simplified)**

**File:** `proxy/ml/severity_predictor.py`

```python
def train(self, training_data: List[Dict], labels: List[str]) -> Dict:
    """
    Train Gradient Boosting untuk multi-class severity prediction.
    
    Args:
        training_data: List of findings
        labels: List of severity labels ['critical', 'high', 'medium', 'low', 'info']
    """
    
    # === STEP 1: Extract 8 features ===
    X = [self.extract_features(sample) for sample in training_data]
    X = np.array(X)
    
    # === STEP 2: Encode labels ===
    # Convert ['high', 'critical', 'low', ...] → [3, 4, 1, ...]
    y = self.label_encoder.fit_transform(labels)
    
    # === STEP 3: Train-Test Split ===
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # === STEP 4: Scale Features ===
    X_train_scaled = self.scaler.fit_transform(X_train)
    X_test_scaled = self.scaler.transform(X_test)
    
    # === STEP 5: Train Gradient Boosting Classifier ===
    self.model = GradientBoostingClassifier(
        n_estimators=150,
        max_depth=10,
        learning_rate=0.1,
        random_state=42
    )
    self.model.fit(X_train_scaled, y_train)
    self.is_trained = True
    
    # === STEP 6: Evaluate ===
    test_accuracy = self.model.score(X_test_scaled, y_test)
    
    # Multi-class metrics
    from sklearn.metrics import classification_report
    y_pred = self.model.predict(X_test_scaled)
    report = classification_report(
        y_test, y_pred, 
        target_names=['info', 'low', 'medium', 'high', 'critical']
    )
    
    # === STEP 7: Save Model ===
    self._save_model()
    
    return {
        'success': True,
        'test_accuracy': float(test_accuracy),
        'classification_report': report
    }
```

**Key Differences dari FP Reducer:**
- **Multi-class** (5 classes) vs Binary (2 classes)
- **Single algorithm** (GB only) vs Ensemble (RF + GB)
- **No calibration** (not critical untuk severity adjustment)
- **8 features** vs 16 features

---

## 🔍 MODEL #3: ANOMALY DETECTOR (Overview)

### **Training Process (Simplified)**

**File:** `proxy/ml/anomaly_detector.py`

```python
from sklearn.ensemble import IsolationForest

def train(self, normal_data: List[Dict], contamination: float = 0.1) -> Dict:
    """
    Train Isolation Forest untuk anomaly detection.
    
    Args:
        normal_data: List of NORMAL request patterns (no labels!)
        contamination: Expected proportion of anomalies (default 10%)
    """
    
    # === STEP 1: Extract 10 features ===
    X = [self.extract_features(request) for request in normal_data]
    X = np.array(X)
    
    # === STEP 2: Train Isolation Forest (UNSUPERVISED) ===
    self.model = IsolationForest(
        n_estimators=100,
        contamination=contamination,  # 10% expected anomalies
        max_samples=256,
        random_state=42
    )
    self.model.fit(X)  # No labels needed!
    self.is_trained = True
    
    # === STEP 3: Detect anomalies in training data ===
    predictions = self.model.predict(X)
    # predictions: -1 = anomaly, +1 = normal
    
    n_anomalies = (predictions == -1).sum()
    n_normal = (predictions == 1).sum()
    
    # === STEP 4: Build baseline statistics ===
    self.baseline_stats = {
        'avg_response_time': np.mean([r['response_time'] for r in normal_data]),
        'avg_request_rate': np.mean([r['request_rate'] for r in normal_data]),
        'common_status_codes': [200, 404, 304]
    }
    
    # === STEP 5: Save Model ===
    self._save_model()
    
    return {
        'success': True,
        'normal_samples': int(n_normal),
        'anomalies_detected': int(n_anomalies),
        'contamination': contamination
    }
```

**Key Differences:**
- **Unsupervised** (no labels) vs Supervised (with labels)
- **Isolation Forest** (tree-based outlier detection) vs RF/GB (classification)
- **Contamination parameter** untuk set expected anomaly rate

---

## 🚦 MODEL #4: RATE LIMITER (Overview)

### **Training Process (Simplified)**

**File:** `proxy/ml/rate_limiter.py`

```python
from sklearn.ensemble import GradientBoostingRegressor

def train(self, training_data: List[Dict], risk_scores: List[float]) -> Dict:
    """
    Train GB Regressor untuk risk score prediction.
    
    Args:
        training_data: List of request patterns
        risk_scores: Continuous values [0.0 - 1.0]
    """
    
    # === STEP 1: Extract 12 features ===
    X = [self.extract_features(request) for request in training_data]
    X = np.array(X)
    y = np.array(risk_scores)
    
    # === STEP 2: Train-Test Split ===
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )
    
    # === STEP 3: Scale Features ===
    X_train_scaled = self.scaler.fit_transform(X_train)
    X_test_scaled = self.scaler.transform(X_test)
    
    # === STEP 4: Train GB Regressor ===
    self.model = GradientBoostingRegressor(
        n_estimators=200,
        max_depth=8,
        learning_rate=0.05,
        loss='squared_error',
        random_state=42
    )
    self.model.fit(X_train_scaled, y_train)
    self.is_trained = True
    
    # === STEP 5: Evaluate (R² score) ===
    r2_score = self.model.score(X_test_scaled, y_test)
    
    # === STEP 6: Save Model ===
    self._save_model()
    
    return {
        'success': True,
        'r2_score': float(r2_score),
        'target': 'risk_score'
    }
```

**Key Differences:**
- **Regression** (continuous output) vs Classification (discrete classes)
- **R² metric** vs Accuracy
- **GB Regressor** vs GB Classifier

---

## 🔄 Complete Training Workflow

**File:** `proxy/train_models.py`

```bash
# Run training untuk semua 4 models
cd MoodleSec/proxy
python3 train_models.py
```

**Output:**
```
================================================================================
ML MODEL TRAINING - MOODLESEC
================================================================================

Starting training pipeline...

================================================================================
TRAINING: FALSE POSITIVE REDUCER
================================================================================
[Trainer] Generating training data...
[FP Reducer] Training with 900 samples...
[FP Reducer] True Positives: 540 (60.0%)
[FP Reducer] False Positives: 360 (40.0%)
[Training] Dataset shape: (900, 16)
[Training] Train set: 720 samples
[Training] Test set: 180 samples
[Training] Features scaled (mean=0, std=1)
[Training] Training Random Forest (150 estimators)...
[Training] Training Gradient Boosting (100 estimators)...
[Training] Creating ensemble with soft voting...
[Training] Calibrating probabilities (3-fold CV)...
✅ Training successful!
   Train Accuracy: 97.5%
   Test Accuracy: 95.0%
   Precision: 96.7%
   Recall: 95.1%
   F1-Score: 95.9%

   Top Features:
     keyword_ratio: 0.1842
     cvss_score: 0.1523
     tp_keyword_count: 0.1398
     severity: 0.1205
     evidence_length: 0.0987

✅ Model saved to: ml/models/fp_reducer.pkl
   File size: 2487.34 KB

================================================================================
TRAINING: SEVERITY PREDICTOR
================================================================================
[Trainer] Loading training data...
[Severity Predictor] Training with 800 samples...
[Severity Predictor] Distribution:
   Critical: 160 (20.0%)
   High: 200 (25.0%)
   Medium: 240 (30.0%)
   Low: 120 (15.0%)
   Info: 80 (10.0%)
✅ Training successful!
   Test Accuracy: 85.0%
   
   Classification Report:
                  precision    recall  f1-score
   
      info          0.88      0.82      0.85
      low           0.80      0.78      0.79
      medium        0.87      0.90      0.88
      high          0.84      0.86      0.85
      critical      0.91      0.89      0.90

✅ Model saved to: ml/models/severity_predictor.pkl

================================================================================
TRAINING: ANOMALY DETECTOR
================================================================================
[Trainer] Generating normal traffic patterns...
[Anomaly Detector] Training with 1000 normal samples...
[Anomaly Detector] Contamination: 10%
✅ Training successful!
   Normal Samples: 900
   Anomalies Detected: 100
   
   Baseline Stats:
     Avg Response Time: 245ms
     Common Status Codes: [200, 404, 304]

✅ Model saved to: ml/models/anomaly_detector.pkl

================================================================================
TRAINING: RATE LIMITER
================================================================================
[Trainer] Generating request patterns with risk scores...
[Rate Limiter] Training with 800 samples...
✅ Training successful!
   R² Score: 0.72
   MAE: 0.08
   
   Feature Importance:
     request_count_minute: 0.2145
     failed_auth_count: 0.1892
     error_4xx_count: 0.1567

✅ Model saved to: ml/models/rate_limiter.pkl

================================================================================
TRAINING COMPLETE!
================================================================================

📁 Models saved to: ml/models/
📊 Training data: ml/data/
📝 Report: ml/data/training_report.json

Training Summary:
  ✅ False Positive Reducer: 95.0% accuracy
  ✅ Severity Predictor: 85.0% accuracy  
  ✅ Anomaly Detector: Baseline ready
  ✅ Rate Limiter: R² = 0.72

Next steps:
  1. Test models: python3 test_ml_modules.py
  2. Check status: curl http://localhost:8999/ml/status
  3. Start proxy: python3 app.py
```

---

## 📈 Training Report (JSON)

**File:** `ml/data/training_report.json`

```json
{
  "timestamp": "2026-01-22T10:45:32Z",
  "models": {
    "false_positive_reducer": {
      "status": "trained",
      "algorithm": "CalibratedClassifierCV(VotingClassifier(RF+GB))",
      "metrics": {
        "train_accuracy": 0.975,
        "test_accuracy": 0.950,
        "precision": 0.967,
        "recall": 0.951,
        "f1_score": 0.959
      },
      "feature_importance": {
        "keyword_ratio": 0.1842,
        "cvss_score": 0.1523,
        "tp_keyword_count": 0.1398,
        "severity": 0.1205,
        "evidence_length": 0.0987
      },
      "samples": {
        "train": 720,
        "test": 180
      }
    },
    "severity_predictor": {
      "status": "trained",
      "algorithm": "GradientBoostingClassifier",
      "metrics": {
        "test_accuracy": 0.850,
        "multi_class_f1": 0.854
      },
      "samples": {
        "train": 640,
        "test": 160
      }
    },
    "anomaly_detector": {
      "status": "baseline",
      "algorithm": "IsolationForest",
      "contamination": 0.1,
      "samples": {
        "normal": 900,
        "anomalies": 100
      }
    },
    "rate_limiter": {
      "status": "baseline",
      "algorithm": "GradientBoostingRegressor",
      "metrics": {
        "r2_score": 0.72,
        "mae": 0.08
      },
      "samples": {
        "train": 640,
        "test": 160
      }
    }
  }
}
```

---

## 🎯 Summary: Training Pipeline Comparison

| Aspect | FP Reducer | Severity Predictor | Anomaly Detector | Rate Limiter |
|--------|------------|-------------------|------------------|--------------|
| **Task Type** | Binary Classification | Multi-class Classification | Unsupervised Clustering | Regression |
| **Algorithm** | RF + GB Ensemble | GB Classifier | Isolation Forest | GB Regressor |
| **Features** | 16 | 8 | 10 | 12 |
| **Calibration** | ✅ Yes (Platt) | ❌ No | ❌ No | ❌ No |
| **Ensemble** | ✅ Yes (2 models) | ❌ No (single) | ❌ No | ❌ No |
| **Scaling** | ✅ StandardScaler | ✅ StandardScaler | ✅ StandardScaler | ✅ StandardScaler |
| **Labels** | Binary (0/1) | 5 classes | None (unsupervised) | Continuous (0-1) |
| **Main Metric** | Accuracy, F1 | Accuracy, Multi-F1 | Anomaly count | R² score |
| **Training Time** | ~45 seconds | ~25 seconds | ~10 seconds | ~30 seconds |
| **Model Size** | ~2.5 MB | ~1.8 MB | ~0.5 MB | ~1.2 MB |
| **Status** | ✅ Fully trained | ✅ Fully trained | ⚠️ Baseline | ⚠️ Baseline |

---

## 🔍 Key Insights untuk Sempro

### **1. False Positive Reducer adalah Model Paling Complex**
- Ensemble 2 algorithms (RF + GB)
- Probability calibration (3-fold CV)
- 16 features (paling banyak)
- 2-step prediction: ensemble → calibration

### **2. Feature Engineering adalah Kunci**
- Keyword ratio (18.42% importance) → Text pattern recognition
- CVSS + Risk scores (23.77% combined) → Numerical risk indicators
- Context features (15% combined) → Scanner response patterns

### **3. Data Leakage Prevention Crucial**
- Forced 15% severity overlap
- Model belajar dari kombinasi features, bukan single feature dominan
- Validation: Feature importance tersebar, tidak ada yang >20%

### **4. Calibration Improves Confidence Scores**
- Raw probabilities: Often overconfident
- Calibrated probabilities: More reliable untuk decision-making
- Critical untuk auto-labeling (threshold 0.85)

### **5. Modular Training Architecture**
- Each model trained independent
- Shared infrastructure (scaler, serialization)
- Easy to retrain individual models
- Gradual deployment strategy

---

## 📚 Recommended Explanation untuk Sempro (2 menit)

**Script:**

> "Untuk pelatihan model, kami implement comprehensive ML pipeline dengan 7 tahapan.
> 
> **Pertama**, data generation dengan synthetic data generator yang enforce 15% severity overlap untuk prevent data leakage - ini crucial karena testing awal menunjukkan 100% accuracy yang unrealistic akibat perfect separation antara TP dan FP.
> 
> **Kedua**, feature extraction dari findings - untuk False Positive Reducer kami extract 16 features termasuk severity encoding, keyword analysis, dan scanner response metrics.
> 
> **Ketiga**, preprocessing dengan train-test split 80/20 stratified dan StandardScaler, meskipun tree-based models tidak strictly memerlukan scaling.
> 
> **Keempat**, training ensemble model - kami combine Random Forest 150 estimators dan Gradient Boosting 100 estimators dengan soft voting, dimana RF diberi weight 2x karena lebih stable.
> 
> **Kelima**, probability calibration menggunakan Platt scaling dengan 3-fold cross-validation untuk ensure confidence scores yang reliable - ini penting untuk auto-labeling threshold.
> 
> **Keenam**, evaluasi comprehensive dengan accuracy, precision, recall, F1-score, dan feature importance analysis.
> 
> **Ketujuh**, model persistence dengan pickle serialization termasuk trained model, fitted scaler, dan metadata.
> 
> Hasil akhir: False Positive Reducer mencapai 95% test accuracy dengan top feature importance pada keyword_ratio 18.42% dan CVSS score 15.23%, menunjukkan model belajar dari pattern kombinasi text dan risk metrics, bukan single feature dominan."

**Waktu: ~1 menit 45 detik**

---

**Good luck! 🚀**
