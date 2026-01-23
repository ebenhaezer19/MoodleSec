# Feature Scaling dan Class Imbalance - Penjelasan Detail

## 📚 Daftar Isi
1. [Feature Scaling](#1-feature-scaling)
2. [Class Imbalance](#2-class-imbalance)
3. [Kesimpulan untuk Sempro](#kesimpulan-untuk-sempro)

---

# 1. Feature Scaling

## 1.1 Apa itu Feature Scaling?

**Feature scaling** adalah proses mengubah nilai-nilai features agar berada dalam range yang sama atau serupa.

### Contoh Konkrit - Tanpa Scaling:

Bayangkan Anda punya 3 features:

```
Feature A: Salary (Gaji)         → Range: 5,000,000 - 50,000,000
Feature B: Age (Umur)            → Range: 22 - 60
Feature C: Years of Experience   → Range: 0 - 30
```

**Masalah:** Feature A punya magnitude (besaran) yang jauh lebih besar dari feature B dan C!

### Dalam Konteks ML Model Kita:

```python
# Data kita (sebelum scaling)
cvss_score       → Range: 0 - 10
severity_encoded → Range: 0 - 4
response_time    → Range: 50 - 5000
evidence_length  → Range: 10 - 500
url_complexity   → Range: 1 - 8
```

**Perbedaan magnitude sangat besar!**
- `response_time` bisa 5000
- `severity_encoded` maksimal hanya 4

---

## 1.2 Teknik Feature Scaling

### A. Min-Max Normalization (Normalisasi)

**Formula:**
```
X_scaled = (X - X_min) / (X_max - X_min)
```

**Hasil:** Semua nilai jadi antara 0 dan 1

**Contoh:**
```python
response_time = 2500
X_min = 50
X_max = 5000

X_scaled = (2500 - 50) / (5000 - 50)
         = 2450 / 4950
         = 0.495

# Jadi response_time 2500 → 0.495
```

**Sebelum scaling:**
```
response_time:    50,  1000,  2500,  5000
                  ↓      ↓      ↓      ↓
Setelah scaling:  0.0,  0.19,  0.49,  1.0
```

---

### B. Standardization (Z-score Normalization)

**Formula:**
```
X_scaled = (X - mean) / std_deviation
```

**Hasil:** Mean = 0, Standard Deviation = 1

**Contoh:**
```python
response_time = [50, 1000, 2500, 5000]
mean = 2137.5
std  = 2025.8

X_scaled = (2500 - 2137.5) / 2025.8
         = 362.5 / 2025.8
         = 0.179

# Jadi response_time 2500 → 0.179
```

**Sebelum scaling:**
```
response_time:    50,    1000,   2500,   5000
                  ↓       ↓       ↓       ↓
Setelah scaling:  -1.03, -0.56,  0.18,   1.41
```

---

## 1.3 Kenapa Tree-Based Models TIDAK Perlu Scaling?

### 🌳 Cara Kerja Decision Tree

Decision tree membuat keputusan berdasarkan **threshold (ambang batas)**:

```
                Root Node
                    │
            ┌───────┴───────┐
            │               │
     cvss_score > 5.5?      │
            │               │
       ┌────┴────┐          │
      YES       NO          │
       │         │          │
   Critical    Medium      Low
```

**Perhatikan:** Tree hanya peduli **"apakah nilai > threshold?"**

### Contoh Konkrit:

**SEBELUM SCALING:**
```python
# Decision tree rule
if cvss_score > 5.5:
    predict = "High Risk"
else:
    predict = "Low Risk"

# Data
cvss_score = 7.2  → 7.2 > 5.5? YES → High Risk ✓
cvss_score = 3.1  → 3.1 > 5.5? NO  → Low Risk ✓
```

**SETELAH SCALING (Min-Max 0-1):**
```python
# cvss_score scaled: [0, 10] → [0, 1]
# Original threshold 5.5 → Scaled 0.55

if cvss_score_scaled > 0.55:
    predict = "High Risk"
else:
    predict = "Low Risk"

# Data
cvss_score = 7.2  → scaled 0.72 → 0.72 > 0.55? YES → High Risk ✓
cvss_score = 3.1  → scaled 0.31 → 0.31 > 0.55? NO  → Low Risk ✓
```

**Hasil prediksi SAMA!** Tree hanya adjust threshold-nya saja.

### 📊 Visualisasi Perbandingan

**Feature: response_time dan cvss_score**

```
TANPA SCALING:
─────────────────────────────────────────────
response_time: |██████████████████████████| 5000
cvss_score:    |██| 10
─────────────────────────────────────────────

Decision tree split:
- response_time > 2500? (split value)
- cvss_score > 5.5?     (split value)

✓ Tree dapat split kedua features dengan baik


DENGAN SCALING (0-1):
─────────────────────────────────────────────
response_time: |████████████| 1.0
cvss_score:    |████████████| 1.0
─────────────────────────────────────────────

Decision tree split:
- response_time > 0.5?  (adjusted split value)
- cvss_score > 0.55?    (adjusted split value)

✓ Tree TETAP dapat split dengan baik (sama saja!)
```

**Kesimpulan:** Scale tidak berpengaruh karena tree hanya perlu tahu "mana yang lebih besar/kecil", bukan nilai absolutnya.

---

## 1.4 Model yang PERLU Scaling vs TIDAK PERLU

### ✅ TIDAK PERLU SCALING (Tree-Based Models)

1. **Decision Tree**
2. **Random Forest** ← Kita pakai ini
3. **Gradient Boosting** ← Kita pakai ini
4. **XGBoost**
5. **LightGBM**
6. **CatBoost**

**Alasan:**
- Berdasarkan threshold splits
- Invariant terhadap monotonic transformations
- Hanya peduli ranking/order, bukan magnitude

---

### ❌ PERLU SCALING (Distance-Based & Gradient-Based Models)

1. **Logistic Regression**
2. **Support Vector Machine (SVM)**
3. **K-Nearest Neighbors (KNN)**
4. **Neural Networks**
5. **Linear Regression**

**Alasan:**
- Menggunakan distance calculations
- Gradient descent sensitive to scale
- Feature dengan magnitude besar mendominasi

---

## 1.5 Kenapa Distance-Based Models Perlu Scaling?

### Contoh: K-Nearest Neighbors (KNN)

KNN mencari tetangga terdekat berdasarkan **Euclidean Distance**:

```
Distance = √[(x₁-x₂)² + (y₁-y₂)²]
```

**TANPA SCALING:**
```python
# Data Point A
cvss_score     = 7.0
response_time  = 1000

# Data Point B
cvss_score     = 7.5
response_time  = 2000

# Calculate distance
distance = √[(7.0-7.5)² + (1000-2000)²]
         = √[0.25 + 1,000,000]
         = √1,000,000.25
         = 1000.0001

# ❌ MASALAH: response_time mendominasi total distance!
# Perbedaan 0.5 di cvss_score vs 1000 di response_time
# → cvss_score jadi tidak berarti!
```

**DENGAN SCALING (0-1):**
```python
# Data Point A (scaled)
cvss_score     = 0.70  # (7.0 / 10)
response_time  = 0.20  # (1000 / 5000)

# Data Point B (scaled)
cvss_score     = 0.75  # (7.5 / 10)
response_time  = 0.40  # (2000 / 5000)

# Calculate distance
distance = √[(0.70-0.75)² + (0.20-0.40)²]
         = √[0.0025 + 0.04]
         = √0.0425
         = 0.206

# ✓ BAIK: Kedua features contribute secara seimbang!
```

---

### Contoh: Neural Network

Neural network menggunakan **gradient descent** untuk training:

```python
# Weight update formula
weight_new = weight_old - learning_rate * gradient
```

**TANPA SCALING:**
```
Feature A (response_time):  Range 0-5000
Feature B (cvss_score):     Range 0-10

Gradient untuk Feature A:  Bisa sangat besar (e.g., 1000)
Gradient untuk Feature B:  Kecil (e.g., 2)

Weight update:
- Weight A berubah drastis → Model unstable
- Weight B berubah pelan  → Convergence lambat
```

**DENGAN SCALING:**
```
Feature A: Range 0-1
Feature B: Range 0-1

Gradient seimbang → Training stabil & cepat!
```

---

## 1.6 Implementasi dalam Kode Kita

### Random Forest dan Gradient Boosting (Model Kita)

```python
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier

# ✓ TIDAK perlu scaling
X_train = features  # Raw features (no scaling needed)

rf = RandomForestClassifier(n_estimators=200)
gb = GradientBoostingClassifier(n_estimators=200)

# Train langsung tanpa scaling
rf.fit(X_train, y_train)
gb.fit(X_train, y_train)
```

**Output:**
```
RandomForestClassifier: Accuracy = 95%
GradientBoostingClassifier: Accuracy = 95%

✓ Bekerja sempurna tanpa scaling!
```

---

### Jika Pakai Neural Network (Hypothetical)

```python
from sklearn.preprocessing import StandardScaler
from sklearn.neural_network import MLPClassifier

# ❌ HARUS scaling!
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

nn = MLPClassifier(hidden_layer_sizes=(100, 50))
nn.fit(X_train_scaled, y_train)  # Pakai data yang sudah di-scale
```

**Tanpa scaling:**
```
MLPClassifier: Accuracy = 65% (buruk!)
Convergence warning: Did not converge
```

**Dengan scaling:**
```
MLPClassifier: Accuracy = 92% (bagus!)
Converged in 150 iterations
```

---

## 1.7 Analogi Sederhana

### 🎯 Analogi: Guru Nilai Ujian

**Guru A (Decision Tree):**
"Yang nilai Matematika > 70 dapat grade A, sisanya grade B"

- Apakah nilai dalam skala 0-100 atau 0-1 tidak penting
- Yang penting: "siapa di atas 70, siapa di bawah?"
- Kalau skala berubah jadi 0-1, threshold jadi 0.7
- **Hasil ranking siswa tetap sama!**

**Guru B (Neural Network):**
"Saya hitung nilai akhir dari weighted average semua mata pelajaran"

```
Final = 0.3*Math + 0.2*Physics + 0.5*Chemistry
```

- Kalau Math dalam skala 0-100, Physics 0-10, Chemistry 0-1
- Math akan dominan (karena magnitude besar!)
- **Tidak fair!**
- Perlu scaling dulu agar semua skala 0-1

---

# 2. Class Imbalance

## 2.1 Apa itu Class Imbalance?

**Class imbalance** terjadi ketika jumlah samples di satu class jauh lebih banyak dari class lain.

### Contoh:

```
Dataset Email Spam Detection:
┌──────────────────────┬──────────┬────────┐
│ Class                │ Samples  │ Ratio  │
├──────────────────────┼──────────┼────────┤
│ Legitimate Email     │  9,900   │  99%   │
│ Spam Email           │    100   │   1%   │
└──────────────────────┴──────────┴────────┘

❌ SEVERELY IMBALANCED (99:1)
```

---

## 2.2 Kenapa Class Imbalance Bermasalah?

### Problem: Majority Class Bias

Model bisa achieve **high accuracy** dengan cara "curang":

```python
# Naive model yang selalu predict "Legitimate"
def predict(email):
    return "Legitimate"  # Always!

# Accuracy
correct = 9,900  # Semua legitimate email benar
total   = 10,000
accuracy = 9900/10000 = 99%

# ❌ MISLEADING!
# Model tidak belajar apapun, tapi accuracy 99%!
# Spam emails (yang penting!) semua salah!
```

### Confusion Matrix Imbalanced Model:

```
                    PREDICTED
                ┌──────────┬──────────┐
                │  Legit   │   Spam   │
        ┌───────┼──────────┼──────────┤
        │ Legit │  9,900   │     0    │
ACTUAL  │       │   (TN)   │   (FP)   │
        ├───────┼──────────┼──────────┤
        │ Spam  │   100    │     0    │
        │       │   (FN)   │   (TP)   │
        └───────┴──────────┴──────────┘

Accuracy = (9900+0) / 10000 = 99%  ← Tinggi!
Recall for Spam = 0 / 100 = 0%     ← Buruk!

❌ Model gagal detect spam (padahal itu yang penting!)
```

---

## 2.3 Cara Deteksi Class Imbalance

### Method 1: Count Ratio

```python
from collections import Counter

# Count samples per class
class_counts = Counter(y_train)
print(class_counts)

# Output
Counter({'TP': 540, 'FP': 360})

# Calculate ratio
majority = 540
minority = 360
ratio = majority / minority
print(f"Ratio: {ratio:.2f}:1")

# Output: Ratio: 1.50:1
```

### Interpretation:

```
┌──────────────┬──────────┬───────────────────┐
│ Ratio        │ Status   │ Action Needed?    │
├──────────────┼──────────┼───────────────────┤
│ 1:1 to 2:1   │ Balanced │ ✅ No action      │
│ 3:1 to 5:1   │ Moderate │ ⚠️  Consider      │
│ 10:1 to 20:1 │ Severe   │ ❌ Must handle    │
│ > 100:1      │ Extreme  │ ❌ Critical issue │
└──────────────┴──────────┴───────────────────┘
```

---

## 2.4 Dataset Kita: 60:40 (Balanced!)

### Our Data Distribution:

```python
# Training data
Total samples: 900
True Positive (TP):  540 samples (60%)
False Positive (FP): 360 samples (40%)

Ratio: 540/360 = 1.5:1
```

### Visualization:

```
TP:  ████████████████████████████████████ 60%
FP:  ████████████████████████        40%

✓ BALANCED - No special handling needed!
```

### Why This is Good:

1. **Ratio < 2:1** → Considered balanced
2. **Model tidak bias** ke salah satu class
3. **Tidak perlu teknik khusus** (SMOTE, undersampling, class weights)
4. **Metrics reliable** (accuracy bukan misleading)

---

## 2.5 Teknik Handling Class Imbalance

### Situasi Hypothetical: Jika Data Kita Imbalanced

```python
# Hypothetical imbalanced data
Total: 1000 samples
TP:   950 samples (95%)  ← Majority
FP:    50 samples (5%)   ← Minority

Ratio: 19:1 (SEVERE!)
```

---

### Technique 1: Oversampling (SMOTE)

**SMOTE (Synthetic Minority Over-sampling Technique)**

**Konsep:** Buat synthetic samples untuk minority class

```python
from imblearn.over_sampling import SMOTE

# Before
TP: 950 samples
FP:  50 samples

# Apply SMOTE
smote = SMOTE(sampling_strategy='minority')
X_resampled, y_resampled = smote.fit_resample(X, y)

# After
TP: 950 samples
FP: 950 samples (900 synthetic + 50 original)

# Now balanced!
```

**Cara Kerja SMOTE:**

```
Original FP samples: A, B, C

1. Pilih sample A
2. Find 5 nearest neighbors (misal: B)
3. Create synthetic sample di antara A dan B

     A ●----------●------● B
          ↑       ↑
       Synthetic samples

4. Repeat until balanced
```

**Pros:**
- ✅ Tidak buang data original
- ✅ Generate samples baru (diversity)

**Cons:**
- ❌ Risk overfitting (synthetic data bisa terlalu mirip original)
- ❌ Computational cost tinggi

---

### Technique 2: Undersampling

**Konsep:** Kurangi majority class samples

```python
from imblearn.under_sampling import RandomUnderSampler

# Before
TP: 950 samples
FP:  50 samples

# Apply undersampling
rus = RandomUnderSampler(sampling_strategy='majority')
X_resampled, y_resampled = rus.fit_resample(X, y)

# After
TP:  50 samples (random pilih 50 dari 950)
FP:  50 samples (keep all)

# Balanced, tapi total data berkurang drastis!
```

**Pros:**
- ✅ Simple dan cepat
- ✅ Mengurangi training time

**Cons:**
- ❌ **Kehilangan data berharga** (900 TP samples dibuang!)
- ❌ Potential information loss

---

### Technique 3: Class Weights

**Konsep:** Beri "penalty" lebih besar untuk misclassify minority class

```python
from sklearn.ensemble import RandomForestClassifier

# Calculate class weights automatically
rf = RandomForestClassifier(
    n_estimators=200,
    class_weight='balanced'  # Auto-adjust weights
)

rf.fit(X_train, y_train)
```

**Cara Kerja:**

```
Normal cost (balanced data):
- Misclassify TP: Cost = 1
- Misclassify FP: Cost = 1

With class_weight='balanced' (imbalanced 19:1):
- Misclassify TP: Cost = 1
- Misclassify FP: Cost = 19 (penalized heavily!)

→ Model dipaksa fokus ke minority class
```

**Class Weight Formula:**

```python
weight_for_class = total_samples / (n_classes * samples_in_class)

# Example (19:1 ratio):
weight_TP = 1000 / (2 * 950) = 0.526
weight_FP = 1000 / (2 * 50)  = 10.0

# FP gets 19x more weight than TP!
```

**Pros:**
- ✅ Tidak perlu modify dataset
- ✅ Tidak kehilangan data
- ✅ Fast dan simple

**Cons:**
- ❌ Bisa overfit to minority class
- ❌ Perlu tuning weight ratio

---

## 2.6 Perbandingan Teknik

| Technique | Data Size | Training Time | Risk Overfitting | Best Use Case |
|-----------|-----------|---------------|------------------|---------------|
| **No Action** | Original | Fast | Low | Balanced data (our case!) |
| **SMOTE** | Increase | Slow | Medium | Moderate imbalance (5:1 - 10:1) |
| **Undersampling** | Decrease | Very Fast | Low | Extreme imbalance + lots of data |
| **Class Weights** | Original | Fast | Medium | Any imbalance + want to keep all data |

---

## 2.7 Evaluation Metrics untuk Imbalanced Data

### ❌ JANGAN HANYA PAKAI ACCURACY!

Untuk imbalanced data, gunakan metrics yang lebih informatif:

### 1. Confusion Matrix

```
                    PREDICTED
                ┌──────────┬──────────┐
                │    FP    │    TP    │
        ┌───────┼──────────┼──────────┤
        │  FP   │    74    │    6     │
ACTUAL  │       │   (TN)   │   (FN)   │
        ├───────┼──────────┼──────────┤
        │  TP   │    4     │   116    │
        │       │   (FP)   │   (TP)   │
        └───────┴──────────┴──────────┘

✓ Lihat semua jenis error (FP dan FN)
```

---

### 2. Precision

**"Dari semua yang diprediksi Positive, berapa yang benar?"**

```
Precision = TP / (TP + FP)
          = 116 / (116 + 4)
          = 116 / 120
          = 96.7%

Interpretation:
"Ketika model bilang 'ini True Positive', 
 ada 96.7% kemungkinan memang benar TP"
```

**Penting untuk:** Meminimalkan False Alarms

---

### 3. Recall (Sensitivity)

**"Dari semua actual Positive, berapa yang terdeteksi?"**

```
Recall = TP / (TP + FN)
       = 116 / (116 + 6)
       = 116 / 122
       = 95.1%

Interpretation:
"Model berhasil catch 95.1% dari semua real vulnerabilities"
```

**Penting untuk:** Meminimalkan Missed Detections

---

### 4. F1-Score

**"Harmonic mean of Precision and Recall"**

```
F1 = 2 * (Precision * Recall) / (Precision + Recall)
   = 2 * (0.967 * 0.951) / (0.967 + 0.951)
   = 2 * 0.919 / 1.918
   = 0.959

Interpretation:
"Overall balance between Precision and Recall"
```

**Penting untuk:** Single metric yang balance kedua aspek

---

### 5. ROC-AUC Score

**"Area Under ROC Curve"**

```
ROC Curve:
     1.0│         ████
        │      ███    
  TPR   │   ███       
(Recall)│ ██          
        │█            
     0.0└─────────────
        0.0    FPR    1.0

AUC = 0.95 (excellent!)

> 0.9:  Excellent
0.8-0.9: Good
0.7-0.8: Fair
< 0.7:  Poor
```

---

## 2.8 Our Model Performance (Balanced Data)

```python
# Our results with 60:40 balanced data
from sklearn.metrics import classification_report

print(classification_report(y_test, y_pred))
```

**Output:**
```
              precision    recall  f1-score   support

          FP       0.95      0.93      0.94        80
          TP       0.97      0.97      0.97       120

    accuracy                           0.95       200
   macro avg       0.96      0.95      0.95       200
weighted avg       0.95      0.95      0.95       200
```

**Interpretation:**

✅ **All metrics > 0.93** → Excellent performance!
✅ **Precision & Recall balanced** → No bias to either class
✅ **F1-score high (0.94-0.97)** → Reliable model

**Conclusion:** Balanced data menghasilkan model yang fair dan reliable!

---

# Kesimpulan untuk Sempro

## 📌 Poin-Poin Penting

### Feature Scaling

**Untuk presentasi, cukup bilang:**

> "Kami menggunakan Random Forest dan Gradient Boosting yang merupakan tree-based models. Models ini tidak memerlukan feature scaling karena hanya berdasarkan threshold splits, bukan distance calculations. Sehingga features seperti CVSS score (0-10) dan response time (0-5000ms) bisa langsung digunakan tanpa normalization."

**Jika ditanya detail:**
- Tree-based models invariant terhadap scale
- Hanya perlu ranking/order features, bukan magnitude
- Berbeda dengan neural network atau SVM yang sensitive to scale

---

### Class Imbalance

**Untuk presentasi, cukup bilang:**

> "Dataset training kami memiliki ratio 60:40 (TP:FP) yang termasuk kategori balanced. Dengan ratio < 2:1, kami tidak perlu teknik khusus seperti SMOTE atau class weights. Model evaluation menggunakan multiple metrics (precision, recall, F1-score) untuk memastikan tidak ada bias ke salah satu class."

**Jika ditanya detail:**
- Balanced data (1.5:1) tidak perlu intervention
- Jika imbalanced berat (>10:1), bisa pakai SMOTE/class weights
- Metrics kami seimbang (precision 95%, recall 97%)

---

## 🎯 Script Sempro (30 detik)

**Gabungan Preprocessing + Scaling + Class Balance:**

> "Untuk data preprocessing, kami ekstrak 16 numerical features dari raw findings. Model yang digunakan adalah Random Forest dan Gradient Boosting yang tidak memerlukan feature scaling karena tree-based. Dataset memiliki ratio 60:40 (TP:FP) yang balanced, sehingga tidak perlu teknik handling imbalance. Evaluasi menggunakan precision, recall, dan F1-score untuk memastikan model fair terhadap kedua class."

---

## ❓ Antisipasi Pertanyaan

**Q1: "Kenapa tidak pakai neural network yang lebih canggih?"**

**A1:** "Neural network memerlukan:
1. Dataset yang jauh lebih besar (ribuan samples minimum)
2. Feature scaling yang teliti
3. Hyperparameter tuning yang kompleks
4. Computational resources lebih tinggi

Dengan 900 samples, tree-based ensemble models lebih cocok dan terbukti mencapai 95% accuracy yang sangat baik untuk production use."

---

**Q2: "Bagaimana kalau nanti di production data jadi imbalanced?"**

**A2:** "Kami punya contingency plan:
1. Monitor class distribution secara periodic
2. Jika ratio > 5:1, apply SMOTE atau class_weight='balanced'
3. Retrain model dengan data baru
4. A/B testing untuk compare performance

Framework sudah modular, mudah untuk add balancing techniques."

---

**Q3: "Apakah tidak scaling bisa pengaruh feature importance?"**

**A3:** "Tidak. Feature importance di tree-based models berdasarkan seberapa sering feature digunakan untuk split dan seberapa besar reduction in impurity, bukan magnitude values. Jadi CVSS score (0-10) dan response_time (0-5000) punya equal opportunity untuk jadi important features."

---

## 📊 Diagram untuk PPT (Opsional)

Jika ada waktu, bisa tambahkan 1 slide perbandingan:

```
┌─────────────────────────────────────────────────────┐
│  WHY TREE-BASED MODELS FOR OUR USE CASE?           │
├─────────────────────────────────────────────────────┤
│                                                     │
│  ✅ Random Forest + Gradient Boosting               │
│     • No feature scaling needed                    │
│     • Handle mixed feature scales well             │
│     • Robust to outliers                           │
│     • Good with moderate dataset (900 samples)     │
│     • Fast training (<5 min)                       │
│     • High interpretability (feature importance)   │
│     • 95% accuracy achieved                        │
│                                                     │
│  ❌ Neural Network (Why not?)                       │
│     • Need feature scaling                         │
│     • Need large dataset (>10k samples)            │
│     • Long training time                           │
│     • Black box (harder to interpret)              │
│     • Risk overfitting with small data             │
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

**Semoga penjelasan ini membantu Anda memahami dengan baik! 🚀**
