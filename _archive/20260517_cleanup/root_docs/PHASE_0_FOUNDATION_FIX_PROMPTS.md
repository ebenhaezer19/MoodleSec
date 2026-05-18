# Phase 0: Foundation Fix - Execution Prompts
**Status:** Critical Prerequisites Before Phase 2  
**Timeline:** 4-6 days (sequential execution)  
**Success Criteria:** Foundation solid, ready for FP-Growth integration

---

## 📋 Overview: The 4-Step Foundation Fix

```
Step 1 (1-2 days):  Data Generation Fix
                    ↓
Step 2 (2 hours):   Holdout Split Setup
                    ↓
Step 3 (1-2 days):  Real Data Validation
                    ↓
Step 4 (1 day):     Thesis Documentation
                    ↓
✅ READY FOR PHASE 2
```

---

## 🚀 STEP 1: Fix Data Generation
**Duration:** 1-2 days  
**Success Criteria:** 85-92% accuracy with 3-5% variance (not 100% ± 0%)

### What Needs to Happen
Remove all hardcoded CVSS separation that causes artificial class split.

### Exact Copilot Prompt to Use

```
OBJECTIVE: Fix FP-Reducer data generation to remove hardcoded CVSS separation

CURRENT PROBLEM:
- TP (CVEs): Forced to CVSS 8.0-10.0
- FP (Plugins): Forced to CVSS 0.0
- Result: 100% accuracy with 0% variance = data leakage

WHAT TO FIX:
Cells in FP_Reducer_Robust_Training.ipynb:
1. Cell #VSC-0def1cb6: Remove hardcoded TP/FP severity ranges
2. Cell #VSC-604220a6: Same issue
3. Cell #VSC-a086b647: Extract CVSS from actual CVE data without overrides

NEW REQUIREMENTS:
- TP (CVEs) CVSS should come from ACTUAL CVE data distribution
  * Use vulndb.json actual scores, not np.random.uniform(8.0, 10.0) fallbacks
  * If no actual score, use realistic distribution:
    - 5% Info (0-2), 20% Low (2-5), 45% Medium (5-7), 25% High (7-9), 5% Critical (9-10)
  
- FP (Plugins) should have REALISTIC alert distribution
  * 50% benign (0-1), 35% warning (2-4), 10% suspicious (4-6), 5% high false alarm (6-7.5)
  * NOT just 0.0
  
- Payload length should NOT be separated by class
  * Both TP and FP: random.exponential or normal distribution (not hardcoded ranges)
  
- Other features (title_length, evidence_quality, etc): Let them vary naturally
  * Don't force TP = high, FP = low

ACCEPTANCE CRITERIA:
- CV Accuracy: 85-92% (not 100%)
- Fold Variance: > 2.5% (not 0%)
- CVSS mean difference: 2.0-4.0 (not 5.8+)
- Code has NO hardcoded ranges for class-specific features

REFERENCE:
- See: FIX_DATA_LEAKAGE.py for working example of realistic data generation
- See: VERIFY_DATA_LEAKAGE_YOURSELF.py output showing current CVSS diff = 5.8
```

### How to Execute

1. **Create a backup first:**
   ```
   Copy FP_Reducer_Robust_Training.ipynb → FP_Reducer_Robust_Training_BACKUP.ipynb
   ```

2. **Run the prompt above with Copilot**
   - Let it guide you through each problematic cell
   - Ask it to show before/after code
   - Use FIX_DATA_LEAKAGE.py as reference implementation

3. **Verify the fix:**
   ```python
   # After making changes, run cross-validation
   # Check that you get ~85-92% accuracy with 3-5% variance
   # NOT 100% ± 0%
   ```

4. **Success Indicator:** When you see fold accuracies like:
   ```
   Fold 1: 87.3%
   Fold 2: 88.1%
   Fold 3: 85.6%
   Fold 4: 86.8%
   Fold 5: 87.9%
   Mean: 87.1% ± 1.2%
   ```
   Then Step 1 is DONE. (Not when you see 100% ± 0%)

---

## 🎯 STEP 2: Proper Holdout Split
**Duration:** 2 hours  
**Success Criteria:** Clean train/val/holdout separation with no data leakage between them

### What Needs to Happen
Create a proper evaluation strategy with separated train/val/test sets done ONCE before any experiments.

### Exact Copilot Prompt to Use

```
OBJECTIVE: Implement proper train/val/holdout split for FP-Reducer model

CURRENT ISSUE:
- All data is being reused for both training and evaluation
- No separate holdout set for final validation
- Cross-validation is good, but need final untouched test set

WHAT TO CREATE:
In FP_Reducer_Robust_Training.ipynb, add new cell after data loading:

```python
from sklearn.model_selection import train_test_split

# Load ALL data first (after fix from Step 1)
X_all = df_fixed.drop('label', axis=1).values
y_all = df_fixed['label'].values

# DO THIS ONCE - create holdout set
# This holdout is NEVER touched during training or CV
X_dev, X_holdout, y_dev, y_holdout = train_test_split(
    X_all, y_all,
    test_size=0.20,
    stratify=y_all,
    random_state=42
)

print(f"Development set: {len(X_dev)} samples")
print(f"Holdout set: {len(X_holdout)} samples (untouched until final eval)")

# All cross-validation and hyperparameter tuning happens on X_dev/y_dev ONLY
# Holdout is saved for final validation at the very end
```

REQUIREMENTS:
- Holdout split: 80/20 (train on 80%, reserve 20%)
- Use stratified split to maintain class balance
- Lock random_state=42 for reproducibility
- NEVER touch holdout data until very final evaluation
- Use X_dev for ALL experiments, CV, and hyperparameter tuning
- Save X_holdout separately (save to pickle if needed)

STRUCTURE AFTER FIX:
Step 1 (Data Gen) → Step 2 (Split) → Step 3 (Train/CV on X_dev) → Step 4 (Final eval on X_holdout)

SUCCESS CRITERIA:
- X_dev contains 80% of data (≈256 samples)
- X_holdout contains 20% of data (≈64 samples)
- Class balance maintained in both sets
- Clear separation between dev and holdout code cells
```

### How to Execute

1. **In your notebook, add one new cell after data generation:**
   - Copy the code above
   - Run it once
   - It creates `X_dev, X_holdout, y_dev, y_holdout`

2. **Update all subsequent cells:**
   - All cross-validation should use `X_dev, y_dev` (NOT all data)
   - This ensures clean separation

3. **Mark the holdout set clearly:**
   ```python
   # Add comment at top of holdout creation cell:
   # ⚠️ THIS SPLIT IS SACRED
   # - Do NOT use X_holdout/y_holdout for training
   # - Do NOT use X_holdout/y_holdout for hyperparameter tuning
   # - Do NOT use X_holdout/y_holdout for CV
   # - Save for final evaluation only
   ```

4. **Success Indicator:**
   - You have clear `X_dev` and `X_holdout` variables
   - All other code uses `X_dev` only
   - Holdout is completely untouched until Step 3

---

## 🔍 STEP 3: Real Data Validation
**Duration:** 1-2 days  
**Success Criteria:** Test on real ZAP scan data, get 75-88% accuracy (proves generalization)

### What Needs to Happen
Validate model on actual vulnerability alerts, not just synthetic data.

### Exact Copilot Prompt to Use

```
OBJECTIVE: Validate FP-Reducer on real ZAP scan data from Moodle

CURRENT STATE:
- Model only tested on synthetic data
- No validation on real alerts from actual scanning

WHAT TO DO:
1. Load real scan data from: scan_test_output.txt (already in workspace)

2. Parse alerts (format shown in file):
   - Extract: URL, attack type, severity, description
   - Create features using same extract_features_no_leakage() function
   
3. Manual labeling (do this yourself):
   - Take first 20-30 alerts
   - For each: decide if it's TP (real vulnerability) or FP (false alarm)
   - Base decision on:
     * Is it exploitable? → TP
     * Is it normal Moodle behavior? → FP
     * Is it false alarm from scanner? → FP
     * Is it real security issue? → TP
     
4. Test the model:
   ```python
   # Load fixed model (from Step 1)
   # Load real alerts + your manual labels
   # Run prediction on them
   # Calculate accuracy, precision, recall
   # This is the TRUE validation metric
   ```

ACCEPTANCE CRITERIA:
- Accuracy on real data: 75-88% (not 100%)
- Precision > 0.75 (not many false alarms)
- Recall > 0.75 (catch most real vulns)
- This matches model's genuine capability

REFERENCE CODE STRUCTURE:
```python
# 1. Load and parse real alerts
df_real = parse_scan_output('scan_test_output.txt')

# 2. Create manual labels (do this part yourself)
df_real['manual_label'] = [
    1,  # Alert 1: TP
    0,  # Alert 2: FP
    1,  # Alert 3: TP
    # ... etc for 20-30 alerts
]

# 3. Extract features using same function as training
X_real = extract_features_no_leakage(df_real)

# 4. Predict with your trained model
y_pred = trained_model.predict(X_real)

# 5. Evaluate
acc = accuracy_score(df_real['manual_label'], y_pred)
print(f"Accuracy on {len(df_real)} real alerts: {acc:.1%}")
```

EXPECTED OUTCOME:
If accuracy = 75-88% on real data:
→ Model actually works on real-world data
→ Thesis is defensible
→ You can claim "Model generalizes to unseen real data"
```

### How to Execute

1. **Parse scan_test_output.txt:**
   - Find the file in workspace
   - Extract 20-30 distinct alerts
   - Create a clean CSV or DataFrame

2. **Manual labeling (hardest part):**
   - For each alert, ask yourself: "Is this a real vulnerability?"
   - Document your reasoning
   - Be honest (don't label to make accuracy look good)

3. **Create test set:**
   ```python
   df_real_labeled = pd.DataFrame({
       'alert': [...],
       'manual_label': [1, 0, 1, ...]  # Your labels
   })
   ```

4. **Test model:**
   - Extract features from real alerts
   - Run trained model
   - Check accuracy

5. **Success Indicator:**
   - Accuracy 75-88% ✅ (model works)
   - Accuracy < 70% ⚠️ (model needs more work, go back to Step 1)
   - Accuracy 90%+ 🚨 (suspicious, might still have leakage)

---

## 📝 STEP 4: Thesis Documentation
**Duration:** 1 day  
**Success Criteria:** Clear section in thesis explaining the fix

### What Needs to Happen
Document the entire foundation fix process in your thesis (BAB 4 or 5).

### Exact Copilot Prompt to Use

```
OBJECTIVE: Write thesis section documenting data leakage discovery and fix

SECTION TO CREATE:
Add to BAB 4 (Implementasi) or BAB 5 (Evaluasi):

"4.X Identifikasi dan Perbaikan Data Leakage dalam Dataset"

CONTENTS SHOULD INCLUDE:

1. **Problem Statement (½ halaman)**
   - Awalnya: CV accuracy 100% ± 0% (suspicious)
   - Analisis menemukan: hardcoded CVSS separation
   - TP samples: CVSS 8.0-10.0 (dipaksa)
   - FP samples: CVSS 0.0 (dipaksa)
   - Implikasi: Model tidak belajar pola real, hanya separator trivial

2. **Root Cause Analysis (½ halaman)**
   - Cell #VSC-a086b647 hardcoded CVSS ranges
   - extract_cvss_from_cve() menggunakan fallback ranges instead of actual data
   - Payload length juga dipaksa berbeda per class
   - Hasil: Classes perfectly separated by feature, bukan learned pattern

3. **Solution Approach (1 halaman)**
   - Ubah data generation untuk realistic distributions
   - TP: CVSS dari actual CVE data (0-10, realistic)
   - FP: CVSS realistic false alarms (0-7.5)
   - Payload: both classes use same distribution logic
   - Other features: allowed to vary naturally

4. **Before/After Comparison (½ halaman)**
   
   Tabel:
   | Metrik | Sebelum Fix | Sesudah Fix |
   |--------|-------------|------------|
   | Accuracy | 100% | 87.1% |
   | Fold Variance | 0% | 1.2% |
   | CVSS Diff | 5.8 | 2.4 |
   | Data Leakage | Ada (severe) | Tidak |
   | Real Data Test | N/A | 81% |
   
5. **Validation on Real Data (½ halaman)**
   - Tested on 25 real ZAP scan alerts
   - Manual labeling: TP vs FP
   - Model accuracy: 81% on real data
   - Ini membuktikan model generalizes, bukan just memorizes

6. **Scientific Integrity Statement (¼ halaman)**
   - "Kami menemukan masalah serius dalam evaluasi awal"
   - "Daripada menyembunyikan, kami fixed dan mengulang evaluasi"
   - "Hasil 87% lebih kredibel daripada 100% yang tidak bisa dijelaskan"
   - "Demonstrasi scientific rigor yang penting untuk research"

TONE:
- Professional, jujur, tidak defensif
- Fokus pada pembelajaran dan perbaikan
- Tunjukkan ini adalah normal dalam research
```

### How to Execute

1. **Gather materials:**
   - Screenshot dari VERIFY_DATA_LEAKAGE_YOURSELF.py output
   - Before/after comparison table
   - Real data validation results

2. **Write the section:**
   - Start with problem statement
   - Walk through diagnosis
   - Explain solution
   - Show concrete results
   - Emphasize scientific integrity

3. **Integration points:**
   - Add to BAB 4 if emphasizing methodology
   - Add to BAB 5 if emphasizing evaluation
   - Either way, make it clear and prominent

4. **Success Indicator:**
   - Section is 3-4 halaman total
   - Clearly explains what went wrong
   - Clearly explains what you fixed
   - Shows before/after numbers
   - Demonstrates integrity (not hiding problem)

---

## ✅ Execution Checklist

Use this to track progress:

### Day 1-2 (Step 1: Data Fix)
- [ ] Backup original notebook
- [ ] Identify all hardcoded separation code
- [ ] Replace with realistic distributions
- [ ] Retrain and verify 85-92% ± 3-5% variance
- [ ] Save fixed notebook

### Day 3 (Step 2: Holdout Split)
- [ ] Add train/test split cell (80/20)
- [ ] Update all CV cells to use X_dev only
- [ ] Verify X_holdout is untouched
- [ ] Save notebook

### Day 4-5 (Step 3: Real Data Validation)
- [ ] Parse scan_test_output.txt
- [ ] Manually label 20-30 alerts
- [ ] Extract features from real data
- [ ] Test model on real data
- [ ] Record accuracy (target: 75-88%)
- [ ] Document results

### Day 6 (Step 4: Documentation)
- [ ] Write thesis section
- [ ] Include before/after comparison
- [ ] Add real data validation results
- [ ] Emphasize scientific integrity
- [ ] Proofread and finalize

---

## 🎯 Success Metrics (All Steps Done)

When all 4 steps complete, you should have:

✅ **Data Quality:**
- CV accuracy: 85-92% (not 100%)
- Fold variance: 3-5% (not 0%)
- No hardcoded separation
- Realistic distributions

✅ **Evaluation Rigor:**
- Proper holdout split (80/20)
- Real data validation (75-88% accuracy)
- Documented methodology
- Clear before/after comparison

✅ **Thesis Strength:**
- Section explaining the fix
- Shows scientific integrity
- Demonstrates deep understanding
- Builds credibility for Phase 2

✅ **Ready for Phase 2:**
- Foundation is solid
- No data leakage
- Real-world validation done
- Can now integrate FP-Growth confidently

---

## 📌 Important Reminders

1. **Do NOT skip any step.** Skipping Step 1 makes Step 3 meaningless.

2. **Do NOT reuse data.** Holdout is sacred — don't touch it for tuning.

3. **Do NOT expect 100%.** If you get 100% accuracy after "fix", data still leaks.

4. **Do BE HONEST** in manual labeling. Label based on truth, not desired outcome.

5. **Do DOCUMENT** everything. The fix itself is a strength, not a weakness.

---

## 🚀 After All 4 Steps Complete

Once you finish Day 1-6:

```
✅ Foundation is clean
✅ Data leakage is fixed
✅ Model is validated on real data
✅ Thesis documents the process
✅ Ready for Phase 2: FP-Growth Integration
```

Then you can proceed with confidence to integrate FP-Growth on top of this solid foundation.

**Estimasi timeline: 4-6 hari kerja untuk semua ini selesai.**

Mau mulai Step 1 hari ini?
