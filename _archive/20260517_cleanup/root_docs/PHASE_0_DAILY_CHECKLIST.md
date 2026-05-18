# PHASE 0: Daily Execution Checklist
**Goal:** Selesaikan Foundation Fix dalam 4-6 hari  
**Status:** Ready to Start  

---

## 📅 Timeline at a Glance

```
Day 1-2: STEP 1 - Data Generation Fix       [ ] Not Started [ ] In Progress [ ] Done
Day 3:   STEP 2 - Holdout Split Setup       [ ] Not Started [ ] In Progress [ ] Done
Day 4-5: STEP 3 - Real Data Validation      [ ] Not Started [ ] In Progress [ ] Done
Day 6:   STEP 4 - Thesis Documentation      [ ] Not Started [ ] In Progress [ ] Done
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
         PHASE 0 COMPLETE ✅ → Ready for Phase 2
```

---

## 🚀 STEP 1: Data Generation Fix
**Estimated:** 1-2 days  
**Target Outcome:** 85-92% ± 3-5% variance (not 100% ± 0%)

### Daily Checklist

**Hour 1-2: Understanding**
- [ ] Read PHASE_0_FOUNDATION_FIX_PROMPTS.md Section "STEP 1"
- [ ] Open FIX_DATA_LEAKAGE.py to see reference implementation
- [ ] Understand: Why hardcoded CVSS = problem

**Hour 3-4: Identification**
- [ ] Open FP_Reducer_Robust_Training.ipynb
- [ ] Locate Cell #VSC-0def1cb6 (hardcoded TP severity)
- [ ] Locate Cell #VSC-604220a6 (hardcoded FP severity)
- [ ] Locate Cell #VSC-a086b647 (CVSS extraction with fallbacks)
- [ ] Screenshot these cells for reference

**Hour 5-6: Backup & Prep**
- [ ] Backup original: `cp FP_Reducer_Robust_Training.ipynb FP_Reducer_Robust_Training_BACKUP.ipynb`
- [ ] Create new development branch/copy
- [ ] Gather reference code from FIX_DATA_LEAKAGE.py

**Day 2, Hour 1-4: Implementation**
- [ ] Use Copilot prompt from PHASE_0_FOUNDATION_FIX_PROMPTS.md
- [ ] Fix Cell #VSC-0def1cb6: Remove hardcoded severity for TP
- [ ] Fix Cell #VSC-604220a6: Remove hardcoded severity for FP
- [ ] Fix Cell #VSC-a086b647: Use actual CVSS from data, not random.uniform(8.0, 10.0)
- [ ] Make sure payload_length is NOT separated by class

**Day 2, Hour 5-8: Verification**
- [ ] Run complete notebook with fixed data
- [ ] Check CV Accuracy: Should be 85-92% (if 100%, something still wrong)
- [ ] Check Fold Variance: Should be > 2.5% (if 0%, data still leaks)
- [ ] Check CVSS difference: Should be 2.0-4.0 (if 5.8+, still has hardcoding)
- [ ] Print results for documentation

**Success Indicator:**
```
Fold 1: 87.3% | Fold 2: 88.1% | Fold 3: 85.6% | Fold 4: 86.8% | Fold 5: 87.9%
Mean: 87.1% ± 1.2%
TP CVSS: 0.2-9.8 (mean 6.1)
FP CVSS: 0.0-7.3 (mean 1.9)
CVSS Difference: 4.1
✅ STEP 1 COMPLETE
```

**If accuracy still 100%:**
- [ ] Find remaining hardcoded separation
- [ ] Check if all features are truly randomized
- [ ] Ask Copilot: "Why is accuracy still 100% after fix?"

---

## 🎯 STEP 2: Holdout Split Setup
**Estimated:** 2 hours  
**Target:** Clean 80/20 separation with no data leakage

### Daily Checklist

**Hour 1: Create Split Cell**
- [ ] In notebook, add new cell after data loading
- [ ] Copy code from PHASE_0_FOUNDATION_FIX_PROMPTS.md Section "STEP 2"
- [ ] Execute the cell
- [ ] Verify: `len(X_dev)` ≈ 256, `len(X_holdout)` ≈ 64

**Hour 2: Update Other Cells**
- [ ] Find all CV cells that use `X, y`
- [ ] Change to use `X_dev, y_dev`
- [ ] Add comment: "⚠️ Using development set only, not holdout"
- [ ] Verify all cells that should use dev set are updated
- [ ] Run to confirm no errors

**Success Indicator:**
```python
X_dev shape: (256, 16)    # 80% of data
X_holdout shape: (64, 16) # 20% of data
Class balance maintained
All subsequent code uses X_dev ✅
Holdout untouched ✅
```

---

## 🔍 STEP 3: Real Data Validation
**Estimated:** 1-2 days  
**Target:** 75-88% accuracy on real ZAP alerts

### Daily Checklist

**Hour 1-2: Data Preparation**
- [ ] Locate `scan_test_output.txt` in workspace
- [ ] Open and examine format
- [ ] Extract 20-30 distinct alerts
- [ ] Create clean CSV or DataFrame from them
- [ ] Save as `real_zap_alerts.csv`

**Hour 3-6: Manual Labeling (Most important!)**
- [ ] For each alert, read carefully
- [ ] Ask: "Is this a real security vulnerability?"
  - [ ] Can it actually be exploited? → TP (label = 1)
  - [ ] Is it normal Moodle behavior? → FP (label = 0)
  - [ ] False alarm from scanner? → FP (label = 0)
  - [ ] Actual vulnerability? → TP (label = 1)
- [ ] Document your reasoning briefly
- [ ] Create manual labels: `y_real = [1, 0, 1, ...]`
- [ ] Save labeled data

**Day 2, Hour 1-4: Model Validation**
- [ ] Load trained model from Step 1
- [ ] Load labeled real alerts
- [ ] Extract features using same `extract_features_no_leakage()` function
- [ ] Run prediction: `y_pred = model.predict(X_real)`
- [ ] Calculate metrics:
  ```python
  accuracy = accuracy_score(y_real, y_pred)
  precision = precision_score(y_real, y_pred)
  recall = recall_score(y_real, y_pred)
  f1 = f1_score(y_real, y_pred)
  ```
- [ ] Save results

**Success Indicator:**
```
Real ZAP Data Results:
Accuracy:  78.2%     ✅ (75-88% range)
Precision: 76.5%     ✅ (> 0.75)
Recall:    80.1%     ✅ (> 0.75)
F1-Score:  0.783     ✅

Model generalizes to real data ✅
```

**If accuracy < 70%:**
- [ ] Go back to Step 1
- [ ] Check if fix was applied correctly
- [ ] May need better features or more training data

**If accuracy 90%+:**
- [ ] Suspicious — might still have data leakage
- [ ] Double-check manual labels are honest
- [ ] Review feature extraction for leakage

---

## 📝 STEP 4: Thesis Documentation
**Estimated:** 1 day  
**Target:** Clear section in BAB 4/5 explaining the fix

### Daily Checklist

**Hour 1-2: Outline**
- [ ] Decide: Add to BAB 4 (Implementasi) or BAB 5 (Evaluasi)?
- [ ] Outline sections:
  - [ ] Problem statement (½ halaman)
  - [ ] Root cause analysis (½ halaman)
  - [ ] Solution approach (1 halaman)
  - [ ] Before/after comparison (½ halaman)
  - [ ] Validation results (½ halaman)
  - [ ] Integrity statement (¼ halaman)

**Hour 3-4: Writing**
- [ ] Start with problem statement
- [ ] Use PHASE_0_FOUNDATION_FIX_PROMPTS.md as template
- [ ] Explain what went wrong (clearly but not shame)
- [ ] Explain how you fixed it (step-by-step)
- [ ] Show before/after numbers (concrete evidence)

**Hour 5-6: Integration**
- [ ] Create before/after comparison table:
  ```
  | Metrik | Sebelum | Sesudah |
  |--------|--------|--------|
  | Accuracy | 100% | 87.1% |
  | Variance | 0% | 1.2% |
  | CVSS Diff | 5.8 | 2.4 |
  | Real Data Test | N/A | 81% |
  ```
- [ ] Add screenshots from VERIFY_DATA_LEAKAGE_YOURSELF.py
- [ ] Add real data validation results

**Hour 7-8: Polish**
- [ ] Read through for clarity
- [ ] Check grammar and flow
- [ ] Ensure tone is professional and honest (not defensive)
- [ ] Final proofread
- [ ] Save document

**Success Indicator:**
```
Section completed: 3-4 halaman
✅ Problem clearly explained
✅ Root cause identified
✅ Solution documented
✅ Before/after numbers shown
✅ Real data validation included
✅ Integrity emphasized
✅ Professional tone maintained
```

---

## 🏁 Final Verification Checklist

Once all 4 steps complete:

### Data Quality
- [ ] CV Accuracy: 85-92%
- [ ] Fold Variance: > 2.5%
- [ ] CVSS Difference: 2.0-4.0
- [ ] No hardcoded feature separation

### Evaluation Rigor
- [ ] Holdout split: Clean 80/20
- [ ] Real data test: 75-88% accuracy
- [ ] All features: Realistic distributions
- [ ] No data leakage: Verified

### Thesis Quality
- [ ] Section 4.X completed: 3-4 halaman
- [ ] Before/after comparison: Clear numbers
- [ ] Real data validation: Documented
- [ ] Scientific integrity: Demonstrated

### Ready for Phase 2?
- [ ] Foundation fix complete ✅
- [ ] Data leakage eliminated ✅
- [ ] Model validated on real data ✅
- [ ] Process documented in thesis ✅
- [ ] **READY TO INTEGRATE FP-GROWTH** ✅

---

## 📞 Troubleshooting

**"Accuracy is still 100% after my fix"**
→ You still have hardcoded separation somewhere
→ Check: CVSS ranges, severity mapping, payload_length bounds
→ Use Copilot: "Find remaining hardcoded separation in my code"

**"CVSS difference is still 5.0+"**
→ extract_cvss_from_cve() still using fallback ranges
→ Fix: Use actual data instead of `np.random.uniform(8.0, 10.0)`

**"Real data accuracy is 60%"**
→ Model might need more training data or better features
→ Or: Your manual labels might be inconsistent
→ Check: Are you labeling truthfully or trying to make accuracy look good?

**"Fold variance is still 0%"**
→ Data still has perfect separation
→ Go back to Step 1, something was missed
→ Run VERIFY_DATA_LEAKAGE_YOURSELF.py to diagnose

---

## 💡 Pro Tips

1. **Save progress daily** - Don't lose work
2. **Keep both versions** - Original BACKUP + Fixed version
3. **Document decisions** - Especially manual labeling rationale
4. **Be honest** - If model isn't 85-92%, that's okay (better than 100%)
5. **Take breaks** - Manual labeling is tedious, don't rush it

---

## 📊 Daily Progress Log

Use this to track actual progress:

```
DAY 1:
⏰ Start time: ___:___
✅ Completed: 
⏱️  Total hours: ___
📝 Notes: 

DAY 2:
⏰ Start time: ___:___
✅ Completed: 
⏱️  Total hours: ___
📝 Notes:

[Continue for each day...]
```

---

## ✨ When Phase 0 is Complete

You'll have:
- ✅ **Data:** Clean, no leakage, realistic distributions
- ✅ **Evaluation:** Proper train/val/test separation
- ✅ **Validation:** Tested on real ZAP data
- ✅ **Documentation:** Process explained in thesis
- ✅ **Integrity:** Demonstrated scientific rigor

**Result:** Solid foundation to build Phase 2 (FP-Growth) on top of.

**Timeline:** 4-6 hari kerja untuk semuanya.

**Ready to start?** Mulai dengan STEP 1 hari ini! 🚀
