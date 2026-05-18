# 🎯 STEP-BY-STEP: MANUAL VERIFICATION & DATA PREPARATION

## OPTION A (SAFE) - YANG ANDA PILIH ✅

```
Manual Verify 25 samples → Check accuracy → Decide → Train
```

---

## 📅 TIMELINE (TODAY)

```
Step 1: Review 25 samples         (30 mins)
Step 2: Check accuracy            (10 mins)  
Step 3: Combine + Augment data    (1 hour)
Step 4: Train model               (30 mins)
────────────────────────────────────────────
TOTAL:                            ~2 hours
```

---

## 🚀 SEKARANG NGAPAIN (EXACT STEPS)

### **STEP 1: MANUAL REVIEW 25 SAMPLES (30 MINS)**

File: `proxy/ml/training_data/verify_200_samples.json`

**Buka di VSCode dan review:**

```
Untuk SETIAP sample:

1. Baca: category, severity, description, evidence
2. Ask: "Apakah ini benar vulnerability?"
3. Check: Sudah benar label?
4. Mark: ✅ CORRECT atau ❌ WRONG

Example:

{
  "finding": {
    "category": "Information Disclosure",
    "description": "Debug information exposed on page"
  },
  "label": 1,  ← FP
  "reason": "Low severity info disclosure, typically FP"
}

My check:
  ✅ CORRECT - debug info bukan actual vulnerability, benar FP!
```

**Lakukan untuk semua 25!**

---

### **STEP 2: COUNT ACCURACY (10 MINS)**

Setelah review semua 25:

```
Berapa yang CORRECT? (contoh: 24)
Berapa yang WRONG? (contoh: 1)

Accuracy = Correct / 25 × 100%
         = 24 / 25 × 100%
         = 96% ✅ BAGUS!
```

**Decision:**
```
✅ > 80% (20/25 correct) → PROCEED TO STEP 3
⚠️  60-80% (15-20 correct) → PROCEED dengan caution  
❌ < 60% (<15 correct) → PAUSE dan review patterns
```

---

### **STEP 3: COMBINE DATA (1 HOUR)**

**Setelah accuracy check OK (>80%), jalankan:**

```bash
python step3_combine_and_augment.py
```

**Yang dilakukan script:**
1. Load: 25 real findings (verified)
2. Load: 346 existing data
3. Load: 1799 ZAP scan data
4. Combine: 25 + 346 + 1799 = 2170
5. Augment: 2170 × 1.2 = 2604 (varian)
6. Downsample: Keep best 1500
7. Output: `combined_augmented_1500.json`

**Time: ~5 mins (auto)**

---

### **STEP 4: TRAIN MODEL (30 MINS)**

**Setelah combine selesai:**

```bash
python train_fp_reducer_final.py --data combined_augmented_1500.json
```

**Hasil expected:**
```
Training: 85-90% accuracy
Validation: 80-85%
Test: 75-80% ✅ (4x improvement from 20%)
Time: ~10 mins
```

---

## 📋 CHECKLIST UNTUK HARI INI

```
[ ] STEP 1: Review verify_200_samples.json
  File lokasi: proxy/ml/training_data/verify_200_samples.json
  Time: 30 mins
  
[ ] STEP 2: Count accuracy
  True Positive (benar): _____ / 25
  False Positive (salah): _____ / 25
  Accuracy: ______%
  Decision: PROCEED? (Y/N)
  
[ ] STEP 3 (jika accuracy > 80%): Run combine script
  Command: python step3_combine_and_augment.py
  Output: combined_augmented_1500.json
  Time: 5 mins
  
[ ] STEP 4 (setelah Step 3): Train model
  Command: python train_fp_reducer_final.py
  Output: Model trained ✅
  Time: 10 mins
  
[ ] VERIFY: Check hasil training
  Test accuracy > 75%? → SUCCESS! 🎉
```

---

## 🎯 KONKRET: MULAI DARI SINI

### **RIGHT NOW:**

```bash
# 1. Open verify file
code proxy/ml/training_data/verify_200_samples.json

# 2. Review semua 25 samples
# (cukup baca di browser/VSCode)
```

### **AFTER REVIEW (30 MINS):**

```
Tulis note berapa yang benar/salah
Hitung accuracy %
```

### **JIKA ACCURACY > 80%:**

```bash
python step3_combine_and_augment.py
python train_fp_reducer_final.py
```

**DONE! Model ready** 🚀

---

## 📁 FILES YANG DIPAKAI

```
INPUT FILES:
  ✅ verify_200_samples.json (25 samples untuk review)
  ✅ existing 346 data
  ✅ ZAP scan 1799 data

OUTPUT FILES:
  → combined_augmented_1500.json (training data)
  → fp_reducer_model.json (trained model)
  → training_results.json (metrics)
```

---

## 🆘 KALAU STUCK

**"Gmana sih cara review?"**
```
Buka file JSON
Baca setiap finding
Tanya: "Benar vulnerability?"
Mark correct/wrong
Hitung total
```

**"Berapa accuracy yang ok?"**
```
> 80% = BAGUS silakan proceed
60-80% = OK tapi caution
< 60% = HARUS review rules
```

**"Butuh help dengan manual review?"**
```
Ask saya! Saya bisa bantu review sample-nya.
```

---

## ✨ SEKARANG ACTION!

**MULAI:**
1. Buka VSCode
2. Buka file: `proxy/ml/training_data/verify_200_samples.json`
3. Review 25 samples
4. Catat accuracy
5. Report back accuracy %

**Saya siap help step 3 & 4 setelah!** 💪

Udah jelas? Mulai sekarang! 🎯
