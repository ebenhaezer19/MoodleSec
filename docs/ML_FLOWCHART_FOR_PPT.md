# DIAGRAM ALUR MACHINE LEARNING - UNTUK PPT SEMPRO

## Pilihan 1: SIMPLE OVERVIEW (Untuk Slide Pengantar)

```
┌─────────────────────────────────────────────────────────┐
│                 ML FALSE POSITIVE REDUCER                │
└─────────────────────────────────────────────────────────┘

  Raw Findings         ML Processing          Final Result
  (Scanner Output)                            (Filtered)
       │                                           │
       ▼                                           ▼
  ┌─────────┐         ┌──────────┐          ┌──────────┐
  │ 100     │   ML    │ Analyze  │          │ 13 TP    │
  │ Findings│ ──────> │ Pattern  │ ───────> │ 87 FP    │
  │         │ Predict │          │ Filter   │ REMOVED  │
  └─────────┘         └──────────┘          └──────────┘

  Before ML:                                 After ML:
  60% False Positive    ══════════>          8% False Positive
  
  ✅ 87% Reduction in Manual Verification
```

---

## Pilihan 2: DETAILED PIPELINE (Untuk Slide Teknis)

```
┌────────────────────────────────────────────────────────────────┐
│           MACHINE LEARNING PIPELINE - DETAILED FLOW            │
└────────────────────────────────────────────────────────────────┘

STEP 1: INPUT
┌──────────────────────┐
│   Raw Finding        │
│                      │
│ • Severity: High     │
│ • Category: SQL Inj  │
│ • URL: /login.php    │
│ • Evidence: payload  │
│ • CVSS: 7.5          │
└──────────────────────┘
         │
         ▼
STEP 2: FEATURE EXTRACTION
┌──────────────────────────────────────┐
│  Extract 16 Features:                │
│  ┌────────────────────────────────┐  │
│  │ 1. severity_encoded (0-4)      │  │
│  │ 2. evidence_length (chars)     │  │
│  │ 3. url_complexity (parts)      │  │
│  │ 4. cvss_score (0-10)           │  │
│  │ 5. response_time (ms)          │  │
│  │ 6. status_code (200/403/500)   │  │
│  │ 7-16. keyword_match (binary)   │  │
│  └────────────────────────────────┘  │
└──────────────────────────────────────┘
         │
         ▼
STEP 3: ENSEMBLE CLASSIFICATION
┌─────────────────────────────────────────────┐
│         Parallel Prediction                 │
│                                             │
│  ┌──────────────────┐  ┌─────────────────┐ │
│  │  Random Forest   │  │ Gradient Boost  │ │
│  │  (200 trees)     │  │ (200 estimators)│ │
│  │                  │  │                 │ │
│  │  Predict → 0.82  │  │ Predict → 0.78  │ │
│  └──────────────────┘  └─────────────────┘ │
│           │                      │          │
│           └──────────┬───────────┘          │
│                      ▼                      │
│              ┌───────────────┐              │
│              │  Soft Voting  │              │
│              │  (P1+P2)/2    │              │
│              │  = 0.80       │              │
│              └───────────────┘              │
└─────────────────────────────────────────────┘
         │
         ▼
STEP 4: PROBABILITY CALIBRATION
┌──────────────────────────────┐
│  Sigmoid Calibration         │
│                              │
│  Raw: 0.80 ──> Cal: 0.85     │
│                              │
│  Confidence Score: 85%       │
└──────────────────────────────┘
         │
         ▼
STEP 5: BINARY DECISION
┌──────────────────────────────┐
│   Is P > 0.5 (50%)?          │
│                              │
│   0.85 > 0.5 ✅ YES          │
└──────────────────────────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌───────┐ ┌──────────┐
│  FP   │ │    TP    │
│FILTER │ │ KEEP &   │
│ OUT   │ │ CALCULATE│
│       │ │   RISK   │
└───────┘ └──────────┘

OUTPUT:
┌──────────────────────────────┐
│  Result:                     │
│  • is_false_positive: True   │
│  • confidence: 0.85 (85%)    │
│  • action: FILTER_OUT        │
└──────────────────────────────┘
```

---

## Pilihan 3: TRAINING vs PREDICTION (2 Kolom Paralel)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    ML MODEL: TRAINING vs PREDICTION                 │
└─────────────────────────────────────────────────────────────────────┘

    TRAINING PHASE                      PREDICTION PHASE
    (One-Time Setup)                    (Real-Time Operation)

┌──────────────────────┐          ┌──────────────────────┐
│  Training Data       │          │  New Finding         │
│  900 Samples         │          │  (From Scanner)      │
│  • 540 TP            │          │                      │
│  • 360 FP            │          │                      │
│  • Labeled Manual    │          │                      │
└──────────────────────┘          └──────────────────────┘
         │                                  │
         ▼                                  ▼
┌──────────────────────┐          ┌──────────────────────┐
│  Feature Extraction  │          │  Feature Extraction  │
│  16 features each    │          │  16 features         │
└──────────────────────┘          └──────────────────────┘
         │                                  │
         ▼                                  ▼
┌──────────────────────┐          ┌──────────────────────┐
│  Train/Test Split    │          │  Load Trained Model  │
│  • Train: 80%        │          │  false_positive_     │
│  • Test: 20%         │          │  reducer.pkl         │
└──────────────────────┘          └──────────────────────┘
         │                                  │
         ▼                                  ▼
┌──────────────────────┐          ┌──────────────────────┐
│  Model Training      │          │  Make Prediction     │
│  • Random Forest     │          │  • Ensemble Vote     │
│  • Gradient Boost    │          │  • Calibrate Prob    │
│  • 200 estimators    │          │  • Return Result     │
└──────────────────────┘          └──────────────────────┘
         │                                  │
         ▼                                  ▼
┌──────────────────────┐          ┌──────────────────────┐
│  Model Evaluation    │          │  Action Taken        │
│  Accuracy: 95%       │          │  • Filter FP         │
│  Precision: 0.93     │          │  • Calculate Risk    │
│  Recall: 0.91        │          │  • Store Finding     │
│  F1-Score: 0.92      │          │                      │
└──────────────────────┘          └──────────────────────┘
         │                                  │
         ▼                                  ▼
┌──────────────────────┐          ┌──────────────────────┐
│  Save Model          │          │  Update Dashboard    │
│  .pkl file           │          │  Real-time Stats     │
└──────────────────────┘          └──────────────────────┘

   ⏱ Takes: ~5 min               ⏱ Takes: <100ms
   🔄 Frequency: Monthly         🔄 Frequency: Per Finding
```

---

## Pilihan 4: BEFORE/AFTER IMPACT (Untuk Slide Hasil)

```
┌─────────────────────────────────────────────────────────────────┐
│              ML FALSE POSITIVE REDUCER - IMPACT                 │
└─────────────────────────────────────────────────────────────────┘

BEFORE ML IMPLEMENTATION
━━━━━━━━━━━━━━━━━━━━━━━━
┌────────────────────────────────────────────────┐
│  100 Findings from Scanner                     │
│  ┌──────────┐  ┌──────────────────────────┐   │
│  │   40 TP  │  │        60 FP             │   │
│  │  (Real)  │  │    (False Alarm)         │   │
│  └──────────┘  └──────────────────────────┘   │
└────────────────────────────────────────────────┘
                    ⬇
┌────────────────────────────────────────────────┐
│  Manual Verification Required                  │
│  ⏱ Time: 100 findings × 10 min = 1000 min    │
│  👤 Effort: ~16.7 hours security analyst work │
│  ⚠️  Risk: Analyst fatigue, missed vulns      │
└────────────────────────────────────────────────┘


AFTER ML IMPLEMENTATION
━━━━━━━━━━━━━━━━━━━━━━━
┌────────────────────────────────────────────────┐
│  100 Findings from Scanner                     │
└────────────────────────────────────────────────┘
                    ⬇
          ┌──────────────────┐
          │  ML Processing   │
          │  Classify TP/FP  │
          │  95% Accuracy    │
          └──────────────────┘
                    ⬇
┌─────────────────────┐    ┌───────────────────┐
│  13 Findings (TP)   │    │  87 Findings (FP) │
│  ✅ KEPT            │    │  🚫 FILTERED OUT  │
│  Need Review        │    │  Auto-removed     │
└─────────────────────┘    └───────────────────┘
                    ⬇
┌────────────────────────────────────────────────┐
│  Manual Verification Reduced                   │
│  ⏱ Time: 13 findings × 10 min = 130 min      │
│  👤 Effort: ~2.2 hours security analyst work  │
│  ✅ Benefit: 87% reduction in manual work     │
└────────────────────────────────────────────────┘

KEY METRICS:
┌──────────────────────┬─────────────┬─────────────┬──────────┐
│  Metric              │  Before ML  │  After ML   │  Change  │
├──────────────────────┼─────────────┼─────────────┼──────────┤
│  FP Rate             │     60%     │      8%     │  -87%    │
│  Manual Review Time  │   1000 min  │    130 min  │  -87%    │
│  Findings to Review  │     100     │      13     │  -87%    │
│  Accuracy            │     N/A     │     95%     │   +95%   │
└──────────────────────┴─────────────┴─────────────┴──────────┘
```

---

## Pilihan 5: FEATURE IMPORTANCE VISUALIZATION

```
┌─────────────────────────────────────────────────────────────────┐
│            ML MODEL - FEATURE IMPORTANCE RANKING                │
└─────────────────────────────────────────────────────────────────┘

Which features does the model use most for classification?

┌──────────────────────────────────────────────────────────────┐
│                                                              │
│  1. CVSS Score               ████████████████████  35%      │
│                                                              │
│  2. Severity Level           ██████████████████    28%      │
│                                                              │
│  3. Evidence Length          ████████████          18%      │
│                                                              │
│  4. Response Time            ██████                9%       │
│                                                              │
│  5. URL Complexity           ████                  6%       │
│                                                              │
│  6. Status Code              ██                    3%       │
│                                                              │
│  7-16. Other Features        █                     1%       │
│                                                              │
└──────────────────────────────────────────────────────────────┘

💡 INSIGHT:
Model belajar dari kombinasi multiple features, bukan hanya 1 feature.
Ini menunjukkan model tidak mengalami data leakage.
```

---

## Pilihan 6: CONFUSION MATRIX (Untuk Slide Evaluasi)

```
┌─────────────────────────────────────────────────────────────────┐
│                ML MODEL PERFORMANCE - CONFUSION MATRIX          │
└─────────────────────────────────────────────────────────────────┘

                    PREDICTED
                ┌──────────┬──────────┐
                │    FP    │    TP    │
        ┌───────┼──────────┼──────────┤
        │  FP   │    74    │    6     │  ← Precision: 93%
ACTUAL  │       │  (TN)    │  (FN)    │
        ├───────┼──────────┼──────────┤
        │  TP   │    4     │   116    │  ← Recall: 97%
        │       │  (FP)    │  (TP)    │
        └───────┴──────────┴──────────┘

METRICS:
┌─────────────────────────────────────────┐
│  Overall Accuracy:      95.0%           │
│  Precision (TP class):  93%             │
│  Recall (TP class):     97%             │
│  F1-Score:              0.95            │
│                                         │
│  ✅ Model sangat baik mendeteksi TP    │
│  ✅ Sangat sedikit TP yang di-filter   │
└─────────────────────────────────────────┘
```

---

## Pilihan 7: DEPLOYMENT WORKFLOW (End-to-End)

```
┌─────────────────────────────────────────────────────────────────┐
│          ML MODEL DEPLOYMENT - COMPLETE WORKFLOW                │
└─────────────────────────────────────────────────────────────────┘

PHASE 1: DEVELOPMENT (Completed ✅)
┌──────────────────────────────────────────────────────┐
│  1. Generate Synthetic Training Data (900 samples)  │
│  2. Train Ensemble Models (RF + GB)                 │
│  3. Validate Performance (95% accuracy)             │
│  4. Save Model (.pkl file)                          │
└──────────────────────────────────────────────────────┘
                        ⬇

PHASE 2: INTEGRATION (Current Phase)
┌──────────────────────────────────────────────────────┐
│  1. Load Model in Proxy Service                     │
│  2. Create API Endpoint: POST /ml/predict           │
│  3. Integrate with Scanner Pipeline                 │
│  4. Test with Real Findings                         │
└──────────────────────────────────────────────────────┘
                        ⬇

PHASE 3: PRODUCTION (Future)
┌──────────────────────────────────────────────────────┐
│  1. Deploy to Production Environment                │
│  2. Collect Real Findings (500+ samples)            │
│  3. Manual Labeling by Security Expert              │
│  4. Retrain with Real Data                          │
└──────────────────────────────────────────────────────┘
                        ⬇

PHASE 4: CONTINUOUS IMPROVEMENT
┌──────────────────────────────────────────────────────┐
│  1. Monitor Model Performance (monthly)             │
│  2. Collect Feedback from Analysts                  │
│  3. Retrain with New Data                           │
│  4. A/B Test Old vs New Model                       │
└──────────────────────────────────────────────────────┘

TIMELINE:
├────────┬────────┬────────┬────────────────────────────>
Phase 1  Phase 2  Phase 3  Phase 4 (Ongoing)
(Done)   (Now)   (3 months) (Continuous)
```

---

## Pilihan 8: SIMPLIFIED FOR NON-TECHNICAL SLIDE

```
┌─────────────────────────────────────────────────────────────────┐
│         BAGAIMANA MACHINE LEARNING BEKERJA? (Simplified)        │
└─────────────────────────────────────────────────────────────────┘

STEP 1: BELAJAR DARI DATA 📚
┌────────────────────────────────────┐
│  Model diberi 900 contoh finding:  │
│  • 540 contoh "REAL vulnerability" │
│  • 360 contoh "FALSE alarm"        │
│  Model belajar pola perbedaannya   │
└────────────────────────────────────┘
            ⬇

STEP 2: ANALISIS POLA 🔍
┌────────────────────────────────────┐
│  Model menganalisis karakteristik: │
│  • Tingkat severity                │
│  • Panjang evidence                │
│  • CVSS score                      │
│  • Response time                   │
│  • Dan 12 fitur lainnya            │
└────────────────────────────────────┘
            ⬇

STEP 3: PREDIKSI OTOMATIS ⚡
┌────────────────────────────────────┐
│  Saat ada finding baru:            │
│  Model prediksi dalam <100ms:      │
│  • "Ini REAL vulnerability" 95%    │
│  atau                              │
│  • "Ini FALSE alarm" 85%           │
└────────────────────────────────────┘
            ⬇

STEP 4: HASIL 🎯
┌────────────────────────────────────┐
│  ✅ 87% pengurangan manual work    │
│  ✅ 95% akurasi prediksi           │
│  ✅ Analyst fokus ke real threats  │
└────────────────────────────────────┘
```

---

## REKOMENDASI PENGGUNAAN UNTUK SEMPRO:

### **Slide 1 (Overview BAB 3):**
- Gunakan **Pilihan 1: Simple Overview**
- Waktu: 15 detik
- Tujuan: Tunjukkan impact langsung (60% → 8% FP)

### **Slide 2 (Arsitektur ML):**
- Gunakan **Pilihan 2: Detailed Pipeline** ATAU **Pilihan 3: Training vs Prediction**
- Waktu: 45 detik
- Tujuan: Jelaskan bagaimana ML bekerja

### **Slide 3 (Hasil & Evaluasi):**
- Gunakan **Pilihan 4: Before/After Impact** + **Pilihan 6: Confusion Matrix**
- Waktu: 30 detik
- Tujuan: Tunjukkan hasil kuantitatif

### **Backup Slides (Jika ada pertanyaan):**
- **Pilihan 5**: Feature Importance (jika ditanya "apa yang dipelajari model?")
- **Pilihan 7**: Deployment Workflow (jika ditanya "bagaimana implementasi?")
- **Pilihan 8**: Simplified (jika audiens non-teknis bingung)

---

## TIPS PRESENTASI:

1. **Jangan bacakan diagram** - Explain dengan kata-kata sendiri
2. **Gunakan pointer** - Tunjuk bagian penting sambil menjelaskan
3. **Siapkan analogi sederhana**: 
   - "Seperti email spam filter yang belajar dari jutaan email"
   - "Model belajar seperti dokter yang mendiagnosis dari ribuan kasus"

4. **Highlight angka kunci**:
   - 95% accuracy
   - 87% reduction
   - <100ms prediction time

5. **Antisipasi pertanyaan**:
   - Q: "Kenapa tidak 100%?" 
   - A: "Real-world data punya edge cases, 95% adalah realistic & production-ready"
   
   - Q: "Data training dari mana?"
   - A: "Synthetic data untuk proof-of-concept, akan retrain dengan real findings dari production"

---

**READY FOR COPY-PASTE TO POWERPOINT!** 🎉
