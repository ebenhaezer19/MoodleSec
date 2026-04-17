#!/usr/bin/env python3
"""
Step 1: Extract 200 samples untuk manual verification
Dan generate checklist template untuk review
"""

import json
import random
from pathlib import Path

# Configuration
INPUT_FILE = "proxy/ml/training_data/real_data/real_findings_20260127_133041_auto_labeled.json"
OUTPUT_SAMPLE = "proxy/ml/training_data/verify_200_samples.json"
OUTPUT_CHECKLIST = "VERIFY_CHECKLIST.md"

print("🔍 STEP 1: EXTRACT 200 SAMPLES UNTUK VERIFICATION\n")

# Load data
print(f"📖 Loading: {INPUT_FILE}")
with open(INPUT_FILE, 'r', encoding='utf-8') as f:
    all_data = json.load(f)

print(f"✅ Total findings: {len(all_data)}")

# Random sample 200
print("\n📊 Sampling 200 random findings...")
sample_200 = random.sample(all_data, min(200, len(all_data)))

# Save sample
print(f"💾 Saving to: {OUTPUT_SAMPLE}")
with open(OUTPUT_SAMPLE, 'w', encoding='utf-8') as f:
    json.dump(sample_200, f, indent=2, ensure_ascii=False)

print(f"✅ Saved {len(sample_200)} samples")

# Generate checklist
print(f"\n📋 Generating checklist: {OUTPUT_CHECKLIST}")

checklist_content = """# 📋 MANUAL VERIFICATION CHECKLIST (200 Samples)

## Instruksi

Untuk setiap finding, buka `verify_200_samples.json` dan check apakah label sudah benar.

**Label meanings:**
- `1` = FALSE POSITIVE (FP) = Not a real vulnerability
- `0` = TRUE POSITIVE (TP) = Real/actual vulnerability

---

## Template Verification (Copy-paste dan fill)

"""

# Add 10 examples from sample
for i, item in enumerate(sample_200[:10]):
    finding = item.get('finding', {})
    category = finding.get('category', 'Unknown')
    severity = finding.get('severity', 'Unknown')
    description = finding.get('description', '')
    evidence = finding.get('evidence', '')
    current_label = item.get('label', 'UNKNOWN')
    current_reason = item.get('reason', 'N/A')
    
    label_name = "FALSE POSITIVE" if current_label == 1 else "TRUE POSITIVE" if current_label == 0 else "UNKNOWN"
    
    checklist_content += f"""
### Sample #{i+1}

**Finding:**
- Category: {category}
- Severity: {severity}
- Description: {description}
- Evidence: {evidence}

**Current Label:** {label_name} (label={current_label})
**Current Reason:** {current_reason}

**Your Verification:**
```
Is this a real vulnerability that can be exploited?
- [ ] YES → TP (True Positive) - Mark as 0
- [ ] NO → FP (False Positive) - Mark as 1
- [ ] UNSURE → Need manual testing

Your note:
_________________________________________
```

---
"""

checklist_content += f"""

## Summary untuk Testing

**Total samples to verify: {len(sample_200)}**

Setelah verify semua:
1. Count berapa yang label TP (0)
2. Count berapa yang label FP (1)
3. Check accuracy:
   - Mismatches / Total = Error rate
   - Goal: < 20% error rate (80%+ accurate)

## Quick Check Criteria

### FP (False Positive) = Likely:
- Missing headers (CSP, HSTS, etc)
- Configuration issues
- Info disclosure dari normal HTML
- Legitimate code flagged as dangerous
- Missing security best practices

### TP (True Positive) = Likely:
- SQL injection yang jalan
- XSS yang reflected/stored
- CSRF tanpa protection
- Command execution
- Authentication bypass
- File inclusion
- Actual exploitable vulns

## Format Data dalam verify_200_samples.json

```json
{{
  "finding": {{
    "severity": "Medium",
    "category": "Cross-Site Scripting (XSS)",
    "description": "...",
    "evidence": "...",
    "url": "...",
    "cvss_score": 6.0
  }},
  "label": 1,
  "label_name": "FALSE_POSITIVE",
  "reason": "...",
  "confidence": 1.0
}}
```

---

## Langkah Verification

1. **Open** `verify_200_samples.json` dalam VS Code
2. **Review** setiap finding
3. **Decide**: TP atau FP?
4. **Note** dibawah setiap item
5. **Count** accuracy di akhir

---

## Automated Accuracy Check (After Manual Review)

Setelah manual review, jalankan:

```bash
python verify_accuracy.py
```

Script akan:
1. Compare manual labels vs automated labels
2. Calculate accuracy % 
3. Show mismatches
4. Recommend: Proceed or Fix rules

---

## Hasil Expected

```
Samples verified: 200

Accuracy:
  - Correct: 160-180 (80-90%)
  - Wrong: 20-40 (10-20%)
  
Conclusion:
  ✅ > 80% → Proceed to training
  ⚠️ 60-80% → Proceed but caution
  ❌ < 60% → Need fix rules
```

---

## Next Actions (After Verification)

IF accuracy > 80%:
  1. Combine 346 + 1799 ZAP data
  2. Augment varian
  3. Train model ✅

IF accuracy < 80%:
  1. Review mismatches
  2. Update pattern rules
  3. Re-verify subset
  4. Then combine + train
"""

with open(OUTPUT_CHECKLIST, 'w', encoding='utf-8') as f:
    f.write(checklist_content)

print(f"✅ Checklist created: {OUTPUT_CHECKLIST}")

print(f"""

✨ DONE!

🎯 Next Step Manual Verification:

1. Open: verify_200_samples.json (dalam VSCode)
2. Review setiap finding
3. Check: Benar TP/FP?
4. Count accuracy
5. Run: python verify_accuracy.py

📋 Reference: VERIFY_CHECKLIST.md

""")
