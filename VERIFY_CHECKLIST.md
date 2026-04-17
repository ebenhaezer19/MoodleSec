# 📋 MANUAL VERIFICATION CHECKLIST (200 Samples)

## Instruksi

Untuk setiap finding, buka `verify_200_samples.json` dan check apakah label sudah benar.

**Label meanings:**
- `1` = FALSE POSITIVE (FP) = Not a real vulnerability
- `0` = TRUE POSITIVE (TP) = Real/actual vulnerability

---

## Template Verification (Copy-paste dan fill)


### Sample #1

**Finding:**
- Category: Cross-Site Scripting (XSS)
- Severity: Info
- Description: Found 14 input field(s) - verify XSS protection
- Evidence: Input fields detected in https://sandbox.moodledemo.net/search/index.php. Ensure proper output encoding.

**Current Label:** FALSE POSITIVE (label=1)
**Current Reason:** User labeled as False Positive

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

### Sample #2

**Finding:**
- Category: File Upload
- Severity: High
- Description: Potential Zip Slip vulnerability in archive extraction
- Evidence: Endpoint: /files/index.php, Zip with path traversal accepted

**Current Label:** FALSE POSITIVE (label=1)
**Current Reason:** User labeled as False Positive

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

### Sample #3

**Finding:**
- Category: Cross-Site Scripting (XSS)
- Severity: Medium
- Description: Potentially dangerous HTML tag detected: <style>
- Evidence: Found 1 instance(s) of <style> tag in http://localhost:9000/user/profile.php

**Current Label:** FALSE POSITIVE (label=1)
**Current Reason:** XSS dangerous tag in Moodle legitimate HTML

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

### Sample #4

**Finding:**
- Category: Information Disclosure
- Severity: Low
- Description: Debug information exposed on page
- Evidence: Page: /, Debug indicators: debugging, stack trace

**Current Label:** FALSE POSITIVE (label=1)
**Current Reason:** Low severity info disclosure, typically FP

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

### Sample #5

**Finding:**
- Category: File Upload
- Severity: High
- Description: Potential path traversal in file upload
- Evidence: Endpoint: /repository/repository_ajax.php, Path: ../../../evil.txt

**Current Label:** FALSE POSITIVE (label=1)
**Current Reason:** User labeled as False Positive

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

### Sample #6

**Finding:**
- Category: API Security
- Severity: Medium
- Description: API endpoint accessible without authentication
- Evidence: URL: /webservice/soap/server.php, Status: 200

**Current Label:** FALSE POSITIVE (label=1)
**Current Reason:** User labeled as False Positive

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

### Sample #7

**Finding:**
- Category: Security Misconfiguration
- Severity: Low
- Description: Missing security header: Strict-Transport-Security
- Evidence: Header not found in API response

**Current Label:** FALSE POSITIVE (label=1)
**Current Reason:** User labeled as False Positive

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

### Sample #8

**Finding:**
- Category: Security Misconfiguration
- Severity: Low
- Description: Missing security header: X-Frame-Options
- Evidence: Header not found in API response

**Current Label:** FALSE POSITIVE (label=1)
**Current Reason:** User labeled as False Positive

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

### Sample #9

**Finding:**
- Category: Input Validation
- Severity: Critical
- Description: Potential SQL injection in API parameter
- Evidence: Endpoint: /lib/ajax/service-nologin.php, Parameter: wstoken, Payload: ' OR '1'='1

**Current Label:** FALSE POSITIVE (label=1)
**Current Reason:** User labeled as False Positive

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

### Sample #10

**Finding:**
- Category: Cross-Site Scripting (XSS)
- Severity: Info
- Description: Found 5 input field(s) - verify XSS protection
- Evidence: Input fields detected in https://sdecdtsepas2024.gnomio.com/login/forgot_password.php. Ensure proper output encoding.

**Current Label:** FALSE POSITIVE (label=1)
**Current Reason:** User labeled as False Positive

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


## Summary untuk Testing

**Total samples to verify: 25**

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
{
  "finding": {
    "severity": "Medium",
    "category": "Cross-Site Scripting (XSS)",
    "description": "...",
    "evidence": "...",
    "url": "...",
    "cvss_score": 6.0
  },
  "label": 1,
  "label_name": "FALSE_POSITIVE",
  "reason": "...",
  "confidence": 1.0
}
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
