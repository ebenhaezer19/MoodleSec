#!/usr/bin/env python3
"""Quick diagnostic: what does the ML pipeline do to typical scanner findings?"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from ml.ml_manager import MLManager

ml = MLManager()

# Simulate the types of findings the scanner produces
test_findings = [
    {"severity": "Medium", "category": "Missing Security Header", "description": "Content-Security-Policy header is missing from the response", "evidence": "No CSP header", "url": "http://localhost/login/index.php"},
    {"severity": "Medium", "category": "Missing Security Header", "description": "X-Frame-Options header is not set", "evidence": "", "url": "http://localhost/login/index.php"},
    {"severity": "Low",    "category": "Cookie Security",         "description": "Cookie without Secure flag detected", "evidence": "MoodleSession", "url": "http://localhost/"},
    {"severity": "Low",    "category": "Cookie Security",         "description": "Cookie without SameSite attribute", "evidence": "MoodleSession", "url": "http://localhost/"},
    {"severity": "Info",   "category": "Information Disclosure",  "description": "Server version disclosed in response headers", "evidence": "Apache/2.4", "url": "http://localhost/"},
    {"severity": "High",   "category": "SQL Injection",           "description": "SQL injection vulnerability found in id parameter", "evidence": "error in SQL syntax", "url": "http://localhost/course/view.php?id=2"},
    {"severity": "High",   "category": "Cross-Site Scripting (XSS)", "description": "Reflected XSS in search parameter", "evidence": "<script>alert(1)</script>", "url": "http://localhost/search.php"},
    {"severity": "Medium", "category": "CSRF",                    "description": "Form does not contain anti-CSRF token", "evidence": "Missing sesskey", "url": "http://localhost/login/index.php"},
]

print("=" * 90)
print(f"  ML Manager status: fp_reducer.is_trained = {ml.fp_reducer.is_trained}")
print("=" * 90)

for i, f in enumerate(test_findings):
    enhanced = ml.process_finding(f, {})
    is_filtered = enhanced.get("filtered", False)
    reason = enhanced.get("filter_reason", "")
    fp_meta = enhanced.get("ml_metadata", {}).get("false_positive", {})
    is_fp = fp_meta.get("is_false_positive", "?")
    conf  = fp_meta.get("confidence", 0)
    method = fp_meta.get("method", "?")
    filtered_by = fp_meta.get("filtered_by", "none")

    status = "❌ FILTERED" if is_filtered else "✅ KEPT"
    print(f"\n[{i+1}] {status}")
    print(f"    Severity : {f['severity']}")
    print(f"    Category : {f['category']}")
    print(f"    FP pred  : is_fp={is_fp}, confidence={conf:.2f}, method={method}")
    print(f"    Filtered : by={filtered_by}")
    if reason:
        print(f"    Reason   : {reason}")

print("\n" + "=" * 90)
result = ml.filter_findings(test_findings)
print(f"\nSummary: {result['original_count']} in → {result['final_count']} out ({result['filtered_count']} filtered)")
