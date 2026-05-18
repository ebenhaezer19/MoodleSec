#!/usr/bin/env python3
"""
Test severity predictor fix for label format
"""

from ml.severity_predictor import SeverityPredictor

# Create test data with string labels (as now fixed)
test_findings = [
    {'severity': 'critical', 'category': 'SQL Injection', 'cvss_score': 9.0}
    for _ in range(10)
] + [
    {'severity': 'high', 'category': 'XSS', 'cvss_score': 7.0}
    for _ in range(10)
] + [
    {'severity': 'medium', 'category': 'CSRF', 'cvss_score': 5.0}
    for _ in range(10)
]

test_labels = ['critical'] * 10 + ['high'] * 10 + ['medium'] * 10

sp = SeverityPredictor()
print(f"✓ Testing with {len(test_findings)} findings and {len(test_labels)} labels...")
print(f"✓ Label types: {set(type(l).__name__ for l in test_labels)}")

try:
    result = sp.train(test_findings, test_labels)
    if 'error' in result:
        print(f"❌ Training error: {result['error']}")
    else:
        print(f"✅ Training successful!")
        print(f"✅ Result: {result}")
except Exception as e:
    print(f"❌ Exception: {e}")
    import traceback
    traceback.print_exc()
