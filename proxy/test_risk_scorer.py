#!/usr/bin/env python3
"""Test risk scorer functionality"""

from risk.risk_scorer import RiskScorer

scorer = RiskScorer()

# Test findings
test_findings = [
    {
        'severity': 'High',
        'category': 'Session Management',
        'description': '2 form(s) missing CSRF protection',
        'evidence': 'Forms checked: 2, Protected: 0',
        'url': 'http://localhost:8998/login/index.php'
    },
    {
        'severity': 'Critical',
        'category': 'Input Validation',
        'description': 'SQL Injection vulnerability',
        'evidence': 'Parameter: id',
        'url': 'http://localhost:8998/api/user'
    },
    {
        'severity': 'Medium',
        'category': 'API Security',
        'description': 'Missing rate limiting',
        'evidence': 'No rate limit headers',
        'url': 'http://localhost:8998/api/login'
    }
]

print("=" * 80)
print("TESTING RISK SCORER")
print("=" * 80)

print("\nOriginal findings:")
for i, f in enumerate(test_findings, 1):
    print(f"\n{i}. {f['category']} ({f['severity']})")
    print(f"   Risk Score: {f.get('risk_score', 'NOT SET')}")
    print(f"   CVSS Score: {f.get('cvss_score', 'NOT SET')}")

print("\n" + "=" * 80)
print("ENRICHING WITH RISK SCORES")
print("=" * 80)

enriched = scorer.batch_enrich_findings(test_findings)

print("\nEnriched findings:")
for i, f in enumerate(enriched, 1):
    print(f"\n{i}. {f['category']} ({f['severity']})")
    print(f"   Risk Score: {f.get('risk_score', 'NOT SET')}")
    print(f"   CVSS Score: {f.get('cvss_score', 'NOT SET')}")
    print(f"   Priority: {f.get('priority', 'NOT SET')}")

print("\n" + "=" * 80)
print("TEST COMPLETE")
print("=" * 80)
