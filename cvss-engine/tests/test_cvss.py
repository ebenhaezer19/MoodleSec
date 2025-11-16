"""
Unit tests for CVSS v3.1 calculator.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cvss_calculator import calculate_cvss, severity


def test_critical_vulnerability():
    """Test CVSS calculation for critical vulnerability (CVE-2017-0144 - EternalBlue)."""
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    
    score = calculate_cvss(vector)
    sev = severity(score)
    
    print(f"Test 1: Critical Vulnerability")
    print(f"  Vector: {vector}")
    print(f"  Score: {score}")
    print(f"  Severity: {sev}")
    
    assert score == 9.8, f"Expected 9.8, got {score}"
    assert sev == "Critical", f"Expected Critical, got {sev}"
    print("  ✅ PASSED\n")


def test_medium_xss_vulnerability():
    """Test CVSS calculation for medium XSS vulnerability."""
    vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
    
    score = calculate_cvss(vector)
    sev = severity(score)
    
    print(f"Test 2: Medium XSS Vulnerability")
    print(f"  Vector: {vector}")
    print(f"  Score: {score}")
    print(f"  Severity: {sev}")
    
    assert score == 6.1, f"Expected 6.1, got {score}"
    assert sev == "Medium", f"Expected Medium, got {sev}"
    print("  ✅ PASSED\n")


def run_all_tests():
    """Run all tests."""
    print("=" * 70)
    print("CVSS v3.1 Calculator - Unit Tests")
    print("=" * 70)
    print()
    
    tests = [
        test_critical_vulnerability,
        test_medium_xss_vulnerability
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  ❌ FAILED: {e}\n")
            failed += 1
        except Exception as e:
            print(f"  ❌ ERROR: {e}\n")
            failed += 1
    
    print("=" * 70)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("=" * 70)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
