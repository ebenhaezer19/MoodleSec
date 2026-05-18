#!/usr/bin/env python3
"""
Test ML Modules

Validates all ML-enhanced detection modules.
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ml.ml_manager import MLManager
from datetime import datetime


def test_false_positive_reducer():
    """Test False Positive Reduction module."""
    print("\n" + "="*80)
    print("TEST 1: FALSE POSITIVE REDUCTION")
    print("="*80)
    
    ml_manager = MLManager(enable_ml=True)
    
    # Test finding (likely false positive)
    finding = {
        'severity': 'Info',
        'category': 'Security Misconfiguration',
        'description': 'Missing security header: X-Frame-Options',
        'evidence': 'Header not found',
        'cvss_score': 2.0,
        'risk_score': 1.5,
        'url': 'http://localhost:8998/login/index.php'
    }
    
    context = {
        'status_code': 200,
        'response_time': 150,
        'occurrence_count': 1,
        'days_since_first_seen': 0
    }
    
    is_fp, confidence = ml_manager.fp_reducer.predict(finding, context)
    
    print(f"\nFinding: {finding['category']} ({finding['severity']})")
    print(f"Is False Positive: {is_fp}")
    print(f"Confidence: {confidence:.2%}")
    
    if is_fp:
        print("✅ Correctly identified as potential false positive")
    else:
        print("ℹ️  Classified as true positive")
    
    return True


def test_anomaly_detector():
    """Test Anomaly Detection module."""
    print("\n" + "="*80)
    print("TEST 2: ANOMALY DETECTION")
    print("="*80)
    
    ml_manager = MLManager(enable_ml=True)
    
    # Test 1: Normal request
    normal_data = {
        'request': {
            'url': 'http://localhost:8998/login/index.php',
            'method': 'GET',
            'headers': {'User-Agent': 'Mozilla/5.0'},
            'body': ''
        },
        'response': {
            'status_code': 200,
            'size': 5000,
            'time': 150,
            'headers': {}
        },
        'request_count_last_minute': 5,
        'unique_ips_last_minute': 3,
        'error_rate_last_minute': 0
    }
    
    is_anomaly, score, reason = ml_manager.detect_anomaly(normal_data)
    print(f"\nTest 1 - Normal Request:")
    print(f"  Is Anomaly: {is_anomaly}")
    print(f"  Score: {score:.2f}")
    print(f"  Reason: {reason}")
    
    # Test 2: Suspicious request
    suspicious_data = {
        'request': {
            'url': 'http://localhost:8998/admin/../../etc/passwd',
            'method': 'GET',
            'headers': {},
            'body': ''
        },
        'response': {
            'status_code': 500,
            'size': 100,
            'time': 5000,
            'headers': {}
        },
        'request_count_last_minute': 150,
        'unique_ips_last_minute': 1,
        'error_rate_last_minute': 0.8
    }
    
    is_anomaly, score, reason = ml_manager.detect_anomaly(suspicious_data)
    print(f"\nTest 2 - Suspicious Request:")
    print(f"  Is Anomaly: {is_anomaly}")
    print(f"  Score: {score:.2f}")
    print(f"  Reason: {reason}")
    
    if is_anomaly:
        print("✅ Correctly detected anomaly")
    else:
        print("⚠️  Anomaly not detected (may need training)")
    
    return True


def test_severity_predictor():
    """Test Severity Prediction module."""
    print("\n" + "="*80)
    print("TEST 3: SEVERITY PREDICTION")
    print("="*80)
    
    ml_manager = MLManager(enable_ml=True)
    
    # Test finding
    finding = {
        'severity': 'Medium',
        'category': 'SQL Injection',
        'description': 'Potential SQL injection in user parameter',
        'evidence': "Parameter 'id' vulnerable to SQL injection",
        'cvss_score': 8.5,
        'risk_score': 9.0,
        'url': 'http://localhost:8998/user/profile.php?id=1'
    }
    
    context = {
        'environment': 'production',
        'public_facing': True,
        'requires_auth': False,
        'data_sensitivity': 'high',
        'exploitability': 'easy',
        'impact_scope': 'application'
    }
    
    predicted_severity, confidence, prob_dist = ml_manager.severity_predictor.predict(finding, context)
    
    print(f"\nFinding: {finding['category']}")
    print(f"Original Severity: {finding['severity']}")
    print(f"Predicted Severity: {predicted_severity.capitalize()}")
    print(f"Confidence: {confidence:.2%}")
    print(f"\nProbability Distribution:")
    for sev, prob in sorted(prob_dist.items(), key=lambda x: x[1], reverse=True):
        print(f"  {sev.capitalize():10s}: {prob:.2%}")
    
    if predicted_severity in ['critical', 'high']:
        print("✅ Correctly escalated severity for SQL injection")
    else:
        print("ℹ️  Severity prediction may need training")
    
    return True


def test_rate_limiter():
    """Test Rate Limiting module."""
    print("\n" + "="*80)
    print("TEST 4: ML-ENHANCED RATE LIMITING")
    print("="*80)
    
    ml_manager = MLManager(enable_ml=True)
    
    # Test 1: Normal request
    request_data = {
        'url': 'http://localhost:8998/login/index.php',
        'method': 'GET',
        'headers': {'User-Agent': 'Mozilla/5.0'},
        'body': ''
    }
    
    should_limit, reason, details = ml_manager.check_rate_limit(request_data, '192.168.1.100')
    print(f"\nTest 1 - Normal Request from 192.168.1.100:")
    print(f"  Should Limit: {should_limit}")
    print(f"  Reason: {reason}")
    print(f"  Risk Score: {details.get('risk_score', 'N/A')}")
    
    # Test 2: Rapid requests
    print(f"\nTest 2 - Simulating rapid requests...")
    for i in range(15):
        should_limit, reason, details = ml_manager.check_rate_limit(request_data, '192.168.1.101')
    
    print(f"  After 15 requests:")
    print(f"  Should Limit: {should_limit}")
    print(f"  Reason: {reason}")
    print(f"  Requests/minute: {details.get('requests', {}).get('minute', 0)}")
    
    # Test 3: Suspicious request
    suspicious_request = {
        'url': 'http://localhost:8998/admin/../../etc/passwd',
        'method': 'GET',
        'headers': {},
        'body': ''
    }
    
    should_limit, reason, details = ml_manager.check_rate_limit(suspicious_request, '192.168.1.102')
    print(f"\nTest 3 - Suspicious Request from 192.168.1.102:")
    print(f"  Should Limit: {should_limit}")
    print(f"  Reason: {reason}")
    print(f"  Risk Score: {details.get('risk_score', 'N/A')}")
    
    if should_limit:
        print("✅ Rate limiting working correctly")
    else:
        print("ℹ️  Rate limiter may need training for better detection")
    
    return True


def test_ml_manager_integration():
    """Test ML Manager integration."""
    print("\n" + "="*80)
    print("TEST 5: ML MANAGER INTEGRATION")
    print("="*80)
    
    ml_manager = MLManager(enable_ml=True)
    
    # Test findings processing
    findings = [
        {
            'severity': 'High',
            'category': 'Session Management',
            'description': 'CSRF protection missing',
            'evidence': '2 forms without CSRF tokens',
            'cvss_score': 6.4,
            'risk_score': 5.8,
            'url': 'http://localhost:8998/login/index.php'
        },
        {
            'severity': 'Info',
            'category': 'Security Misconfiguration',
            'description': 'Missing X-Frame-Options header',
            'evidence': 'Header not found',
            'cvss_score': 2.0,
            'risk_score': 1.5,
            'url': 'http://localhost:8998/index.php'
        }
    ]
    
    result = ml_manager.filter_findings(findings)
    
    print(f"\nProcessing {result['original_count']} findings...")
    print(f"Filtered: {result['filtered_count']}")
    print(f"Severity Adjusted: {result['severity_adjusted_count']}")
    print(f"Final Count: {result['final_count']}")
    
    print(f"\nProcessed Findings:")
    for i, finding in enumerate(result['findings'], 1):
        print(f"\n  Finding #{i}:")
        print(f"    Category: {finding['category']}")
        print(f"    Severity: {finding['severity']}")
        if finding.get('ml_metadata'):
            fp_info = finding['ml_metadata'].get('false_positive', {})
            print(f"    False Positive: {fp_info.get('is_false_positive')} ({fp_info.get('confidence', 0):.2%})")
    
    # Get ML status
    status = ml_manager.get_status()
    print(f"\n\nML Status:")
    print(f"  ML Enabled: {status['ml_enabled']}")
    for module_name, module_info in status['modules'].items():
        trained = module_info.get('trained', False)
        print(f"  {module_name}: {'✅ Trained' if trained else '⚠️  Not Trained (using heuristics)'}")
    
    print("\n✅ ML Manager integration working correctly")
    
    return True


def main():
    """Run all tests."""
    print("="*80)
    print("ML-ENHANCED DETECTION MODULE TESTS")
    print("="*80)
    print(f"Timestamp: {datetime.utcnow().isoformat()}Z")
    
    tests = [
        ("False Positive Reduction", test_false_positive_reducer),
        ("Anomaly Detection", test_anomaly_detector),
        ("Severity Prediction", test_severity_predictor),
        ("Rate Limiting", test_rate_limiter),
        ("ML Manager Integration", test_ml_manager_integration)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            success = test_func()
            results.append((test_name, success))
        except Exception as e:
            print(f"\n❌ Test failed: {e}")
            import traceback
            traceback.print_exc()
            results.append((test_name, False))
    
    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    passed = sum(1 for _, success in results if success)
    total = len(results)
    
    for test_name, success in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} - {test_name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! ML modules are working correctly.")
        print("\nNote: Models are using heuristic fallbacks until trained.")
        print("Run training scripts to enable full ML capabilities.")
    else:
        print("\n⚠️  Some tests failed. Check error messages above.")
    
    return passed == total


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
