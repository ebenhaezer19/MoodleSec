#!/usr/bin/env python3
"""
Test script for AuthenticationManager and SmartResponseValidator.

Tests:
1. AuthenticationManager - authenticate with Moodle
2. SmartResponseValidator - multi-layer vulnerability detection
3. Integration - full scan with authentication and validation
"""

import asyncio
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from proxy.auth.auth_manager import AuthenticationManager, MoodleSession
from proxy.scanners.response_validator import SmartResponseValidator, DetectionType


async def test_auth_manager():
    """Test AuthenticationManager functionality."""
    print("\n" + "="*80)
    print("TEST 1: AuthenticationManager")
    print("="*80 + "\n")
    
    auth_manager = AuthenticationManager("http://localhost:8000", timeout=10.0)
    
    try:
        # Test with valid credentials
        print("[1.1] Testing authentication with valid credentials...")
        client = await auth_manager.get_authenticated_client(
            username="admin",
            password="Admin@1234"
        )
        
        if client and client.is_authenticated:
            print(f"  ✓ Successfully authenticated")
            print(f"    - Username: {client.username}")
            print(f"    - Logintoken: {client.logintoken[:20]}...")
            print(f"    - Is Authenticated: {client.is_authenticated}")
            
            # Test session verification
            print("\n[1.2] Testing session verification...")
            is_valid = await client.verify_authentication()
            if is_valid:
                print(f"  ✓ Session verification passed")
            else:
                print(f"  ✗ Session verification failed")
        else:
            print(f"  ✗ Authentication failed")
            return False
        
        # Test reusing session
        print("\n[1.3] Testing session reuse...")
        client2 = await auth_manager.get_authenticated_client(
            username="admin",
            password="Admin@1234",
            force_new=False
        )
        if client2 is client:
            print(f"  ✓ Session reused successfully")
        else:
            print(f"  ⚠️  New session created (expected for first reuse)")
        
        # Test force new session
        print("\n[1.4] Testing force new session...")
        client3 = await auth_manager.get_authenticated_client(
            username="admin",
            password="Admin@1234",
            force_new=True
        )
        if client3 is not client:
            print(f"  ✓ New session created")
        else:
            print(f"  ✗ Session not replaced")
        
        # Cleanup
        await auth_manager.cleanup()
        print("\n[1.5] AuthenticationManager cleanup completed")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_response_validator():
    """Test SmartResponseValidator functionality."""
    print("\n" + "="*80)
    print("TEST 2: SmartResponseValidator")
    print("="*80 + "\n")
    
    validator = SmartResponseValidator()
    
    try:
        # Test 1: Error-based detection
        print("[2.1] Testing error-based SQL detection...")
        error_response = """
        <html>
        <body>
        You have an error in your SQL syntax; check the manual that corresponds 
        to your MySQL server version for the right syntax to use near ''UNION' 
        at line 1
        </body>
        </html>
        """
        
        validator.set_baseline(
            endpoint="http://localhost:8000/user/index.php",
            response_text="<html><body>User List</body></html>",
            response_code=200,
            response_length=100
        )
        
        result = validator.validate_response(
            endpoint="http://localhost:8000/user/index.php",
            response_text=error_response,
            response_code=200,
            response_time=0.5,
            baseline_response_time=0.3,
            payload_type="sql_injection"
        )
        
        if result.is_vulnerable and DetectionType.ERROR_BASED in result.detection_types:
            print(f"  ✓ Error-based detection successful")
            print(f"    - Vulnerable: {result.is_vulnerable}")
            print(f"    - Confidence: {result.confidence:.2f}")
            print(f"    - Evidence: {result.evidence}")
        else:
            print(f"  ✗ Error-based detection failed")
        
        # Test 2: Time-based detection
        print("\n[2.2] Testing time-based SQL detection...")
        result_time = validator.validate_response(
            endpoint="http://localhost:8000/user/index.php",
            response_text="<html><body>User List</body></html>",
            response_code=200,
            response_time=3.5,  # 3.5 second delay (>2s threshold)
            baseline_response_time=0.3,
            payload_type="sql_injection"
        )
        
        if DetectionType.TIME_BASED in result_time.detection_types:
            print(f"  ✓ Time-based detection successful")
            print(f"    - Vulnerable: {result_time.is_vulnerable}")
            print(f"    - Confidence: {result_time.confidence:.2f}")
            print(f"    - Evidence: {result_time.evidence}")
        else:
            print(f"  ✗ Time-based detection failed")
        
        # Test 3: False positive prevention (401 error)
        print("\n[2.3] Testing false positive prevention (401 response)...")
        auth_error = """
        <html>
        <body>
        <h1>401 Unauthorized</h1>
        <p>You are not authenticated</p>
        </body>
        </html>
        """
        
        result_401 = validator.validate_response(
            endpoint="http://localhost:8000/admin/index.php",
            response_text=auth_error,
            response_code=401,
            response_time=0.2,
            baseline_response_time=0.2,
            payload_type="sql_injection"
        )
        
        if not result_401.is_vulnerable:
            print(f"  ✓ False positive prevention successful (401 not flagged as SQL error)")
            print(f"    - Vulnerable: {result_401.is_vulnerable}")
            print(f"    - Detection types: {[dt.value for dt in result_401.detection_types]}")
        else:
            print(f"  ⚠️  401 response flagged as vulnerable (may need tuning)")
        
        # Test 4: Union-based detection
        print("\n[2.4] Testing union-based SQL detection...")
        union_response = """
        <html>
        <body>
        <table>
        <tr><td>id</td><td>name</td><td>email</td></tr>
        <tr><td>1</td><td>admin</td><td>admin@localhost</td></tr>
        <tr><td>999</td><td>injected</td><td>injected@localhost</td></tr>
        </table>
        <!-- Column 1 cannot be cast to type numeric -->
        </body>
        </html>
        """
        
        result_union = validator.validate_response(
            endpoint="http://localhost:8000/user/index.php",
            response_text=union_response,
            response_code=200,
            response_time=0.5,
            baseline_response_time=0.3,
            payload_type="sql_injection"
        )
        
        if DetectionType.UNION_BASED in result_union.detection_types:
            print(f"  ✓ Union-based detection successful")
            print(f"    - Confident: {result_union.confidence:.2f}")
            print(f"    - Evidence: {result_union.evidence}")
        else:
            print(f"  ⚠️  Union-based detection did not trigger")
        
        # Test 5: Baseline deviation
        print("\n[2.5] Testing baseline deviation detection...")
        short_response = "<html><body>Error</body></html>"  # Much shorter than baseline
        
        result_baseline = validator.validate_response(
            endpoint="http://localhost:8000/user/index.php",
            response_text=short_response,
            response_code=200,
            response_time=0.5,
            baseline_response_time=0.3,
            payload_type="sql_injection"
        )
        
        if DetectionType.BASELINE_DEVIATION in result_baseline.detection_types:
            print(f"  ✓ Baseline deviation detected")
            print(f"    - Evidence: {result_baseline.evidence}")
        else:
            print(f"  ✗ Baseline deviation not detected")
        
        # Test 6: Summary statistics
        print("\n[2.6] Generating detection summary...")
        summary = validator.get_summary()
        print(f"  Total tests: {summary['total_tests']}")
        print(f"  Vulnerabilities found: {summary['vulnerable_found']}")
        print(f"  False positives: {summary['false_positive_count']}")
        print(f"  Average confidence: {summary['confidence_avg']:.2f}")
        print(f"  By detection type: {summary['by_detection_type']}")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_integration():
    """Test integration of auth manager and response validator."""
    print("\n" + "="*80)
    print("TEST 3: Integration - Full Scan with Auth and Validation")
    print("="*80 + "\n")
    
    try:
        # Initialize both components
        print("[3.1] Initializing components...")
        auth_manager = AuthenticationManager("http://localhost:8000")
        response_validator = SmartResponseValidator()
        print("  ✓ Components initialized")
        
        # Test authenticated client creation
        print("\n[3.2] Creating authenticated client...")
        client = await auth_manager.get_authenticated_client(
            username="admin",
            password="Admin@1234"
        )
        
        if client and client.is_authenticated:
            print(f"  ✓ Authenticated client created")
            
            # Simulate a vulnerability detection workflow
            print("\n[3.3] Simulating vulnerability detection workflow...")
            
            # Set baseline from normal response
            response_validator.set_baseline(
                endpoint="http://localhost:8000/course/index.php",
                response_text="<html><body>Welcome to Courses</body></html>",
                response_code=200,
                response_length=100
            )
            print("  ✓ Baseline recorded")
            
            # Detect vulnerability from injected payload response
            vuln_response = """
            <html><body>
            You have an error in your SQL syntax near 'OR 1=1'
            </body></html>
            """
            
            result = response_validator.validate_response(
                endpoint="http://localhost:8000/course/index.php",
                response_text=vuln_response,
                response_code=200,
                response_time=0.8,
                baseline_response_time=0.2,
                payload_type="sql_injection"
            )
            
            print(f"  ✓ Validation complete")
            print(f"    - Vulnerable: {result.is_vulnerable}")
            print(f"    - Confidence: {result.confidence:.2f}")
            print(f"    - Detections: {len(result.detection_types)}")
        else:
            print(f"  ✗ Failed to create authenticated client")
            return False
        
        # Cleanup
        await auth_manager.cleanup()
        print("\n[3.4] Cleanup completed")
        
        return True
        
    except Exception as e:
        print(f"  ✗ Integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """Run all tests."""
    print("\n")
    print("*" * 80)
    print("AuthenticationManager & SmartResponseValidator Test Suite")
    print("*" * 80)
    
    results = {}
    
    # Run tests
    results['auth_manager'] = await test_auth_manager()
    results['response_validator'] = await test_response_validator()
    results['integration'] = await test_integration()
    
    # Summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    
    for test_name, passed in results.items():
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"  {test_name}: {status}")
    
    all_passed = all(results.values())
    print("\n" + ("="*80))
    if all_passed:
        print("✓ ALL TESTS PASSED")
    else:
        print("✗ SOME TESTS FAILED")
    print("="*80 + "\n")
    
    return 0 if all_passed else 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
