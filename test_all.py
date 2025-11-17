#!/usr/bin/env python3
"""
Automated Testing Script for MoodleSec Backend (Python version)
Usage: python test_all.py
"""

import requests
import json
import time
from typing import Dict, Any, Tuple
from colorama import init, Fore, Style

# Initialize colorama for Windows support
init(autoreset=True)

# Test counters
passed = 0
failed = 0

# Service URLs
CVSS_URL = "http://localhost:8001"
PROXY_URL = "http://localhost:8999"


def print_header(text: str):
    """Print section header"""
    print(f"\n{Fore.BLUE}{'=' * 60}")
    print(f"{Fore.BLUE}{text}")
    print(f"{Fore.BLUE}{'=' * 60}\n")


def print_test(text: str):
    """Print test description"""
    print(f"{Fore.YELLOW}Testing:{Style.RESET_ALL} {text}")


def print_success(text: str):
    """Print success message"""
    global passed
    print(f"{Fore.GREEN}✅ PASSED:{Style.RESET_ALL} {text}")
    passed += 1


def print_failure(text: str, details: str = ""):
    """Print failure message"""
    global failed
    print(f"{Fore.RED}❌ FAILED:{Style.RESET_ALL} {text}")
    if details:
        print(f"  Details: {details}")
    failed += 1


def check_service(url: str, name: str) -> bool:
    """Check if service is running"""
    try:
        response = requests.get(f"{url}/health", timeout=5)
        if response.status_code == 200:
            print_success(f"{name} is running")
            return True
        else:
            print_failure(f"{name} returned status {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print_failure(f"{name} is not running", str(e))
        return False


def test_get_endpoint(url: str, expected: str, description: str) -> bool:
    """Test GET endpoint"""
    print_test(description)
    try:
        response = requests.get(url, timeout=10)
        response_text = response.text
        
        if expected in response_text or response.status_code == 200:
            print_success(description)
            return True
        else:
            print_failure(description, f"Expected '{expected}' in response")
            return False
    except Exception as e:
        print_failure(description, str(e))
        return False


def test_post_endpoint(url: str, data: Dict[str, Any], expected: str, description: str) -> Tuple[bool, Any]:
    """Test POST endpoint"""
    print_test(description)
    try:
        response = requests.post(
            url,
            json=data,
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        response_text = response.text
        
        if expected in response_text:
            print_success(description)
            return True, response.json() if response.text else None
        else:
            print_failure(description, f"Expected '{expected}' in response")
            return False, None
    except Exception as e:
        print_failure(description, str(e))
        return False, None


def test_cvss_engine():
    """Test CVSS Engine"""
    print_header("2. CVSS Engine Tests")
    
    # Test 2.1: Health check
    test_get_endpoint(f"{CVSS_URL}/health", "ok", "CVSS health check")
    
    # Test 2.2: Calculate critical vulnerability
    test_post_endpoint(
        f"{CVSS_URL}/score",
        {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
        "9.8",
        "Calculate critical CVSS score (9.8)"
    )
    
    # Test 2.3: Calculate medium vulnerability
    test_post_endpoint(
        f"{CVSS_URL}/score",
        {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
        "6.1",
        "Calculate medium CVSS score (6.1)"
    )
    
    # Test 2.4: Invalid vector
    success, _ = test_post_endpoint(
        f"{CVSS_URL}/score",
        {"vector": "INVALID"},
        "detail",
        "Handle invalid CVSS vector"
    )


def test_proxy_service():
    """Test Proxy Service"""
    print_header("3. Proxy Service Tests")
    
    # Test 3.1: Health check
    test_get_endpoint(f"{PROXY_URL}/health", "ok", "Proxy health check")
    
    # Test 3.2: Get logs
    test_get_endpoint(f"{PROXY_URL}/logs", "count", "Get proxy logs")
    
    # Test 3.3: Trigger scan - login page
    test_post_endpoint(
        f"{PROXY_URL}/scan-trigger",
        {"path": "/login/index.php", "method": "POST"},
        "scan_id",
        "Trigger scan for login page"
    )
    
    # Test 3.4: Trigger scan - admin page
    test_post_endpoint(
        f"{PROXY_URL}/scan-trigger",
        {"path": "/admin/settings.php", "method": "GET"},
        "High",
        "Trigger scan for admin page (should detect High severity)"
    )
    
    # Test 3.5: Get logs after scans
    time.sleep(1)  # Wait for logs to be written
    test_get_endpoint(f"{PROXY_URL}/logs?limit=5", "dast_scan", "Get logs after scans")


def test_integration():
    """Test integration between services"""
    print_header("4. Integration Tests")
    
    # Test 4.1: Complete workflow
    print_test("Complete scan workflow")
    try:
        # Trigger scan
        response = requests.post(
            f"{PROXY_URL}/scan-trigger",
            json={"path": "/test/page.php", "method": "GET"},
            timeout=10
        )
        
        if response.status_code == 200:
            scan_data = response.json()
            scan_id = scan_data.get("scan_id", "")
            findings_count = len(scan_data.get("findings", []))
            
            print_success(f"Scan triggered successfully (ID: {scan_id}, Findings: {findings_count})")
            
            # Verify in logs
            time.sleep(1)
            log_response = requests.get(f"{PROXY_URL}/logs?limit=1", timeout=10)
            if scan_id in log_response.text:
                print_success("Scan logged successfully")
            else:
                print_failure("Scan not found in logs")
        else:
            print_failure("Failed to trigger scan", f"Status: {response.status_code}")
    except Exception as e:
        print_failure("Complete scan workflow", str(e))
    
    # Test 4.2: CVSS calculation
    print_test("Calculate CVSS for typical finding")
    try:
        response = requests.post(
            f"{CVSS_URL}/score",
            json={"vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"},
            timeout=10
        )
        
        if response.status_code == 200:
            cvss_data = response.json()
            score = cvss_data.get("score", 0)
            severity = cvss_data.get("severity", "")
            print_success(f"CVSS calculated: {score} ({severity})")
        else:
            print_failure("CVSS calculation failed")
    except Exception as e:
        print_failure("CVSS calculation", str(e))


def test_error_handling():
    """Test error handling"""
    print_header("5. Error Handling Tests")
    
    # Test 5.1: Missing required field
    print_test("Handle missing required field")
    try:
        response = requests.post(
            f"{PROXY_URL}/scan-trigger",
            json={},
            timeout=10
        )
        if response.status_code in [400, 422]:
            print_success("Missing required field rejected")
        else:
            print_failure("Missing required field not handled properly")
    except Exception as e:
        print_failure("Missing required field test", str(e))
    
    # Test 5.2: Invalid CVSS vector
    print_test("Handle invalid CVSS vector")
    try:
        response = requests.post(
            f"{CVSS_URL}/score",
            json={"vector": "NOT:A:VALID:VECTOR"},
            timeout=10
        )
        if response.status_code == 400:
            print_success("Invalid CVSS vector rejected")
        else:
            print_failure("Invalid CVSS vector not handled properly")
    except Exception as e:
        print_failure("Invalid CVSS vector test", str(e))


def test_performance():
    """Test performance"""
    print_header("6. Performance Tests")
    
    print_test("Multiple concurrent requests (20 requests)")
    
    import concurrent.futures
    
    def make_request(url):
        try:
            requests.get(url, timeout=5)
            return True
        except:
            return False
    
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        urls = [f"{CVSS_URL}/health", f"{PROXY_URL}/health"] * 10
        results = list(executor.map(make_request, urls))
    
    duration = time.time() - start_time
    success_count = sum(results)
    
    if duration < 5 and success_count >= 18:  # Allow 2 failures
        print_success(f"Handled 20 concurrent requests in {duration:.2f}s ({success_count}/20 successful)")
    else:
        print_failure(f"Performance issue: took {duration:.2f}s, {success_count}/20 successful")


def print_summary():
    """Print test summary"""
    print_header("Test Summary")
    
    total = passed + failed
    pass_rate = (passed * 100 // total) if total > 0 else 0
    
    print(f"Total Tests: {total}")
    print(f"{Fore.GREEN}Passed: {passed}")
    print(f"{Fore.RED}Failed: {failed}")
    print(f"Pass Rate: {pass_rate}%")
    
    if failed == 0:
        print(f"\n{Fore.GREEN}🎉 All tests passed! Backend is ready.{Style.RESET_ALL}\n")
        return 0
    else:
        print(f"\n{Fore.RED}⚠️  Some tests failed. Please review the output above.{Style.RESET_ALL}\n")
        return 1


def main():
    """Main test function"""
    print_header("MoodleSec Backend Testing Suite")
    
    # Check if services are running
    print_header("1. Service Health Checks")
    
    cvss_running = check_service(CVSS_URL, "CVSS Engine")
    proxy_running = check_service(PROXY_URL, "Proxy Service")
    
    if not cvss_running or not proxy_running:
        print(f"\n{Fore.RED}⚠️  Some services are not running!{Style.RESET_ALL}")
        print("Please start the services first:")
        print("  Terminal 1: cd cvss-engine && python api.py")
        print("  Terminal 2: cd proxy && python app.py")
        return 1
    
    # Run all tests
    try:
        test_cvss_engine()
        test_proxy_service()
        test_integration()
        test_error_handling()
        test_performance()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Tests interrupted by user{Style.RESET_ALL}")
        return 1
    
    # Print summary
    return print_summary()


if __name__ == "__main__":
    exit(main())
