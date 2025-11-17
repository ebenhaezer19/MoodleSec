#!/bin/bash

# Automated Testing Script for MoodleSec Backend
# Usage: ./test_all.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counters
PASSED=0
FAILED=0

# Helper functions
print_header() {
    echo -e "\n${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}\n"
}

print_test() {
    echo -e "${YELLOW}Testing:${NC} $1"
}

print_success() {
    echo -e "${GREEN}✅ PASSED:${NC} $1"
    ((PASSED++))
}

print_failure() {
    echo -e "${RED}❌ FAILED:${NC} $1"
    ((FAILED++))
}

# Check if services are running
check_service() {
    local url=$1
    local name=$2
    
    if curl -s "$url" > /dev/null 2>&1; then
        print_success "$name is running"
        return 0
    else
        print_failure "$name is not running"
        return 1
    fi
}

# Test HTTP endpoint
test_endpoint() {
    local method=$1
    local url=$2
    local data=$3
    local expected=$4
    local description=$5
    
    print_test "$description"
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s "$url")
    else
        response=$(curl -s -X "$method" "$url" -H "Content-Type: application/json" -d "$data")
    fi
    
    if echo "$response" | grep -q "$expected"; then
        print_success "$description"
        return 0
    else
        print_failure "$description"
        echo "Response: $response"
        return 1
    fi
}

# Main testing flow
main() {
    print_header "MoodleSec Backend Testing Suite"
    
    # ============================================
    # 1. Check if services are running
    # ============================================
    print_header "1. Service Health Checks"
    
    check_service "http://localhost:8001/health" "CVSS Engine"
    CVSS_RUNNING=$?
    
    check_service "http://localhost:8999/health" "Proxy Service"
    PROXY_RUNNING=$?
    
    if [ $CVSS_RUNNING -ne 0 ] || [ $PROXY_RUNNING -ne 0 ]; then
        echo -e "\n${RED}⚠️  Some services are not running!${NC}"
        echo "Please start the services first:"
        echo "  Terminal 1: cd cvss-engine && python api.py"
        echo "  Terminal 2: cd proxy && python app.py"
        exit 1
    fi
    
    # ============================================
    # 2. Test CVSS Engine
    # ============================================
    print_header "2. CVSS Engine Tests"
    
    # Test 2.1: Health check
    test_endpoint "GET" "http://localhost:8001/health" "" "ok" "CVSS health check"
    
    # Test 2.2: Calculate critical vulnerability
    test_endpoint "POST" "http://localhost:8001/score" \
        '{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}' \
        "9.8" \
        "Calculate critical CVSS score"
    
    # Test 2.3: Calculate medium vulnerability
    test_endpoint "POST" "http://localhost:8001/score" \
        '{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}' \
        "6.1" \
        "Calculate medium CVSS score"
    
    # Test 2.4: Invalid vector
    test_endpoint "POST" "http://localhost:8001/score" \
        '{"vector":"INVALID"}' \
        "error\|detail" \
        "Handle invalid CVSS vector"
    
    # ============================================
    # 3. Test Proxy Service
    # ============================================
    print_header "3. Proxy Service Tests"
    
    # Test 3.1: Health check
    test_endpoint "GET" "http://localhost:8999/health" "" "ok" "Proxy health check"
    
    # Test 3.2: Get logs (initially empty or with data)
    test_endpoint "GET" "http://localhost:8999/logs" "" "count\|logs" "Get proxy logs"
    
    # Test 3.3: Trigger scan - login page
    test_endpoint "POST" "http://localhost:8999/scan-trigger" \
        '{"path":"/login/index.php","method":"POST"}' \
        "scan_id\|findings" \
        "Trigger scan for login page"
    
    # Test 3.4: Trigger scan - admin page
    test_endpoint "POST" "http://localhost:8999/scan-trigger" \
        '{"path":"/admin/settings.php","method":"GET"}' \
        "High\|admin" \
        "Trigger scan for admin page"
    
    # Test 3.5: Get logs after scans
    test_endpoint "GET" "http://localhost:8999/logs?limit=5" "" "dast_scan" "Get logs after scans"
    
    # ============================================
    # 4. Test Integration
    # ============================================
    print_header "4. Integration Tests"
    
    # Test 4.1: Complete workflow
    print_test "Complete scan workflow"
    
    # Trigger scan
    scan_response=$(curl -s -X POST "http://localhost:8999/scan-trigger" \
        -H "Content-Type: application/json" \
        -d '{"path":"/test/page.php","method":"GET"}')
    
    if echo "$scan_response" | grep -q "scan_id"; then
        scan_id=$(echo "$scan_response" | grep -o '"scan_id":"[^"]*"' | cut -d'"' -f4)
        print_success "Scan triggered successfully (ID: $scan_id)"
        
        # Verify in logs
        sleep 1
        log_response=$(curl -s "http://localhost:8999/logs?limit=1")
        if echo "$log_response" | grep -q "$scan_id"; then
            print_success "Scan logged successfully"
        else
            print_failure "Scan not found in logs"
        fi
    else
        print_failure "Failed to trigger scan"
    fi
    
    # Test 4.2: CVSS calculation for finding
    print_test "Calculate CVSS for typical finding"
    cvss_response=$(curl -s -X POST "http://localhost:8001/score" \
        -H "Content-Type: application/json" \
        -d '{"vector":"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"}')
    
    if echo "$cvss_response" | grep -q "score"; then
        score=$(echo "$cvss_response" | grep -o '"score":[0-9.]*' | cut -d':' -f2)
        severity=$(echo "$cvss_response" | grep -o '"severity":"[^"]*"' | cut -d'"' -f4)
        print_success "CVSS calculated: $score ($severity)"
    else
        print_failure "CVSS calculation failed"
    fi
    
    # ============================================
    # 5. Test Error Handling
    # ============================================
    print_header "5. Error Handling Tests"
    
    # Test 5.1: Missing required field
    test_endpoint "POST" "http://localhost:8999/scan-trigger" \
        '{}' \
        "error\|detail\|field required" \
        "Handle missing required field"
    
    # Test 5.2: Invalid HTTP method
    print_test "Invalid HTTP method"
    response=$(curl -s -X DELETE "http://localhost:8999/health" -w "%{http_code}")
    if echo "$response" | grep -q "405\|Method Not Allowed"; then
        print_success "Invalid HTTP method rejected"
    else
        print_failure "Invalid HTTP method not handled"
    fi
    
    # ============================================
    # 6. Performance Test (Light)
    # ============================================
    print_header "6. Performance Tests"
    
    print_test "Multiple concurrent requests"
    
    start_time=$(date +%s)
    for i in {1..10}; do
        curl -s "http://localhost:8001/health" > /dev/null &
        curl -s "http://localhost:8999/health" > /dev/null &
    done
    wait
    end_time=$(date +%s)
    duration=$((end_time - start_time))
    
    if [ $duration -lt 5 ]; then
        print_success "Handled 20 concurrent requests in ${duration}s"
    else
        print_failure "Performance issue: took ${duration}s for 20 requests"
    fi
    
    # ============================================
    # Summary
    # ============================================
    print_header "Test Summary"
    
    TOTAL=$((PASSED + FAILED))
    PASS_RATE=$((PASSED * 100 / TOTAL))
    
    echo -e "Total Tests: $TOTAL"
    echo -e "${GREEN}Passed: $PASSED${NC}"
    echo -e "${RED}Failed: $FAILED${NC}"
    echo -e "Pass Rate: ${PASS_RATE}%"
    
    if [ $FAILED -eq 0 ]; then
        echo -e "\n${GREEN}🎉 All tests passed! Backend is ready.${NC}\n"
        exit 0
    else
        echo -e "\n${RED}⚠️  Some tests failed. Please review the output above.${NC}\n"
        exit 1
    fi
}

# Run main function
main
