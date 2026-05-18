#!/bin/bash
# Test ZAP API endpoints

echo "=== ZAP API Testing ==="
echo ""

# Test 1: Version endpoint (check)
echo "[1] Testing /JSON/core/view/version"
curl -s "http://localhost:8080/JSON/core/view/version" | jq . 2>/dev/null || echo "Failed"
echo ""

# Test 2: Alerts endpoint
echo "[2] Testing /JSON/core/view/alerts"
curl -s "http://localhost:8080/JSON/core/view/alerts" | jq . 2>/dev/null | head -20 || echo "Failed"
echo ""

# Test 3: Simple status check
echo "[3] Testing root endpoint"
curl -s "http://localhost:8080/" | head -20
echo ""

# Test 4: Info
echo "[4] Testing /info.html"
curl -s "http://localhost:8080/info.html" | head -20
echo ""
