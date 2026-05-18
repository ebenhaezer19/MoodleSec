#!/bin/bash

echo "=== TESTING IMPROVED REST SCANNER ==="
echo "Expected: Significantly fewer findings (0-5 instead of 38)"
echo ""

cd ~/TA/adaptive-moodle-security/MoodleSec

echo "[1] Pulling latest changes..."
git pull origin main

echo ""
echo "[2] Restarting proxy service..."
cd proxy
pkill -f "uvicorn app:app"
sleep 3
nohup uvicorn app:app --host 0.0.0.0 --port 8999 > /tmp/scanner.log 2>&1 &
sleep 5

echo ""
echo "[3] Running API scan..."
curl -X POST http://localhost:8999/scan-api

echo ""
echo ""
echo "=== COMPARISON ==="
echo "BEFORE (commit 1d29bec):"
echo "  - 20 Critical (SQL Injection - FALSE POSITIVE)"
echo "  - 13 Medium (HTTP Methods - FALSE POSITIVE)"
echo "  - 1 High (Mass Assignment)"
echo "  - 1 Medium (Rate Limiting)"
echo "  - 4 Low (Security Headers)"
echo "  - TOTAL: 38 findings"
echo ""
echo "AFTER (commit d0fb620):"
echo "  - Expected: 0-2 Critical (if real SQL errors found)"
echo "  - Expected: 0-3 Medium (if methods truly dangerous)"
echo "  - 1 High (Mass Assignment - need verification)"
echo "  - 1 Medium (Rate Limiting - real issue)"
echo "  - 4 Low (Security Headers - real issue)"
echo "  - EXPECTED TOTAL: 6-11 findings"
echo ""
echo "Check logs above for actual results!"
