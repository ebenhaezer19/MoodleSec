#!/bin/bash

echo "================================================================================"
echo "TESTING NEW API SCANNER (Not Full Scan!)"
echo "================================================================================"
echo ""
echo "Difference:"
echo "  - /scan-full: Old crawler-based scanner (finds 53 XSS)"
echo "  - /scan-api: NEW targeted scanner with XSS, File Upload, Info Disclosure"
echo ""
echo "================================================================================"

ssh krisopras1913@103.127.132.74 << 'ENDSSH'

cd ~/TA/adaptive-moodle-security/MoodleSec

echo "[1/4] Pulling latest code..."
git pull origin main | tail -5

echo ""
echo "[2/4] Checking if new scanners exist..."
if [ -f "proxy/api/xss_scanner.py" ]; then
    echo "✅ XSS Scanner found"
    grep "class XSSScanner" proxy/api/xss_scanner.py
else
    echo "❌ XSS Scanner not found - need to pull!"
fi

if [ -f "proxy/api/file_upload_scanner.py" ]; then
    echo "✅ File Upload Scanner found"
else
    echo "❌ File Upload Scanner not found"
fi

if [ -f "proxy/api/info_disclosure_scanner.py" ]; then
    echo "✅ Info Disclosure Scanner found"
else
    echo "❌ Info Disclosure Scanner not found"
fi

echo ""
echo "[3/4] Restarting proxy..."
cd proxy
pkill -f "uvicorn app:app"
sleep 3
nohup uvicorn app:app --host 0.0.0.0 --port 8999 > /tmp/api_scan.log 2>&1 &
sleep 5

echo ""
echo "[4/4] Running API scan (with new scanners)..."
echo ""
echo "This will test:"
echo "  - REST API endpoints"
echo "  - XSS vulnerabilities (NEW)"
echo "  - File upload vulnerabilities (NEW)"
echo "  - Information disclosure (NEW)"
echo ""

curl -X POST http://localhost:8999/scan-api 2>&1 | grep -E "\[.*Scanner\]|Complete|Summary|findings"

echo ""
echo ""
echo "================================================================================"
echo "Check full logs:"
echo "  tail -100 /tmp/api_scan.log"
echo "================================================================================"

ENDSSH
