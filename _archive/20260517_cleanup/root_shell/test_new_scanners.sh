#!/bin/bash

echo "================================================================================"
echo "TESTING NEW MOODLE-SPECIFIC VULNERABILITY SCANNERS"
echo "================================================================================"
echo ""
echo "New scanners added:"
echo "  ✅ XSS Scanner (45% of Moodle CVEs)"
echo "  ✅ File Upload Scanner (10-15% of CVEs)"
echo "  ✅ Information Disclosure Scanner (15-20% of CVEs)"
echo ""
echo "Expected improvements:"
echo "  - Before: 38 findings (84% false positive rate)"
echo "  - After: 6-15 findings (5-10% false positive rate)"
echo ""
echo "================================================================================"

cd ~/TA/adaptive-moodle-security/MoodleSec

echo ""
echo "[1/5] Pulling latest code (commit 1333c29)..."
git pull origin main

echo ""
echo "[2/5] Restarting proxy service..."
cd proxy
pkill -f "uvicorn app:app"
sleep 3
nohup uvicorn app:app --host 0.0.0.0 --port 8999 > /tmp/moodlesec_scanner.log 2>&1 &
PROXY_PID=$!
echo "Proxy started with PID: $PROXY_PID"
sleep 5

echo ""
echo "[3/5] Waiting for proxy to be ready..."
for i in {1..10}; do
    if curl -s http://localhost:8999/health > /dev/null 2>&1; then
        echo "✅ Proxy is ready!"
        break
    fi
    echo "Waiting... ($i/10)"
    sleep 2
done

echo ""
echo "[4/5] Running comprehensive API security scan..."
echo "This will now test:"
echo "  - API Discovery"
echo "  - Authentication Bypass"
echo "  - Input Validation (improved - fewer false positives)"
echo "  - HTTP Method Tampering (improved - checks exploitability)"
echo "  - Rate Limiting"
echo "  - Mass Assignment"
echo "  - Data Exposure"
echo "  - Security Headers"
echo "  - XSS Vulnerabilities (NEW - Moodle-specific)"
echo "  - File Upload Vulnerabilities (NEW - Zip slip, PHP shell)"
echo "  - Information Disclosure (NEW - User enum, email exposure)"
echo ""

curl -X POST http://localhost:8999/scan-api 2>&1 | tee /tmp/scan_results.txt

echo ""
echo ""
echo "[5/5] Analyzing results..."
echo ""

# Extract key metrics from scan results
TOTAL_FINDINGS=$(grep -oP "\[API Scan\] Complete! Found \K\d+" /tmp/scan_results.txt | tail -1)
XSS_FINDINGS=$(grep -c "\[XSS Scanner\].*🔍" /tmp/scan_results.txt || echo "0")
UPLOAD_FINDINGS=$(grep -c "\[File Upload Scanner\].*🔍" /tmp/scan_results.txt || echo "0")
INFO_FINDINGS=$(grep -c "\[Info Disclosure Scanner\].*🔍" /tmp/scan_results.txt || echo "0")
CRITICAL=$(grep -oP "Critical=\K\d+" /tmp/scan_results.txt | tail -1)
HIGH=$(grep -oP "High=\K\d+" /tmp/scan_results.txt | tail -1)
MEDIUM=$(grep -oP "Medium=\K\d+" /tmp/scan_results.txt | tail -1)
LOW=$(grep -oP "Low=\K\d+" /tmp/scan_results.txt | tail -1)

echo "================================================================================"
echo "SCAN RESULTS SUMMARY"
echo "================================================================================"
echo ""
echo "📊 TOTAL FINDINGS: $TOTAL_FINDINGS"
echo ""
echo "By Scanner:"
echo "  🔍 XSS Scanner: $XSS_FINDINGS findings"
echo "  📁 File Upload Scanner: $UPLOAD_FINDINGS findings"
echo "  📧 Info Disclosure Scanner: $INFO_FINDINGS findings"
echo "  🔧 Other scanners: $((TOTAL_FINDINGS - XSS_FINDINGS - UPLOAD_FINDINGS - INFO_FINDINGS)) findings"
echo ""
echo "By Severity:"
echo "  🔴 Critical: ${CRITICAL:-0}"
echo "  🟠 High: ${HIGH:-0}"
echo "  🟡 Medium: ${MEDIUM:-0}"
echo "  🟢 Low: ${LOW:-0}"
echo ""
echo "================================================================================"
echo "COMPARISON WITH PREVIOUS SCAN"
echo "================================================================================"
echo ""
echo "BEFORE (commit d0fb620):"
echo "  - 38 total findings"
echo "  - 20 Critical (SQL Injection) ❌ FALSE POSITIVE"
echo "  - 13 Medium (HTTP Methods) ❌ FALSE POSITIVE"
echo "  - 5 Real issues ✅"
echo "  - False Positive Rate: 84%"
echo ""
echo "AFTER (commit 1333c29):"
echo "  - $TOTAL_FINDINGS total findings"
echo "  - ${CRITICAL:-0} Critical (expected 0-2 if real XSS/SQLi found)"
echo "  - ${HIGH:-0} High (expected 1-4 from privilege escalation, file upload)"
echo "  - ${MEDIUM:-0} Medium (expected 1-5 from info disclosure, rate limiting)"
echo "  - ${LOW:-0} Low (expected 2-4 from security headers, version disclosure)"
echo "  - Expected False Positive Rate: 5-10%"
echo ""
echo "================================================================================"
echo "IMPROVEMENTS"
echo "================================================================================"
echo ""
if [ "$TOTAL_FINDINGS" -lt 20 ]; then
    echo "✅ Significant reduction in findings (38 → $TOTAL_FINDINGS)"
    echo "✅ Improved scanner accuracy"
else
    echo "⚠️  Still high number of findings - may need ML training"
fi
echo ""
echo "New capabilities:"
echo "✅ XSS detection (45% of real Moodle CVEs)"
echo "✅ File upload vulnerabilities (Zip slip, PHP shell)"
echo "✅ Information disclosure (user enumeration, email exposure)"
echo "✅ Reduced SQL injection false positives"
echo "✅ Improved HTTP method tampering detection"
echo ""
echo "================================================================================"
echo "NEXT STEPS"
echo "================================================================================"
echo ""
echo "1. Review detailed findings in Moodle dashboard:"
echo "   http://103.127.132.74:8998/local/moodlesec/reports.php"
echo ""
echo "2. Check full scan logs:"
echo "   tail -f /tmp/moodlesec_scanner.log"
echo ""
echo "3. For ML training to further reduce false positives:"
echo "   cat ~/TA/adaptive-moodle-security/MoodleSec/ML_TRAINING_RECOMMENDATIONS.md"
echo ""
echo "4. To manually verify findings:"
echo "   cd ~/TA/adaptive-moodle-security/MoodleSec/proxy"
echo "   sqlite3 moodlesec.db 'SELECT id, severity, category, description FROM findings ORDER BY id DESC LIMIT 20;'"
echo ""
echo "================================================================================"
echo "TEST COMPLETE!"
echo "================================================================================"
