#!/bin/bash

echo "================================================================================"
echo "VERIFY XSS FINDINGS - Are they real or false positive?"
echo "================================================================================"

echo ""
echo "[1] Checking last scan results from database..."

ssh krisopras1913@103.127.132.74 << 'ENDSSH'
cd ~/TA/adaptive-moodle-security/MoodleSec/proxy

echo ""
echo "Last 10 findings (including filtered by ML):"
sqlite3 moodlesec.db "SELECT id, severity, category, description, evidence, ml_is_false_positive FROM findings ORDER BY id DESC LIMIT 10;"

echo ""
echo ""
echo "XSS findings breakdown:"
sqlite3 moodlesec.db "SELECT 
    severity,
    COUNT(*) as total,
    SUM(CASE WHEN ml_is_false_positive = 1 THEN 1 ELSE 0 END) as filtered_by_ml,
    SUM(CASE WHEN ml_is_false_positive = 0 THEN 1 ELSE 0 END) as kept
FROM findings 
WHERE category LIKE '%XSS%' OR category LIKE '%Cross-Site%'
GROUP BY severity;"

echo ""
echo ""
echo "Sample of FILTERED findings (ML marked as FP):"
sqlite3 moodlesec.db "SELECT id, description, evidence FROM findings WHERE ml_is_false_positive = 1 AND category LIKE '%XSS%' LIMIT 5;"

echo ""
echo ""
echo "Sample of KEPT findings (NOT filtered by ML):"
sqlite3 moodlesec.db "SELECT id, description, evidence FROM findings WHERE ml_is_false_positive = 0 AND category LIKE '%XSS%' LIMIT 5;"

ENDSSH

echo ""
echo "================================================================================"
echo "ANALYSIS"
echo "================================================================================"
echo ""
echo "If filtered findings show:"
echo "  - Evidence: 'Output: &lt;script&gt;' → ✅ Correct FP (safely encoded)"
echo "  - Evidence: 'CSP header present' → ✅ Correct FP (protected by CSP)"
echo "  - Evidence: '<script> in HTML comments' → ✅ Correct FP (not executable)"
echo ""
echo "If kept findings show:"
echo "  - Evidence: '<script>alert(1)</script> reflected' → ❌ Real vulnerability"
echo "  - Evidence: 'innerHTML = user_input' → ❌ Real vulnerability"
echo ""
echo "================================================================================"
