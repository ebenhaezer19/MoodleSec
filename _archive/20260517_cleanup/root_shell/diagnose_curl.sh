#!/bin/bash

echo "=== Moodle Update Error Diagnostics ==="
echo ""

# Test 1: Basic connectivity
echo "[1] Testing DNS resolution..."
nslookup download.moodle.org 2>&1 | head -5

echo ""
echo "[2] Testing HTTP connectivity to moodle.org..."
curl -I -m 5 https://download.moodle.org/releases/ 2>&1 | head -10

echo ""
echo "[3] Testing if PHP curl is enabled..."
php -r 'if (extension_loaded("curl")) { echo "✅ PHP curl is enabled\n"; echo "SSL: " . curl_version()["ssl_version"] . "\n"; } else { echo "❌ PHP curl is NOT enabled\n"; }'

echo ""
echo "[4] Checking Moodle certificate settings..."
grep -i "sslverify\|curlopt_ssl" /var/www/html/moodle/public/config.php 2>/dev/null || echo "No explicit SSL settings found (using defaults)"

echo ""
echo "[5] Testing with curl --insecure (disable cert check)..."
curl -I -k -m 5 https://download.moodle.org/releases/ 2>&1 | head -5

echo ""
echo "[6] Checking network connectivity to Google DNS..."
ping -c 1 8.8.8.8 -W 2 2>&1 | head -2
