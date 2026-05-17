#!/bin/bash
# Deploy Phishing Detection Feature
# Run from: ~/TA/adaptive-moodle-security/MoodleSec/

set -e  # Exit on error

echo "🚀 Deploying Phishing Detection Feature..."
echo ""

# Define paths
DEV_MOODLE="$HOME/TA/adaptive-moodle-security/MoodleSec/moodle-plugin"
DEV_PROXY="$HOME/TA/adaptive-moodle-security/MoodleSec/proxy"
PROD_MOODLE="/var/www/html/moodle/public/local/security_dashboard"
PROD_PROXY="$HOME/TA/adaptive-moodle-security/MoodleSec/proxy"  # Proxy runs from repo

# Check if running from correct directory
if [ ! -d "moodle-plugin" ] || [ ! -d "proxy" ]; then
    echo "❌ Error: Run this script from MoodleSec/ directory"
    exit 1
fi

echo "📋 Step 1: Copying Moodle Plugin Files..."
echo "   From: $DEV_MOODLE"
echo "   To:   $PROD_MOODLE"
echo ""

# Copy new PHP file
sudo cp -v "$DEV_MOODLE/scan_phishing_content.php" "$PROD_MOODLE/"

# Update existing files (index.php, settings.php)
sudo cp -v "$DEV_MOODLE/index.php" "$PROD_MOODLE/"
sudo cp -v "$DEV_MOODLE/settings.php" "$PROD_MOODLE/"

# Set correct permissions
sudo chown -R www-data:www-data "$PROD_MOODLE/"
sudo chmod -R 755 "$PROD_MOODLE/"

echo "✅ Moodle plugin files copied successfully!"
echo ""

echo "📋 Step 2: Verify Proxy Files..."
echo "   Checking: $DEV_PROXY/scanners/phishing_detector.py"
echo "   Checking: $DEV_PROXY/api/phishing_scan_api.py"
echo ""

# Check if phishing detection files exist
if [ -f "$DEV_PROXY/scanners/phishing_detector.py" ]; then
    echo "   ✅ phishing_detector.py exists"
else
    echo "   ❌ phishing_detector.py NOT FOUND!"
    exit 1
fi

if [ -f "$DEV_PROXY/api/phishing_scan_api.py" ]; then
    echo "   ✅ phishing_scan_api.py exists"
else
    echo "   ❌ phishing_scan_api.py NOT FOUND!"
    exit 1
fi

echo ""
echo "📋 Step 3: Check Python Dependencies..."
echo ""

# Activate venv if exists
if [ -d "venv" ]; then
    source venv/bin/activate
    echo "   ✅ Virtual environment activated"
else
    echo "   ⚠️  No venv found, using system Python"
fi

# Check for required package (tldextract)
if python3 -c "import tldextract" 2>/dev/null; then
    echo "   ✅ tldextract package installed"
else
    echo "   ⚠️  Installing tldextract..."
    pip install tldextract
fi

echo ""
echo "📋 Step 4: Update proxy/app.py to register phishing API..."
echo ""

# Check if phishing API is already registered
if grep -q "phishing_scan_api" "$DEV_PROXY/app.py" 2>/dev/null; then
    echo "   ✅ Phishing API already registered in app.py"
else
    echo "   ⚠️  Need to manually add phishing API registration to app.py"
    echo ""
    echo "   Add these lines after other blueprint registrations:"
    echo ""
    echo "   # Import phishing detection API"
    echo "   from api.phishing_scan_api import phishing_api, init_phishing_detector"
    echo ""
    echo "   # Register blueprint"
    echo "   app.register_blueprint(phishing_api)"
    echo ""
    echo "   # Initialize detector (after config loaded)"
    echo "   init_phishing_detector(MOODLE_BASE_DOMAIN)"
    echo ""
fi

echo ""
echo "📋 Step 5: Restart Proxy Service (Native - No Docker)..."
echo ""

# Check if proxy is running
if pgrep -f "uvicorn.*app:app" > /dev/null || pgrep -f "python.*app.py" > /dev/null; then
    echo "   Stopping existing proxy service..."
    pkill -f "uvicorn.*app:app" 2>/dev/null || true
    pkill -f "python.*app.py" 2>/dev/null || true
    sleep 2
fi

# Start proxy service
echo "   Starting proxy service..."
cd "$DEV_PROXY"

# Try uvicorn first (recommended)
if command -v uvicorn &> /dev/null; then
    nohup uvicorn app:app --host 0.0.0.0 --port 8999 > ../logs/proxy.log 2>&1 &
    echo "   ✅ Proxy started with uvicorn on port 8999"
else
    # Fall back to python
    nohup python3 app.py > ../logs/proxy.log 2>&1 &
    echo "   ✅ Proxy started with python on port 8999"
fi

sleep 3

# Verify proxy is running
if curl -s http://localhost:8999/health > /dev/null 2>&1; then
    echo "   ✅ Proxy service is running"
else
    echo "   ⚠️  Proxy service may not be running properly"
    echo "   Check logs: tail -f ~/TA/adaptive-moodle-security/MoodleSec/logs/proxy.log"
fi

echo ""
echo "📋 Step 6: Clear Moodle Cache..."
echo ""

# Clear Moodle cache
sudo -u www-data php "$PROD_MOODLE/../../admin/cli/purge_caches.php"
echo "   ✅ Moodle cache cleared"

echo ""
echo "🎉 Deployment Complete!"
echo ""
echo "📝 Next Steps:"
echo "   1. Check if phishing API registered in proxy/app.py (see Step 4 above)"
echo "   2. Test access: Login to Moodle as admin"
echo "   3. Navigate to: Site Administration → Local plugins → Security Dashboard"
echo "   4. Click: 🛡️ Phishing Scanner button"
echo "   5. Try scanning user profiles or forum posts"
echo ""
echo "🔍 Testing URLs:"
echo "   Moodle Dashboard: http://your-moodle-url/local/security_dashboard/"
echo "   Phishing Scanner: http://your-moodle-url/local/security_dashboard/scan_phishing_content.php"
echo "   Proxy API Test:   http://localhost:8999/phishing/stats"
echo ""
echo "📚 Documentation:"
echo "   User Guide: PHISHING_DETECTION_GUIDE.md"
echo ""
