#!/bin/bash
# PHASE 2 QUICK START GUIDE
# Dynamic Payload Management & ZAP Integration

echo "=================================================="
echo "  PHASE 2: Dynamic Payload Management Quick Start"
echo "=================================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check prerequisites
echo "[*] Checking prerequisites..."

# Check if running from correct directory
if [ ! -f "proxy/app.py" ]; then
    echo -e "${RED}❌ Error: Run from MoodleSec root directory${NC}"
    echo "Usage: cd ~/TA/adaptive-moodle-security/MoodleSec && bash PHASE_2_QUICKSTART.sh"
    exit 1
fi

echo -e "${GREEN}✓${NC} Running from correct directory"

# Step 1: Start the proxy app
echo ""
echo "[STEP 1] Starting proxy app..."
cd proxy

if pgrep -f "python.*app.py" > /dev/null; then
    echo -e "${YELLOW}⚠${NC} App already running. Skipping..."
else
    echo "[*] Starting: python3 app.py &"
    python3 app.py &
    APP_PID=$!
    sleep 4
    echo -e "${GREEN}✓${NC} App started (PID: $APP_PID)"
fi

# Step 2: Check health
echo ""
echo "[STEP 2] Checking app health..."
HEALTH=$(curl -s http://localhost:8999/health)
if echo "$HEALTH" | grep -q "ok"; then
    echo -e "${GREEN}✓${NC} App is healthy"
else
    echo -e "${RED}❌${NC} App not responding properly"
    exit 1
fi

# Step 3: Show current payload stats
echo ""
echo "[STEP 3] Current payload repository status:"
curl -s http://localhost:8999/api/payload-stats | python3 -m json.tool | head -30

# Step 4: ZAP integration options
echo ""
echo "[STEP 4] Available Operations:"
echo ""
echo "Option A - Import payloads from ZAP:"
echo "  curl -X POST http://localhost:8999/api/payloads/import-from-zap"
echo ""
echo "Option B - Reload payloads (after ZAP import):"
echo "  curl -X POST http://localhost:8999/api/payloads/reload"
echo ""
echo "Option C - Reload specific category:"
echo "  curl -X POST 'http://localhost:8999/api/payloads/reload?category=XSS'"
echo ""
echo "Option D - Reload scanners with new payloads:"
echo "  curl -X POST http://localhost:8999/api/scanners/reload-payloads"
echo ""
echo "Option E - Check import status:"
echo "  curl http://localhost:8999/api/payloads/import-status | python3 -m json.tool"
echo ""
echo "Option F - Get top XSS payloads:"
echo "  curl 'http://localhost:8999/api/payload-top/XSS?limit=5' | python3 -m json.tool"
echo ""

# Step 5: Run integration tests (optional)
echo "[STEP 5] Optional: Run integration tests"
echo "  cd proxy && python3 test_phase2_integration.py"
echo ""

echo -e "${GREEN}=================================================="
echo "  Phase 2 is ready! Choose an operation above."
echo "==================================================${NC}"
