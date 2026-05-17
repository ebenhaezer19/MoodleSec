#!/bin/bash
# Script untuk verify dan setup debug system di WSL
# Run: bash setup_debug_wsl.sh

set -e

echo "════════════════════════════════════════════════════════════"
echo "🔍 Debug System Setup - WSL Verification"
echo "════════════════════════════════════════════════════════════"
echo ""

# Set paths
MOODLE_PATH="/mnt/c/Users/Admin/OneDrive/Desktop/Kuliah Guwa/TA/MoodleSec"
PROXY_PATH="$MOODLE_PATH/proxy"

# Check if paths exist
if [ ! -d "$MOODLE_PATH" ]; then
    echo "❌ MoodleSec path not found: $MOODLE_PATH"
    exit 1
fi

echo "✅ MoodleSec path found: $MOODLE_PATH"
echo ""

# Files to verify
echo "📋 Checking files..."
echo ""

declare -a FILES=(
    "proxy/utils/payload_debug_logger.py"
    "proxy/utils/debug_endpoints.py"
    "proxy/app.py"
    "proxy/INTEGRATION_INSTRUCTIONS.txt"
    "moodle-plugin/debug_display.php"
    "moodle-plugin/DEBUG_INTEGRATION_GUIDE.md"
    "DEBUG_SYSTEM_COMPLETION_REPORT.md"
    "ARCHITECTURE_DIAGRAMS.md"
    "QUICK_ACTION_STEPS.md"
)

SUCCESS=0
MISSING=0

for file in "${FILES[@]}"; do
    FULL_PATH="$MOODLE_PATH/$file"
    if [ -f "$FULL_PATH" ]; then
        SIZE=$(du -h "$FULL_PATH" | cut -f1)
        echo "✅ $file ($SIZE)"
        ((SUCCESS++))
    else
        echo "❌ Missing: $file"
        ((MISSING++))
    fi
done

echo ""
echo "════════════════════════════════════════════════════════════"
echo "Summary: $SUCCESS files found, $MISSING missing"
echo "════════════════════════════════════════════════════════════"
echo ""

if [ $MISSING -eq 0 ]; then
    echo "🎉 All files are ready!"
    echo ""
    echo "📦 Backend Files:"
    echo "  - proxy/utils/payload_debug_logger.py"
    echo "  - proxy/utils/debug_endpoints.py"
    echo "  - proxy/app.py (with debug integration)"
    echo ""
    echo "🎨 Frontend Files:"
    echo "  - moodle-plugin/debug_display.php"
    echo ""
    echo "📖 Documentation:"
    echo "  - DEBUG_INTEGRATION_GUIDE.md"
    echo "  - INTEGRATION_INSTRUCTIONS.txt"
    echo "  - QUICK_ACTION_STEPS.md"
    echo "  - DEBUG_SYSTEM_COMPLETION_REPORT.md"
    echo "  - ARCHITECTURE_DIAGRAMS.md"
    echo ""
    echo "🚀 Next Steps:"
    echo "  1. Read: QUICK_ACTION_STEPS.md"
    echo "  2. Choose integration path (A, B, or C)"
    echo "  3. Start proxy: python proxy/app.py"
    echo "  4. Test: curl http://localhost:8999/api/debug/health"
    echo ""
else
    echo "⚠️  Some files are missing!"
    echo ""
    echo "To fix:"
    echo "1. In PowerShell (Windows), run:"
    echo "   powershell -ExecutionPolicy Bypass -File sync_to_wsl.ps1"
    echo "2. Then run this script again"
    echo ""
fi

# Show database location
echo "💾 Database Location:"
echo "   $PROXY_PATH/data/debug_logs.db (auto-created on first run)"
echo ""

# Show proxy status
echo "🔌 Proxy Configuration:"
echo "   URL: http://localhost:8999"
echo "   Debug Endpoints: http://localhost:8999/api/debug/*"
echo ""

# Python check
if command -v python3 &> /dev/null; then
    PYTHON_VER=$(python3 --version)
    echo "✅ Python3 found: $PYTHON_VER"
else
    echo "⚠️  Python3 not found in WSL"
fi

echo ""
echo "✨ Setup complete! Ready for integration."
echo ""
