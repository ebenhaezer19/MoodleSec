#!/bin/bash
# Script untuk copy moodle-plugin files ke Moodle installation
# Run: bash copy_to_moodle.sh

echo "=========================================="
echo "🔄 Copying Security Dashboard Plugin Files"
echo "=========================================="
echo ""

# Paths
SOURCE_DIR="$HOME/TA/adaptive-moodle-security/MoodleSec/moodle-plugin"
DEST_DIR="/var/www/html/moodle/public/local/security_dashboard"

# Check source directory
if [ ! -d "$SOURCE_DIR" ]; then
    echo "❌ Source directory not found: $SOURCE_DIR"
    exit 1
fi

echo "✅ Source: $SOURCE_DIR"
echo "✅ Destination: $DEST_DIR"
echo ""

# Create destination if not exists
if [ ! -d "$DEST_DIR" ]; then
    echo "📁 Creating destination directory..."
    mkdir -p "$DEST_DIR"
    echo "✅ Directory created"
else
    echo "✅ Destination directory exists"
fi

echo ""
echo "📋 Files to copy:"
echo ""

# List of files to copy
FILES=(
    "debug_display.php"
    "lib.php"
    "payload_management.php"
    "settings.php"
    "version.php"
    "index.php"
    "scan.php"
    "fullscan.php"
    "auth_scan.php"
    "native_auth_scan.php"
    "scheduler.php"
)

SUCCESS=0
FAILED=0

for file in "${FILES[@]}"; do
    SOURCE="$SOURCE_DIR/$file"
    if [ -f "$SOURCE" ]; then
        cp -v "$SOURCE" "$DEST_DIR/$file"
        if [ $? -eq 0 ]; then
            echo "✅ $file"
            ((SUCCESS++))
        else
            echo "❌ $file (copy failed)"
            ((FAILED++))
        fi
    else
        echo "⚠️  $file (not found in source)"
    fi
done

echo ""
echo "=========================================="
echo "📊 Summary:"
echo "✅ Successfully copied: $SUCCESS files"
echo "❌ Failed: $FAILED files"
echo "=========================================="
echo ""

# Verify by listing destination
echo "📁 Files in $DEST_DIR:"
ls -lh "$DEST_DIR" | grep -E "\.php$"

echo ""
echo "✨ Copy complete!"
