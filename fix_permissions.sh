#!/bin/bash
# Script untuk fix permissions di Moodle security dashboard plugin

PLUGIN_DIR="/var/www/html/moodle/public/local/security_dashboard"

if [ ! -d "$PLUGIN_DIR" ]; then
    echo "❌ Plugin directory not found: $PLUGIN_DIR"
    exit 1
fi

echo "🔧 Fixing permissions in $PLUGIN_DIR"
echo "════════════════════════════════════════════════════════"
echo ""

# Fix all PHP files - ownership to www-data:www-data
echo "📝 Setting ownership to www-data:www-data..."
sudo chown -R www-data:www-data "$PLUGIN_DIR"/*.php
echo "✅ PHP files ownership fixed"

# Fix permissions - 644 for files, 755 for directories
echo ""
echo "🔒 Setting file permissions to 644 (rw-r--r--)..."
sudo find "$PLUGIN_DIR" -type f -name "*.php" -exec chmod 644 {} \;
echo "✅ File permissions fixed"

echo ""
echo "📁 Setting directory permissions to 755 (rwxr-xr-x)..."
sudo find "$PLUGIN_DIR" -type d -exec chmod 755 {} \;
echo "✅ Directory permissions fixed"

echo ""
echo "════════════════════════════════════════════════════════"
echo "✨ Permission fix complete!"
echo ""

# Verify
echo "📊 Verification - PHP files ownership:"
echo "════════════════════════════════════════════════════════"
ls -la "$PLUGIN_DIR"/*.php | awk '{print $3":"$4, $9}'

echo ""
echo "✅ All files should now be owned by www-data:www-data"
echo "✅ All files should have 644 permissions"
