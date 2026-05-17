#!/bin/bash
# Copy updated moodle-plugin files with sudo

echo "asdfghjkl6689" | sudo -S bash << 'EOF'
echo "Copying fixed lib.php..."
cp '/mnt/c/Users/Admin/OneDrive/Desktop/Kuliah Guwa/TA/MoodleSec/moodle-plugin/lib.php' '/var/www/html/moodle/public/local/security_dashboard/lib.php'

echo ""
echo "Verifying deployment..."
ls -lh '/var/www/html/moodle/public/local/security_dashboard/lib.php'

echo ""
echo "File size in local dir:"
wc -l '/mnt/c/Users/Admin/OneDrive/Desktop/Kuliah Guwa/TA/MoodleSec/moodle-plugin/lib.php'

echo ""
echo "File size in production:"
wc -l '/var/www/html/moodle/public/local/security_dashboard/lib.php'

echo ""
echo "✓ Deployment complete!"
EOF
