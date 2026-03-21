#!/bin/bash

# Copy lib.php
cat /mnt/c/Users/Admin/OneDrive/Desktop/Kuliah\ Guwa/TA/MoodleSec/moodle-plugin/lib.php > /var/www/html/moodle/public/local/security_dashboard/lib.php.tmp
mv /var/www/html/moodle/public/local/security_dashboard/lib.php.tmp /var/www/html/moodle/public/local/security_dashboard/lib.php 2>/dev/null || {
    echo "Trying alternative method for lib.php..."
    install -m 644 -o www-data -g www-data /tmp/lib_new.php /var/www/html/moodle/public/local/security_dashboard/lib.php 2>/dev/null || {
        echo "Failed to update lib.php"
    }
}

# Copy index.php  
cat /mnt/c/Users/Admin/OneDrive/Desktop/Kuliah\ Guwa/TA/MoodleSec/moodle-plugin/index.php > /var/www/html/moodle/public/local/security_dashboard/index.php.tmp
mv /var/www/html/moodle/public/local/security_dashboard/index.php.tmp /var/www/html/moodle/public/local/security_dashboard/index.php 2>/dev/null || {
    echo "Trying alternative method for index.php..."
    install -m 644 -o www-data -g www-data /tmp/index_new.php /var/www/html/moodle/public/local/security_dashboard/index.php 2>/dev/null || {
        echo "Failed to update index.php"
    }
}

echo "Files updated successfully"
