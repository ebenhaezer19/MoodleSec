<?php
// File copy script for WSL

$files_to_copy = [
    '/mnt/c/Users/Admin/OneDrive/Desktop/Kuliah\ Guwa/TA/MoodleSec/moodle-plugin/lib.php' => '/var/www/html/moodle/public/local/security_dashboard/lib.php',
    '/mnt/c/Users/Admin/OneDrive/Desktop/Kuliah\ Guwa/TA/MoodleSec/moodle-plugin/index.php' => '/var/www/html/moodle/public/local/security_dashboard/index.php',
];

foreach ($files_to_copy as $src => $dst) {
    $src = str_replace('\ ', ' ', $src);
    if (file_exists($src)) {
        $content = file_get_contents($src);
        if (file_put_contents($dst, $content)) {
            echo "✓ Updated: " . basename($dst) . "\n";
        } else {
            echo "✗ Failed to update: " . basename($dst) . "\n";
        }
    } else {
        echo "✗ Source file not found: " . $src . "\n";
    }
}

echo "\nDone!\n";
?>
