<?php
/**
 * File Update Script (Web-accessible)
 * Run via: http://localhost:8998/local/security_dashboard/admin/update_files.php?key=YOUR_RANDOM_KEY
 */

// Simple security check
if ($_GET['key'] !== 'update_now_2026') {
    die('Unauthorized');
}

require_once(__DIR__ . '/../../../config.php');

$updates = [
    [
        'src' => '/mnt/c/Users/Admin/OneDrive/Desktop/Kuliah\ Guwa/TA/MoodleSec/moodle-plugin/lib.php',
        'dst' => $CFG->dirroot . '/local/security_dashboard/lib.php',
        'name' => 'lib.php'
    ],
    [
        'src' => '/mnt/c/Users/Admin/OneDrive/Desktop/Kuliah\ Guwa/TA/MoodleSec/moodle-plugin/index.php',
        'dst' => $CFG->dirroot . '/local/security_dashboard/index.php',
        'name' => 'index.php'
    ]
];

echo "<h2>File Update Tool</h2>\n";

foreach ($updates as $file) {
    $src = str_replace('\ ', ' ', $file['src']);
    
    if (!file_exists($src)) {
        echo "❌ Source not found: " . $file['name'] . "\n<br>";
        continue;
    }
    
    $content = @file_get_contents($src);
    if ($content === false) {
        echo "❌ Cannot read: " . $file['name'] . "\n<br>";
        continue;
    }
    
    if (@file_put_contents($file['dst'], $content)) {
        echo "✅ Updated: " . $file['name'] . " (" . strlen($content) . " bytes)\n<br>";
    } else {
        echo "❌ Failed to write: " . $file['name'] . "\n<br>";
    }
}

echo "\n<h3>Done!</h3>";
?>
