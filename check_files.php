<?php
// Quick verification script
$files = [
    '/var/www/html/moodle/public/local/security_dashboard/lib.php',
    '/var/www/html/moodle/public/local/security_dashboard/index.php'
];

foreach ($files as $f) {
    $mtime = filemtime($f);
    $size = filesize($f);
    echo "$f: ".date('Y-m-d H:i:s', $mtime)." ($size bytes)\n";
}
?>
