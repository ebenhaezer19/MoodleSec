<?php
require 'config.php';
global $DB;

// Get recent ZAP scans dari database
$scans = $DB->get_records('local_security_scans', [], 'timecreated DESC', '*', 0, 5);

echo "Recent ZAP Scans from Database:\n";
echo str_repeat('=', 60) . "\n";

if (empty($scans)) {
    echo "No scans found.\n";
} else {
    foreach ($scans as $scan) {
        echo "Scan ID: " . $scan->scan_id . "\n";
        echo "Type: " . $scan->scan_type . "\n";
        echo "URL: " . $scan->target_url . "\n";
        echo "Findings: " . $scan->total_findings . " (H:" . $scan->high_count . " M:" . $scan->medium_count . " L:" . $scan->low_count . ")\n";
        echo "Created: " . date('Y-m-d H:i:s', $scan->timecreated) . "\n";
        echo str_repeat('-', 60) . "\n";
    }
}
?>
