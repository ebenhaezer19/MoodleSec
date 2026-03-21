<?php
define('CLI_SCRIPT', true);
require('/var/www/html/moodle/public/config.php');

global $DB;

echo "=== Local Security Scans Table ===\n";
$scans = $DB->get_records('local_security_scans', [], '', '*', 0, 1);
foreach ($scans as $scan) {
    echo "\nScan Record Properties:\n";
    foreach ((array)$scan as $key => $value) {
        echo "  - $key: " . (is_scalar($value) ? $value : gettype($value)) . "\n";
    }
    break;
}

echo "\n=== Local Security Findings Table ===\n";
$findings = $DB->get_records('local_security_findings', [], '', '*', 0, 1);
foreach ($findings as $finding) {
    echo "\nFinding Record Properties:\n";
    foreach ((array)$finding as $key => $value) {
        echo "  - $key: " . (is_scalar($value) ? substr($value, 0, 50) : gettype($value)) . "\n";
    }
    break;
}
