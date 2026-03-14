<?php
/**
 * Test script for ZAP integration functions
 */

// Change to the plugin directory
chdir('/var/www/html/moodle/public/local/security_dashboard');

// Include Moodle config
require_once('/var/www/html/moodle/public/config.php');

// Include the ZAP integration library
require_once($CFG->dirroot . '/local/security_dashboard/lib/zap_integration.php');

echo "Testing ZAP Integration Functions\n";
echo "==================================\n\n";

// Test 1: Check if function exists
echo "Test 1: Checking if local_security_dashboard_check_zap_status exists... ";
if (function_exists('local_security_dashboard_check_zap_status')) {
    echo "✓ PASS\n";
} else {
    echo "✗ FAIL\n";
    exit(1);
}

// Test 2: Call the function
echo "Test 2: Calling local_security_dashboard_check_zap_status()... ";
try {
    $result = local_security_dashboard_check_zap_status();
    if (is_array($result) && isset($result['connected'])) {
        echo "✓ PASS\n";
        echo "   - Connected: " . ($result['connected'] ? 'YES' : 'NO') . "\n";
        echo "   - Host: " . $result['host'] . "\n";
        echo "   - Port: " . $result['port'] . "\n";
        echo "   - Version: " . $result['version'] . "\n";
    } else {
        echo "✗ FAIL - Invalid return value\n";
        var_dump($result);
        exit(1);
    }
} catch (Exception $e) {
    echo "✗ FAIL - Exception: " . $e->getMessage() . "\n";
    exit(1);
}

// Test 3: Check other functions exist
echo "\nTest 3: Checking if all ZAP functions exist...\n";
$required_functions = [
    'local_security_dashboard_check_zap_status',
    'local_security_dashboard_trigger_zap_scan',
    'local_security_dashboard_store_scan',
    'local_security_dashboard_get_scan',
    'local_security_dashboard_get_scan_findings',
    'local_security_dashboard_get_recent_scans',
    'local_security_dashboard_get_vulnerability_trends',
    'local_security_dashboard_get_vulnerability_types',
    'local_security_dashboard_get_monthly_statistics',
    'local_security_dashboard_get_compliance_report',
    'local_security_dashboard_notify_findings'
];

$all_exist = true;
foreach ($required_functions as $func) {
    if (function_exists($func)) {
        echo "   ✓ $func\n";
    } else {
        echo "   ✗ $func - MISSING\n";
        $all_exist = false;
    }
}

if (!$all_exist) {
    echo "\n✗ FAIL - Some functions are missing\n";
    exit(1);
}

echo "\n✓ ALL TESTS PASSED!\n";
?>
