<?php
/**
 * Test scan lookup - verify db_id integration
 */

define('CLI_SCRIPT', true);
require('/var/www/html/moodle/public/config.php');
require_once($CFG->libdir . '/filelib.php');
require_once('/var/www/html/moodle/public/local/security_dashboard/lib.php');
require_once('/var/www/html/moodle/public/local/security_dashboard/lib/zap_integration.php');

// 1. Test get_logs() - verify db_id is present
echo "=== Testing get_logs() Function ===\n";
$logs_result = local_security_dashboard_get_logs(10);
$logs = $logs_result['logs'] ?? [];

echo "Total logs returned: " . count($logs) . "\n\n";

foreach ($logs as $i => $log) {
    if ($log['source'] === 'zap') {
        echo "Log #" . ($i + 1) . " (ZAP):\n";
        echo "  - scan_id: " . $log['scan_id'] . "\n";
        echo "  - db_id: " . ($log['db_id'] ?? 'MISSING') . "\n";
        echo "  - findings: " . $log['findings'] . "\n";
        
        // 2. Test scan lookup with db_id
        if (!empty($log['db_id'])) {
            $scan = local_security_dashboard_get_scan($log['db_id']);
            if ($scan) {
                echo "  ✓ Lookup with db_id='" . $log['db_id'] . "': SUCCESS\n";
                echo "    - Found scan: " . $scan->scan_id . "\n";
            } else {
                echo "  ✗ Lookup with db_id='" . $log['db_id'] . "': FAILED\n";
            }
        }
        echo "\n";
    }
}

echo "=== Test Complete ===\n";
