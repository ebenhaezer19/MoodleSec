<?php
/**
 * Example usage of database layer
 *
 * @package    local_security_dashboard
 * @copyright  2024 Your Name
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../../config.php');
require_once($CFG->dirroot . '/local/security_dashboard/classes/db_manager.php');
require_once($CFG->dirroot . '/local/security_dashboard/classes/api_client.php');

use local_security_dashboard\db_manager;
use local_security_dashboard\api_client;

require_login();
require_capability('local/security_dashboard:scan', context_system::instance());

// ============================================
// EXAMPLE 1: Trigger scan and save to database
// ============================================

echo "<h2>Example 1: Trigger Scan and Save</h2>";

$api = new api_client();

// Trigger scan
$scan_result = $api->trigger_scan('/login/index.php', 'POST');

if ($scan_result && !isset($scan_result->error)) {
    // Save to database
    $scan_id = db_manager::save_scan($scan_result, $USER->id);
    
    echo "✅ Scan saved with ID: $scan_id<br>";
    echo "Findings: " . count($scan_result->findings) . "<br>";
} else {
    echo "❌ Scan failed: " . ($scan_result->error ?? 'Unknown error') . "<br>";
}

// ============================================
// EXAMPLE 2: Retrieve recent scans
// ============================================

echo "<h2>Example 2: Get Recent Scans</h2>";

$recent_scans = db_manager::get_recent_scans(5);

echo "<table border='1'>";
echo "<tr><th>Scan ID</th><th>Path</th><th>Findings</th><th>Critical</th><th>High</th><th>Date</th></tr>";

foreach ($recent_scans as $scan) {
    echo "<tr>";
    echo "<td>{$scan->scan_id}</td>";
    echo "<td>{$scan->scan_path}</td>";
    echo "<td>{$scan->total_findings}</td>";
    echo "<td>{$scan->critical_count}</td>";
    echo "<td>{$scan->high_count}</td>";
    echo "<td>" . date('Y-m-d H:i', $scan->timecreated) . "</td>";
    echo "</tr>";
}

echo "</table>";

// ============================================
// EXAMPLE 3: Get statistics
// ============================================

echo "<h2>Example 3: Get Statistics (Last 30 Days)</h2>";

$stats = db_manager::get_statistics(30);

echo "<ul>";
echo "<li>Total Scans: {$stats->total_scans}</li>";
echo "<li>Total Findings: {$stats->total_findings}</li>";
echo "<li>Critical: {$stats->critical_findings}</li>";
echo "<li>High: {$stats->high_findings}</li>";
echo "<li>Medium: {$stats->medium_findings}</li>";
echo "<li>Low: {$stats->low_findings}</li>";
echo "<li>Average per scan: {$stats->avg_findings_per_scan}</li>";
echo "</ul>";

echo "<h3>Top Vulnerability Categories:</h3>";
echo "<ol>";
foreach ($stats->top_categories as $category) {
    echo "<li>{$category->category}: {$category->count}</li>";
}
echo "</ol>";

// ============================================
// EXAMPLE 4: Get scan history for charts
// ============================================

echo "<h2>Example 4: Scan History (Last 7 Days)</h2>";

$history = db_manager::get_scan_history(7);

echo "<table border='1'>";
echo "<tr><th>Date</th><th>Day</th><th>Scans</th><th>Findings</th><th>Critical</th><th>High</th></tr>";

foreach ($history as $day) {
    echo "<tr>";
    echo "<td>{$day['date']}</td>";
    echo "<td>{$day['day_name']}</td>";
    echo "<td>{$day['scan_count']}</td>";
    echo "<td>{$day['findings_count']}</td>";
    echo "<td>{$day['critical']}</td>";
    echo "<td>{$day['high']}</td>";
    echo "</tr>";
}

echo "</table>";

// ============================================
// EXAMPLE 5: Get findings for a specific scan
// ============================================

echo "<h2>Example 5: Get Findings for Latest Scan</h2>";

$latest_scan = reset($recent_scans);

if ($latest_scan) {
    $findings = db_manager::get_findings($latest_scan->id);
    
    echo "<h3>Scan: {$latest_scan->scan_id}</h3>";
    echo "<table border='1'>";
    echo "<tr><th>Severity</th><th>Category</th><th>Description</th><th>Status</th></tr>";
    
    foreach ($findings as $finding) {
        echo "<tr>";
        echo "<td>{$finding->severity}</td>";
        echo "<td>{$finding->category}</td>";
        echo "<td>" . substr($finding->description, 0, 100) . "...</td>";
        echo "<td>{$finding->status}</td>";
        echo "</tr>";
    }
    
    echo "</table>";
}

// ============================================
// EXAMPLE 6: Update finding status
// ============================================

echo "<h2>Example 6: Update Finding Status</h2>";

if (!empty($findings)) {
    $first_finding = reset($findings);
    
    // Mark as false positive
    $success = db_manager::update_finding_status($first_finding->id, 'false_positive');
    
    if ($success) {
        echo "✅ Finding #{$first_finding->id} marked as false positive<br>";
    }
}

// ============================================
// EXAMPLE 7: Add custom log
// ============================================

echo "<h2>Example 7: Add Custom Log</h2>";

$log_id = db_manager::add_log(
    null,
    'custom_action',
    'info',
    'User viewed database examples page',
    json_encode(['page' => 'database_usage.php']),
    $USER->id
);

echo "✅ Log entry created with ID: $log_id<br>";

// ============================================
// EXAMPLE 8: Get logs
// ============================================

echo "<h2>Example 8: Recent Logs</h2>";

$logs = db_manager::get_logs(null, 10);

echo "<table border='1'>";
echo "<tr><th>Type</th><th>Level</th><th>Message</th><th>Time</th></tr>";

foreach ($logs as $log) {
    echo "<tr>";
    echo "<td>{$log->log_type}</td>";
    echo "<td>{$log->log_level}</td>";
    echo "<td>{$log->message}</td>";
    echo "<td>" . date('Y-m-d H:i:s', $log->timecreated) . "</td>";
    echo "</tr>";
}

echo "</table>";

// ============================================
// EXAMPLE 9: Calculate CVSS for a finding
// ============================================

echo "<h2>Example 9: Calculate CVSS Score</h2>";

$cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H";
$cvss_result = $api->calculate_cvss($cvss_vector);

if ($cvss_result && !isset($cvss_result->error)) {
    echo "Vector: {$cvss_vector}<br>";
    echo "Score: {$cvss_result->score}<br>";
    echo "Severity: {$cvss_result->severity}<br>";
} else {
    echo "❌ CVSS calculation failed<br>";
}

// ============================================
// EXAMPLE 10: Check service health
// ============================================

echo "<h2>Example 10: Service Health Check</h2>";

$health = $api->check_all_health();

echo "<ul>";
echo "<li>Proxy Service: " . ($health->proxy ? '✅ Online' : '❌ Offline') . "</li>";
echo "<li>CVSS Engine: " . ($health->cvss ? '✅ Online' : '❌ Offline') . "</li>";
echo "<li>Overall Status: " . ($health->overall ? '✅ All Systems Operational' : '⚠️ Some Services Down') . "</li>";
echo "</ul>";

echo "<hr>";
echo "<p><strong>All examples completed!</strong></p>";
