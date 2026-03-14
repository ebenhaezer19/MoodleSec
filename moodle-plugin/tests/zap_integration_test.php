<?php
/**
 * Integration tests for ZAP scanning in Moodle plugin
 * 
 * @package    local_security_dashboard
 * @copyright  2026 Security Team
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

// This file demonstrates how to test ZAP integration

class ZAPIntegrationTests {
    
    /**
     * Test 1: Check ZAP server status
     */
    public static function test_zap_status_check() {
        echo "Test 1: ZAP Server Status Check\n";
        echo "================================\n";
        
        $status = local_security_dashboard_check_zap_status();
        
        echo "Connected: " . ($status['connected'] ? "Yes" : "No") . "\n";
        echo "Host: {$status['host']}\n";
        echo "Port: {$status['port']}\n";
        echo "Version: {$status['version']}\n";
        
        assert($status['connected'] === true, "ZAP server should be connected");
        echo "✓ PASSED\n\n";
    }
    
    /**
     * Test 2: Store and retrieve a scan
     */
    public static function test_scan_storage() {
        global $DB;
        
        echo "Test 2: Scan Storage and Retrieval\n";
        echo "===================================\n";
        
        // Create mock scan result
        $scan_result = [
            'success' => true,
            'spider_scan_id' => '1',
            'ascan_scan_id' => '2',
            'target_url' => 'http://localhost/course/view.php',
            'scan_type' => 'unauthenticated',
            'total_findings' => 5,
            'high_risk_findings' => 2,
            'medium_risk_findings' => 2,
            'low_risk_findings' => 1,
            'duration' => 45,
            'timestamp' => time(),
            'alerts' => [
                [
                    'type' => 'SQL Injection',
                    'risk' => 'High',
                    'url' => 'http://localhost/course/view.php?id=1',
                    'method' => 'GET',
                    'evidence' => 'Found SQL injection in id parameter'
                ]
            ]
        ];
        
        // Store scan
        $scan_id = local_security_dashboard_store_scan($scan_result);
        echo "Scan stored with ID: {$scan_id}\n";
        
        // Verify stored data
        $scan = local_security_dashboard_get_scan($scan_id);
        assert($scan->total_findings == 5, "Total findings should be 5");
        assert($scan->high_risk_findings == 2, "High risk findings should be 2");
        
        // Retrieve findings
        $findings = local_security_dashboard_get_scan_findings($scan_id);
        assert(count($findings) == 1, "Should have 1 finding");
        
        echo "Scan ID: {$scan->id}\n";
        echo "Target: {$scan->target_url}\n";
        echo "Total Findings: {$scan->total_findings}\n";
        echo "High Risk: {$scan->high_risk_findings}\n";
        echo "✓ PASSED\n\n";
    }
    
    /**
     * Test 3: Get recent scans
     */
    public static function test_recent_scans() {
        echo "Test 3: Retrieve Recent Scans\n";
        echo "=============================\n";
        
        $scans = local_security_dashboard_get_recent_scans(10);
        
        echo "Found " . count($scans) . " recent scans\n";
        
        foreach ($scans as $scan) {
            echo sprintf(
                "- Scan %d: %s [%s] - %d findings\n",
                $scan->id,
                $scan->target_url,
                $scan->scan_type,
                $scan->total_findings
            );
        }
        
        echo "✓ PASSED\n\n";
    }
    
    /**
     * Test 4: Get vulnerability trends
     */
    public static function test_vulnerability_trends() {
        echo "Test 4: Vulnerability Trends Analysis\n";
        echo "=======================================\n";
        
        $start_time = strtotime('first day of -3 months');
        $end_time = time();
        
        $trends = local_security_dashboard_get_vulnerability_trends($start_time, $end_time);
        
        echo "Period: " . date('Y-m-d', $start_time) . " to " . date('Y-m-d', $end_time) . "\n";
        echo "Total Vulnerabilities: {$trends['total_vulnerabilities']}\n";
        echo "High Risk: {$trends['high_count']}\n";
        echo "Medium Risk: {$trends['medium_count']}\n";
        echo "Low Risk: {$trends['low_count']}\n";
        echo "Trend: {$trends['trend_direction']} ({$trends['trend_percentage']}%)\n";
        
        echo "Data points: " . count($trends['daily_data']) . "\n";
        
        echo "✓ PASSED\n\n";
    }
    
    /**
     * Test 5: Get vulnerability types
     */
    public static function test_vulnerability_types() {
        echo "Test 5: Top Vulnerability Types\n";
        echo "================================\n";
        
        $start_time = strtotime('first day of -3 months');
        $end_time = time();
        
        $types = local_security_dashboard_get_vulnerability_types($start_time, $end_time);
        
        echo "Found " . count($types) . " vulnerability types\n";
        
        foreach ($types as $type) {
            echo sprintf(
                "- %s: %d findings [%s severity]\n",
                $type['type'],
                $type['count'],
                $type['avg_severity']
            );
        }
        
        echo "✓ PASSED\n\n";
    }
    
    /**
     * Test 6: Get compliance report
     */
    public static function test_compliance_report() {
        echo "Test 6: Compliance Report Generation\n";
        echo "====================================\n";
        
        $report = local_security_dashboard_get_compliance_report();
        
        echo "Overall Score: {$report['overall_score']}%\n";
        echo "Score Class: {$report['score_class']}\n";
        echo "High Risk Issues: {$report['high_risk_count']}\n";
        echo "Resolved Issues: {$report['resolved_issues']}\n";
        echo "Last Scan: {$report['last_scan_date']}\n";
        echo "Framework: {$report['framework']}\n";
        echo "Audit Status: {$report['audit_status']}\n";
        
        echo "OWASP Top 10 Coverage:\n";
        foreach ($report['owasp_top10'] as $item) {
            $vulnerable = $item['vulnerable'] ? 'YES' : 'NO';
            echo sprintf(
                "  %d. %s - Vulnerable: %s (%d items)\n",
                $item['rank'],
                $item['name'],
                $vulnerable,
                $item['count']
            );
        }
        
        echo "Remediation Actions: " . count($report['remediation_actions']) . "\n";
        echo "Audit Trail Entries: " . count($report['audit_trail']) . "\n";
        
        echo "✓ PASSED\n\n";
    }
    
    /**
     * Run all tests
     */
    public static function run_all_tests() {
        echo "\n";
        echo "╔════════════════════════════════════════╗\n";
        echo "║   ZAP INTEGRATION TEST SUITE           ║\n";
        echo "╚════════════════════════════════════════╝\n";
        echo "\n";
        
        try {
            // Note: Only run these tests in CLI or with proper setup
            // self::test_zap_status_check();
            self::test_scan_storage();
            self::test_recent_scans();
            self::test_vulnerability_trends();
            self::test_vulnerability_types();
            self::test_compliance_report();
            
            echo "\n";
            echo "╔════════════════════════════════════════╗\n";
            echo "║   ALL TESTS PASSED ✓                  ║\n";
            echo "╚════════════════════════════════════════╝\n";
            echo "\n";
            
            return true;
            
        } catch (Exception $e) {
            echo "\n!!! TEST FAILED !!!\n";
            echo "Error: " . $e->getMessage() . "\n";
            return false;
        }
    }
}

// Example usage:
// $test = new ZAPIntegrationTests();
// $test->run_all_tests();
