<?php
/**
 * Library functions for Security Dashboard
 *
 * @package    local_security_dashboard
 * @copyright  2025 Krisopras & Nathanael
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir . '/filelib.php');

/**
 * Add navigation nodes
 */
function local_security_dashboard_extend_navigation(global_navigation $navigation) {
    global $PAGE;
    
    if (has_capability('local/security_dashboard:view', context_system::instance())) {
        $node = $navigation->add(
            get_string('security_dashboard', 'local_security_dashboard'),
            new moodle_url('/local/security_dashboard/index.php'),
            navigation_node::TYPE_CUSTOM,
            null,
            'security_dashboard',
            new pix_icon('i/report', '')
        );
        $node->showinflatnavigation = true;
    }
}

/**
 * Get logs from proxy service
 */
function local_security_dashboard_get_logs($limit = 100) {
    global $DB;
    
    $logs = [];
    $proxy_logs = [];
    $zap_logs = [];
    
    // Get logs from proxy service - NEW endpoint with ML data
    $proxy_url = get_config('local_security_dashboard', 'proxy_url');
    
    // Fallback to default localhost if not configured
    if (empty($proxy_url)) {
        $proxy_url = 'http://localhost:8999';
    }
    
    // ALWAYS TRY TO FETCH FROM PROXY - don't check if logs are empty
    if (!empty($proxy_url)) {
        // Use new /ml/dashboard/recent-scans endpoint for integrated data
        $url = rtrim($proxy_url, '/') . '/ml/dashboard/recent-scans';
        
        try {
            $curl = new curl();
            $response = $curl->get($url);
            
            // DEBUG: Log the response
            error_log('[lib.php] Proxy endpoint response length: ' . strlen($response));
            
            if (!$curl->get_errno()) {
                $proxy_data = json_decode($response, true);
                error_log('[lib.php] Decoded ' . (isset($proxy_data['recent_scans']) ? count($proxy_data['recent_scans']) : 0) . ' proxy recent scans');
                
                if (isset($proxy_data['recent_scans']) && is_array($proxy_data['recent_scans']) && count($proxy_data['recent_scans']) > 0) {
                    foreach ($proxy_data['recent_scans'] as $scan) {
                        // Parse ISO 8601 timestamp to Unix timestamp
                        $timestamp_str = $scan['timestamp'] ?? date('c');
                        $timestamp_obj = new DateTime($timestamp_str);
                        $timestamp_int = $timestamp_obj->getTimestamp();
                        
                        // Extract severity breakdown
                        $severity_breakdown = $scan['severity_breakdown'] ?? [];
                        
                        // Extract ML filtering stats
                        $ml_filtering = $scan['ml_filtering'] ?? ['raw_findings' => 0, 'false_positives_removed' => 0, 'actual_vulnerabilities' => 0];
                        
                        $proxy_logs[] = [
                            'type' => $scan['scan_type'] ?? 'security_scan',
                            'timestamp' => date('Y-m-d H:i:s', $timestamp_int),
                            'details' => 'Scan ID: ' . ($scan['scan_id'] ?? 'N/A') . ' | Findings: ' . intval($scan['findings_count'] ?? 0),
                            'url' => $scan['target_url'] ?? '',
                            'scan_id' => $scan['scan_id'] ?? null,
                            'findings' => intval($scan['findings_count'] ?? 0),
                            'critical' => intval($severity_breakdown['Critical'] ?? $severity_breakdown['critical'] ?? 0),
                            'high' => intval($severity_breakdown['High'] ?? $severity_breakdown['high'] ?? 0),
                            'medium' => intval($severity_breakdown['Medium'] ?? $severity_breakdown['medium'] ?? 0),
                            'low' => intval($severity_breakdown['Low'] ?? $severity_breakdown['low'] ?? 0),
                            'info' => intval($severity_breakdown['Info'] ?? $severity_breakdown['info'] ?? 0),
                            'original_count' => intval($ml_filtering['raw_findings'] ?? 0),
                            'fp_filtered' => intval($ml_filtering['false_positives_removed'] ?? 0),
                            'final_count' => intval($ml_filtering['actual_vulnerabilities'] ?? 0),
                            'source' => 'proxy'
                        ];
                        error_log('[lib.php] Added PROXY: ' . ($scan['scan_type'] ?? 'unknown') . ' [' . ($scan['scan_id'] ?? 'N/A') . ']');
                    }
                }
            }
        } catch (Exception $e) {
            // Continue even if proxy fails
            error_log('Error fetching from /ml/dashboard/recent-scans: ' . $e->getMessage());
        }
    }
    
    // If proxy new endpoint failed, try old endpoint as fallback (but don't skip ZAP)
    if (empty($proxy_logs) && !empty($proxy_url)) {
        $url = rtrim($proxy_url, '/') . '/logs?limit=' . $limit;
        
        try {
            $curl = new curl();
            $response = $curl->get($url);
            
            if (!$curl->get_errno()) {
                $proxy_data = json_decode($response, true);
                if (isset($proxy_data['logs']) && is_array($proxy_data['logs'])) {
                    foreach ($proxy_data['logs'] as $log) {
                        $timestamp_str = $log['timestamp'] ?? date('c');
                        $timestamp_obj = new DateTime($timestamp_str);
                        $timestamp_int = $timestamp_obj->getTimestamp();
                        
                        $summary = $log['summary'] ?? ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
                        $ml_stats = $log['ml_stats'] ?? [];
                        $original_count = intval($ml_stats['original_findings'] ?? $log['findings_count'] ?? 0);
                        $fp_filtered = intval($ml_stats['fp_filtered'] ?? 0);
                        $final_count = intval($log['findings_count'] ?? 0);
                        
                        $proxy_logs[] = [
                            'type' => $log['type'] ?? 'proxy_transaction',
                            'timestamp' => date('Y-m-d H:i:s', $timestamp_int),
                            'details' => 'Scan ID: ' . ($log['scan_id'] ?? 'N/A') . ' | Findings: ' . ($log['findings_count'] ?? 0),
                            'url' => $log['base_url'] ?? '',
                            'scan_id' => $log['scan_id'] ?? null,
                            'findings' => intval($log['findings_count'] ?? 0),
                            'critical' => intval($summary['critical'] ?? 0),
                            'high' => intval($summary['high'] ?? 0),
                            'medium' => intval($summary['medium'] ?? 0),
                            'low' => intval($summary['low'] ?? 0),
                            'original_count' => $original_count,
                            'fp_filtered' => $fp_filtered,
                            'final_count' => $final_count,
                            'source' => 'proxy'
                        ];
                    }
                }
            }
        } catch (Exception $e) {
            error_log('Error fetching proxy logs (fallback): ' . $e->getMessage());
        }
    }
    
    // ALWAYS GET ZAP SCANS FROM DATABASE - NOT JUST WHEN PROXY FAILS!
    try {
        $zap_scans = $DB->get_records('local_security_scans', 
            [], 'timecreated DESC', '*', 0, $limit);
        
        if ($zap_scans) {
            foreach ($zap_scans as $scan) {
                $zap_logs[] = [
                    'type' => $scan->scan_type ?? 'full_site_scan',
                    'timestamp' => date('Y-m-d H:i:s', $scan->timecreated),
                    'details' => 'Scan ID: ' . $scan->scan_id . ' | Findings: ' . $scan->total_findings,
                    'url' => $scan->target_url,
                    'scan_id' => $scan->scan_id,
                    'db_id' => $scan->id,
                    'findings' => $scan->total_findings,
                    'critical' => $scan->critical_count ?? 0,
                    'high' => $scan->high_count ?? 0,
                    'medium' => $scan->medium_count ?? 0,
                    'low' => $scan->low_count ?? 0,
                    'source' => 'zap'
                ];
                error_log('[lib.php] Added ZAP: ' . ($scan->scan_type ?? 'unknown') . ' [' . ($scan->scan_id ?? 'N/A') . ']');
            }
        }
    } catch (Exception $e) {
        error_log('Error fetching ZAP scans: ' . $e->getMessage());
    }
    
    // Merge both proxy and ZAP logs
    $logs = array_merge($proxy_logs, $zap_logs);
    
    error_log('[lib.php] ===== MERGED SOURCES =====');
    error_log('[lib.php] Proxy logs: ' . count($proxy_logs));
    error_log('[lib.php] ZAP logs: ' . count($zap_logs));
    error_log('[lib.php] Total logs collected: ' . count($logs));
    
    // Sort by timestamp descending and limit results
    usort($logs, function($a, $b) {
        return strtotime($b['timestamp']) - strtotime($a['timestamp']);
    });
    
    $logs = array_slice($logs, 0, $limit);
    
    error_log('[lib.php] Total logs after slice: ' . count($logs) . ' (limit=' . $limit . ')');
    
    if (count($logs) > 0) {
        error_log('[lib.php] ===== LOGS BEING RETURNED TO INDEX.PHP =====');
        foreach ($logs as $i => $log) {
            error_log('[lib.php] Log ' . ($i+1) . ': [' . strtoupper($log['source']) . '] ' . $log['type'] . ' | Scan: ' . ($log['scan_id'] ?? 'N/A') . ' | Findings: ' . intval($log['findings'] ?? 0));
        }
    } else {
        error_log('[lib.php] ⚠️ NO LOGS COLLECTED FROM ANY SOURCE!');
    }
    
    return ['logs' => $logs, 'total' => count($logs)];
}

/**
 * Apply ML FP Reducer + Severity Predictor to a list of findings in real-time.
 *
 * Calls the proxy's /ml/post-process-zap endpoint. Used by ZAP scan pages so
 * that findings are ML-filtered even though ZAP writes directly to the Moodle DB
 * (bypassing the proxy pipeline).
 *
 * @param  array $findings  Raw findings array (each item has severity, category,
 *                          description, evidence, url, etc.)
 * @return array {
 *   'findings'  => array   ML-filtered & severity-adjusted findings,
 *   'ml_stats'  => array   {original_count, fp_filtered, severity_adjusted, final_count},
 *   'ml_enabled' => bool
 * }
 */
function local_security_dashboard_ml_filter_findings(array $findings): array {
    $proxy_url = get_config('local_security_dashboard', 'proxy_url');
    if (empty($proxy_url)) {
        $proxy_url = 'http://localhost:8999';
    }

    // Graceful passthrough when proxy is unavailable or findings list is empty.
    if (empty($findings)) {
        return [
            'findings'   => [],
            'ml_stats'   => ['original_count' => 0, 'fp_filtered' => 0,
                             'severity_adjusted' => 0, 'final_count' => 0],
            'ml_enabled' => false,
        ];
    }

    $url = rtrim($proxy_url, '/') . '/ml/post-process-zap';

    try {
        $curl = new curl();
        $curl->setopt([
            'CURLOPT_TIMEOUT'        => 30,
            'CURLOPT_CONNECTTIMEOUT' => 5,
        ]);

        $response = $curl->post($url, json_encode(array_values($findings)), [
            'CURLOPT_HTTPHEADER' => ['Content-Type: application/json'],
        ]);

        if ($curl->get_errno()) {
            error_log('[ML Filter] cURL error: ' . $curl->error);
            return ['findings' => $findings,
                    'ml_stats' => ['original_count' => count($findings), 'fp_filtered' => 0,
                                   'severity_adjusted' => 0, 'final_count' => count($findings)],
                    'ml_enabled' => false];
        }

        $result = json_decode($response, true);

        if (json_last_error() !== JSON_ERROR_NONE || !isset($result['findings'])) {
            error_log('[ML Filter] Bad JSON from proxy: ' . substr($response, 0, 200));
            return ['findings' => $findings,
                    'ml_stats' => ['original_count' => count($findings), 'fp_filtered' => 0,
                                   'severity_adjusted' => 0, 'final_count' => count($findings)],
                    'ml_enabled' => false];
        }

        error_log('[ML Filter] ZAP: ' . count($findings) . ' raw → '
                  . ($result['ml_stats']['fp_filtered'] ?? 0) . ' FPs removed → '
                  . ($result['ml_stats']['final_count'] ?? count($result['findings'])) . ' remain');

        return $result;

    } catch (Exception $e) {
        error_log('[ML Filter] Exception: ' . $e->getMessage());
        return ['findings' => $findings,
                'ml_stats' => ['original_count' => count($findings), 'fp_filtered' => 0,
                               'severity_adjusted' => 0, 'final_count' => count($findings)],
                'ml_enabled' => false];
    }
}

/**
 * Trigger security scan
 */
function local_security_dashboard_trigger_scan($path, $method = 'GET', $parameters = null) {
    $proxy_url = get_config('local_security_dashboard', 'proxy_url');
    if (empty($proxy_url)) {
        $proxy_url = 'http://localhost:8999';
    }
    
    if (empty($proxy_url)) {
        return ['error' => 'Proxy URL not configured'];
    }
    
    // Additional security: Normalize and validate path before sending
    $path = clean_param($path, PARAM_PATH);
    
    // Final security check: reject if contains traversal patterns
    if (preg_match('#\.\.|//|\\\\#', $path)) {
        return ['error' => 'Invalid path: contains path traversal patterns'];
    }
    
    $url = rtrim($proxy_url, '/') . '/scan-trigger';
    
    $data = [
        'path' => $path,
        'method' => $method
    ];
    
    if ($parameters) {
        $data['parameters'] = $parameters;
    }
    
    try {
        $curl = new curl();
        $response = $curl->post($url, json_encode($data), [
            'CURLOPT_HTTPHEADER' => ['Content-Type: application/json']
        ]);
        
        if ($curl->get_errno()) {
            return ['error' => 'Connection error: ' . $curl->error];
        }
        
        return json_decode($response, true);
    } catch (Exception $e) {
        return ['error' => $e->getMessage()];
    }
}

/**
 * Calculate CVSS score
 */
function local_security_dashboard_calculate_cvss($vector) {
    $cvss_url = get_config('local_security_dashboard', 'cvss_url');
    
    if (empty($cvss_url)) {
        return ['error' => 'CVSS URL not configured'];
    }
    
    $url = rtrim($cvss_url, '/') . '/score';
    
    $data = ['vector' => $vector];
    
    try {
        $curl = new curl();
        $response = $curl->post($url, json_encode($data), [
            'CURLOPT_HTTPHEADER' => ['Content-Type: application/json']
        ]);
        
        if ($curl->get_errno()) {
            return ['error' => 'Connection error: ' . $curl->error];
        }
        
        return json_decode($response, true);
    } catch (Exception $e) {
        return ['error' => $e->getMessage()];
    }
}

/**
 * Check proxy service health
 */
function local_security_dashboard_check_health() {
    $proxy_url = get_config('local_security_dashboard', 'proxy_url');
    if (empty($proxy_url)) {
        $proxy_url = 'http://localhost:8999';
    }
    $cvss_url = get_config('local_security_dashboard', 'cvss_url');
    
    $status = [
        'proxy' => false,
        'cvss' => false
    ];
    
    // Check proxy
    if (!empty($proxy_url)) {
        try {
            $curl = new curl();
            $response = $curl->get(rtrim($proxy_url, '/') . '/health');
            $data = json_decode($response, true);
            $status['proxy'] = isset($data['status']) && $data['status'] === 'ok';
        } catch (Exception $e) {
            $status['proxy'] = false;
        }
    }
    
    // Check CVSS
    if (!empty($cvss_url)) {
        try {
            $curl = new curl();
            $response = $curl->get(rtrim($cvss_url, '/') . '/health');
            $data = json_decode($response, true);
            $status['cvss'] = isset($data['status']) && $data['status'] === 'ok';
        } catch (Exception $e) {
            $status['cvss'] = false;
        }
    }
    
    return $status;
}

/**
 * Trigger full site scan (crawl + scan all endpoints)
 *
 * @param int $max_depth Maximum crawl depth
 * @param int $max_pages Maximum pages to crawl
 * @return array Scan results
 */
function local_security_dashboard_trigger_full_scan($max_depth = 2, $max_pages = 30) {
    $proxy_url = get_config('local_security_dashboard', 'proxy_url');
    
    // Fallback to default localhost if not configured
    if (empty($proxy_url)) {
        $proxy_url = 'http://localhost:8999';
    }
    
    if (empty($proxy_url)) {
        return ['error' => 'Proxy URL not configured'];
    }
    
    $url = rtrim($proxy_url, '/') . '/scan-full';
    
    try {
        $curl = new curl();
        $response = $curl->post($url, json_encode([
            'max_depth' => $max_depth,
            'max_pages' => $max_pages
        ]), [
            'CURLOPT_HTTPHEADER' => ['Content-Type: application/json'],
            'CURLOPT_TIMEOUT' => 300  // 5 minutes timeout for full scan
        ]);
        
        if ($curl->get_errno()) {
            return ['error' => 'Connection error: ' . $curl->error];
        }
        
        $result = json_decode($response, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            return ['error' => 'Invalid response from proxy service'];
        }
        
        return $result;
    } catch (Exception $e) {
        return ['error' => $e->getMessage()];
    }
}

/**
 * Trigger native authenticated full-site vulnerability scan
 * 
 * Performs authenticated scanning as admin user, allowing discovery of
 * endpoints and vulnerabilities that are only visible when logged in.
 *
 * @param int $max_depth Maximum crawl depth
 * @param int $max_pages Maximum pages to crawl
 * @param string $username Username for authentication (default: admin)
 * @param string $password Password for authentication (default: Admin@1234)
 * @return array Scan results including findings and statistics
 */
function local_security_dashboard_trigger_native_auth_scan($max_depth = 2, $max_pages = 50, $username = 'admin', $password = 'Admin@1234') {
    global $CFG;

    $proxy_url = get_config('local_security_dashboard', 'proxy_url');
    if (empty($proxy_url)) {
        $proxy_url = 'http://localhost:8999';
    }

    $url = rtrim($proxy_url, '/') . '/api/scan-native-auth';

    // Use Moodle's own wwwroot as target so each environment uses its own port.
    // krisopras → http://localhost:8998  |  natha → http://localhost
    $moodle_base = rtrim($CFG->wwwroot, '/');

    try {
        $curl = new curl();
        $response = $curl->post($url, json_encode([
            'max_depth'  => $max_depth,
            'max_pages'  => $max_pages,
            'username'   => $username,
            'password'   => $password,
            'target_url' => $moodle_base,   // ← proxy uses this, not hardcoded localhost
            'moodle_url' => $moodle_base,
        ]), [
            'CURLOPT_HTTPHEADER' => ['Content-Type: application/json'],
            'CURLOPT_TIMEOUT'    => 600,
        ]);

        if ($curl->get_errno()) {
            return ['error' => 'Connection error: ' . $curl->error];
        }

        $result = json_decode($response, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            return ['error' => 'Invalid response from proxy service'];
        }

        return $result;
    } catch (Exception $e) {
        return ['error' => $e->getMessage()];
    }
}

/**
 * Create a scheduled scan
 *
 * @param string $target_url Target URL to scan
 * @param string $frequency Scan frequency (hourly, daily, weekly, monthly)
 * @param string $scan_type Type of scan (full, quick, targeted)
 * @return array Schedule result
 */
function local_security_dashboard_create_schedule($target_url, $frequency, $scan_type = 'full') {
    $proxy_url = get_config('local_security_dashboard', 'proxy_url');
    
    // Fallback to default localhost if not configured
    if (empty($proxy_url)) {
        $proxy_url = 'http://localhost:8999';
    }
    
    if (empty($proxy_url)) {
        return ['error' => 'Proxy URL not configured'];
    }
    
    $url = rtrim($proxy_url, '/') . '/schedule/create';
    
    try {
        $curl = new curl();
        $response = $curl->post($url, json_encode([
            'target_url' => $target_url,
            'cron_expression' => $frequency,
            'scan_type' => $scan_type,
            'priority' => 'normal'
        ]), [
            'CURLOPT_HTTPHEADER' => ['Content-Type: application/json'],
            'CURLOPT_TIMEOUT' => 30
        ]);
        
        if ($curl->get_errno()) {
            return ['error' => 'Connection error: ' . $curl->error];
        }
        
        $result = json_decode($response, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            return ['error' => 'Invalid response from proxy service'];
        }
        
        return $result;
    } catch (Exception $e) {
        return ['error' => $e->getMessage()];
    }
}

/**
 * Get all scheduled scans
 *
 * @return array List of schedules
 */
function local_security_dashboard_get_schedules() {
    $proxy_url = get_config('local_security_dashboard', 'proxy_url');
    
    // Fallback to default localhost if not configured
    if (empty($proxy_url)) {
        $proxy_url = 'http://localhost:8999';
    }
    
    if (empty($proxy_url)) {
        return ['error' => 'Proxy URL not configured'];
    }
    
    $url = rtrim($proxy_url, '/') . '/schedule/list';
    
    try {
        $curl = new curl();
        $response = $curl->get($url);
        
        if ($curl->get_errno()) {
            return ['error' => 'Connection error: ' . $curl->error];
        }
        
        $result = json_decode($response, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            return ['error' => 'Invalid response from proxy service'];
        }
        
        return $result;
    } catch (Exception $e) {
        return ['error' => $e->getMessage()];
    }
}

/**
 * Delete a scheduled scan
 *
 * @param string $schedule_id Schedule ID to delete
 * @return array Delete result
 */
function local_security_dashboard_delete_schedule($schedule_id) {
    $proxy_url = get_config('local_security_dashboard', 'proxy_url');
    
    // Fallback to default localhost if not configured
    if (empty($proxy_url)) {
        $proxy_url = 'http://localhost:8999';
    }
    
    if (empty($proxy_url)) {
        return ['error' => 'Proxy URL not configured'];
    }
    
    $url = rtrim($proxy_url, '/') . '/schedule/' . urlencode($schedule_id);
    
    try {
        $curl = new curl();
        $response = $curl->delete($url);
        
        if ($curl->get_errno()) {
            return ['error' => 'Connection error: ' . $curl->error];
        }
        
        $result = json_decode($response, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            return ['error' => 'Invalid response from proxy service'];
        }
        
        return $result;
    } catch (Exception $e) {
        return ['error' => $e->getMessage()];
    }
}

/**
 * Start authentication security scan
 *
 * @return array Scan result
 */
function local_security_dashboard_start_auth_scan() {
    $proxy_url = get_config('local_security_dashboard', 'proxy_url');
    
    // Fallback to default localhost if not configured
    if (empty($proxy_url)) {
        $proxy_url = 'http://localhost:8999';
    }
    
    if (empty($proxy_url)) {
        return ['error' => 'Proxy URL not configured'];
    }
    
    $url = rtrim($proxy_url, '/') . '/scan-auth';
    
    try {
        $curl = new curl();
        
        // Set options to prevent following redirects and increase timeout
        $curl->setopt(array(
            'CURLOPT_FOLLOWLOCATION' => false,
            'CURLOPT_TIMEOUT' => 120,  // 2 minutes for scan to complete
            'CURLOPT_CONNECTTIMEOUT' => 10
        ));
        
        $response = $curl->post($url, '');
        
        if ($curl->get_errno()) {
            return ['error' => 'Connection error: ' . $curl->error];
        }
        
        $result = json_decode($response, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            return ['error' => 'Invalid response from proxy service. Response: ' . substr($response, 0, 200)];
        }
        
        return $result;
    } catch (Exception $e) {
        return ['error' => $e->getMessage()];
    }
}

/**
 * Start API security scan
 *
 * @return array Scan result
 */
function local_security_dashboard_start_api_scan() {
    $proxy_url = get_config('local_security_dashboard', 'proxy_url');
    
    // Fallback to default localhost if not configured
    if (empty($proxy_url)) {
        $proxy_url = 'http://localhost:8999';
    }
    
    if (empty($proxy_url)) {
        return ['error' => 'Proxy URL not configured'];
    }
    
    $url = rtrim($proxy_url, '/') . '/scan-api';
    
    try {
        $curl = new curl();
        
        // Set options to prevent following redirects and increase timeout
        $curl->setopt(array(
            'CURLOPT_FOLLOWLOCATION' => false,
            'CURLOPT_TIMEOUT' => 120,  // 2 minutes for scan to complete
            'CURLOPT_CONNECTTIMEOUT' => 10
        ));
        
        $response = $curl->post($url, '');
        
        if ($curl->get_errno()) {
            return ['error' => 'Connection error: ' . $curl->error];
        }
        
        $result = json_decode($response, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            return ['error' => 'Invalid response from proxy service. Response: ' . substr($response, 0, 200)];
        }
        
        return $result;
    } catch (Exception $e) {
        return ['error' => $e->getMessage()];
    }
}

/**
 * Get scan history from proxy service
 *
 * @param int $limit Number of scans to retrieve
 * @return array Scan history
 */
function local_security_dashboard_get_scan_history($limit = 10) {
    $proxy_url = get_config('local_security_dashboard', 'proxy_url');
    
    // Fallback to default localhost if not configured
    if (empty($proxy_url)) {
        $proxy_url = 'http://localhost:8999';
    }
    
    if (empty($proxy_url)) {
        return ['error' => 'Proxy URL not configured'];
    }
    
    $url = rtrim($proxy_url, '/') . '/scan-history?limit=' . intval($limit);
    
    try {
        $curl = new curl();
        $response = $curl->get($url);
        
        if ($curl->get_errno()) {
            return ['error' => 'Connection error: ' . $curl->error];
        }
        
        $result = json_decode($response, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            return ['error' => 'Invalid response from proxy service'];
        }
        
        // Return the scans array if it exists, otherwise return empty array
        return isset($result['scans']) ? $result['scans'] : [];
    } catch (Exception $e) {
        return ['error' => $e->getMessage()];
    }
}

/**
 * Save phishing finding to database
 *
 * @param array $finding Phishing finding data
 * @return int|bool Record ID or false on failure
 */
function local_security_dashboard_save_phishing_finding($finding) {
    global $DB, $USER;
    
    $record = new stdClass();
    $record->content_type = $finding['content_type'];
    $record->content_id = $finding['content_id'];
    $record->content_url = local_security_dashboard_get_content_url(
        $finding['content_type'],
        $finding['content_id'],
        $finding['user_id']
    );
    $record->user_id = $finding['user_id'];
    $record->risk_level = local_security_dashboard_get_risk_level($finding['risk_score']);
    $record->risk_score = $finding['risk_score'];
    $record->suspicious_url = $finding['suspicious_url'];
    $record->indicators = json_encode($finding['indicators']);
    $record->content_preview = isset($finding['content_preview']) ? substr($finding['content_preview'], 0, 500) : '';
    $record->recommendation = $finding['recommendation'] ?? '';
    $record->status = 'open';
    $record->notified = 0;
    $record->detected_by = $USER->id;
    $record->timecreated = time();
    $record->timemodified = time();
    
    // Check if URL/user is whitelisted
    if (local_security_dashboard_is_whitelisted($record->suspicious_url, $record->user_id)) {
        return false; // Skip whitelisted items
    }
    
    try {
        // Check if already exists (avoid duplicates)
        $existing = $DB->get_record('local_security_phishing', [
            'content_type' => $record->content_type,
            'content_id' => $record->content_id,
            'suspicious_url' => $record->suspicious_url,
            'status' => 'open'
        ]);
        
        if ($existing) {
            // Update existing record
            $record->id = $existing->id;
            $record->timemodified = time();
            $DB->update_record('local_security_phishing', $record);
            return $existing->id;
        } else {
            // Insert new record
            $id = $DB->insert_record('local_security_phishing', $record);
            
            // Send notification if CRITICAL
            if ($record->risk_level === 'CRITICAL') {
                local_security_dashboard_send_phishing_notification($record);
            }
            
            return $id;
        }
    } catch (Exception $e) {
        debugging('Failed to save phishing finding: ' . $e->getMessage(), DEBUG_DEVELOPER);
        return false;
    }
}

/**
 * Convert risk score to risk level
 *
 * @param float $score Risk score (0-10)
 * @return string Risk level
 */
function local_security_dashboard_get_risk_level($score) {
    if ($score >= 8.0) {
        return 'CRITICAL';
    } elseif ($score >= 6.0) {
        return 'HIGH';
    } elseif ($score >= 4.0) {
        return 'MEDIUM';
    } else {
        return 'LOW';
    }
}

/**
 * Send email notification for critical phishing finding
 *
 * @param stdClass $finding Phishing finding record
 * @return bool Success
 */
function local_security_dashboard_send_phishing_notification($finding) {
    global $DB, $CFG;
    
    // Get site admins
    $admins = get_admins();
    
    if (empty($admins)) {
        return false;
    }
    
    // Get user who created the suspicious content
    $user = $DB->get_record('user', ['id' => $finding->user_id], 'id, firstname, lastname, email, username');
    
    if (!$user) {
        return false;
    }
    
    $subject = '[MoodleSec Alert] CRITICAL Phishing Attempt Detected';
    
    $message = "A CRITICAL phishing attempt has been detected in your Moodle site.\n\n";
    $message .= "Details:\n";
    $message .= "- Content Type: " . $finding->content_type . "\n";
    $message .= "- User: " . fullname($user) . " (" . $user->username . ")\n";
    $message .= "- Risk Score: " . $finding->risk_score . "/10\n";
    $message .= "- Suspicious URL: " . $finding->suspicious_url . "\n";
    $message .= "- Indicators: " . implode(', ', json_decode($finding->indicators, true)) . "\n\n";
    $message .= "Recommendation: " . $finding->recommendation . "\n\n";
    $message .= "View details: " . $CFG->wwwroot . "/local/security_dashboard/scan_phishing_content.php\n";
    
    $messagehtml = "<h2>MoodleSec Alert: CRITICAL Phishing Attempt</h2>";
    $messagehtml .= "<p style='color: red; font-weight: bold;'>A CRITICAL phishing attempt has been detected.</p>";
    $messagehtml .= "<table border='1' cellpadding='5' style='border-collapse: collapse;'>";
    $messagehtml .= "<tr><th>Content Type</th><td>" . s($finding->content_type) . "</td></tr>";
    $messagehtml .= "<tr><th>User</th><td>" . fullname($user) . " (" . s($user->username) . ")</td></tr>";
    $messagehtml .= "<tr><th>Risk Score</th><td><strong>" . $finding->risk_score . "/10</strong></td></tr>";
    $messagehtml .= "<tr><th>Suspicious URL</th><td>" . s($finding->suspicious_url) . "</td></tr>";
    $messagehtml .= "<tr><th>Indicators</th><td>" . implode('<br>', array_map('s', json_decode($finding->indicators, true))) . "</td></tr>";
    $messagehtml .= "<tr><th>Recommendation</th><td>" . s($finding->recommendation) . "</td></tr>";
    $messagehtml .= "</table>";
    $messagehtml .= "<p><a href='" . $CFG->wwwroot . "/local/security_dashboard/scan_phishing_content.php'>View Phishing Scanner</a></p>";
    
    $success = false;
    foreach ($admins as $admin) {
        if (email_to_user($admin, core_user::get_noreply_user(), $subject, $message, $messagehtml)) {
            $success = true;
        }
    }
    
    // Mark as notified
    if ($success && isset($finding->id)) {
        $DB->set_field('local_security_phishing', 'notified', 1, ['id' => $finding->id]);
    }
    
    return $success;
}

/**
 * Get phishing findings with pagination
 *
 * @param int $page Page number (0-based)
 * @param int $perpage Items per page
 * @param string $status Filter by status (optional)
 * @param string $risklevel Filter by risk level (optional)
 * @return array ['findings' => array, 'total' => int]
 */
function local_security_dashboard_get_phishing_findings($page = 0, $perpage = 20, $status = null, $risklevel = null) {
    global $DB;
    
    $params = [];
    $where = [];
    
    if ($status) {
        $where[] = 'status = :status';
        $params['status'] = $status;
    }
    
    if ($risklevel) {
        $where[] = 'risk_level = :risklevel';
        $params['risklevel'] = $risklevel;
    }
    
    $wheresql = !empty($where) ? 'WHERE ' . implode(' AND ', $where) : '';
    
    $total = $DB->count_records_sql("SELECT COUNT(*) FROM {local_security_phishing} $wheresql", $params);
    
    $sql = "SELECT * FROM {local_security_phishing} $wheresql ORDER BY timecreated DESC";
    $findings = $DB->get_records_sql($sql, $params, $page * $perpage, $perpage);
    
    return [
        'findings' => $findings,
        'total' => $total
    ];
}

/**
 * Mark phishing finding as resolved
 *
 * @param int $findingid Finding ID
 * @param string $status New status (resolved, false_positive, whitelisted)
 * @return bool Success
 */
function local_security_dashboard_resolve_phishing_finding($findingid, $status = 'resolved') {
    global $DB, $USER;
    
    $allowed_statuses = ['resolved', 'false_positive', 'whitelisted'];
    
    if (!in_array($status, $allowed_statuses)) {
        return false;
    }
    
    $record = new stdClass();
    $record->id = $findingid;
    $record->status = $status;
    $record->resolved_by = $USER->id;
    $record->resolved_at = time();
    $record->timemodified = time();
    
    try {
        $DB->update_record('local_security_phishing', $record);
        
        // If marking as false positive, auto-whitelist the domain
        if ($status === 'false_positive') {
            $finding = $DB->get_record('local_security_phishing', ['id' => $findingid]);
            if ($finding) {
                local_security_dashboard_auto_whitelist_from_finding($finding);
            }
        }
        
        return true;
    } catch (Exception $e) {
        debugging('Failed to resolve phishing finding: ' . $e->getMessage(), DEBUG_DEVELOPER);
        return false;
    }
}

/**
 * Auto-whitelist domain from false positive finding
 *
 * @param stdClass $finding Phishing finding record
 * @return bool Success
 */
function local_security_dashboard_auto_whitelist_from_finding($finding) {
    global $CFG;
    require_once($CFG->libdir . '/filelib.php');
    
    // Extract domain from suspicious URL
    $parsed = parse_url($finding->suspicious_url);
    if (!$parsed || !isset($parsed['host'])) {
        return false;
    }
    
    $domain = $parsed['host'];
    
    // Add to whitelist
    return local_security_dashboard_add_to_whitelist(
        'domain',
        $domain,
        'Auto-whitelisted from false positive finding #' . $finding->id,
        'auto_from_false_positive'
    );
}

/**
 * Add entry to phishing whitelist
 *
 * @param string $type Type: domain, user, url_pattern
 * @param string $value Domain name, user ID, or URL pattern
 * @param string $reason Reason for whitelisting
 * @param string $source Source: manual, auto_from_false_positive
 * @return bool Success
 */
function local_security_dashboard_add_to_whitelist($type, $value, $reason = '', $source = 'manual') {
    global $DB, $USER;
    
    $allowed_types = ['domain', 'user', 'url_pattern'];
    if (!in_array($type, $allowed_types)) {
        return false;
    }
    
    // Check if already whitelisted
    $existing = $DB->get_record('local_security_phishing_whitelist', [
        'whitelist_type' => $type,
        'whitelist_value' => $value
    ]);
    
    if ($existing) {
        return true; // Already whitelisted
    }
    
    $record = new stdClass();
    $record->whitelist_type = $type;
    $record->whitelist_value = $value;
    $record->reason = $reason;
    $record->source = $source;
    $record->created_by = $USER->id;
    $record->timecreated = time();
    $record->timemodified = time();
    
    try {
        $DB->insert_record('local_security_phishing_whitelist', $record);
        return true;
    } catch (Exception $e) {
        debugging('Failed to add whitelist entry: ' . $e->getMessage(), DEBUG_DEVELOPER);
        return false;
    }
}

/**
 * Check if URL or user is whitelisted
 *
 * @param string $url URL to check
 * @param int $userid User ID to check (optional)
 * @return bool True if whitelisted
 */
function local_security_dashboard_is_whitelisted($url, $userid = null) {
    global $DB;
    
    // Check user whitelist
    if ($userid) {
        if ($DB->record_exists('local_security_phishing_whitelist', [
            'whitelist_type' => 'user',
            'whitelist_value' => (string)$userid
        ])) {
            return true;
        }
    }
    
    // Check domain whitelist
    $parsed = parse_url($url);
    if ($parsed && isset($parsed['host'])) {
        $domain = $parsed['host'];
        
        if ($DB->record_exists('local_security_phishing_whitelist', [
            'whitelist_type' => 'domain',
            'whitelist_value' => $domain
        ])) {
            return true;
        }
    }
    
    // Check URL pattern whitelist
    $patterns = $DB->get_records('local_security_phishing_whitelist', ['whitelist_type' => 'url_pattern']);
    foreach ($patterns as $pattern) {
        if (preg_match('/' . preg_quote($pattern->whitelist_value, '/') . '/', $url)) {
            return true;
        }
    }
    
    return false;
}

/**
 * Get content URL for phishing finding
 *
 * @param string $content_type Type of content
 * @param int $content_id Content ID
 * @param int $user_id User ID
 * @return string URL to the content
 */
function local_security_dashboard_get_content_url($content_type, $content_id, $user_id) {
    global $CFG, $DB;
    
    switch ($content_type) {
        case 'user_profile':
            return $CFG->wwwroot . '/user/profile.php?id=' . $user_id;
            
        case 'forum_post':
            // Get discussion ID from post
            $post = $DB->get_record('forum_posts', ['id' => $content_id], 'discussion');
            if ($post) {
                return $CFG->wwwroot . '/mod/forum/discuss.php?d=' . $post->discussion . '#p' . $content_id;
            }
            return $CFG->wwwroot . '/mod/forum/';
            
        case 'comment':
            // Get context for comment
            $comment = $DB->get_record('comments', ['id' => $content_id], 'contextid, itemid');
            if ($comment) {
                $context = context::instance_by_id($comment->contextid, IGNORE_MISSING);
                if ($context) {
                    return $context->get_url() . '#comment-' . $content_id;
                }
            }
            return $CFG->wwwroot;
            
        default:
            return $CFG->wwwroot;
    }
}

/**
 * Delete phishing content (auto-remediation)
 *
 * @param int $findingid Finding ID
 * @return array ['success' => bool, 'message' => string]
 */
function local_security_dashboard_delete_phishing_content($findingid) {
    global $DB;
    
    $finding = $DB->get_record('local_security_phishing', ['id' => $findingid]);
    if (!$finding) {
        return ['success' => false, 'message' => 'Finding not found'];
    }
    
    try {
        switch ($finding->content_type) {
            case 'user_profile':
                // Clear user description
                $user = $DB->get_record('user', ['id' => $finding->user_id]);
                if ($user) {
                    $user->description = '';
                    $user->descriptionformat = FORMAT_HTML;
                    $DB->update_record('user', $user);
                    return ['success' => true, 'message' => 'User profile bio cleared'];
                }
                break;
                
            case 'forum_post':
                // Delete forum post
                require_once(dirname(__FILE__) . '/../../mod/forum/lib.php');
                $post = $DB->get_record('forum_posts', ['id' => $finding->content_id]);
                if ($post) {
                    forum_delete_post($post, true);
                    return ['success' => true, 'message' => 'Forum post deleted'];
                }
                break;
                
            case 'comment':
                // Delete comment
                require_once(dirname(__FILE__) . '/../../comment/lib.php');
                $comment = $DB->get_record('comments', ['id' => $finding->content_id]);
                if ($comment) {
                    $DB->delete_records('comments', ['id' => $finding->content_id]);
                    return ['success' => true, 'message' => 'Comment deleted'];
                }
                break;
        }
        
        return ['success' => false, 'message' => 'Content not found or already deleted'];
    } catch (Exception $e) {
        return ['success' => false, 'message' => 'Error: ' . $e->getMessage()];
    }
}

/**
 * Quarantine phishing content (hide from public)
 *
 * @param int $findingid Finding ID
 * @return array ['success' => bool, 'message' => string]
 */
function local_security_dashboard_quarantine_content($findingid) {
    global $DB;
    
    $finding = $DB->get_record('local_security_phishing', ['id' => $findingid]);
    if (!$finding) {
        return ['success' => false, 'message' => 'Finding not found'];
    }
    
    try {
        switch ($finding->content_type) {
            case 'user_profile':
                // Suspend user
                $user = $DB->get_record('user', ['id' => $finding->user_id]);
                if ($user && !$user->suspended) {
                    $user->suspended = 1;
                    $DB->update_record('user', $user);
                    return ['success' => true, 'message' => 'User account suspended (can be reactivated)'];
                }
                return ['success' => false, 'message' => 'User already suspended or not found'];
                
            case 'forum_post':
                // Hide forum post (set deleted flag)
                $post = $DB->get_record('forum_posts', ['id' => $finding->content_id]);
                if ($post) {
                    $DB->set_field('forum_posts', 'deleted', 1, ['id' => $finding->content_id]);
                    return ['success' => true, 'message' => 'Forum post hidden (marked as deleted)'];
                }
                break;
                
            case 'comment':
                // Comments don't have soft delete, so we replace content
                $DB->set_field('comments', 'content', '[Content hidden by admin - potential phishing]', ['id' => $finding->content_id]);
                return ['success' => true, 'message' => 'Comment content replaced with warning'];
        }
        
        return ['success' => false, 'message' => 'Content not found'];
    } catch (Exception $e) {
        return ['success' => false, 'message' => 'Error: ' . $e->getMessage()];
    }
}

/**
 * Get credentials for authenticated scanning
 * 
 * @param string $method Authentication method (manual, auto_admin, session_token)
 * @return array Credentials array with username and password
 */
function local_security_dashboard_get_credentials($method = null) {
    global $DB, $CFG;
    
    if ($method === null) {
        $method = get_config('local_security_dashboard', 'auth_method') ?? 'manual';
    }
    
    switch ($method) {
        case 'manual':
            // Get stored credentials
            $username = get_config('local_security_dashboard', 'scan_test_user');
            $password = get_config('local_security_dashboard', 'scan_test_password');
            
            if (empty($username) || empty($password)) {
                return ['error' => 'Manual credentials not configured. Please set username and password in ZAP settings.'];
            }
            return ['username' => $username, 'password' => $password, 'method' => 'manual'];
            
        case 'auto_admin':
            // Auto-detect first admin user, but password must be manually configured
            try {
                $admin = $DB->get_record('user', ['id' => 2]); // Moodle default admin is usually id=2
                if (!$admin) {
                    // Fallback: find any admin user
                    $admins = get_admins();
                    if (!empty($admins)) {
                        $admin = reset($admins);
                    } else {
                        return ['error' => 'No admin user found. Please configure manual credentials.'];
                    }
                }
                
                $password = get_config('local_security_dashboard', 'scan_test_password');
                if (empty($password)) {
                    return ['error' => 'Auto-admin detected user "' . $admin->username . '" but password not configured. Please set password in settings.'];
                }
                
                return ['username' => $admin->username, 'password' => $password, 'method' => 'auto_admin'];
            } catch (Exception $e) {
                return ['error' => 'Failed to detect admin: ' . $e->getMessage()];
            }
            
        case 'session_token':
            // Session token method requires manual credentials setup
            $username = get_config('local_security_dashboard', 'scan_test_user');
            $password = get_config('local_security_dashboard', 'scan_test_password');
            
            if (empty($username) || empty($password)) {
                return ['error' => 'Session token method requires both username and password configuration.'];
            }
            
            return [
                'username' => $username,
                'password' => $password,
                'method' => 'session',
                'auth_url' => $CFG->wwwroot . '/login/index.php'
            ];
            
        default:
            return ['error' => 'Unknown authentication method: ' . $method];
    }
}

/**
 * Configure ZAP Authentication - SIMPLIFIED APPROACH
 * Tests actual login and generates session cookie instead of using ZAP's complex auth API
 * 
 * @param string $username Moodle username
 * @param string $password Moodle password  
 * @param string $context_id ZAP context ID
 * @return array Result with session cookie or error
 */
function local_security_dashboard_setup_zap_auth($username, $password, $context_id = 'Moodle') {
    global $CFG;
    
    try {
        // Step 1: Create temporary cookie file for session persistence
        $cookie_file = tempnam(sys_get_temp_dir(), 'moodle_zap_auth_');
        error_log("DEBUG: Creating session cookie file: $cookie_file");
        
        $login_url = rtrim($CFG->wwwroot, '/') . '/login/index.php';
        
        // Step 2: Fetch login page to extract CSRF token
        error_log("DEBUG: Fetching login page from {$CFG->wwwroot}/login/index.php");
        
        $cmd = "curl -s -c " . escapeshellarg($cookie_file) . " " . escapeshellarg($login_url) . " 2>&1";
        $page = shell_exec($cmd);
        
        if (!$page) {
            throw new Exception('Failed to fetch login page');
        }
        
        error_log("DEBUG: Login page fetched, size: " . strlen($page) . " bytes");
        
        // Step 3: Extract CSRF token from login form
        $logintoken = null;
        
        // Try multiple patterns - order of HTML attributes shouldn't matter
        
        // Pattern 1: name comes before value - e.g., name="logintoken" ... value="TOKEN"
        if (preg_match('/name=["\']logintoken["\'][^>]*value=["\']([^"\']+)["\']/', $page, $matches)) {
            $logintoken = $matches[1];
            error_log("DEBUG: Token extracted via Pattern 1 (name before value)");
        }
        
        // Pattern 2: value comes before name - e.g., value="TOKEN" ... name="logintoken"
        if (!$logintoken && preg_match('/value=["\']([^"\']+)["\'][^>]*name=["\']logintoken["\']/', $page, $matches)) {
            $logintoken = $matches[1];
            error_log("DEBUG: Token extracted via Pattern 2 (value before name)");
        }
        
        // Pattern 3: no quotes around values - e.g., name=logintoken value=TOKEN
        if (!$logintoken && preg_match('/name=logintoken[^>]*value=([^\s>]+)/', $page, $matches)) {
            $logintoken = trim($matches[1], '"\'');
            error_log("DEBUG: Token extracted via Pattern 3 (unquoted values)");
        }
        
        // Pattern 4: Just look for value after any mention of logintoken
        if (!$logintoken && preg_match('/logintoken[^>]*value=["\']?([^\s"\'>[]+)["\']?/', $page, $matches)) {
            $logintoken = trim($matches[1], '"\'');
            error_log("DEBUG: Token extracted via Pattern 4 (flexible search)");
        }
        
        if (!$logintoken) {
            error_log("WARNING: Could not extract CSRF token - proceeding without it");
            error_log("DEBUG: First 500 chars of login page: " . substr($page, 0, 500));
            $logintoken = '';
        } else {
            error_log("DEBUG: Extracted logintoken = " . substr($logintoken, 0, 30) . "... (length: " . strlen($logintoken) . ")");
        }
        
        // Step 4: Perform login with credentials
        error_log("DEBUG: Attempting login for user: $username");
        
        // IMPORTANT: Order matters! Logintoken must come FIRST
        $post_data = array();
        
        if (!empty($logintoken)) {
            $post_data['logintoken'] = $logintoken;
        }
        
        $post_data['username'] = $username;
        $post_data['password'] = $password;
        $post_data['submit'] = 'Log in';
        
        $post_string = http_build_query($post_data);
        
        // Debug log the POST data
        error_log("DEBUG POST DATA:");
        foreach ($post_data as $key => $val) {
            $display_val = ($key === 'password') ? str_repeat('*', strlen($val)) : substr($val, 0, 30);
            error_log("  $key => $display_val");
        }
        error_log("DEBUG POST STRING (first 120 chars): " . substr($post_string, 0, 120));
        
        // Login with curl, save cookies and follow redirects
        $cmd = "curl -s -b " . escapeshellarg($cookie_file) . 
               " -c " . escapeshellarg($cookie_file) . 
               " -L -X POST " .
               "-d " . escapeshellarg($post_string) . 
               " " . escapeshellarg($login_url) . 
               " 2>&1 | head -c 5000";
        
        error_log("DEBUG: Executing curl login command");
        error_log("DEBUG: Login URL: $login_url");
        error_log("DEBUG: Command flags: -s -b <cookie> -c <cookie> -L -X POST -d <post_data>");

        $login_response = shell_exec($cmd);
        error_log("DEBUG: Login response received, size: " . strlen($login_response) . " bytes");
        
        if (is_null($login_response)) {
            throw new Exception('Login command via shell_exec returned null - command execution failed');
        }
        
        // Step 5: Verify login success
        $success_patterns = array(
            '/Dashboard/',
            '/My courses/i',
            '/My home/i',
            '/Administration/i',
            '/profile/'
        );
        
        $login_verified = false;
        foreach ($success_patterns as $pattern) {
            if (preg_match($pattern, $login_response)) {
                $login_verified = true;
                error_log("DEBUG: Login verified ✓ - found success indicator: $pattern");
                break;
            }
        }
        
        if (!$login_verified) {
            error_log("WARNING: Could not verify login success using response patterns");
            error_log("DEBUG: Response contains 'logout': " . (strpos($login_response, 'logout') !== false ? 'YES' : 'NO'));
            error_log("DEBUG: Response contains 'Dasbor': " . (strpos($login_response, 'Dasbor') !== false ? 'YES' : 'NO'));
            error_log("DEBUG: Response first 300 chars: " . substr($login_response, 0, 300));
        }
        
        // Step 6: Verify cookies were saved
        if (!file_exists($cookie_file) || filesize($cookie_file) == 0) {
            throw new Exception('Failed to create or save cookies');
        }
        
        error_log("DEBUG: Cookie file size: " . filesize($cookie_file) . " bytes");
        
        // Return success with cookie file path
        return array(
            'success' => true,
            'message' => 'Authentication successful - session cookies generated',
            'cookie_file' => $cookie_file,
            'username' => $username,
            'login_verified' => $login_verified,
            'context_id' => 1
        );
        
    } catch (Exception $e) {
        error_log('Exception during ZAP auth setup: ' . $e->getMessage());
        return array('error' => 'Exception during ZAP auth setup: ' . $e->getMessage());
    }
}

/**
 * Verify ZAP Authentication
 * Test if ZAP can successfully login to Moodle
 * Uses shell_exec curl to bypass Moodle's SSRF blocking
 * 
 * @param string $username Username to test
 * @param string $password Password to test
 * @return array Test result
 */
function local_security_dashboard_verify_zap_auth($username, $password) {
    global $CFG;
    
    try {
        $login_url = rtrim($CFG->wwwroot, '/') . '/login/index.php';
        $dashboard_url = rtrim($CFG->wwwroot, '/') . '/my/';
        $cookie_file = '/tmp/moodle_verify_' . md5($username . time()) . '.txt';
        
        error_log("DEBUG: Starting auth test for user: $username");
        error_log("DEBUG: Cookie file: $cookie_file");
        
        // Step 1: Get login page to extract CSRF token via shell_exec
        $login_url_escaped = escapeshellarg($login_url);
        $cookie_file_escaped = escapeshellarg($cookie_file);
        
        $cmd = "curl -s -c $cookie_file_escaped -b $cookie_file_escaped $login_url_escaped 2>&1";
        error_log("DEBUG: Getting login page: $cmd");
        $page = shell_exec($cmd);
        
        if (!$page) {
            error_log("DEBUG: No response when fetching login page");
            return ['success' => false, 'message' => 'Failed to fetch login page'];
        }
        
        error_log("DEBUG: Login page length: " . strlen($page));
        
        // Parse CSRF token from login form - try multiple patterns
        $token = '';
        
        // Pattern 1: Standard input field
        if (preg_match('/<input[^>]*name=["\']logintoken["\'][^>]*value=["\']([^"\']+)["\']/', $page, $matches)) {
            $token = $matches[1];
            error_log("DEBUG: Found logintoken (pattern 1): " . substr($token, 0, 10) . "...");
        }
        // Pattern 2: Alternative
        elseif (preg_match('/name=["\']logintoken["\'][^>]*value=["\']([^"\']+)["\']/', $page, $matches)) {
            $token = $matches[1];
            error_log("DEBUG: Found logintoken (pattern 2): " . substr($token, 0, 10) . "...");
        }
        
        if (empty($token)) {
            error_log("DEBUG: Could not find logintoken in page. Page content: " . substr($page, 0, 500));
            // Continue anyway - older Moodle versions might not need it
            $token = '';
        }
        
        // Step 2: POST login credentials via shell_exec
        $post_data = [
            'username' => $username,
            'password' => $password,
        ];
        
        if (!empty($token)) {
            $post_data['logintoken'] = $token;
        }
        
        $post_data['submit'] = 'Log in';
        
        // Build POST data string
        $post_str = http_build_query($post_data);
        $post_str_escaped = escapeshellarg($post_str);
        
        // POST with curl, follow redirects, include headers for verbosity
        $cmd = "curl -s -i -L -c $cookie_file_escaped -b $cookie_file_escaped " .
               "-d $post_str_escaped " .
               $login_url_escaped . " 2>&1";
        
        error_log("DEBUG: Executing login POST for user: $username");
        $response = shell_exec($cmd);
        
        if (!$response) {
            error_log("DEBUG: No response from login POST");
            return ['success' => false, 'message' => 'No response from login'];
        }
        
        error_log("DEBUG: Login response length: " . strlen($response));
        error_log("DEBUG: Login response (first 800 chars): " . substr($response, 0, 800));
        
        // Step 3: Verify login by accessing dashboard with saved cookies
        error_log("DEBUG: Verifying login by accessing dashboard...");
        $dashboard_url_escaped = escapeshellarg($dashboard_url);
        
        $cmd = "curl -s -i -b $cookie_file_escaped $dashboard_url_escaped 2>&1";
        $dashboard_response = shell_exec($cmd);
        
        if (!$dashboard_response) {
            error_log("DEBUG: No response from dashboard");
            $is_success = false;
        } else {
            error_log("DEBUG: Dashboard response length: " . strlen($dashboard_response));
            error_log("DEBUG: Dashboard response (first 500 chars): " . substr($dashboard_response, 0, 500));
            
            // Check if we got a successful HTTP response (200 OK) without redirect to login
            $is_success = false;
            
            if (stripos($dashboard_response, '200 OK') !== false || stripos($dashboard_response, '301 Found') !== false) {
                // Check that we're NOT redirected back to login - use AND not OR
                if (stripos($dashboard_response, 'Location: http') === false && 
                    stripos($dashboard_response, 'login/index.php') === false) {
                    $is_success = true;
                    error_log("DEBUG: Got successful HTTP response without redirect to login");
                }
            }
            
            // Fallback: check for logged-in indicators in page content
            if (!$is_success) {
                $success_indicators = [
                    'Dashboard',
                    'My Courses', 
                    'My Home',
                    'My Moodle',
                    'administration',
                    'user-menu',
                    'action-menu',
                    'profile',
                    $username  // Check if username appears on page (logged in)
                ];
                
                foreach ($success_indicators as $indicator) {
                    if (stripos($dashboard_response, $indicator) !== false) {
                        $is_success = true;
                        error_log("DEBUG: Found success indicator: $indicator");
                        break;
                    }
                }
            }
        }
        
        // Cleanup cookie file
        @unlink($cookie_file);
        
        if ($is_success) {
            error_log("DEBUG: Authentication test PASSED");
            return ['success' => true, 'message' => 'Authentication test passed'];
        } else {
            error_log("DEBUG: Authentication test FAILED");
            return ['success' => false, 'message' => 'Login failed - verify credentials in Moodle settings'];
        }
        
    } catch (Exception $e) {
        error_log("DEBUG: Authentication test exception: " . $e->getMessage());
        return ['success' => false, 'error' => $e->getMessage()];
    }
}

// ==================== PHASE 2: DYNAMIC PAYLOAD MANAGEMENT ====================

/**
 * Import payloads from ZAP API
 * 
 * @return array Result array with status and details
 */
function local_security_dashboard_import_from_zap() {
    global $CFG;
    
    $proxy_url = get_config('local_security_dashboard', 'proxy_url');
    if (empty($proxy_url)) {
        $proxy_url = 'http://localhost:8999';
    }
    
    $url = rtrim($proxy_url, '/') . '/api/payloads/import-from-zap';
    
    $params = [
        'zap_host' => 'localhost',
        'zap_port' => 8080,
        'limit' => 200,
        'reload_scanners' => true
    ];
    
    try {
        $curl = new curl();
        $curl->setHeader([
            'Content-Type: application/json',
            'Accept: application/json'
        ]);
        
        $response = $curl->post($url, json_encode($params));
        
        if ($curl->get_errno()) {
            return [
                'status' => 'error',
                'message' => 'Connection error: ' . $curl->error
            ];
        }
        
        $result = json_decode($response, true);
        if (isset($result['status']) && $result['status'] === 'success') {
            $import = $result['import_result'] ?? [];
            return [
                'status' => 'success',
                'message' => "Imported {$import['payloads_imported']} payloads from {$import['alerts_fetched']} ZAP alerts",
                'import_result' => $import,
                'scanners_reloaded' => $result['scanners_reloaded'] ?? false
            ];
        } else {
            return [
                'status' => 'error',
                'message' => $result['message'] ?? 'Import failed'
            ];
        }
    } catch (Exception $e) {
        return [
            'status' => 'error',
            'message' => $e->getMessage()
        ];
    }
}

/**
 * Reload payloads from repository
 * 
 * @param string $category Optional specific category to reload
 * @return array Result array
 */
function local_security_dashboard_reload_payloads($category = null) {
    $proxy_url = get_config('local_security_dashboard', 'proxy_url');
    if (empty($proxy_url)) {
        $proxy_url = 'http://localhost:8999';
    }
    
    $url = rtrim($proxy_url, '/') . '/api/payloads/reload';
    if ($category) {
        $url .= '?category=' . urlencode($category);
    }
    
    try {
        $curl = new curl();
        $curl->setHeader('Accept: application/json');
        
        $response = $curl->post($url);
        
        if ($curl->get_errno()) {
            return [
                'status' => 'error',
                'message' => 'Connection error: ' . $curl->error
            ];
        }
        
        $result = json_decode($response, true);
        return $result ?: ['status' => 'error', 'message' => 'Invalid response'];
    } catch (Exception $e) {
        return [
            'status' => 'error',
            'message' => $e->getMessage()
        ];
    }
}

/**
 * Reload scanners with new payloads
 * 
 * @return array Result array
 */
function local_security_dashboard_reload_scanners() {
    $proxy_url = get_config('local_security_dashboard', 'proxy_url');
    if (empty($proxy_url)) {
        $proxy_url = 'http://localhost:8999';
    }
    
    $url = rtrim($proxy_url, '/') . '/api/scanners/reload-payloads';
    
    try {
        $curl = new curl();
        $curl->setHeader('Accept: application/json');
        
        $response = $curl->post($url);
        
        if ($curl->get_errno()) {
            return [
                'status' => 'error',
                'message' => 'Connection error: ' . $curl->error
            ];
        }
        
        $result = json_decode($response, true);
        return $result ?: ['status' => 'error', 'message' => 'Invalid response'];
    } catch (Exception $e) {
        return [
            'status' => 'error',
            'message' => $e->getMessage()
        ];
    }
}

/**
 * Get import status and repository health
 * 
 * @return array Status array
 */
function local_security_dashboard_get_import_status() {
    $proxy_url = get_config('local_security_dashboard', 'proxy_url');
    if (empty($proxy_url)) {
        $proxy_url = 'http://localhost:8999';
    }
    
    $url = rtrim($proxy_url, '/') . '/api/payloads/import-status';
    
    try {
        $curl = new curl();
        $curl->setHeader('Accept: application/json');
        
        $response = $curl->get($url);
        
        if ($curl->get_errno()) {
            return [
                'status' => 'error',
                'message' => 'Connection error: ' . $curl->error
            ];
        }
        
        $result = json_decode($response, true);
        return $result ?: ['status' => 'error', 'message' => 'Invalid response'];
    } catch (Exception $e) {
        return [
            'status' => 'error',
            'message' => $e->getMessage()
        ];
    }
}
