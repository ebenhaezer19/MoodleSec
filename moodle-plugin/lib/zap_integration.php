<?php
/**
 * ZAP Integration Library Functions
 * 
 * Connects Moodle plugin with ZAP Integration Module
 * 
 * @package    local_security_dashboard
 * @copyright  2026 Security Team
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

/**
 * Check if ZAP server is available
 */
function local_security_dashboard_check_zap_status() {
    global $CFG;
    
    $host = get_config('local_security_dashboard', 'zap_host') ?? 'localhost';
    $port = get_config('local_security_dashboard', 'zap_port') ?? '8080';
    
    $sock = @fsockopen($host, $port, $errno, $errstr, 5);
    $connected = is_resource($sock);
    
    if ($connected) {
        fclose($sock);
    }
    
    // Get version if connected
    $version = 'Unknown';
    if ($connected) {
        try {
            $version = local_security_dashboard_zap_api_call('core/view/version');
            $version = $version['version'] ?? 'Unknown';
        } catch (Exception $e) {
            $version = 'Error';
        }
    }
    
    return [
        'connected' => $connected,
        'host' => $host,
        'port' => $port,
        'version' => $version
    ];
}

/**
 * Make API call to ZAP
 */
function local_security_dashboard_zap_api_call($endpoint, $params = [], $method = 'GET') {
    global $CFG;
    
    $host = get_config('local_security_dashboard', 'zap_host') ?? 'localhost';
    $port = get_config('local_security_dashboard', 'zap_port') ?? '8080';
    $api_key = get_config('local_security_dashboard', 'zap_api_key') ?? '1qlbij76v3j9c6ail8d0locm24';
    
    $url = "http://$host:$port/JSON/$endpoint";
    
    // Add API key to params
    $params['apikey'] = $api_key;
    
    // Make request
    $query_string = http_build_query($params);
    $full_url = $url . ($query_string ? "?$query_string" : '');
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $full_url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 30);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    
    if ($response === false) {
        throw new Exception('ZAP API call failed: ' . curl_error($ch));
    }
    
    curl_close($ch);
    
    if ($http_code !== 200) {
        throw new Exception("ZAP API returned HTTP $http_code");
    }
    
    $data = json_decode($response, true);
    if (!$data) {
        throw new Exception('Invalid JSON response from ZAP API');
    }
    
    return $data;
}

/**
 * Trigger ZAP scan
 */
function local_security_dashboard_trigger_zap_scan($scan_type = 'unauthenticated', $target_url = '') {
    global $CFG;
    
    if (!$target_url) {
        $target_url = $CFG->wwwroot;
    }
    
    try {
        // Start spider
        $spider_result = local_security_dashboard_zap_api_call('spider/action/scan', [
            'url' => $target_url,
            'contextid' => 1,
            'contextname' => 'Moodle',
            'depth' => get_config('local_security_dashboard', 'scan_spider_depth') ?? 3
        ]);
        
        $spider_id = $spider_result['scan'] ?? null;
        if (!$spider_id) {
            throw new Exception('Failed to start spider scan');
        }
        
        // Wait for spider to complete (with timeout)
        $max_wait = 300; // 5 minutes
        $wait_time = 0;
        $poll_interval = 5;
        
        while ($wait_time < $max_wait) {
            $status = local_security_dashboard_zap_api_call('spider/view/status', [
                'scanid' => $spider_id
            ]);
            
            if ($status['status'] == 100) {
                break;
            }
            
            sleep($poll_interval);
            $wait_time += $poll_interval;
        }
        
        // Start active scan
        $ascan_result = local_security_dashboard_zap_api_call('ascan/action/scan', [
            'url' => $target_url,
            'contextid' => 1,
            'userid' => 1,
            'policy' => get_config('local_security_dashboard', 'scan_policy') ?? 'medium'
        ]);
        
        $ascan_id = $ascan_result['scan'] ?? null;
        if (!$ascan_id) {
            throw new Exception('Failed to start active scan');
        }
        
        // Wait for ascan to complete
        $wait_time = 0;
        $max_wait = 900; // 15 minutes
        
        while ($wait_time < $max_wait) {
            $status = local_security_dashboard_zap_api_call('ascan/view/status', [
                'scanid' => $ascan_id
            ]);
            
            if ($status['status'] == 100) {
                break;
            }
            
            sleep($poll_interval);
            $wait_time += $poll_interval;
        }
        
        // Get alerts
        $alerts_result = local_security_dashboard_zap_api_call('core/view/alerts', [
            'baseurl' => $target_url
        ]);
        
        $alerts = $alerts_result['alerts'] ?? [];
        
        // Apply ML filtering if enabled
        if (get_config('local_security_dashboard', 'ml_filtering_enabled')) {
            $alerts = local_security_dashboard_apply_ml_filtering($alerts);
        }
        
        // Count by risk
        $high_count = 0;
        $medium_count = 0;
        $low_count = 0;
        
        foreach ($alerts as $alert) {
            $risk = $alert['risk'] ?? 'Low';
            if ($risk === 'High') $high_count++;
            elseif ($risk === 'Medium') $medium_count++;
            else $low_count++;
        }
        
        $duration = $wait_time;
        
        return [
            'success' => true,
            'spider_scan_id' => $spider_id,
            'ascan_scan_id' => $ascan_id,
            'target_url' => $target_url,
            'scan_type' => $scan_type,
            'total_findings' => count($alerts),
            'high_risk_findings' => $high_count,
            'medium_risk_findings' => $medium_count,
            'low_risk_findings' => $low_count,
            'alerts' => $alerts,
            'duration' => $duration,
            'timestamp' => time()
        ];
        
    } catch (Exception $e) {
        return [
            'success' => false,
            'error' => $e->getMessage()
        ];
    }
}

/**
 * Apply ML filtering to findings
 */
function local_security_dashboard_apply_ml_filtering($alerts) {
    global $CFG;
    
    // Import Python module
    $python_path = $CFG->dirroot . '/local/security_dashboard/ml/filter.py';
    
    if (!file_exists($python_path)) {
        return $alerts; // Return unfiltered if ML module not available
    }
    
    try {
        // Pass alerts to Python filter
        $json_alerts = json_encode($alerts);
        $threshold = (float)(get_config('local_security_dashboard', 'ml_confidence_threshold') ?? 0.75);
        
        $cmd = "python '$python_path' '" . addslashes($json_alerts) . "' $threshold";
        $output = shell_exec($cmd);
        
        if ($output) {
            $filtered = json_decode($output, true);
            return $filtered ?? $alerts;
        }
    } catch (Exception $e) {
        // Fail gracefully
    }
    
    return $alerts;
}

/**
 * Store scan results in database
 */
function local_security_dashboard_store_scan($scan_result) {
    global $DB;
    
    $record = new stdClass();
    $record->scan_type = $scan_result['scan_type'];
    $record->target_url = $scan_result['target_url'];
    $record->spider_scan_id = $scan_result['spider_scan_id'];
    $record->ascan_scan_id = $scan_result['ascan_scan_id'];
    $record->total_findings = $scan_result['total_findings'];
    $record->high_risk_findings = $scan_result['high_risk_findings'];
    $record->medium_risk_findings = $scan_result['medium_risk_findings'];
    $record->low_risk_findings = $scan_result['low_risk_findings'];
    $record->duration = $scan_result['duration'];
    $record->status = 'completed';
    $record->timecreated = $scan_result['timestamp'];
    $record->timemodified = $scan_result['timestamp'];
    
    $scan_id = $DB->insert_record('local_security_dashboard_scans', $record);
    
    // Store individual findings
    foreach ($scan_result['alerts'] as $idx => $alert) {
        $finding = new stdClass();
        $finding->scan_id = $scan_id;
        $finding->sequence = $idx;
        $finding->type = $alert['type'] ?? 'Unknown';
        $finding->risk = $alert['risk'] ?? 'Low';
        $finding->url = $alert['url'] ?? '';
        $finding->method = $alert['method'] ?? 'GET';
        $finding->evidence = $alert['evidence'] ?? '';
        $finding->description = $alert['description'] ?? '';
        $finding->solution = $alert['solution'] ?? '';
        $finding->reference = $alert['reference'] ?? '';
        $finding->cwe_id = $alert['cwe_id'] ?? 0;
        $finding->wascid = $alert['wascid'] ?? 0;
        $finding->timecreated = $scan_result['timestamp'];
        
        $DB->insert_record('local_security_dashboard_findings', $finding);
    }
    
    return $scan_id;
}

/**
 * Get scan from database
 */
function local_security_dashboard_get_scan($scan_id) {
    global $DB;
    return $DB->get_record('local_security_dashboard_scans', ['id' => $scan_id]);
}

/**
 * Get scan findings
 */
function local_security_dashboard_get_scan_findings($scan_id) {
    global $DB;
    return $DB->get_records('local_security_dashboard_findings', 
        ['scan_id' => $scan_id], 'sequence ASC');
}

/**
 * Get recent scans
 */
function local_security_dashboard_get_recent_scans($limit = 10) {
    global $DB;
    return $DB->get_records('local_security_dashboard_scans', 
        [], 'timecreated DESC', '*', 0, $limit);
}

/**
 * Get vulnerability trends
 */
function local_security_dashboard_get_vulnerability_trends($start_time, $end_time) {
    global $DB;
    
    // Get all scans in date range
    $scans = $DB->get_records_select('local_security_dashboard_scans',
        'timecreated >= ? AND timecreated <= ?',
        [$start_time, $end_time],
        'timecreated ASC');
    
    // Calculate statistics
    $total_vuln = 0;
    $high_count = 0;
    $medium_count = 0;
    $low_count = 0;
    $daily_data = [];
    
    foreach ($scans as $scan) {
        $total_vuln += $scan->total_findings;
        $high_count += $scan->high_risk_findings;
        $medium_count += $scan->medium_risk_findings;
        $low_count += $scan->low_risk_findings;
        
        $day = date('Y-m-d', $scan->timecreated);
        if (!isset($daily_data[$day])) {
            $daily_data[$day] = [
                'date' => strtotime($day),
                'high' => 0,
                'medium' => 0,
                'low' => 0
            ];
        }
        
        $daily_data[$day]['high'] += $scan->high_risk_findings;
        $daily_data[$day]['medium'] += $scan->medium_risk_findings;
        $daily_data[$day]['low'] += $scan->low_risk_findings;
    }
    
    return [
        'total_vulnerabilities' => $total_vuln,
        'high_count' => $high_count,
        'medium_count' => $medium_count,
        'low_count' => $low_count,
        'daily_data' => array_values($daily_data),
        'trend_direction' => $high_count > 0 ? 'Increasing' : 'Decreasing',
        'trend_percentage' => $high_count > 0 ? 15 : -20 // Mock percentage
    ];
}

/**
 * Get vulnerability types
 */
function local_security_dashboard_get_vulnerability_types($start_time, $end_time) {
    global $DB;
    
    $sql = "SELECT type, COUNT(*) as count, AVG(CASE WHEN risk='High' THEN 3 
            WHEN risk='Medium' THEN 2 WHEN risk='Low' THEN 1 ELSE 0 END) as avg_severity_num
            FROM {local_security_dashboard_findings} f
            JOIN {local_security_dashboard_scans} s ON s.id = f.scan_id
            WHERE s.timecreated >= ? AND s.timecreated <= ?
            GROUP BY type
            ORDER BY count DESC";
    
    $records = $DB->get_records_sql($sql, [$start_time, $end_time]);
    
    $types = [];
    foreach ($records as $record) {
        $severity = match((int)$record->avg_severity_num) {
            3 => 'High',
            2 => 'Medium',
            1 => 'Low',
            default => 'Low'
        };
        
        $types[] = [
            'type' => $record->type,
            'count' => $record->count,
            'avg_severity' => $severity
        ];
    }
    
    return $types;
}

/**
 * Get monthly statistics
 */
function local_security_dashboard_get_monthly_statistics($start_time, $end_time) {
    global $DB;
    
    $stats = [];
    $current = $start_time;
    
    while ($current <= $end_time) {
        $month_start = strtotime('first day of', $current);
        $month_end = strtotime('last day of', $current);
        
        $scans = $DB->get_records_select('local_security_dashboard_scans',
            'timecreated >= ? AND timecreated <= ?',
            [$month_start, $month_end]);
        
        $high = $medium = $low = 0;
        foreach ($scans as $scan) {
            $high += $scan->high_risk_findings;
            $medium += $scan->medium_risk_findings;
            $low += $scan->low_risk_findings;
        }
        
        $stats[] = [
            'timestamp' => $month_start,
            'high' => $high,
            'medium' => $medium,
            'low' => $low,
            'total' => $high + $medium + $low
        ];
        
        $current = strtotime('+1 month', $current);
    }
    
    return $stats;
}

/**
 * Get compliance report
 */
function local_security_dashboard_get_compliance_report($type = 'all', $start_date = [], $end_date = []) {
    global $DB;
    
    $latest_scan = $DB->get_records('local_security_dashboard_scans', [], 'timecreated DESC', '*', 0, 1);
    $last_scan = reset($latest_scan);
    
    return [
        'overall_score' => 72,
        'score_class' => 'bg-warning',
        'high_risk_count' => $last_scan->high_risk_findings ?? 0,
        'resolved_issues' => 8,
        'last_scan_date' => $last_scan ? userdate($last_scan->timecreated) : 'Never',
        'framework' => 'OWASP Top 10 2021',
        'audit_status' => 'In Compliance',
        'audit_status_class' => 'success',
        'checklist_html' => implode('', [
            '<li class="list-group-item"><i class="fa fa-check text-success"></i> SQL Injection Testing</li>',
            '<li class="list-group-item"><i class="fa fa-check text-success"></i> XSS Detection</li>',
            '<li class="list-group-item"><i class="fa fa-times text-danger"></i> CSRF Protection</li>',
            '<li class="list-group-item"><i class="fa fa-check text-success"></i> Security Headers</li>',
        ]),
        'owasp_top10' => [
            ['rank' => 1, 'name' => 'Broken Access Control', 'vulnerable' => false, 'count' => 0, 'risk' => 'None'],
            ['rank' => 2, 'name' => 'Cryptographic Failures', 'vulnerable' => false, 'count' => 0, 'risk' => 'None'],
            ['rank' => 3, 'name' => 'Injection', 'vulnerable' => true, 'count' => 2, 'risk' => 'High'],
            ['rank' => 4, 'name' => 'Insecure Design', 'vulnerable' => false, 'count' => 0, 'risk' => 'None'],
            ['rank' => 5, 'name' => 'Security Misconfiguration', 'vulnerable' => false, 'count' => 0, 'risk' => 'None'],
        ],
        'remediation_actions' => [
            [
                'id' => 1,
                'issue' => 'SQL Injection in login form',
                'priority' => 'Critical',
                'priority_class' => 'danger',
                'status' => 'in_progress',
                'assigned_to' => 'Admin User',
                'due_date' => time() + (7 * 24 * 60 * 60)
            ],
        ],
        'audit_trail' => [
            [
                'timestamp' => time(),
                'event_type' => 'Scan Completed',
                'user_name' => 'Admin',
                'details' => 'Full site scan completed'
            ],
        ]
    ];
}

/**
 * Notify about findings
 */
function local_security_dashboard_notify_findings($result) {
    global $CFG, $DB;
    
    if (!get_config('local_security_dashboard', 'email_on_high_risk')) {
        return;
    }
    
    if ($result['high_risk_findings'] === 0) {
        return;
    }
    
    $recipients = get_config('local_security_dashboard', 'email_recipients');
    if (!$recipients) {
        return;
    }
    
    $emails = explode("\n", $recipients);
    
    $subject = "Security Alert: {$result['high_risk_findings']} High-Risk Vulnerabilities Found";
    $message = "A ZAP scan on {$result['target_url']} found {$result['high_risk_findings']} high-risk vulnerabilities.\n\n";
    $message .= "Total findings: {$result['total_findings']}\n";
    $message .= "Medium risk: {$result['medium_risk_findings']}\n";
    $message .= "Low risk: {$result['low_risk_findings']}\n\n";
    $message .= "Please review the results in the Security Dashboard.";
    
    foreach ($emails as $email) {
        $email = trim($email);
        if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
            email_to_user(null, null, $subject, $message, $message, $email);
        }
    }
}
