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
    $proxy_url = get_config('local_security_dashboard', 'proxy_url');
    
    if (empty($proxy_url)) {
        return ['error' => 'Proxy URL not configured'];
    }
    
    $url = rtrim($proxy_url, '/') . '/logs?limit=' . $limit;
    
    try {
        $curl = new curl();
        $response = $curl->get($url);
        
        if ($curl->get_errno()) {
            return ['error' => 'Connection error: ' . $curl->error];
        }
        
        return json_decode($response, true);
    } catch (Exception $e) {
        return ['error' => $e->getMessage()];
    }
}

/**
 * Trigger security scan
 */
function local_security_dashboard_trigger_scan($path, $method = 'GET', $parameters = null) {
    $proxy_url = get_config('local_security_dashboard', 'proxy_url');
    
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
 * Create a scheduled scan
 *
 * @param string $target_url Target URL to scan
 * @param string $frequency Scan frequency (hourly, daily, weekly, monthly)
 * @param string $scan_type Type of scan (full, quick, targeted)
 * @return array Schedule result
 */
function local_security_dashboard_create_schedule($target_url, $frequency, $scan_type = 'full') {
    $proxy_url = get_config('local_security_dashboard', 'proxy_url');
    
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
        return true;
    } catch (Exception $e) {
        debugging('Failed to resolve phishing finding: ' . $e->getMessage(), DEBUG_DEVELOPER);
        return false;
    }
}
