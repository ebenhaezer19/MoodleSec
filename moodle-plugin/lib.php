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
