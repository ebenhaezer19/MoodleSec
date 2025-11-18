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
        $response = $curl->post($url, '');
        
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
        $response = $curl->post($url, '');
        
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
