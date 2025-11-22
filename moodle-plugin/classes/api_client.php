<?php
/**
 * API client for external security services
 *
 * @package    local_security_dashboard
 * @copyright  2025 Krisopras & Nathanael
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace local_security_dashboard;

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir . '/filelib.php');

/**
 * API client for proxy and CVSS services
 */
class api_client {
    
    /** @var string Proxy service base URL */
    private $proxy_url;
    
    /** @var string CVSS engine base URL */
    private $cvss_url;
    
    /** @var int Request timeout in seconds */
    private $timeout = 30;
    
    /**
     * Constructor
     */
    public function __construct() {
        $this->proxy_url = get_config('local_security_dashboard', 'proxy_url');
        $this->cvss_url = get_config('local_security_dashboard', 'cvss_url');
    }
    
    /**
     * Trigger security scan
     *
     * @param string $path Path to scan
     * @param string $method HTTP method
     * @param array $parameters Optional parameters
     * @return object|false Scan result or false on error
     */
    public function trigger_scan($path, $method = 'GET', $parameters = null) {
        if (empty($this->proxy_url)) {
            return $this->error_response('Proxy URL not configured');
        }
        
        $url = rtrim($this->proxy_url, '/') . '/scan-trigger';
        
        $data = [
            'path' => $path,
            'method' => $method
        ];
        
        if ($parameters) {
            $data['parameters'] = $parameters;
        }
        
        $response = $this->post_request($url, $data);
        
        if ($response && !isset($response->error)) {
            // Log successful scan
            db_manager::add_log(
                null,
                'scan_triggered',
                'info',
                "Scan triggered for path: $path",
                json_encode($data)
            );
        }
        
        return $response;
    }
    
    /**
     * Get logs from proxy service
     *
     * @param int $limit Number of logs to retrieve
     * @return object|false Logs data or false on error
     */
    public function get_proxy_logs($limit = 100) {
        if (empty($this->proxy_url)) {
            return $this->error_response('Proxy URL not configured');
        }
        
        $url = rtrim($this->proxy_url, '/') . '/logs?limit=' . $limit;
        
        return $this->get_request($url);
    }
    
    /**
     * Calculate CVSS score
     *
     * @param string $vector CVSS vector string
     * @return object|false CVSS calculation result or false on error
     */
    public function calculate_cvss($vector) {
        if (empty($this->cvss_url)) {
            return $this->error_response('CVSS URL not configured');
        }
        
        $url = rtrim($this->cvss_url, '/') . '/score';
        
        $data = ['vector' => $vector];
        
        return $this->post_request($url, $data);
    }
    
    /**
     * Check proxy service health
     *
     * @return bool Service is healthy
     */
    public function check_proxy_health() {
        if (empty($this->proxy_url)) {
            return false;
        }
        
        $url = rtrim($this->proxy_url, '/') . '/health';
        $response = $this->get_request($url);
        
        return $response && isset($response->status) && $response->status === 'ok';
    }
    
    /**
     * Check CVSS service health
     *
     * @return bool Service is healthy
     */
    public function check_cvss_health() {
        if (empty($this->cvss_url)) {
            return false;
        }
        
        $url = rtrim($this->cvss_url, '/') . '/health';
        $response = $this->get_request($url);
        
        return $response && isset($response->status) && $response->status === 'ok';
    }
    
    /**
     * Check all services health
     *
     * @return object Health status object
     */
    public function check_all_health() {
        $status = new \stdClass();
        $status->proxy = $this->check_proxy_health();
        $status->cvss = $this->check_cvss_health();
        $status->overall = $status->proxy && $status->cvss;
        
        return $status;
    }
    
    /**
     * Perform GET request
     *
     * @param string $url Request URL
     * @return object|false Response data or false on error
     */
    private function get_request($url) {
        try {
            $curl = new \curl(['timeout' => $this->timeout]);
            $response = $curl->get($url);
            
            if ($curl->get_errno()) {
                debugging('GET request error: ' . $curl->error, DEBUG_DEVELOPER);
                return $this->error_response('Connection error: ' . $curl->error);
            }
            
            $data = json_decode($response);
            
            if (json_last_error() !== JSON_ERROR_NONE) {
                debugging('JSON decode error: ' . json_last_error_msg(), DEBUG_DEVELOPER);
                return $this->error_response('Invalid JSON response');
            }
            
            return $data;
            
        } catch (\Exception $e) {
            debugging('GET request exception: ' . $e->getMessage(), DEBUG_DEVELOPER);
            return $this->error_response($e->getMessage());
        }
    }
    
    /**
     * Perform POST request
     *
     * @param string $url Request URL
     * @param array $data Request data
     * @return object|false Response data or false on error
     */
    private function post_request($url, $data) {
        try {
            $curl = new \curl(['timeout' => $this->timeout]);
            
            $options = [
                'CURLOPT_HTTPHEADER' => [
                    'Content-Type: application/json',
                    'Accept: application/json'
                ]
            ];
            
            $response = $curl->post($url, json_encode($data), $options);
            
            if ($curl->get_errno()) {
                debugging('POST request error: ' . $curl->error, DEBUG_DEVELOPER);
                return $this->error_response('Connection error: ' . $curl->error);
            }
            
            $result = json_decode($response);
            
            if (json_last_error() !== JSON_ERROR_NONE) {
                debugging('JSON decode error: ' . json_last_error_msg(), DEBUG_DEVELOPER);
                return $this->error_response('Invalid JSON response');
            }
            
            return $result;
            
        } catch (\Exception $e) {
            debugging('POST request exception: ' . $e->getMessage(), DEBUG_DEVELOPER);
            return $this->error_response($e->getMessage());
        }
    }
    
    /**
     * Create error response object
     *
     * @param string $message Error message
     * @return object Error response
     */
    private function error_response($message) {
        $error = new \stdClass();
        $error->error = $message;
        $error->success = false;
        return $error;
    }
    
    /**
     * Set request timeout
     *
     * @param int $timeout Timeout in seconds
     */
    public function set_timeout($timeout) {
        $this->timeout = $timeout;
    }
}
