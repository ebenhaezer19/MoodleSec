<?php
/**
 * Ad-hoc task for on-demand security scans
 *
 * @package    local_security_dashboard
 * @copyright  2025 Krisopras & Nathanael
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace local_security_dashboard\task;

defined('MOODLE_INTERNAL') || die();

/**
 * Ad-hoc task to run on-demand security scans in background
 */
class scan_adhoc_task extends \core\task\adhoc_task {
    
    /**
     * Execute the task
     */
    public function execute() {
        global $CFG;
        require_once($CFG->dirroot . '/local/security_dashboard/lib.php');
        
        $data = $this->get_custom_data();
        
        if (empty($data->path)) {
            mtrace('Error: No scan path provided');
            return;
        }
        
        $path = $data->path;
        $method = $data->method ?? 'GET';
        $parameters = $data->parameters ?? null;
        
        mtrace("Starting ad-hoc scan for path: {$path}");
        
        try {
            $result = local_security_dashboard_trigger_scan($path, $method, $parameters);
            
            if (isset($result['error'])) {
                mtrace("Scan failed: {$result['error']}");
            } else {
                $scan_id = $result['scan_id'] ?? 'unknown';
                $findings_count = $result['findings_count'] ?? 0;
                mtrace("Scan completed! Scan ID: {$scan_id}, Findings: {$findings_count}");
                
                // Store scan_id in custom data for retrieval
                $data->scan_id = $scan_id;
                $data->completed = true;
                $this->set_custom_data($data);
            }
        } catch (\Exception $e) {
            mtrace("Scan exception: " . $e->getMessage());
        }
    }
}
