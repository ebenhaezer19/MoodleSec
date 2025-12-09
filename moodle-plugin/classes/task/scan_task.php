<?php
/**
 * Scheduled task for periodic security scans
 *
 * @package    local_security_dashboard
 * @copyright  2025 Krisopras & Nathanael
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace local_security_dashboard\task;

defined('MOODLE_INTERNAL') || die();

/**
 * Scheduled task to run periodic security scans
 */
class scan_task extends \core\task\scheduled_task {
    
    /**
     * Get task name
     */
    public function get_name() {
        return get_string('scan_task', 'local_security_dashboard');
    }
    
    /**
     * Execute the task
     */
    public function execute() {
        global $CFG;
        require_once($CFG->dirroot . '/local/security_dashboard/lib.php');
        
        mtrace('Starting scheduled security scan...');
        
        // Get configured scan paths from settings
        $scan_paths = get_config('local_security_dashboard', 'scheduled_scan_paths');
        
        if (empty($scan_paths)) {
            mtrace('No scan paths configured. Skipping.');
            return;
        }
        
        // Parse paths (comma-separated)
        $paths = array_map('trim', explode(',', $scan_paths));
        
        foreach ($paths as $path) {
            if (empty($path)) {
                continue;
            }
            
            mtrace("Scanning path: {$path}");
            
            try {
                $result = local_security_dashboard_trigger_scan($path, 'GET');
                
                if (isset($result['error'])) {
                    mtrace("  Error: {$result['error']}");
                } else {
                    $scan_id = $result['scan_id'] ?? 'unknown';
                    $findings_count = $result['findings_count'] ?? 0;
                    mtrace("  Success! Scan ID: {$scan_id}, Findings: {$findings_count}");
                }
            } catch (\Exception $e) {
                mtrace("  Exception: " . $e->getMessage());
            }
            
            // Sleep between scans to avoid overwhelming the proxy
            sleep(5);
        }
        
        mtrace('Scheduled security scan completed.');
    }
}
