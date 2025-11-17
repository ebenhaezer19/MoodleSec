<?php
/**
 * Database manager class for Security Dashboard
 *
 * @package    local_security_dashboard
 * @copyright  2024 Your Name
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace local_security_dashboard;

defined('MOODLE_INTERNAL') || die();

/**
 * Database operations manager
 */
class db_manager {
    
    /**
     * Save scan result to database
     *
     * @param object $scan_data Scan data from API
     * @param int $userid User ID who triggered the scan
     * @return int Scan record ID
     */
    public static function save_scan($scan_data, $userid) {
        global $DB;
        
        $now = time();
        
        // Prepare scan record
        $scan = new \stdClass();
        $scan->scan_id = $scan_data->scan_id ?? uniqid('scan_');
        $scan->target_url = $scan_data->target_url ?? '';
        $scan->scan_path = self::extract_path($scan_data->target_url ?? '');
        $scan->scan_method = $scan_data->method ?? 'GET';
        $scan->scan_type = $scan_data->scan_type ?? 'manual';
        $scan->status = 'completed';
        
        // Count findings by severity
        $summary = $scan_data->summary ?? new \stdClass();
        $scan->total_findings = count($scan_data->findings ?? []);
        $scan->critical_count = $summary->critical ?? 0;
        $scan->high_count = $summary->high ?? 0;
        $scan->medium_count = $summary->medium ?? 0;
        $scan->low_count = $summary->low ?? 0;
        $scan->info_count = $summary->info ?? 0;
        
        $scan->triggered_by = $userid;
        $scan->timecreated = $now;
        $scan->timemodified = $now;
        
        // Insert scan record
        $scan_id = $DB->insert_record('local_security_scans', $scan);
        
        // Save findings
        if (!empty($scan_data->findings)) {
            foreach ($scan_data->findings as $finding) {
                self::save_finding($scan_id, $finding);
            }
        }
        
        // Log the scan
        self::add_log($scan_id, 'scan_completed', 'info', 
            'Scan completed with ' . $scan->total_findings . ' findings', 
            json_encode($summary), $userid);
        
        return $scan_id;
    }
    
    /**
     * Save individual finding
     *
     * @param int $scan_id Scan record ID
     * @param object $finding Finding data
     * @return int Finding record ID
     */
    public static function save_finding($scan_id, $finding) {
        global $DB;
        
        $now = time();
        
        $record = new \stdClass();
        $record->scan_id = $scan_id;
        $record->severity = $finding->severity ?? 'Info';
        $record->category = $finding->category ?? 'Unknown';
        $record->title = $finding->description ?? 'No title';
        $record->description = $finding->description ?? '';
        $record->evidence = $finding->evidence ?? '';
        $record->cvss_score = $finding->cvss_base_score ?? null;
        $record->cvss_vector = $finding->cvss_vector ?? null;
        $record->cwe_id = $finding->cwe_id ?? null;
        $record->remediation = $finding->remediation ?? '';
        $record->status = 'open';
        $record->false_positive = 0;
        $record->timecreated = $now;
        $record->timemodified = $now;
        
        return $DB->insert_record('local_security_findings', $record);
    }
    
    /**
     * Get scan by ID
     *
     * @param int $scan_id Scan record ID
     * @return object|false Scan record or false
     */
    public static function get_scan($scan_id) {
        global $DB;
        return $DB->get_record('local_security_scans', ['id' => $scan_id]);
    }
    
    /**
     * Get scan by scan_id string
     *
     * @param string $scan_id Scan identifier string
     * @return object|false Scan record or false
     */
    public static function get_scan_by_scan_id($scan_id) {
        global $DB;
        return $DB->get_record('local_security_scans', ['scan_id' => $scan_id]);
    }
    
    /**
     * Get recent scans
     *
     * @param int $limit Number of scans to retrieve
     * @param int $offset Offset for pagination
     * @return array Array of scan records
     */
    public static function get_recent_scans($limit = 10, $offset = 0) {
        global $DB;
        
        return $DB->get_records('local_security_scans', null, 'timecreated DESC', '*', $offset, $limit);
    }
    
    /**
     * Get findings for a scan
     *
     * @param int $scan_id Scan record ID
     * @param string $severity Filter by severity (optional)
     * @return array Array of finding records
     */
    public static function get_findings($scan_id, $severity = null) {
        global $DB;
        
        $params = ['scan_id' => $scan_id];
        if ($severity) {
            $params['severity'] = $severity;
        }
        
        return $DB->get_records('local_security_findings', $params, 'severity DESC, timecreated DESC');
    }
    
    /**
     * Get scan statistics
     *
     * @param int $days Number of days to look back (0 = all time)
     * @return object Statistics object
     */
    public static function get_statistics($days = 30) {
        global $DB;
        
        $stats = new \stdClass();
        
        // Build time condition
        $timecondition = '';
        $params = [];
        if ($days > 0) {
            $timecondition = 'WHERE timecreated >= :timestart';
            $params['timestart'] = time() - ($days * 86400);
        }
        
        // Total scans
        $sql = "SELECT COUNT(*) as total FROM {local_security_scans} $timecondition";
        $stats->total_scans = $DB->count_records_sql($sql, $params);
        
        // Total findings by severity
        $sql = "SELECT 
                    SUM(critical_count) as critical,
                    SUM(high_count) as high,
                    SUM(medium_count) as medium,
                    SUM(low_count) as low,
                    SUM(info_count) as info,
                    SUM(total_findings) as total
                FROM {local_security_scans} $timecondition";
        $findings = $DB->get_record_sql($sql, $params);
        
        $stats->critical_findings = (int)($findings->critical ?? 0);
        $stats->high_findings = (int)($findings->high ?? 0);
        $stats->medium_findings = (int)($findings->medium ?? 0);
        $stats->low_findings = (int)($findings->low ?? 0);
        $stats->info_findings = (int)($findings->info ?? 0);
        $stats->total_findings = (int)($findings->total ?? 0);
        
        // Most common vulnerability categories
        $sql = "SELECT category, COUNT(*) as count 
                FROM {local_security_findings} f
                JOIN {local_security_scans} s ON f.scan_id = s.id
                $timecondition
                GROUP BY category
                ORDER BY count DESC
                LIMIT 5";
        $stats->top_categories = $DB->get_records_sql($sql, $params);
        
        // Average findings per scan
        if ($stats->total_scans > 0) {
            $stats->avg_findings_per_scan = round($stats->total_findings / $stats->total_scans, 2);
        } else {
            $stats->avg_findings_per_scan = 0;
        }
        
        return $stats;
    }
    
    /**
     * Get scan history for charts
     *
     * @param int $days Number of days
     * @return array Array of daily statistics
     */
    public static function get_scan_history($days = 7) {
        global $DB;
        
        $history = [];
        $now = time();
        
        for ($i = $days - 1; $i >= 0; $i--) {
            $day_start = strtotime('today', $now) - ($i * 86400);
            $day_end = $day_start + 86400;
            
            $sql = "SELECT 
                        COUNT(*) as scan_count,
                        SUM(total_findings) as findings_count,
                        SUM(critical_count) as critical,
                        SUM(high_count) as high
                    FROM {local_security_scans}
                    WHERE timecreated >= :start AND timecreated < :end";
            
            $data = $DB->get_record_sql($sql, [
                'start' => $day_start,
                'end' => $day_end
            ]);
            
            $history[] = [
                'date' => date('Y-m-d', $day_start),
                'day_name' => date('D', $day_start),
                'scan_count' => (int)($data->scan_count ?? 0),
                'findings_count' => (int)($data->findings_count ?? 0),
                'critical' => (int)($data->critical ?? 0),
                'high' => (int)($data->high ?? 0)
            ];
        }
        
        return $history;
    }
    
    /**
     * Update finding status
     *
     * @param int $finding_id Finding record ID
     * @param string $status New status
     * @return bool Success
     */
    public static function update_finding_status($finding_id, $status) {
        global $DB;
        
        $valid_statuses = ['open', 'fixed', 'false_positive', 'accepted'];
        if (!in_array($status, $valid_statuses)) {
            return false;
        }
        
        $record = new \stdClass();
        $record->id = $finding_id;
        $record->status = $status;
        $record->timemodified = time();
        
        if ($status === 'false_positive') {
            $record->false_positive = 1;
        }
        
        return $DB->update_record('local_security_findings', $record);
    }
    
    /**
     * Add log entry
     *
     * @param int $scan_id Scan ID (optional)
     * @param string $log_type Log type
     * @param string $log_level Log level (info, warning, error)
     * @param string $message Log message
     * @param string $data Additional data (JSON)
     * @param int $userid User ID (optional)
     * @return int Log record ID
     */
    public static function add_log($scan_id, $log_type, $log_level, $message, $data = null, $userid = null) {
        global $DB, $USER;
        
        $log = new \stdClass();
        $log->scan_id = $scan_id;
        $log->log_type = $log_type;
        $log->log_level = $log_level;
        $log->message = $message;
        $log->data = $data;
        $log->user_id = $userid ?? $USER->id;
        $log->timecreated = time();
        
        return $DB->insert_record('local_security_logs', $log);
    }
    
    /**
     * Get logs
     *
     * @param int $scan_id Filter by scan ID (optional)
     * @param int $limit Limit
     * @return array Array of log records
     */
    public static function get_logs($scan_id = null, $limit = 100) {
        global $DB;
        
        $params = [];
        $where = '';
        
        if ($scan_id) {
            $where = 'WHERE scan_id = :scan_id';
            $params['scan_id'] = $scan_id;
        }
        
        $sql = "SELECT * FROM {local_security_logs} $where ORDER BY timecreated DESC LIMIT $limit";
        
        return $DB->get_records_sql($sql, $params);
    }
    
    /**
     * Save scheduled scan
     *
     * @param object $schedule Schedule data
     * @return int Schedule record ID
     */
    public static function save_schedule($schedule) {
        global $DB, $USER;
        
        $now = time();
        
        if (empty($schedule->id)) {
            // New schedule
            $schedule->created_by = $USER->id;
            $schedule->timecreated = $now;
            $schedule->timemodified = $now;
            return $DB->insert_record('local_security_schedules', $schedule);
        } else {
            // Update existing
            $schedule->timemodified = $now;
            $DB->update_record('local_security_schedules', $schedule);
            return $schedule->id;
        }
    }
    
    /**
     * Get scheduled scans
     *
     * @param bool $enabled_only Get only enabled schedules
     * @return array Array of schedule records
     */
    public static function get_schedules($enabled_only = false) {
        global $DB;
        
        $params = [];
        if ($enabled_only) {
            $params['is_enabled'] = 1;
        }
        
        return $DB->get_records('local_security_schedules', $params, 'name ASC');
    }
    
    /**
     * Delete scan and related data
     *
     * @param int $scan_id Scan record ID
     * @return bool Success
     */
    public static function delete_scan($scan_id) {
        global $DB;
        
        $transaction = $DB->start_delegated_transaction();
        
        try {
            // Delete findings
            $DB->delete_records('local_security_findings', ['scan_id' => $scan_id]);
            
            // Delete logs
            $DB->delete_records('local_security_logs', ['scan_id' => $scan_id]);
            
            // Delete scan
            $DB->delete_records('local_security_scans', ['id' => $scan_id]);
            
            $transaction->allow_commit();
            return true;
        } catch (\Exception $e) {
            $transaction->rollback($e);
            return false;
        }
    }
    
    /**
     * Extract path from URL
     *
     * @param string $url Full URL
     * @return string Path component
     */
    private static function extract_path($url) {
        $parsed = parse_url($url);
        return $parsed['path'] ?? '/';
    }
}
