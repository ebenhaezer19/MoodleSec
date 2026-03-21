<?php
/**
 * Login Monitor - Event Observer
 * 
 * Captures all login attempts and logs them with geolocation
 * 
 * @package    local_security_dashboard
 * @copyright  2026 Krisopras & Nathanael
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace local_security_dashboard;

defined('MOODLE_INTERNAL') || die();

class login_observer {
    
    /**
     * Handle user login success
     * 
     * @param \core\event\user_loggedin $event
     */
    public static function user_loggedin(\core\event\user_loggedin $event) {
        global $DB;
        
        $userid = $event->userid;
        $user = $DB->get_record('user', ['id' => $userid]);
        
        if (!$user) {
            return;
        }
        
        // Get geolocation data
        $geoinfo = self::get_geolocation($_SERVER['REMOTE_ADDR']);
        
        // Calculate risk score
        $risk_score = self::calculate_risk_score($user, $_SERVER['REMOTE_ADDR'], $geoinfo);
        
        // Log successful login
        $log = new \stdClass();
        $log->userid = $userid;
        $log->username = $user->username;
        $log->success = 1;
        $log->ip_address = $_SERVER['REMOTE_ADDR'];
        $log->user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        $log->country = $geoinfo['country'] ?? null;
        $log->city = $geoinfo['city'] ?? null;
        $log->region = $geoinfo['region'] ?? null;
        $log->isp = $geoinfo['isp'] ?? null;
        $log->latitude = $geoinfo['latitude'] ?? null;
        $log->longitude = $geoinfo['longitude'] ?? null;
        $log->is_suspicious = ($risk_score > 70) ? 1 : 0;
        $log->risk_score = $risk_score;
        $log->fail_reason = null;
        $log->session_id = session_id();
        $log->timecreated = time();
        
        $DB->insert_record('local_security_login_log', $log);
        
        // Send alert if suspicious
        if ($log->is_suspicious) {
            self::send_suspicious_login_alert($log, $user);
        }
    }
    
    /**
     * Handle user login failed
     * 
     * @param \core\event\user_login_failed $event
     */
    public static function user_login_failed(\core\event\user_login_failed $event) {
        global $DB;
        
        $username = $event->other['username'] ?? 'unknown';
        $reason = $event->other['reason'] ?? 'unknown';
        
        // Get geolocation
        $geoinfo = self::get_geolocation($_SERVER['REMOTE_ADDR']);
        
        // Log failed login
        $log = new \stdClass();
        $log->userid = null;
        $log->username = $username;
        $log->success = 0;
        $log->ip_address = $_SERVER['REMOTE_ADDR'];
        $log->user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        $log->country = $geoinfo['country'] ?? null;
        $log->city = $geoinfo['city'] ?? null;
        $log->region = $geoinfo['region'] ?? null;
        $log->isp = $geoinfo['isp'] ?? null;
        $log->latitude = $geoinfo['latitude'] ?? null;
        $log->longitude = $geoinfo['longitude'] ?? null;
        $log->is_suspicious = 1; // Always flag failed logins as suspicious
        $log->risk_score = 80;
        $log->fail_reason = $reason;
        $log->session_id = session_id();
        $log->timecreated = time();
        
        $DB->insert_record('local_security_login_log', $log);
        
        // Check for brute force attack
        self::check_brute_force($_SERVER['REMOTE_ADDR'], $username);
    }
    
    /**
     * Get geolocation from IP address
     * 
     * @param string $ip
     * @return array Geolocation data
     */
    private static function get_geolocation($ip) {
        // Skip for localhost/private IPs
        if ($ip == '127.0.0.1' || $ip == '::1' || strpos($ip, '192.168.') === 0 || strpos($ip, '10.') === 0) {
            return [
                'country' => 'Local',
                'city' => 'Localhost',
                'region' => 'Local',
                'isp' => 'Local Network',
                'latitude' => 0,
                'longitude' => 0
            ];
        }
        
        try {
            // Use free IP geolocation API
            $url = "http://ip-api.com/json/{$ip}?fields=status,country,city,regionName,isp,lat,lon";
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 5);
            $response = curl_exec($ch);
            curl_close($ch);
            
            if ($response) {
                $data = json_decode($response, true);
                if ($data && $data['status'] == 'success') {
                    return [
                        'country' => $data['country'] ?? null,
                        'city' => $data['city'] ?? null,
                        'region' => $data['regionName'] ?? null,
                        'isp' => $data['isp'] ?? null,
                        'latitude' => $data['lat'] ?? null,
                        'longitude' => $data['lon'] ?? null
                    ];
                }
            }
        } catch (\Exception $e) {
            debugging('Geolocation lookup failed: ' . $e->getMessage(), DEBUG_DEVELOPER);
        }
        
        return [];
    }
    
    /**
     * Calculate risk score for login attempt
     * 
     * @param object $user
     * @param string $ip
     * @param array $geoinfo
     * @return int Risk score (0-100)
     */
    private static function calculate_risk_score($user, $ip, $geoinfo) {
        global $DB;
        
        $risk = 0;
        
        // Check if new location
        $previous_logins = $DB->get_records('local_security_login_log', [
            'userid' => $user->id,
            'success' => 1
        ], 'timecreated DESC', '*', 0, 10);
        
        $known_location = false;
        foreach ($previous_logins as $prev) {
            if ($prev->country == $geoinfo['country']) {
                $known_location = true;
                break;
            }
        }
        
        if (!$known_location && count($previous_logins) > 0) {
            $risk += 30; // New country
        }
        
        // Check for multiple failed attempts from this IP
        $recent_fails = $DB->count_records_select('local_security_login_log',
            'ip_address = ? AND success = 0 AND timecreated > ?',
            [$ip, time() - 3600] // Last hour
        );
        
        if ($recent_fails > 0) {
            $risk += min(50, $recent_fails * 10);
        }
        
        // Check if IP is on blocklist
        if ($DB->record_exists('local_security_ip_blocklist', ['ip_address' => $ip, 'is_active' => 1])) {
            $risk += 50;
        }
        
        // Check for impossible travel (login from 2 distant locations in short time)
        if (count($previous_logins) > 0) {
            $last_login = reset($previous_logins);
            $time_diff = time() - $last_login->timecreated;
            
            if ($time_diff < 3600 && $last_login->country != $geoinfo['country']) {
                // Logged in from different country within 1 hour
                $risk += 40;
            }
        }
        
        return min(100, $risk);
    }
    
    /**
     * Check for brute force attacks
     * 
     * @param string $ip
     * @param string $username
     */
    private static function check_brute_force($ip, $username) {
        global $DB;
        
        // Count recent failed attempts
        $recent_fails = $DB->count_records_select('local_security_login_log',
            'ip_address = ? AND success = 0 AND timecreated > ?',
            [$ip, time() - 900] // Last 15 minutes
        );
        
        // Auto-block IP after 5 failed attempts
        if ($recent_fails >= 5) {
            $blocklist = new \stdClass();
            $blocklist->ip_address = $ip;
            $blocklist->reason = "Automatic block: {$recent_fails} failed login attempts in 15 minutes";
            $blocklist->block_type = 'auto_brute_force';
            $blocklist->fail_count = $recent_fails;
            $blocklist->first_seen = time() - 900;
            $blocklist->last_seen = time();
            $blocklist->blocked_by = null;
            $blocklist->expires = time() + (24 * 3600); // Block for 24 hours
            $blocklist->is_active = 1;
            $blocklist->timecreated = time();
            $blocklist->timemodified = time();
            
            try {
                $DB->insert_record('local_security_ip_blocklist', $blocklist);
                
                // Send alert to admins
                self::send_brute_force_alert($ip, $username, $recent_fails);
            } catch (\Exception $e) {
                // IP already blocked, update fail count
                $existing = $DB->get_record('local_security_ip_blocklist', ['ip_address' => $ip]);
                if ($existing) {
                    $existing->fail_count = $recent_fails;
                    $existing->last_seen = time();
                    $existing->timemodified = time();
                    $DB->update_record('local_security_ip_blocklist', $existing);
                }
            }
        }
    }
    
    /**
     * Send suspicious login alert
     * 
     * @param object $log
     * @param object $user
     */
    private static function send_suspicious_login_alert($log, $user) {
        global $CFG;
        
        // Skip email sending if messaging is disabled
        if (empty($CFG->mnet_dispatcher_mode) || $CFG->mnet_dispatcher_mode !== 'off') {
            return; // Email system not fully configured, skip
        }
        
        $admins = get_admins();
        if (empty($admins)) {
            return;
        }
        
        $subject = '[MoodleSec Alert] Suspicious Login Detected';
        $message = "A suspicious login was detected:\n\n";
        $message .= "User: " . fullname($user) . " ({$user->username})\n";
        $message .= "IP Address: {$log->ip_address}\n";
        $message .= "Location: {$log->city}, {$log->country}\n";
        $message .= "Risk Score: {$log->risk_score}/100\n";
        $message .= "Time: " . userdate($log->timecreated) . "\n\n";
        $message .= "View login logs: {$CFG->wwwroot}/local/security_dashboard/login_monitor.php\n";
        
        try {
            $noreply = \core_user::get_noreply_user();
            // Only send if noreply user is valid and has email
            if ($noreply && !empty($noreply->email) && strpos($noreply->email, 'localhost') === false) {
                foreach ($admins as $admin) {
                    @email_to_user($admin, $noreply, $subject, $message);
                }
            }
        } catch (\Exception $e) {
            // Silent fail - email system not configured properly
            // Log error for debugging but don't break the login flow
            error_log('MoodleSec: Email alert failed - ' . $e->getMessage());
        }
    }
    
    /**
     * Send brute force alert
     * 
     * @param string $ip
     * @param string $username
     * @param int $fail_count
     */
    private static function send_brute_force_alert($ip, $username, $fail_count) {
        global $CFG;
        
        $admins = get_admins();
        if (empty($admins)) {
            return;
        }
        
        $subject = '[MoodleSec Alert] Brute Force Attack Detected - IP Blocked';
        $message = "Automatic IP block triggered:\n\n";
        $message .= "IP Address: {$ip}\n";
        $message .= "Target Username: {$username}\n";
        $message .= "Failed Attempts: {$fail_count}\n";
        $message .= "Block Duration: 24 hours\n";
        $message .= "Time: " . userdate(time()) . "\n\n";
        $message .= "View blocklist: {$CFG->wwwroot}/local/security_dashboard/login_monitor.php\n";
        
        foreach ($admins as $admin) {
            email_to_user($admin, \core_user::get_noreply_user(), $subject, $message);
        }
    }
}
