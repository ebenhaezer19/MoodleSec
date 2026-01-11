<?php
/**
 * Security Dashboard main page
 *
 * @package    local_security_dashboard
 * @copyright  2025 Krisopras & Nathanael
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php');
require_once($CFG->libdir . '/adminlib.php');

require_login();
require_capability('local/security_dashboard:view', context_system::instance());

$PAGE->set_url(new moodle_url('/local/security_dashboard/index.php'));
$PAGE->set_context(context_system::instance());
$PAGE->set_title(get_string('security_dashboard', 'local_security_dashboard'));
$PAGE->set_heading(get_string('security_dashboard', 'local_security_dashboard'));
$PAGE->set_pagelayout('admin');

echo $OUTPUT->header();

// Check service health
$health = local_security_dashboard_check_health();

// Display health status
echo html_writer::start_div('alert alert-' . ($health['proxy'] && $health['cvss'] ? 'success' : 'warning'));
echo html_writer::tag('h4', 'Service Status');
echo html_writer::tag('p', 'Proxy Service: ' . ($health['proxy'] ? '✅ Online' : '❌ Offline'));
echo html_writer::tag('p', 'CVSS Engine: ' . ($health['cvss'] ? '✅ Online' : '❌ Offline'));
echo html_writer::end_div();

// Get recent logs
$logs_data = local_security_dashboard_get_logs(10);

if (isset($logs_data['error'])) {
    echo html_writer::div($logs_data['error'], 'alert alert-danger');
} else {
    // Display summary
    echo html_writer::start_div('row');
    
    // Scan buttons
    echo html_writer::start_div('col-md-12 mb-3');
    echo html_writer::link(
        new moodle_url('/local/security_dashboard/scan.php'),
        '<i class="fa fa-search"></i> ' . get_string('scan_now', 'local_security_dashboard'),
        ['class' => 'btn btn-primary mr-2']
    );
    echo html_writer::link(
        new moodle_url('/local/security_dashboard/fullscan.php'),
        '<i class="fa fa-globe"></i> Full Site Scan',
        ['class' => 'btn btn-success mr-2']
    );
    echo html_writer::link(
        new moodle_url('/local/security_dashboard/auth_scan.php'),
        '<i class="fa fa-lock"></i> Auth & API Scan',
        ['class' => 'btn btn-primary mr-2']
    );
    echo html_writer::link(
        new moodle_url('/local/security_dashboard/scheduler.php'),
        '<i class="fa fa-clock-o"></i> Scheduler',
        ['class' => 'btn btn-info mr-2']
    );
    echo html_writer::link(
        new moodle_url('/local/security_dashboard/reports.php'),
        '<i class="fa fa-file-pdf-o"></i> Reports',
        ['class' => 'btn btn-warning mr-2']
    );
    echo html_writer::link(
        new moodle_url('/local/security_dashboard/ml_dashboard.php'),
        '<i class="fa fa-brain"></i> ML Dashboard',
        ['class' => 'btn btn-info mr-2']
    );
    echo html_writer::link(
        new moodle_url('/local/security_dashboard/scan_phishing_content.php'),
        '<i class="fa fa-shield"></i> Phishing Scanner',
        ['class' => 'btn btn-danger mr-2']
    );
    echo html_writer::link(
        new moodle_url('/local/security_dashboard/vulnerability_map.php'),
        '<i class="fa fa-map-marked"></i> Vulnerability Map',
        ['class' => 'btn btn-primary']
    );
    echo html_writer::end_div();
    
    echo html_writer::end_div();
    
    // Display recent logs
    echo html_writer::tag('h3', get_string('recent_scans', 'local_security_dashboard'));
    
    if (empty($logs_data['logs'])) {
        echo html_writer::div(get_string('no_scans', 'local_security_dashboard'), 'alert alert-info');
    } else {
        $table = new html_table();
        $table->head = ['Type', 'Timestamp', 'Details'];
        $table->attributes['class'] = 'generaltable';
        
        foreach ($logs_data['logs'] as $log) {
            $row = [];
            
            // XSS Prevention: Sanitize all log data
            $row[] = s($log['type'] ?? 'N/A');
            $row[] = s($log['timestamp'] ?? 'N/A');
            
            // Format details based on log type
            $details = '';
            if (isset($log['scan_id'])) {
                $details .= 'Scan ID: ' . s($log['scan_id']) . '<br>';
            }
            if (isset($log['target_url'])) {
                $details .= 'URL: ' . s($log['target_url']) . '<br>';
            }
            if (isset($log['findings_count'])) {
                $details .= 'Findings: ' . intval($log['findings_count']) . '<br>';
            }
            if (isset($log['summary'])) {
                $summary = $log['summary'];
                $details .= 'Critical: ' . intval($summary['critical'] ?? 0) . ' | ';
                $details .= 'High: ' . intval($summary['high'] ?? 0) . ' | ';
                $details .= 'Medium: ' . intval($summary['medium'] ?? 0) . ' | ';
                $details .= 'Low: ' . intval($summary['low'] ?? 0);
            }
            
            $row[] = $details ?: 'N/A';
            $table->data[] = $row;
        }
        
        echo html_writer::table($table);
    }
}

echo $OUTPUT->footer();
