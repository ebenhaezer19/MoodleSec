<?php
/**
 * Security Dashboard main page
 *
 * @package    local_security_dashboard
 * @copyright  2024 Your Name
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
    
    // Scan button
    echo html_writer::start_div('col-md-12 mb-3');
    echo html_writer::link(
        new moodle_url('/local/security_dashboard/scan.php'),
        get_string('scan_now', 'local_security_dashboard'),
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
            $row[] = $log['type'] ?? 'N/A';
            $row[] = $log['timestamp'] ?? 'N/A';
            
            // Format details based on log type
            $details = '';
            if (isset($log['scan_id'])) {
                $details .= 'Scan ID: ' . $log['scan_id'] . '<br>';
            }
            if (isset($log['target_url'])) {
                $details .= 'URL: ' . $log['target_url'] . '<br>';
            }
            if (isset($log['findings_count'])) {
                $details .= 'Findings: ' . $log['findings_count'] . '<br>';
            }
            if (isset($log['summary'])) {
                $summary = $log['summary'];
                $details .= 'Critical: ' . ($summary['critical'] ?? 0) . ' | ';
                $details .= 'High: ' . ($summary['high'] ?? 0) . ' | ';
                $details .= 'Medium: ' . ($summary['medium'] ?? 0) . ' | ';
                $details .= 'Low: ' . ($summary['low'] ?? 0);
            }
            
            $row[] = $details ?: 'N/A';
            $table->data[] = $row;
        }
        
        echo html_writer::table($table);
    }
}

echo $OUTPUT->footer();
