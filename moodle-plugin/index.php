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
        new moodle_url('/local/security_dashboard/login_monitor.php'),
        '<i class="fa fa-user-shield"></i> Login Monitor',
        ['class' => 'btn btn-info mr-2']
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

            // Format type with badge for ZAP scans
            $type_display = s($log['type'] ?? 'N/A');
            if ($log['source'] === 'zap') {
                $type_display = '<span class="badge badge-info">ZAP</span> ' . $type_display;
            } else {
                $type_display = '<span class="badge badge-secondary">Proxy</span> ' . $type_display;
            }
            $row[] = $type_display;
            
            // Timestamp
            $row[] = s($log['timestamp'] ?? 'N/A');

            // Format details
            $details = '';
            
            // For ZAP scans - show findings summary
            if ($log['source'] === 'zap') {
                $details .= 'URL: ' . s($log['url']) . '<br>';
                $details .= 'Findings: ' . intval($log['findings'] ?? 0);
                
                if ($log['findings'] > 0) {
                    $summary_parts = [];
                    if ($log['critical'] > 0) $summary_parts[] = 'Critical: ' . intval($log['critical']);
                    if ($log['high'] > 0) $summary_parts[] = 'High: ' . intval($log['high']);
                    if ($log['medium'] > 0) $summary_parts[] = 'Medium: ' . intval($log['medium']);
                    if ($log['low'] > 0) $summary_parts[] = 'Low: ' . intval($log['low']);
                    
                    if (!empty($summary_parts)) {
                        $details .= '<br>' . implode(' | ', $summary_parts);
                    }
                }
                
                // Add link to view results
                if (!empty($log['scan_id'])) {
                    $details .= '<br>' . html_writer::link(
                        new moodle_url('/local/security_dashboard/zap_results.php', 
                            ['scan_id' => strtolower(str_replace('zap_', '', $log['scan_id']))]),
                        'View Results →',
                        ['class' => 'small', 'style' => 'margin-top: 5px; display: inline-block;']
                    );
                }
            } else {
                // For proxy logs - show details as-is
                $details = s($log['details'] ?? 'N/A');
                if (!empty($log['url'])) {
                    $details .= '<br>URL: ' . s($log['url']);
                }
            }

            $row[] = $details ?: 'N/A';
            $table->data[] = $row;
        }

        echo html_writer::table($table);
    }
}

// ZAP INTEGRATION SECTION (Phase 2)
echo html_writer::start_div('', ['style' => 'margin-top: 30px;']);
echo html_writer::tag('h3', 'ZAP Vulnerability Scanning');

echo html_writer::start_div('', ['style' => 'margin-top: 15px;']);

echo html_writer::link(
    new moodle_url('/admin/settings.php?section=local_security_dashboard_zap'),
    '⚙️ ZAP Settings',
    ['class' => 'btn btn-secondary', 'style' => 'margin-right: 10px;']
);

echo html_writer::link(
    new moodle_url('/local/security_dashboard/zap_scan.php'),
    '🔍 Trigger Scan',
    ['class' => 'btn btn-primary', 'style' => 'margin-right: 10px;']
);

echo html_writer::link(
    new moodle_url('/local/security_dashboard/zap_results.php'),
    '📊 Scan Results',
    ['class' => 'btn btn-info', 'style' => 'margin-right: 10px;']
);

echo html_writer::link(
    new moodle_url('/local/security_dashboard/zap_trends.php'),
    '📈 Trends',
    ['class' => 'btn btn-warning', 'style' => 'margin-right: 10px;']
);

echo html_writer::link(
    new moodle_url('/local/security_dashboard/zap_compliance.php'),
    '✅ Compliance',
    ['class' => 'btn btn-danger']
);

echo html_writer::end_div();
echo html_writer::end_div();

// Display footer
echo $OUTPUT->footer();
?>