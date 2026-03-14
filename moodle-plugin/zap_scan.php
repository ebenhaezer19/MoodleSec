<?php
/**
 * ZAP Scan Trigger Interface
 * 
 * @package    local_security_dashboard
 * @copyright  2026 Security Team
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php');
require_once($CFG->libdir . '/adminlib.php');
require_once($CFG->dirroot . '/local/security_dashboard/lib/zap_integration.php');

require_login();
require_capability('local/security_dashboard:scan', context_system::instance());

$PAGE->set_url(new moodle_url('/local/security_dashboard/zap_scan.php'));
$PAGE->set_context(context_system::instance());
$PAGE->set_title(get_string('zap_scan', 'local_security_dashboard'));
$PAGE->set_heading(get_string('zap_scan', 'local_security_dashboard'));
$PAGE->set_pagelayout('admin');

// Check if ZAP is enabled
$zap_enabled = get_config('local_security_dashboard', 'zap_enabled');
if (!$zap_enabled) {
    echo $OUTPUT->header();
    echo $OUTPUT->notification(get_string('zap_disabled', 'local_security_dashboard'), 'error');
    echo $OUTPUT->footer();
    die();
}

// Handle scan submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    confirm_sesskey();
    
    $scan_type = required_param('scan_type', PARAM_ALPHA);
    $target_url = optional_param('target_url', $CFG->wwwroot, PARAM_URL);
    
    try {
        $result = local_security_dashboard_trigger_zap_scan($scan_type, $target_url);
        
        if ($result['success']) {
            // Store scan in database and get scan_id
            $scan_id = local_security_dashboard_store_scan($result);
            
            // Send notification if high-risk findings
            if ($result['total_findings'] > 0) {
                local_security_dashboard_notify_findings($result);
            }
            
            redirect(new moodle_url('/local/security_dashboard/zap_results.php', 
                ['scan_id' => $scan_id]));
        } else {
            $error = $result['error'];
        }
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}

echo $OUTPUT->header();

// Display ZAP Status
$zap_status = local_security_dashboard_check_zap_status();
$status_class = $zap_status['connected'] ? 'alert-success' : 'alert-danger';

echo html_writer::start_div("alert $status_class");
echo html_writer::tag('h4', get_string('zap_status', 'local_security_dashboard'));
echo html_writer::tag('p', 
    get_string('zap_version', 'local_security_dashboard') . ': ' . 
    ($zap_status['version'] ?? 'Unknown'));
echo html_writer::tag('p',
    get_string('connection_status', 'local_security_dashboard') . ': ' .
    ($zap_status['connected'] ? '<span class="badge badge-success">Online</span>' : 
                                 '<span class="badge badge-danger">Offline</span>'));
echo html_writer::end_div();

// Display error if any
if (isset($error)) {
    echo $OUTPUT->notification($error, 'error');
}

// Scan Type Selection Form
$form_html = <<<HTML
<div class="card">
    <div class="card-header">
        <h5>ZAP Vulnerability Scan</h5>
    </div>
    <div class="card-body">
        <form method="post" class="form-inline">
            <input type="hidden" name="sesskey" value="' . sesskey() . '">
            
            <div class="form-group mb-2 mr-2">
                <label for="scan_type" class="mr-2">Scan Type:</label>
                <select name="scan_type" id="scan_type" class="form-control" onchange="updateScanInfo()">
                    <option value="unauthenticated">Unauthenticated Scan</option>
                    <option value="authenticated">Authenticated Scan (Moodle Account)</option>
                    <option value="api">API & Auth Endpoints</option>
                </select>
            </div>
            
            <div class="form-group mb-2 mr-2">
                <label for="target_url" class="mr-2">Target URL:</label>
                <input type="url" name="target_url" id="target_url" class="form-control" 
                       value="$CFG->wwwroot" placeholder="$CFG->wwwroot">
            </div>
            
            <button type="submit" class="btn btn-primary">
                <i class="fa fa-play"></i> Start Scan
            </button>
        </form>
    </div>
</div>

<div class="card mt-3">
    <div class="card-header">
        <h5>Scan Options</h5>
    </div>
    <div class="card-body">
        <div class="form-group">
            <label>Spider Depth: 
                <strong>{get_config('local_security_dashboard', 'scan_spider_depth')}</strong>
            </label>
        </div>
        <div class="form-group">
            <label>Scan Policy: 
                <strong>{get_config('local_security_dashboard', 'scan_policy')}</strong>
            </label>
        </div>
        <div class="form-group">
            <label>ML Filtering: 
                <strong>{(get_config('local_security_dashboard', 'ml_filtering_enabled') ? 'Enabled' : 'Disabled')}</strong>
            </label>
        </div>
    </div>
</div>

<div class="card mt-3">
    <div class="card-header">
        <h5>Scan Information</h5>
    </div>
    <div class="card-body">
        <div id="scan-info">
            <p><strong>Unauthenticated Scan:</strong></p>
            <ul>
                <li>Scans without login credentials</li>
                <li>Tests publicly accessible pages</li>
                <li>Spider depth: configurable</li>
                <li>Detects common vulnerabilities</li>
            </ul>
        </div>
    </div>
</div>

<script>
function updateScanInfo() {
    const type = document.getElementById('scan_type').value;
    const info = document.getElementById('scan-info');
    
    const descriptions = {
        'unauthenticated': '<p><strong>Unauthenticated Scan:</strong></p><ul><li>Scans without login credentials</li><li>Tests publicly accessible pages</li><li>Spider depth: configurable</li><li>Detects common vulnerabilities</li></ul>',
        'authenticated': '<p><strong>Authenticated Scan:</strong></p><ul><li>Logs in as test user</li><li>Scans authenticated areas</li><li>Verifies auth mechanisms</li><li>Tests access controls</li></ul>',
        'api': '<p><strong>API & Auth Scan:</strong></p><ul><li>Focuses on API endpoints</li><li>Tests authentication flows</li><li>Checks auth headers</li><li>Verifies token handling</li></ul>'
    };
    
    info.innerHTML = descriptions[type];
}
</script>
HTML;

echo $form_html;

// Show recent scans
$recent_scans = local_security_dashboard_get_recent_scans(5);

echo html_writer::start_div('card mt-4');
echo html_writer::div('Recent Scans', 'card-header');
echo html_writer::start_div('card-body');

if (empty($recent_scans)) {
    echo html_writer::div('No scans performed yet', 'alert alert-info');
} else {
    $table = new html_table();
    $table->head = ['Scan Type', 'Target', 'Date', 'Status', 'Findings', 'Actions'];
    $table->data = [];
    
    foreach ($recent_scans as $scan) {
        $status_badge = $scan->status === 'completed' ? 
            '<span class="badge badge-success">Completed</span>' :
            '<span class="badge badge-warning">Running</span>';
        
        $actions = html_writer::link(
            new moodle_url('/local/security_dashboard/zap_results.php', ['scan_id' => $scan->id]),
            'View Results',
            ['class' => 'btn btn-sm btn-info']
        );
        
        $table->data[] = [
            ucfirst($scan->scan_type),
            $scan->target_url,
            userdate($scan->timecreated),
            $status_badge,
            $scan->total_findings,
            $actions
        ];
    }
    
    echo html_writer::table($table);
}

echo html_writer::end_div();
echo html_writer::end_div();

echo $OUTPUT->footer();

