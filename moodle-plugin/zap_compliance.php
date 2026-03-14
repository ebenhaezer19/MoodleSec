<?php
/**
 * Compliance Reporting and Audit Trail
 * 
 * @package    local_security_dashboard
 * @copyright  2026 Security Team
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php');
require_once($CFG->libdir . '/adminlib.php');

require_login();
require_capability('local/security_dashboard:view', context_system::instance());

$PAGE->set_url(new moodle_url('/local/security_dashboard/zap_compliance.php'));
$PAGE->set_context(context_system::instance());
$PAGE->set_title(get_string('compliance_report', 'local_security_dashboard'));
$PAGE->set_heading(get_string('compliance_report', 'local_security_dashboard'));
$PAGE->set_pagelayout('admin');

$compliance_type = optional_param('type', 'all', PARAM_ALPHA);
$start_date = optional_param_array('date_range_start', [], PARAM_INT);
$end_date = optional_param_array('date_range_end', [], PARAM_INT);

require_once($CFG->dirroot . '/local/security_dashboard/lib/zap_integration.php');

// Get compliance data
$compliance_data = local_security_dashboard_get_compliance_report($compliance_type, $start_date, $end_date);

echo $OUTPUT->header();

// Compliance Status Overview
echo html_writer::start_div('card');
echo html_writer::start_div('card-header');
echo html_writer::tag('h4', 'Security Compliance Report');
echo html_writer::end_div();

echo html_writer::start_div('card-body');

$compliance_html = <<<HTML
<div class="row mb-4">
    <div class="col-md-4">
        <div class="compliance-box text-center">
            <h3>{$compliance_data['overall_score']}%</h3>
            <p>Overall Compliance Score</p>
            <div class="progress">
                <div class="progress-bar {$compliance_data['score_class']}" 
                     style="width: {$compliance_data['overall_score']}%"></div>
            </div>
        </div>
    </div>
    <div class="col-md-4">
        <div class="compliance-box text-center">
            <h3>{$compliance_data['high_risk_count']}</h3>
            <p>High Risk Issues</p>
            <span class="badge badge-danger">Critical</span>
        </div>
    </div>
    <div class="col-md-4">
        <div class="compliance-box text-center">
            <h3>{$compliance_data['resolved_issues']}</h3>
            <p>Resolved Issues</p>
            <span class="badge badge-success">Fixed</span>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-6">
        <h5>Security Status</h5>
        <ul class="list-group">
            <li class="list-group-item">
                <strong>Last Security Scan:</strong>
                <span class="float-right">{$compliance_data['last_scan_date']}</span>
            </li>
            <li class="list-group-item">
                <strong>Compliance Framework:</strong>
                <span class="float-right">{$compliance_data['framework']}</span>
            </li>
            <li class="list-group-item">
                <strong>Audit Status:</strong>
                <span class="float-right">
                    <span class="badge badge-{$compliance_data['audit_status_class']}">
                        {$compliance_data['audit_status']}
                    </span>
                </span>
            </li>
        </ul>
    </div>
    <div class="col-md-6">
        <h5>Compliance Checklist</h5>
        <ul class="list-group">
            {$compliance_data['checklist_html']}
        </ul>
    </div>
</div>
HTML;

echo $compliance_html;
echo html_writer::end_div();
echo html_writer::end_div();

// OWASP Top 10 Compliance
echo html_writer::start_div('card mt-4');
echo html_writer::start_div('card-header');
echo html_writer::tag('h5', 'OWASP Top 10 Coverage');
echo html_writer::end_div();
echo html_writer::start_div('card-body');

$owasp_table = new html_table();
$owasp_table->head = ['#', 'OWASP Top 10 Category', 'Status', 'Vulnerabilities Found', 'Risk Level'];
$owasp_table->data = [];

foreach ($compliance_data['owasp_top10'] as $item) {
    $status_icon = $item['vulnerable'] ? '❌ Vulnerable' : '✅ Secure';
    $risk_class = $item['vulnerable'] ? 'badge-danger' : 'badge-success';
    
    $owasp_table->data[] = [
        $item['rank'],
        $item['name'],
        $status_icon,
        $item['count'],
        "<span class='badge {$risk_class}'>{$item['risk']}</span>"
    ];
}

echo html_writer::table($owasp_table);
echo html_writer::end_div();
echo html_writer::end_div();

// Remediation Actions
echo html_writer::start_div('card mt-4');
echo html_writer::start_div('card-header');
echo html_writer::tag('h5', 'Remediation Actions');
echo html_writer::end_div();
echo html_writer::start_div('card-body');

$remediation_table = new html_table();
$remediation_table->head = ['Issue', 'Priority', 'Status', 'Assigned To', 'Due Date', 'Action'];
$remediation_table->data = [];

foreach ($compliance_data['remediation_actions'] as $action) {
    $status_badge = match($action['status']) {
        'open' => 'badge-danger',
        'in_progress' => 'badge-warning',
        'resolved' => 'badge-success',
        default => 'badge-secondary'
    };
    
    $remediation_table->data[] = [
        $action['issue'],
        "<span class='badge badge-{$action['priority_class']}'>{$action['priority']}</span>",
        "<span class='badge {$status_badge}'>" . ucfirst($action['status']) . "</span>",
        $action['assigned_to'] ?? 'Unassigned',
        isset($action['due_date']) ? date('M d, Y', $action['due_date']) : 'N/A',
        html_writer::link(
            new moodle_url('/local/security_dashboard/zap_remediation.php', 
                ['action_id' => $action['id']]),
            'View',
            ['class' => 'btn btn-sm btn-info']
        )
    ];
}

if (empty($compliance_data['remediation_actions'])) {
    echo html_writer::div('No open remediation actions', 'alert alert-success');
} else {
    echo html_writer::table($remediation_table);
}

echo html_writer::end_div();
echo html_writer::end_div();

// Audit Trail
echo html_writer::start_div('card mt-4');
echo html_writer::start_div('card-header');
echo html_writer::tag('h5', 'Audit Trail');
echo html_writer::end_div();
echo html_writer::start_div('card-body');

$audit_table = new html_table();
$audit_table->head = ['Date/Time', 'Event', 'User', 'Details'];
$audit_table->data = [];

foreach ($compliance_data['audit_trail'] as $event) {
    $audit_table->data[] = [
        userdate($event['timestamp']),
        $event['event_type'],
        $event['user_name'],
        $event['details']
    ];
}

echo html_writer::table($audit_table);
echo html_writer::end_div();
echo html_writer::end_div();

// Export and Certification
echo html_writer::start_div('card mt-4');
echo html_writer::start_div('card-header');
echo html_writer::tag('h5', 'Report Actions');
echo html_writer::end_div();
echo html_writer::start_div('card-body');

echo html_writer::link(
    new moodle_url('/local/security_dashboard/zap_compliance_export.php', 
        ['type' => $compliance_type, 'format' => 'pdf']),
    '<i class="fa fa-file-pdf-o"></i> Export as PDF',
    ['class' => 'btn btn-secondary']
) . ' ';

echo html_writer::link(
    new moodle_url('/local/security_dashboard/zap_compliance_export.php',
        ['type' => $compliance_type, 'format' => 'html']),
    '<i class="fa fa-html5"></i> Export as HTML',
    ['class' => 'btn btn-secondary']
) . ' ';

echo html_writer::link(
    '#',
    '<i class="fa fa-certificate"></i> Generate Certification',
    ['class' => 'btn btn-success', 'id' => 'generate-cert']
);

echo html_writer::end_div();
echo html_writer::end_div();

echo $OUTPUT->footer();
