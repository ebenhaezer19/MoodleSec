<?php
/**
 * ZAP Scan Results Display
 * 
 * @package    local_security_dashboard
 * @copyright  2026 Security Team
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php');
require_once($CFG->libdir . '/adminlib.php');

require_login();
require_capability('local/security_dashboard:view', context_system::instance());

$scan_id = required_param('scan_id', PARAM_INT);

$PAGE->set_url(new moodle_url('/local/security_dashboard/zap_results.php', ['scan_id' => $scan_id]));
$PAGE->set_context(context_system::instance());
$PAGE->set_title(get_string('scan_results', 'local_security_dashboard'));
$PAGE->set_heading(get_string('scan_results', 'local_security_dashboard'));
$PAGE->set_pagelayout('admin');

// Load scan results
require_once($CFG->dirroot . '/local/security_dashboard/lib/zap_integration.php');

$scan = local_security_dashboard_get_scan($scan_id);
if (!$scan) {
    echo $OUTPUT->header();
    echo $OUTPUT->notification('Scan not found', 'error');
    echo $OUTPUT->footer();
    die();
}

$findings = local_security_dashboard_get_scan_findings($scan_id);

echo $OUTPUT->header();

// Scan Header
echo html_writer::start_div('card');
echo html_writer::start_div('card-header');
echo html_writer::tag('h4', 'Scan Results - ' . ucfirst($scan->scan_type));
echo html_writer::end_div();

echo html_writer::start_div('card-body');

// Scan Summary
$summary_html = <<<HTML
<div class="row">
    <div class="col-md-3">
        <div class="stat-box">
            <h3 class="stat-number">{$scan->total_findings}</h3>
            <p class="stat-label">Total Findings</p>
        </div>
    </div>
    <div class="col-md-3">
        <div class="stat-box">
            <h3 class="stat-number" style="color: #dc3545;">{$scan->high_risk_findings}</h3>
            <p class="stat-label">High Risk</p>
        </div>
    </div>
    <div class="col-md-3">
        <div class="stat-box">
            <h3 class="stat-number" style="color: #ffc107;">{$scan->medium_risk_findings}</h3>
            <p class="stat-label">Medium Risk</p>
        </div>
    </div>
    <div class="col-md-3">
        <div class="stat-box">
            <h3 class="stat-number" style="color: #28a745;">{$scan->low_risk_findings}</h3>
            <p class="stat-label">Low Risk</p>
        </div>
    </div>
</div>

<div class="row mt-3">
    <div class="col-md-6">
        <p><strong>Target URL:</strong> {$scan->target_url}</p>
        <p><strong>Scan Type:</strong> {$scan->scan_type}</p>
    </div>
    <div class="col-md-6">
        <p><strong>Status:</strong> <span class="badge badge-success">{$scan->status}</span></p>
        <p><strong>Scan Duration:</strong> {$scan->duration} seconds</p>
        <p><strong>Scanned:</strong> {userdate($scan->timecreated)}</p>
    </div>
</div>

<div class="mt-3">
    <a href="zap_results_export.php?scan_id={$scan_id}&format=pdf" class="btn btn-secondary">
        <i class="fa fa-pdf"></i> Export PDF
    </a>
    <a href="zap_results_export.php?scan_id={$scan_id}&format=json" class="btn btn-secondary">
        <i class="fa fa-download"></i> Export JSON
    </a>
</div>
HTML;

echo $summary_html;
echo html_writer::end_div();
echo html_writer::end_div();

// Findings Table
if (!empty($findings)) {
    echo html_writer::start_div('card mt-4');
    echo html_writer::start_div('card-header');
    echo html_writer::tag('h5', 'Detailed Findings');
    echo html_writer::end_div();
    
    echo html_writer::start_div('card-body');
    
    $table = new html_table();
    $table->head = ['#', 'Type', 'Severity', 'URL', 'Evidence', 'Solution'];
    $table->data = [];
    
    $i = 1;
    foreach ($findings as $finding) {
        // Risk color
        $risk_color = 'danger';
        if ($finding->risk === 'Medium') $risk_color = 'warning';
        if ($finding->risk === 'Low') $risk_color = 'info';
        
        $table->data[] = [
            $i++,
            $finding->type,
            "<span class='badge badge-{$risk_color}'>{$finding->risk}</span>",
            str_truncate($finding->url, 50),
            str_truncate($finding->evidence, 30),
            str_truncate($finding->solution, 40)
        ];
    }
    
    echo html_writer::table($table);
    echo html_writer::end_div();
    echo html_writer::end_div();
    
    // Detailed View
    echo html_writer::start_div('card mt-4');
    echo html_writer::start_div('card-header');
    echo html_writer::tag('h5', 'Detailed Analysis');
    echo html_writer::end_div();
    echo html_writer::start_div('card-body');
    
    foreach ($findings as $finding) {
        $risk_color = match($finding->risk) {
            'High' => '#dc3545',
            'Medium' => '#ffc107',
            'Low' => '#17a2b8',
            default => '#6c757d'
        };
        
        echo html_writer::start_div('finding-detail mb-3', ['style' => "border-left: 4px solid $risk_color; padding-left: 10px;"]);
        echo html_writer::tag('h6', $finding->type . " [{$finding->risk}]");
        echo "<p><strong>URL:</strong> {$finding->url}</p>";
        echo "<p><strong>Evidence:</strong></p>";
        echo "<pre class='bg-light p-2'>" . htmlspecialchars($finding->evidence) . "</pre>";
        echo "<p><strong>Description:</strong></p>";
        echo "<p>{$finding->description}</p>";
        echo "<p><strong>Solution:</strong></p>";
        echo "<p>{$finding->solution}</p>";
        echo "<p><small>Reference: <a href='{$finding->reference}' target='_blank'>{$finding->reference}</a></small></p>";
        echo html_writer::end_div();
    }
    
    echo html_writer::end_div();
    echo html_writer::end_div();
} else {
    echo html_writer::div('No security findings detected!', 'alert alert-success mt-4');
}

// Back button
echo html_writer::link(
    new moodle_url('/local/security_dashboard/zap_scan.php'),
    'Back to Scan Interface',
    ['class' => 'btn btn-secondary mt-4']
);

echo $OUTPUT->footer();
