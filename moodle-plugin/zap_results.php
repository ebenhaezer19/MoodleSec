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

/**
 * Helper function to truncate string
 */
if (!function_exists('str_truncate')) {
    function str_truncate($str, $length = 50) {
        if (strlen($str) > $length) {
            return substr($str, 0, $length) . '...';
        }
        return $str;
    }
}

$scan_id = optional_param('scan_id', 0, PARAM_INT);

// If no scan_id provided, redirect to dashboard or show message
if (!$scan_id) {
    redirect(new moodle_url('/local/security_dashboard/index.php'));
}

$PAGE->set_url(new moodle_url('/local/security_dashboard/zap_results.php', ['scan_id' => $scan_id]));
$PAGE->set_context(context_system::instance());
$PAGE->set_title(get_string('scan_results', 'local_security_dashboard'));
$PAGE->set_heading(get_string('scan_results', 'local_security_dashboard'));
$PAGE->set_pagelayout('admin');

require_once($CFG->dirroot . '/local/security_dashboard/lib.php');
require_once($CFG->dirroot . '/local/security_dashboard/lib/zap_integration.php');

$scan = local_security_dashboard_get_scan($scan_id);
if (!$scan) {
    echo $OUTPUT->header();
    echo $OUTPUT->notification('Scan not found', 'error');
    echo $OUTPUT->footer();
    die();
}

// Load raw findings from DB
$findings_raw = local_security_dashboard_get_scan_findings($scan_id);

// === REAL-TIME ML FILTERING (FP Reducer + Severity Predictor) ===
// Convert DB objects to plain arrays for the proxy API call.
$findings_array = [];
foreach ($findings_raw as $f) {
    $findings_array[] = [
        'severity'    => $f->severity    ?? 'Info',
        'category'    => $f->category    ?? 'General',
        'description' => $f->description ?? '',
        'evidence'    => $f->evidence    ?? '',
        'url'         => $scan->target_url ?? '',
        'title'       => $f->title       ?? ($f->category ?? ''),
        'remediation' => $f->remediation ?? '',
        'cwe_id'      => $f->cwe_id      ?? null,
    ];
}

$ml_result  = local_security_dashboard_ml_filter_findings($findings_array);
$ml_stats   = $ml_result['ml_stats'];
$ml_enabled = $ml_result['ml_enabled'] ?? true;

// Rebuild the findings list from ML-filtered results (preserving DB fields).
// We match by index (same ordering as $findings_raw).
$filtered_findings = [];
if (!empty($ml_result['findings'])) {
    // Build a lookup of which original indices survived.
    // Strategy: find non-filtered items from ml_result and reconstruct.
    // Simpler: iterate ml_result findings (already filtered array of assoc arrays)
    // and wrap them in a stdClass compatible with the template below.
    foreach ($ml_result['findings'] as $mf) {
        $obj = new stdClass();
        $obj->severity    = $mf['severity']    ?? 'Info';
        $obj->category    = $mf['category']    ?? 'General';
        $obj->description = $mf['description'] ?? '';
        $obj->evidence    = $mf['evidence']    ?? '';
        $obj->title       = $mf['title']       ?? ($mf['category'] ?? '');
        $obj->remediation = $mf['remediation'] ?? '';
        $obj->cwe_id      = $mf['cwe_id']      ?? null;
        // Preserve ML metadata for badge display
        $obj->ml_is_fp_reduced       = !empty($mf['ml_processed']);
        $obj->ml_severity_adjusted   = !empty($mf['severity_adjusted']);
        $obj->ml_original_severity   = $mf['original_severity'] ?? null;
        $filtered_findings[] = $obj;
    }
} else {
    // Fallback: proxy unavailable, show raw findings
    $filtered_findings = $findings_raw;
}

$findings = $filtered_findings;   // use filtered set from here on

echo $OUTPUT->header();

// === ML STATS BANNER ===
if ($ml_enabled && !empty($ml_stats)) {
    $orig    = intval($ml_stats['original_count']   ?? count($findings_raw));
    $removed = intval($ml_stats['fp_filtered']      ?? 0);
    $adj     = intval($ml_stats['severity_adjusted'] ?? 0);
    $final   = intval($ml_stats['final_count']      ?? count($findings));

    $banner_class = $removed > 0 ? 'alert-info' : 'alert-success';
    echo html_writer::start_div("alert $banner_class mt-2");
    echo html_writer::tag('strong', '🤖 ML Processing Complete &nbsp;');
    echo html_writer::tag('span',
        "Raw findings: <strong>{$orig}</strong> &nbsp;|&nbsp; "
        . "FPs removed: <strong>{$removed}</strong> &nbsp;|&nbsp; "
        . "Severities adjusted: <strong>{$adj}</strong> &nbsp;|&nbsp; "
        . "Final: <strong>{$final}</strong>",
        ['style' => 'font-size:0.95em;']
    );
    echo html_writer::end_div();
}

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
            <h3 class="stat-number" style="color: #dc3545;">{$scan->high_count}</h3>
            <p class="stat-label">High Risk</p>
        </div>
    </div>
    <div class="col-md-3">
        <div class="stat-box">
            <h3 class="stat-number" style="color: #ffc107;">{$scan->medium_count}</h3>
            <p class="stat-label">Medium Risk</p>
        </div>
    </div>
    <div class="col-md-3">
        <div class="stat-box">
            <h3 class="stat-number" style="color: #28a745;">{$scan->low_count}</h3>
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
        <p><strong>Scan Duration:</strong> {$scan->scan_duration} seconds</p>
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
        // Risk color based on severity
        $risk_color = 'danger';
        if ($finding->severity === 'Medium') $risk_color = 'warning';
        if ($finding->severity === 'Low') $risk_color = 'info';
        
        $table->data[] = [
            $i++,
            $finding->title ?? $finding->category,
            "<span class='badge badge-{$risk_color}'>{$finding->severity}</span>",
            str_truncate($scan->target_url, 50),
            str_truncate($finding->evidence, 30),
            str_truncate($finding->remediation, 40)
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
        $risk_color = match($finding->severity) {
            'High' => '#dc3545',
            'Medium' => '#ffc107',
            'Low' => '#17a2b8',
            default => '#6c757d'
        };
        
        echo html_writer::start_div('finding-detail mb-3', ['style' => "border-left: 4px solid $risk_color; padding-left: 10px;"]);
        echo html_writer::tag('h6', ($finding->title ?? $finding->category) . " [{$finding->severity}]");
        echo "<p><strong>URL:</strong> {$scan->target_url}</p>";
        echo "<p><strong>Category:</strong> {$finding->category}</p>";
        echo "<p><strong>Evidence:</strong></p>";
        echo "<pre class='bg-light p-2'>" . htmlspecialchars($finding->evidence) . "</pre>";
        echo "<p><strong>Description:</strong></p>";
        echo "<p>{$finding->description}</p>";
        echo "<p><strong>Remediation:</strong></p>";
        echo "<p>{$finding->remediation}</p>";
        if (!empty($finding->cwe_id)) {
            echo "<p><small>CWE: <a href='https://cwe.mitre.org/data/definitions/{$finding->cwe_id}.html' target='_blank'>CWE-{$finding->cwe_id}</a></small></p>";
        }
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
