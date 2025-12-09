<?php
/**
 * Trigger security scan page
 *
 * @package    local_security_dashboard
 * @copyright  2024 Krisopras & Nathanael
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php');
require_once($CFG->libdir . '/adminlib.php');
require_once(__DIR__ . '/lib.php');

require_login();
require_capability('local/security_dashboard:scan', context_system::instance());

$PAGE->set_url(new moodle_url('/local/security_dashboard/scan.php'));
$PAGE->set_context(context_system::instance());
$PAGE->set_title(get_string('trigger_scan', 'local_security_dashboard'));
$PAGE->set_heading(get_string('trigger_scan', 'local_security_dashboard'));
$PAGE->set_pagelayout('admin');

// Add custom CSS for severity badges
$PAGE->requires->css('/local/security_dashboard/styles.css');

// Handle form submission
$scan_triggered = false;
$scan_result = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && confirm_sesskey()) {
    // Enhanced input validation
    $path = required_param('path', PARAM_PATH);
    $method = required_param('method', PARAM_ALPHA);
    
    // Validate method
    $allowed_methods = ['GET', 'POST'];
    if (!in_array($method, $allowed_methods)) {
        $method = 'GET';
    }
    
    // Strict path validation - prevent path traversal
    $validation_errors = [];
    
    // Check 1: Must start with /
    if (!preg_match('#^/#', $path)) {
        $validation_errors[] = 'Path must start with /';
    }
    
    // Check 2: No path traversal patterns
    if (preg_match('#\.\.|//|\\\\#', $path)) {
        $validation_errors[] = 'Path contains invalid patterns (.. or // or \\)';
    }
    
    // Check 3: Only allowed characters
    if (!preg_match('#^/[a-zA-Z0-9/_\-\.]+$#', $path)) {
        $validation_errors[] = 'Path contains invalid characters';
    }
    
    // Check 4: Path length limit
    if (strlen($path) > 255) {
        $validation_errors[] = 'Path is too long (max 255 characters)';
    }
    
    if (!empty($validation_errors)) {
        foreach ($validation_errors as $error) {
            echo $OUTPUT->notification($error, 'error');
        }
    } else {
        $scan_result = local_security_dashboard_trigger_scan($path, $method);
        $scan_triggered = true;
    }
}

echo $OUTPUT->header();

// Display scan form
echo html_writer::start_tag('form', ['method' => 'post', 'action' => '', 'class' => 'mform']);
echo html_writer::empty_tag('input', ['type' => 'hidden', 'name' => 'sesskey', 'value' => sesskey()]);

echo html_writer::start_div('form-group');
echo html_writer::tag('label', get_string('scan_path', 'local_security_dashboard'), ['for' => 'path']);
echo html_writer::empty_tag('input', [
    'type' => 'text',
    'name' => 'path',
    'id' => 'path',
    'class' => 'form-control',
    'placeholder' => '/login/index.php',
    'required' => 'required'
]);
echo html_writer::end_div();

echo html_writer::start_div('form-group');
echo html_writer::tag('label', get_string('scan_method', 'local_security_dashboard'), ['for' => 'method']);
echo html_writer::start_tag('select', ['name' => 'method', 'id' => 'method', 'class' => 'form-control']);
echo html_writer::tag('option', 'GET', ['value' => 'GET']);
echo html_writer::tag('option', 'POST', ['value' => 'POST']);
echo html_writer::end_tag('select');
echo html_writer::end_div();

echo html_writer::start_div('form-group');
echo html_writer::empty_tag('input', [
    'type' => 'submit',
    'value' => get_string('trigger_scan', 'local_security_dashboard'),
    'class' => 'btn btn-primary'
]);
echo html_writer::end_div();

echo html_writer::end_tag('form');

// Display scan results
if ($scan_triggered) {
    if (isset($scan_result['error'])) {
        echo html_writer::div($scan_result['error'], 'alert alert-danger');
    } else {
        echo html_writer::div(get_string('scan_success', 'local_security_dashboard'), 'alert alert-success');
        
        // Display scan details
        echo html_writer::tag('h3', 'Scan Results');
        
        echo html_writer::start_div('card');
        echo html_writer::start_div('card-body');
        
        // XSS Prevention: Sanitize all output
        $scan_id = s($scan_result['scan_id'] ?? 'N/A');
        $target_url = s($scan_result['target_url'] ?? 'N/A');
        $timestamp = s($scan_result['timestamp'] ?? 'N/A');
        
        echo html_writer::tag('p', '<strong>Scan ID:</strong> ' . $scan_id);
        echo html_writer::tag('p', '<strong>Target URL:</strong> ' . $target_url);
        echo html_writer::tag('p', '<strong>Timestamp:</strong> ' . $timestamp);
        
        // Download Report Button
        if ($scan_id !== 'N/A') {
            $proxy_url = get_config('local_security_dashboard', 'proxy_url');
            $report_url = rtrim($proxy_url, '/') . '/reports/executive-summary?scan_id=' . urlencode($scan_id);
            echo html_writer::div(
                html_writer::link(
                    $report_url,
                    '📄 Download PDF Report',
                    ['class' => 'btn btn-success', 'target' => '_blank']
                ),
                'mt-2 mb-3'
            );
        }
        
        // Summary
        if (isset($scan_result['summary'])) {
            echo html_writer::tag('h4', get_string('vulnerability_summary', 'local_security_dashboard'));
            $summary = $scan_result['summary'];
            echo html_writer::start_tag('ul');
            echo html_writer::tag('li', '🔴 Critical: ' . ($summary['critical'] ?? 0));
            echo html_writer::tag('li', '🟠 High: ' . ($summary['high'] ?? 0));
            echo html_writer::tag('li', '🟡 Medium: ' . ($summary['medium'] ?? 0));
            echo html_writer::tag('li', '🔵 Low: ' . ($summary['low'] ?? 0));
            echo html_writer::tag('li', '⚪ Info: ' . ($summary['info'] ?? 0));
            echo html_writer::end_tag('ul');
        }
        
        // Findings
        if (isset($scan_result['findings']) && !empty($scan_result['findings'])) {
            echo html_writer::tag('h4', 'Findings');
            
            $table = new html_table();
            $table->head = ['Severity', 'Category', 'Description', 'Evidence'];
            $table->attributes['class'] = 'generaltable';
            
            foreach ($scan_result['findings'] as $finding) {
                $row = [];
                
                // XSS Prevention: Sanitize all finding data
                $severity = s($finding['severity'] ?? 'N/A');
                $category = s($finding['category'] ?? 'N/A');
                $description = s($finding['description'] ?? 'N/A');
                $evidence = s($finding['evidence'] ?? 'N/A');
                
                $severity_lower = strtolower($severity);
                
                // Map severity to Bootstrap badge classes
                $badge_map = [
                    'critical' => 'danger',
                    'high' => 'warning',
                    'medium' => 'info',
                    'low' => 'secondary',
                    'info' => 'light'
                ];
                
                $badge_class = $badge_map[$severity_lower] ?? 'secondary';
                $row[] = html_writer::span(ucfirst($severity), 'badge badge-' . $badge_class . ' severity-badge');
                
                $row[] = $category;
                $row[] = $description;
                $row[] = $evidence;
                
                $table->data[] = $row;
            }
            
            echo html_writer::table($table);
        }
        
        echo html_writer::end_div();
        echo html_writer::end_div();
    }
}

// Back button
echo html_writer::div(
    html_writer::link(
        new moodle_url('/local/security_dashboard/index.php'),
        '← Back to Dashboard',
        ['class' => 'btn btn-secondary mt-3']
    ),
    'mt-3'
);

echo $OUTPUT->footer();
