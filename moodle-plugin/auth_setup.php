<?php
/**
 * Test and Configure ZAP Authentication
 * 
 * @package    local_security_dashboard
 * @copyright  2026 Krisopras & Nathanael
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php');
require_once($CFG->libdir . '/adminlib.php');

require_login();
require_capability('local/security_dashboard:view', context_system::instance());

require_once($CFG->dirroot . '/local/security_dashboard/lib.php');
require_once($CFG->dirroot . '/local/security_dashboard/lib/zap_integration.php');

$action = optional_param('action', 'info', PARAM_ALPHA);
$test_user = optional_param('test_user', '', PARAM_TEXT);
$test_pass = optional_param('test_pass', '', PARAM_TEXT);

$PAGE->set_url(new moodle_url('/local/security_dashboard/auth_setup.php'));
$PAGE->set_context(context_system::instance());
$PAGE->set_title('ZAP Authentication Setup');
$PAGE->set_heading('ZAP Authentication Setup');
$PAGE->set_pagelayout('admin');

echo $OUTPUT->header();

$auth_method = get_config('local_security_dashboard', 'auth_method') ?? 'manual';
$current_user = get_config('local_security_dashboard', 'scan_test_user') ?? '';

echo html_writer::start_div('card');
echo html_writer::start_div('card-header');
echo html_writer::tag('h3', 'Authentication Configuration');
echo html_writer::end_div();

echo html_writer::start_div('card-body');
echo html_writer::tag('h5', 'Current Settings');
echo '<p><strong>Authentication Method:</strong> <code>' . s($auth_method) . '</code></p>';
echo '<p><strong>Test User:</strong> <code>' . s($current_user) . '</code></p>';

if ($auth_method === 'manual' && !empty($current_user)) {
    $pass_set = !empty(get_config('local_security_dashboard', 'scan_test_password'));
    $status = $pass_set ? '<span class="badge badge-success">✓ Set</span>' : '<span class="badge badge-warning">✗ Not set</span>';
    echo '<p><strong>Password:</strong> ' . $status . '</p>';
}

echo html_writer::end_div();
echo html_writer::end_div();

// Authentication Methods Explanation
echo html_writer::start_div('card mt-3');
echo html_writer::start_div('card-header');
echo html_writer::tag('h5', 'Authentication Methods');
echo html_writer::end_div();

echo html_writer::start_div('card-body');

echo html_writer::tag('h6', '1. Manual Credentials (Recommended for Setup)');
echo '<ul class="list-unstyled">';
echo '<li>✓ Admin manually enters credentials in plugin settings</li>';
echo '<li>✓ Works reliably across Moodle versions</li>';
echo '<li>✓ Credentials encrypted in database</li>';
echo '<li>✗ Requires manual configuration per Moodle instance</li>';
echo '<li class="mt-2"><strong>Setup:</strong> Go to Settings → ZAP Authentication → Select "Manual Credentials"</li>';
echo '</ul>';

echo html_writer::tag('h6', '2. Auto-Detect Admin (Semi-Automated)', array('class' => 'mt-4'));
echo '<ul class="list-unstyled">';
echo '<li>+ Automatically finds admin user</li>';
echo '<li>✗ Still requires password in settings</li>';
echo '<li>✗ Not fully automated</li>';
echo '</ul>';

echo html_writer::tag('h6', '3. Session Token (Most Secure)', array('class' => 'mt-4'));
echo '<ul class="list-unstyled">';
echo '<li>+ Most secure - no plain password storage</li>';
echo '<li>+ Uses Moodle session mechanism</li>';
echo '<li>✗ More complex setup</li>';
echo '<li>✗ Requires browser automation</li>';
echo '</ul>';

echo html_writer::end_div();
echo html_writer::end_div();

// Test Credentials
if ($action === 'test') {
    echo html_writer::start_div('card mt-3');
    echo html_writer::start_div('card-header');
    echo html_writer::tag('h5', 'Authentication Test Results');
    echo html_writer::end_div();
    
    echo html_writer::start_div('card-body');
    
    if (empty($test_user) || empty($test_pass)) {
        echo $OUTPUT->notification('Please provide both username and password', 'error');
    } else {
        $result = local_security_dashboard_verify_zap_auth($test_user, $test_pass);
        
        if (isset($result['success']) && $result['success']) {
            echo $OUTPUT->notification('✓ ' . $result['message'], 'success');
            
            $zap_setup = local_security_dashboard_setup_zap_auth($test_user, $test_pass);
            if (isset($zap_setup['success']) && $zap_setup['success']) {
                echo $OUTPUT->notification('✓ ZAP Authentication configured: ' . $zap_setup['message'], 'success');
            } else {
                $error_msg = isset($zap_setup['error']) ? $zap_setup['error'] : 'Unknown error';
                echo $OUTPUT->notification('⚠ Login verified but ZAP setup failed: ' . $error_msg, 'warning');
            }
        } else {
            $message = isset($result['message']) ? $result['message'] : 'Authentication test failed';
            echo $OUTPUT->notification('✗ ' . $message, 'error');
        }
    }
    
    echo html_writer::end_div();
    echo html_writer::end_div();
}

// Test Form
echo html_writer::start_div('card mt-3');
echo html_writer::start_div('card-header');
echo html_writer::tag('h5', 'Test Credentials');
echo html_writer::end_div();

echo html_writer::start_div('card-body');
echo '<form method="post">';
echo '<input type="hidden" name="action" value="test">';

echo html_writer::start_div('form-group');
echo html_writer::label('test_user', 'Username:');
echo html_writer::empty_tag('input', array(
    'type' => 'text',
    'id' => 'test_user',
    'name' => 'test_user',
    'class' => 'form-control',
    'placeholder' => 'admin',
    'value' => s($test_user)
));
echo html_writer::end_div();

echo html_writer::start_div('form-group');
echo html_writer::label('test_pass', 'Password:');
echo html_writer::empty_tag('input', array(
    'type' => 'password',
    'id' => 'test_pass',
    'name' => 'test_pass',
    'class' => 'form-control',
    'placeholder' => 'Your password'
));
echo html_writer::end_div();

echo html_writer::tag('button', 'Test Authentication', array(
    'type' => 'submit',
    'class' => 'btn btn-primary'
));
echo '</form>';

echo html_writer::end_div();
echo html_writer::end_div();

// Settings Links
echo html_writer::start_div('mt-3');
echo html_writer::link('Configure Settings →', new moodle_url('/admin/settings.php', array('section' => 'local_security_dashboard_zap')), array('class' => 'btn btn-secondary'));
echo ' ';
echo html_writer::link('Back to Dashboard →', new moodle_url('/local/security_dashboard/'), array('class' => 'btn btn-secondary'));
echo html_writer::end_div();

echo $OUTPUT->footer();
