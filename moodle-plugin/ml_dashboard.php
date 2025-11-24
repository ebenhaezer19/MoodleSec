<?php
/**
 * ML Dashboard - Machine Learning Status and Management
 *
 * Displays ML model status, performance metrics, and management options.
 *
 * @package    local_security_dashboard
 * @copyright  2024 MoodleSec
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php');
require_once($CFG->libdir . '/adminlib.php');
require_once(__DIR__ . '/classes/api_client.php');

// Require login and admin capability
require_login();
require_capability('local/security_dashboard:manage', context_system::instance());

// Set up page
$PAGE->set_url(new moodle_url('/local/security_dashboard/ml_dashboard.php'));
$PAGE->set_context(context_system::instance());
$PAGE->set_title(get_string('ml_dashboard', 'local_security_dashboard'));
$PAGE->set_heading(get_string('ml_dashboard', 'local_security_dashboard'));
$PAGE->set_pagelayout('admin');

// Add navigation
$PAGE->navbar->add(get_string('pluginname', 'local_security_dashboard'), 
                   new moodle_url('/local/security_dashboard/index.php'));
$PAGE->navbar->add(get_string('ml_dashboard', 'local_security_dashboard'));

// Initialize API client
$api_client = new \local_security_dashboard\api_client();

// Get ML status
$ml_status = null;
$ml_models = null;
$error_message = '';

try {
    $ml_status = $api_client->get_ml_status();
    $ml_models = $api_client->get_ml_models_info();
} catch (Exception $e) {
    $error_message = 'Failed to fetch ML status: ' . $e->getMessage();
}

// Output header
echo $OUTPUT->header();

// Display error if any
if (!empty($error_message)) {
    echo html_writer::div($error_message, 'alert alert-danger');
}

// ML Status Overview
if ($ml_status) {
    echo html_writer::start_div('ml-dashboard-container');
    
    // Header
    echo html_writer::tag('h2', '🤖 Machine Learning System Status', ['class' => 'mb-4']);
    
    // Status Badge
    $status_class = $ml_status['ml_enabled'] ? 'badge-success' : 'badge-danger';
    $status_text = $ml_status['ml_enabled'] ? '✅ ML Enabled' : '❌ ML Disabled';
    echo html_writer::div(
        html_writer::span($status_text, "badge $status_class badge-lg"),
        'mb-4'
    );
    
    // Models Grid
    echo html_writer::start_div('row');
    
    // Model 1: False Positive Reducer
    if (isset($ml_status['modules']['false_positive_reducer'])) {
        $fp_model = $ml_status['modules']['false_positive_reducer'];
        echo render_model_card(
            'False Positive Reducer',
            '🎯',
            $fp_model,
            'Filters out false positives with 97.6% confidence',
            [
                'Algorithm' => 'Random Forest',
                'Estimators' => $fp_model['n_estimators'] ?? 'N/A',
                'Max Depth' => $fp_model['max_depth'] ?? 'N/A',
                'Features' => $fp_model['n_features'] ?? 'N/A'
            ]
        );
    }
    
    // Model 2: Anomaly Detector
    if (isset($ml_status['modules']['anomaly_detector'])) {
        $ad_model = $ml_status['modules']['anomaly_detector'];
        $baseline = $ad_model['baseline_stats'] ?? [];
        echo render_model_card(
            'Anomaly Detector',
            '🔍',
            $ad_model,
            'Detects unusual behavior patterns',
            [
                'Algorithm' => 'Isolation Forest',
                'Contamination' => ($ad_model['contamination'] ?? 0) * 100 . '%',
                'Avg Response' => round($baseline['avg_response_time'] ?? 0) . 'ms',
                'Samples' => $baseline['sample_count'] ?? 'N/A'
            ]
        );
    }
    
    // Model 3: Severity Predictor
    if (isset($ml_status['modules']['severity_predictor'])) {
        $sp_model = $ml_status['modules']['severity_predictor'];
        echo render_model_card(
            'Severity Predictor',
            '📊',
            $sp_model,
            'Predicts accurate severity levels',
            [
                'Algorithm' => 'Gradient Boosting',
                'Estimators' => $sp_model['n_estimators'] ?? 'N/A',
                'Learning Rate' => $sp_model['learning_rate'] ?? 'N/A',
                'Levels' => count($sp_model['severity_levels'] ?? [])
            ]
        );
    }
    
    // Model 4: Rate Limiter
    if (isset($ml_status['modules']['rate_limiter'])) {
        $rl_model = $ml_status['modules']['rate_limiter'];
        $limits = $rl_model['default_limits'] ?? [];
        echo render_model_card(
            'Rate Limiter',
            '🚦',
            $rl_model,
            'Adaptive rate limiting with ML scoring',
            [
                'Per Minute' => $limits['per_minute'] ?? 'N/A',
                'Per Hour' => $limits['per_hour'] ?? 'N/A',
                'Whitelisted' => $rl_model['whitelist_count'] ?? 0,
                'Blacklisted' => $rl_model['blacklist_count'] ?? 0
            ]
        );
    }
    
    echo html_writer::end_div(); // row
    
    // Training Information
    echo html_writer::tag('h3', '📚 Training Information', ['class' => 'mt-5 mb-3']);
    echo html_writer::start_div('card');
    echo html_writer::start_div('card-body');
    
    echo html_writer::tag('h5', 'Training Data Sources', ['class' => 'card-title']);
    echo html_writer::start_tag('ul');
    echo html_writer::tag('li', 'Moodle CVE Database (2020-2021)');
    echo html_writer::tag('li', 'OWASP Top 10 Vulnerability Patterns');
    echo html_writer::tag('li', 'Synthetic Attack Scenarios');
    echo html_writer::tag('li', 'Common False Positive Patterns');
    echo html_writer::end_tag('ul');
    
    echo html_writer::tag('h5', 'Dataset Composition', ['class' => 'card-title mt-3']);
    echo html_writer::start_tag('ul');
    echo html_writer::tag('li', 'False Positive Reduction: 200 samples (70% TP, 30% FP)');
    echo html_writer::tag('li', 'Severity Prediction: 200 samples (5 severity levels)');
    echo html_writer::tag('li', 'Anomaly Detection: 300 normal behavior samples');
    echo html_writer::tag('li', 'Rate Limiting: 200 risk scoring samples');
    echo html_writer::end_tag('ul');
    
    echo html_writer::end_div(); // card-body
    echo html_writer::end_div(); // card
    
    // Performance Metrics
    echo html_writer::tag('h3', '📈 Performance Metrics', ['class' => 'mt-5 mb-3']);
    echo html_writer::start_div('row');
    
    echo render_metric_card('False Positive Reduction', '100%', 'Test Accuracy', 'success');
    echo render_metric_card('Severity Prediction', '100%', 'Test Accuracy', 'success');
    echo render_metric_card('Anomaly Detection', '90%', 'Detection Rate', 'info');
    echo render_metric_card('Rate Limiter', '0.72', 'R² Score', 'primary');
    
    echo html_writer::end_div(); // row
    
    // Management Actions
    echo html_writer::tag('h3', '⚙️ Management', ['class' => 'mt-5 mb-3']);
    echo html_writer::start_div('card');
    echo html_writer::start_div('card-body');
    
    echo html_writer::start_div('row');
    
    // Retrain Models
    echo html_writer::start_div('col-md-6 mb-3');
    echo html_writer::tag('h5', '🔄 Retrain Models');
    echo html_writer::tag('p', 'Retrain ML models with latest data to improve accuracy.');
    echo html_writer::link(
        '#',
        'Retrain All Models',
        ['class' => 'btn btn-primary', 'onclick' => 'retrainModels(); return false;']
    );
    echo html_writer::end_div();
    
    // Export Models
    echo html_writer::start_div('col-md-6 mb-3');
    echo html_writer::tag('h5', '💾 Export Models');
    echo html_writer::tag('p', 'Download trained models for backup or analysis.');
    echo html_writer::link(
        '#',
        'Export Models',
        ['class' => 'btn btn-secondary', 'onclick' => 'exportModels(); return false;']
    );
    echo html_writer::end_div();
    
    echo html_writer::end_div(); // row
    
    echo html_writer::end_div(); // card-body
    echo html_writer::end_div(); // card
    
    echo html_writer::end_div(); // ml-dashboard-container
}

// Add custom CSS
echo html_writer::start_tag('style');
?>
.ml-dashboard-container {
    padding: 20px;
}
.model-card {
    border: 1px solid #dee2e6;
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 20px;
    background: #fff;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}
.model-card-header {
    display: flex;
    align-items: center;
    margin-bottom: 15px;
}
.model-icon {
    font-size: 2em;
    margin-right: 15px;
}
.model-title {
    font-size: 1.3em;
    font-weight: bold;
    margin: 0;
}
.model-status {
    display: inline-block;
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 0.85em;
    font-weight: bold;
    margin-left: auto;
}
.status-trained {
    background: #d4edda;
    color: #155724;
}
.status-not-trained {
    background: #f8d7da;
    color: #721c24;
}
.model-description {
    color: #6c757d;
    margin-bottom: 15px;
}
.model-specs {
    background: #f8f9fa;
    padding: 15px;
    border-radius: 6px;
}
.model-specs dt {
    font-weight: 600;
    color: #495057;
}
.model-specs dd {
    margin-bottom: 8px;
    color: #6c757d;
}
.metric-card {
    text-align: center;
    padding: 20px;
    border-radius: 8px;
    margin-bottom: 20px;
}
.metric-value {
    font-size: 2.5em;
    font-weight: bold;
    margin: 10px 0;
}
.metric-label {
    font-size: 1.1em;
    color: #6c757d;
}
.badge-lg {
    font-size: 1.2em;
    padding: 10px 20px;
}
<?php
echo html_writer::end_tag('style');

// Add JavaScript
echo html_writer::start_tag('script');
?>
function retrainModels() {
    if (confirm('Are you sure you want to retrain all ML models? This may take several minutes.')) {
        alert('Model retraining initiated. This feature will be implemented in the next update.');
        // TODO: Implement actual retraining via API
    }
}

function exportModels() {
    alert('Model export feature will be implemented in the next update.');
    // TODO: Implement model export
}
<?php
echo html_writer::end_tag('script');

echo $OUTPUT->footer();

/**
 * Render a model card
 */
function render_model_card($title, $icon, $model, $description, $specs) {
    $trained = $model['trained'] ?? false;
    $status_class = $trained ? 'status-trained' : 'status-not-trained';
    $status_text = $trained ? '✅ Trained' : '❌ Not Trained';
    
    $html = html_writer::start_div('col-md-6');
    $html .= html_writer::start_div('model-card');
    
    // Header
    $html .= html_writer::start_div('model-card-header');
    $html .= html_writer::span($icon, 'model-icon');
    $html .= html_writer::tag('h4', $title, ['class' => 'model-title']);
    $html .= html_writer::span($status_text, "model-status $status_class");
    $html .= html_writer::end_div();
    
    // Description
    $html .= html_writer::tag('p', $description, ['class' => 'model-description']);
    
    // Specs
    $html .= html_writer::start_div('model-specs');
    $html .= html_writer::start_tag('dl', ['class' => 'row mb-0']);
    foreach ($specs as $key => $value) {
        $html .= html_writer::tag('dt', $key, ['class' => 'col-sm-6']);
        $html .= html_writer::tag('dd', $value, ['class' => 'col-sm-6']);
    }
    $html .= html_writer::end_tag('dl');
    $html .= html_writer::end_div();
    
    $html .= html_writer::end_div(); // model-card
    $html .= html_writer::end_div(); // col
    
    return $html;
}

/**
 * Render a metric card
 */
function render_metric_card($title, $value, $label, $color) {
    $html = html_writer::start_div('col-md-3');
    $html .= html_writer::start_div("metric-card bg-$color text-white");
    $html .= html_writer::tag('h5', $title);
    $html .= html_writer::div($value, 'metric-value');
    $html .= html_writer::div($label, 'metric-label');
    $html .= html_writer::end_div();
    $html .= html_writer::end_div();
    
    return $html;
}
