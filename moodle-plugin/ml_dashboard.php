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
// Check if user has manage capability, otherwise check for view capability
$context = context_system::instance();
if (!has_capability('local/security_dashboard:view', $context)) {
    require_capability('local/security_dashboard:view', $context);
}

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
            'Filters false positives — 92.9% ±6.9% CV (RF+GB Ensemble, Phase 5 Clean-14, no shortcuts)',
            [
                'Algorithm' => 'RF + GB Ensemble + CalibratedClassifierCV',
                'Features' => '14 (occurrence_count & days_since_first_seen removed)',
                'CV Accuracy' => '92.9% ± 6.9% (5-fold)',
                'Test Accuracy' => '86.4% (22-sample holdout)'
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
    

    
    echo html_writer::end_div(); // row
    
    // Training Information
    echo html_writer::tag('h3', '📚 Training Information', ['class' => 'mt-5 mb-3']);
    echo html_writer::start_div('card');
    echo html_writer::start_div('card-body');
    
    echo html_writer::tag('h5', 'Training Data Sources', ['class' => 'card-title']);
    echo html_writer::start_tag('ul');
    echo html_writer::tag('li', 'Phase 0: 186 synthetic samples (data leakage removed, realistic overlapping distributions)');
    echo html_writer::tag('li', 'Phase 2: 46 real HAR samples from OWASP ZAP (imbalanced: 82.6% TP / 17.4% FP)');
    echo html_writer::tag('li', 'Phase 3: 76 real balanced samples from HAR files (38 TP SQLi + 38 Normal traffic)');
    echo html_writer::tag('li', '40 synthetic augmented TP samples (SQLi, XSS, CSRF, Auth Bypass, Path Traversal)');
    echo html_writer::end_tag('ul');
    
    echo html_writer::tag('h5', 'Dataset Composition (Phase 3 Final)', ['class' => 'card-title mt-3']);
    echo html_writer::start_tag('ul');
    echo html_writer::tag('li', 'FP Reducer: 76 real balanced (38:38) + 40 synthetic TP augmentation');
    echo html_writer::tag('li', 'Anomaly Detector: 306 normal behaviour samples (Isolation Forest, unsupervised)');
    echo html_writer::end_tag('ul');
    
    echo html_writer::end_div(); // card-body
    echo html_writer::end_div(); // card
    
    // Performance Metrics
    echo html_writer::tag('h3', '📈 Performance Metrics', ['class' => 'mt-5 mb-3']);
    echo html_writer::start_div('row');
    
    echo render_metric_card('FP Reducer (Phase 5)', '92.9%', 'CV Acc ±6.9% (14 clean features)', 'success');
    echo render_metric_card('Anomaly Detection', '~90%', 'Detection Rate', 'info');
    
    echo html_writer::end_div(); // row

    echo html_writer::end_div(); // card

    // ── GPT API Key Settings ──────────────────────────────────────────────
    echo html_writer::start_div('card mt-4', ['id' => 'gpt-settings-card']);
    echo html_writer::start_div('card-header bg-dark text-white d-flex justify-content-between align-items-center');
    echo html_writer::tag('h5', '🤖 GPT Recommendation Settings', ['class' => 'mb-0']);
    echo html_writer::tag('span', '', ['id' => 'gpt-status-badge', 'class' => 'badge badge-secondary']);
    echo html_writer::end_div();
    echo html_writer::start_div('card-body');

    echo html_writer::tag('p',
        'Set your OpenAI API key to enable GPT-powered recommendations. ' .
        'When set, scan findings will receive AI-generated remediation advice instead of static templates. ' .
        'If quota is exceeded or key is invalid, the system automatically falls back to static templates.');

    // Status row
    echo '<div class="alert alert-info" id="gpt-current-status">Loading GPT status...</div>';

    // API key input form
    echo '<div class="form-group">';
    echo '<label for="gpt-api-key-input"><strong>OpenAI API Key</strong> <small class="text-muted">(starts with sk-)</small></label>';
    echo '<div class="input-group">';
    echo '<input type="password" class="form-control" id="gpt-api-key-input"
           placeholder="sk-proj-..." autocomplete="off"
           style="font-family: monospace; font-size: 13px;">';
    echo '<div class="input-group-append">';
    echo '<button class="btn btn-outline-secondary" type="button" onclick="toggleGptKeyVisibility()">👁</button>';
    echo '</div>';
    echo '</div>';
    echo '<small class="form-text text-muted">Key is stored encrypted server-side and never sent to browser after save.</small>';
    echo '</div>';

    echo '<button class="btn btn-success" id="gpt-save-btn" onclick="saveGptApiKey()">💾 Save & Activate GPT</button>';
    echo ' <button class="btn btn-outline-secondary ml-2" onclick="checkGptStatus()">🔄 Refresh Status</button>';

    echo '<div id="gpt-save-result" class="mt-3" style="display:none;"></div>';

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
// Store proxy URL from Moodle config
const proxyUrl = '<?php echo get_config('local_security_dashboard', 'proxy_url'); ?>' || 'http://localhost:8999';

function retrainModels() {
    if (confirm('Are you sure you want to retrain all ML models with recent scan data? This may take several minutes.')) {
        showRetrainingModal();
        startRetraining();
    }
}

function showRetrainingModal() {
    // Create modal HTML
    const modalHtml = `
        <div id="retrainingModal" class="modal fade show" style="display: block; background: rgba(0,0,0,0.5);">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">🔄 ML Models Retraining</h5>
                    </div>
                    <div class="modal-body">
                        <div class="retraining-info mb-3">
                            <p id="retrainingStatus">Initializing retraining process...</p>
                            <div class="progress" style="height: 25px;">
                                <div id="retrainingProgressBar" class="progress-bar progress-bar-striped progress-bar-animated" role="progressbar" style="width: 0%" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">0%</div>
                            </div>
                        </div>
                        <div id="retrainingDetails" style="background: #f8f9fa; padding: 10px; border-radius: 5px; max-height: 300px; overflow-y: auto;">
                            <small id="retrainingLog">Waiting to start...</small>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" id="closeRetrainingBtn" disabled>Close</button>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Remove existing modal if any
    const existing = document.getElementById('retrainingModal');
    if (existing) existing.remove();
    
    // Add modal to page
    document.body.insertAdjacentHTML('beforeend', modalHtml);
}

async function startRetraining() {
    try {
        const logElement = document.getElementById('retrainingLog');
        const statusElement = document.getElementById('retrainingStatus');
        const progressBar = document.getElementById('retrainingProgressBar');
        const closeBtn = document.getElementById('closeRetrainingBtn');
        
        // Add log entry function
        const addLog = (message) => {
            const timestamp = new Date().toLocaleTimeString();
            logElement.innerHTML += `<div>[${timestamp}] ${message}</div>`;
            logElement.parentElement.scrollTop = logElement.parentElement.scrollHeight;
        };
        
        addLog('🟢 Starting retraining process...');
        
        // Step 1: Trigger retraining
        addLog('📊 Requesting retraining from server...');
        const retrainResponse = await fetch(`${proxyUrl}/ml/retrain`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'}
        });
        
        if (!retrainResponse.ok) {
            throw new Error(`Retraining request failed: ${retrainResponse.statusText}`);
        }
        
        const retrainData = await retrainResponse.json();
        addLog('✅ Retraining initiated');
        addLog(`Status: ${retrainData.message}`);
        
        // Step 2: Monitor progress
        let isComplete = false;
        let checkCount = 0;
        const maxChecks = 120; // Max 2 minutes (60 checks * 2 seconds)
        
        statusElement.textContent = 'Monitoring retraining progress...';
        
        while (!isComplete && checkCount < maxChecks) {
            checkCount++;
            await new Promise(resolve => setTimeout(resolve, 2000)); // Wait 2 seconds
            
            try {
                const statusResponse = await fetch(`${proxyUrl}/ml/retrain/status`);
                const statusData = await statusResponse.json();
                
                // Update UI with status
                const progress = statusData.progress || 0;
                progressBar.style.width = progress + '%';
                progressBar.textContent = progress + '%';
                progressBar.setAttribute('aria-valuenow', progress);
                
                statusElement.textContent = statusData.message || 'Processing...';
                
                // Add current model info
                if (statusData.current_model) {
                    const modelName = statusData.current_model.replace(/_/g, ' ').toUpperCase();
                    addLog(`⚙️ Retraining ${modelName}...`);
                }
                
                // Check if complete
                if (statusData.status === 'completed') {
                    isComplete = true;
                    addLog('✅ Retraining completed successfully!');
                    
                    // Show results
                    if (statusData.models_results) {
                        for (const [model, result] of Object.entries(statusData.models_results)) {
                            const modelName = model.replace(/_/g, ' ').toUpperCase();
                            if (result.success) {
                                addLog(`✅ ${modelName}: ${result.message}`);
                                if (result.samples_used) {
                                    addLog(`   └─ Samples used: ${result.samples_used}`);
                                }
                            } else {
                                addLog(`❌ ${modelName}: ${result.message}`);
                            }
                        }
                    }
                    
                    // Update dashboard
                    addLog('🔄 Refreshing dashboard...');
                    setTimeout(() => location.reload(), 2000);
                    
                } else if (statusData.status === 'failed') {
                    isComplete = true;
                    addLog(`❌ Retraining failed: ${statusData.message}`);
                }
            } catch (e) {
                addLog(`⚠️ Status check error: ${e.message}`);
            }
        }
        
        if (!isComplete) {
            addLog('⚠️ Retraining timeout - still processing');
        }
        
        // Enable close button
        closeBtn.disabled = false;
        closeBtn.onclick = () => {
            document.getElementById('retrainingModal').remove();
        };
        
    } catch (error) {
        const logElement = document.getElementById('retrainingLog');
        const errorMsg = `❌ Error: ${error.message}`;
        logElement.innerHTML += `<div style="color: red;">${errorMsg}</div>`;
        
        // Enable close button
        const closeBtn = document.getElementById('closeRetrainingBtn');
        closeBtn.disabled = false;
        closeBtn.onclick = () => {
            document.getElementById('retrainingModal').remove();
        };
    }
}

function exportModels() {
    alert('Model export feature will be implemented in the next update.');
}

// ── GPT API Key Management ─────────────────────────────────────────────────

const proxyApiUrl = '<?php echo (new moodle_url("/local/security_dashboard/proxy_api.php"))->out(false); ?>';
const sesskey     = '<?php echo sesskey(); ?>';

function toggleGptKeyVisibility() {
    const inp = document.getElementById('gpt-api-key-input');
    inp.type = (inp.type === 'password') ? 'text' : 'password';
}

async function checkGptStatus() {
    const statusDiv   = document.getElementById('gpt-current-status');
    const badgeSpan   = document.getElementById('gpt-status-badge');
    statusDiv.textContent = 'Checking GPT status...';
    try {
        const resp = await fetch(`${proxyApiUrl}?action=gpt-status&sesskey=${sesskey}`);
        const data = await resp.json();

        if (data.gpt_active) {
            badgeSpan.className = 'badge badge-success';
            badgeSpan.textContent = '🤖 GPT Active';
            statusDiv.className = 'alert alert-success';
            statusDiv.innerHTML = `<strong>✅ GPT Mode Active</strong><br>
                Key: <code>${data.gpt_key_preview || '(set)'}</code><br>
                Scan findings will use GPT-powered recommendations.`;
        } else if (data.gpt_key_set) {
            badgeSpan.className = 'badge badge-warning';
            badgeSpan.textContent = '⚠️ Key Set (GPT Off)';
            statusDiv.className = 'alert alert-warning';
            statusDiv.innerHTML = `<strong>⚠️ API Key is set but GPT engine reports inactive.</strong><br>
                Key: <code>${data.gpt_key_preview}</code><br>
                May be quota issue — static templates are being used as fallback.`;
        } else {
            badgeSpan.className = 'badge badge-secondary';
            badgeSpan.textContent = '📋 Static Templates';
            statusDiv.className = 'alert alert-info';
            statusDiv.innerHTML = `<strong>📋 Static Template Mode</strong><br>
                No OpenAI API key set. Enter your key below to activate GPT recommendations.<br>
                <small class="text-muted">Get a key at <a href="https://platform.openai.com/api-keys" target="_blank">platform.openai.com/api-keys</a></small>`;
        }
    } catch(e) {
        statusDiv.className = 'alert alert-danger';
        statusDiv.textContent = 'Could not reach proxy: ' + e.message;
    }
}

async function saveGptApiKey() {
    const key     = document.getElementById('gpt-api-key-input').value.trim();
    const btn     = document.getElementById('gpt-save-btn');
    const result  = document.getElementById('gpt-save-result');

    if (!key || !key.startsWith('sk-')) {
        result.style.display = 'block';
        result.className = 'alert alert-danger';
        result.textContent = 'Invalid key format. Must start with sk-';
        return;
    }

    btn.disabled = true;
    btn.textContent = '⏳ Saving...';
    result.style.display = 'none';

    try {
        const resp = await fetch(
            `${proxyApiUrl}?action=save-openai-key&sesskey=${sesskey}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: `api_key=${encodeURIComponent(key)}`
            }
        );
        const data = await resp.json();

        result.style.display = 'block';
        if (data.success) {
            result.className = 'alert alert-success';
            result.innerHTML = `<strong>✅ ${data.message}</strong><br>
                <small>Proxy ACK: ${data.proxy_ack || 'ok'}</small>`;
            document.getElementById('gpt-api-key-input').value = '';
            document.getElementById('gpt-api-key-input').placeholder = '(key saved — enter new key to update)';
            checkGptStatus(); // refresh status
        } else {
            result.className = 'alert alert-danger';
            result.textContent = 'Error: ' + (data.error || 'Unknown error');
        }
    } catch(e) {
        result.style.display = 'block';
        result.className = 'alert alert-danger';
        result.textContent = 'Connection error: ' + e.message;
    }

    btn.disabled = false;
    btn.textContent = '💾 Save & Activate GPT';
}

// Load GPT status on page load
document.addEventListener('DOMContentLoaded', checkGptStatus);

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

