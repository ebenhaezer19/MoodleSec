<?php
/**
 * Phase 2: Dynamic Payload Management & ZAP Integration UI
 *
 * @package    local_security_dashboard
 * @copyright  2024 MoodleSec
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php');
require_once($CFG->libdir . '/adminlib.php');
require_once(__DIR__ . '/lib.php');

admin_externalpage_setup('local_security_dashboard_payload_mgmt');

$PAGE->set_url(new moodle_url('/local/security_dashboard/payload_management.php'));
$PAGE->set_title(get_string('pluginname', 'local_security_dashboard') . ' - Payload Management');
$PAGE->set_heading('Phase 2: Dynamic Payload Management & ZAP Integration');

// Add CSS
$PAGE->requires->css('/local/security_dashboard/styles.css');

// Handle actions via AJAX
$action = optional_param('action', '', PARAM_ALPHA);
if (!empty($action) && confirm_sesskey()) {
    header('Content-Type: application/json');
    
    switch ($action) {
        case 'import_zap':
            $result = local_security_dashboard_import_from_zap();
            echo json_encode($result);
            exit;
            
        case 'reload_payloads':
            $category = optional_param('category', null, PARAM_ALPHA);
            $result = local_security_dashboard_reload_payloads($category);
            echo json_encode($result);
            exit;
            
        case 'reload_scanners':
            $result = local_security_dashboard_reload_scanners();
            echo json_encode($result);
            exit;
            
        case 'get_status':
            $result = local_security_dashboard_get_import_status();
            echo json_encode($result);
            exit;
    }
}

echo $OUTPUT->header();
?>

<style>
.phase2-container {
    max-width: 1200px;
    margin: 0 auto;
}

.phase2-header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 30px;
    border-radius: 8px;
    margin-bottom: 30px;
}

.phase2-header h1 {
    margin: 0 0 10px 0;
    font-size: 28px;
}

.phase2-header p {
    margin: 5px 0;
    opacity: 0.9;
}

.phase2-section {
    background: white;
    border-radius: 8px;
    padding: 24px;
    margin-bottom: 24px;
    border-left: 4px solid #667eea;
}

.phase2-section h3 {
    margin-top: 0;
    color: #1f2937;
    font-size: 20px;
}

.status-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px;
    margin: 20px 0;
}

.status-card {
    background: #f9fafb;
    padding: 16px;
    border-radius: 6px;
    border-left: 4px solid #667eea;
}

.status-card h4 {
    margin: 0 0 12px 0;
    color: #374151;
    font-size: 14px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.status-card .value {
    font-size: 28px;
    font-weight: bold;
    color: #667eea;
    margin-bottom: 8px;
}

.status-card .detail {
    font-size: 12px;
    color: #6b7280;
}

.workflow-steps {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 16px;
    margin: 20px 0;
}

.workflow-step {
    background: #f0f4ff;
    border: 2px solid #dbeafe;
    border-radius: 8px;
    padding: 20px;
    text-align: center;
    transition: all 0.3s;
}

.workflow-step:hover {
    border-color: #667eea;
    background: #f8faff;
}

.workflow-step .step-number {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 40px;
    height: 40px;
    background: #667eea;
    color: white;
    border-radius: 50%;
    font-weight: bold;
    margin-bottom: 12px;
}

.workflow-step .step-title {
    font-weight: 600;
    color: #1f2937;
    margin-bottom: 8px;
}

.workflow-step .step-desc {
    font-size: 12px;
    color: #6b7280;
    line-height: 1.5;
}

.action-buttons {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
    margin: 20px 0;
}

.btn-action {
    padding: 12px 24px;
    border: none;
    border-radius: 6px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
}

.btn-import {
    background: #10b981;
    color: white;
}

.btn-import:hover {
    background: #059669;
}

.btn-reload {
    background: #3b82f6;
    color: white;
}

.btn-reload:hover {
    background: #2563eb;
}

.btn-scanners {
    background: #f59e0b;
    color: white;
}

.btn-scanners:hover {
    background: #d97706;
}

.btn-refresh {
    background: #8b5cf6;
    color: white;
}

.btn-refresh:hover {
    background: #7c3aed;
}

.loading {
    display: none;
    text-align: center;
    padding: 16px;
    font-size: 14px;
    color: #6b7280;
}

.loading.active {
    display: block;
}

.loading-spinner {
    border: 3px solid #f0f0f0;
    border-top: 3px solid #667eea;
    border-radius: 50%;
    width: 20px;
    height: 20px;
    animation: spin 1s linear infinite;
    margin: 0 auto 10px;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

.status-message {
    padding: 16px;
    border-radius: 6px;
    margin: 16px 0;
    display: none;
}

.status-message.show {
    display: block;
}

.status-message.success {
    background: #dcfce7;
    border-left: 4px solid #10b981;
    color: #166534;
}

.status-message.error {
    background: #fee2e2;
    border-left: 4px solid #ef4444;
    color: #991b1b;
}

.status-message.info {
    background: #dbeafe;
    border-left: 4px solid #3b82f6;
    color: #1e40af;
}

.payload-categories {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    gap: 12px;
    margin: 16px 0;
}

.category-badge {
    background: #f0f4ff;
    border: 1px solid #dbeafe;
    padding: 12px;
    border-radius: 6px;
    text-align: center;
}

.category-badge .category-name {
    font-weight: 600;
    color: #1f2937;
    font-size: 14px;
}

.category-badge .category-count {
    font-size: 20px;
    font-weight: bold;
    color: #667eea;
    margin: 8px 0;
}

.category-badge .category-percent {
    font-size: 12px;
    color: #6b7280;
}
</style>

<div class="phase2-container">
    
    <div class="phase2-header">
        <h1>🚀 Phase 2: Dynamic Payload Management</h1>
        <p>Automated ZAP integration • Smart payload reuse • Real-time scanner updates</p>
    </div>

    <!-- Status Overview -->
    <div class="phase2-section">
        <h3>📊 Repository Status</h3>
        <div id="status-container" class="status-grid">
            <div class="status-card">
                <h4>Total Payloads</h4>
                <div class="value" id="total-payloads">--</div>
                <div class="detail">Unique payloads stored</div>
            </div>
            <div class="status-card">
                <h4>Vulnerable Payloads</h4>
                <div class="value" id="vulnerable-payloads">--</div>
                <div class="detail">High effectiveness</div>
            </div>
            <div class="status-card">
                <h4>Categories</h4>
                <div class="value" id="total-categories">--</div>
                <div class="detail">Vulnerability types</div>
            </div>
            <div class="status-card">
                <h4>Scanner Status</h4>
                <div class="value" id="scanner-status">--</div>
                <div class="detail">Active & ready</div>
            </div>
        </div>
        <div id="categories-display"></div>
    </div>

    <!-- Automated Workflow -->
    <div class="phase2-section">
        <h3>⚙️ Automated Workflow</h3>
        <p>Phase 2 automates the entire payload lifecycle. Just click "Start Import" and everything else happens automatically:</p>
        
        <div class="workflow-steps">
            <div class="workflow-step">
                <div class="step-number">1</div>
                <div class="step-title">Connect to ZAP</div>
                <div class="step-desc">Proxy connects to ZAP API at localhost:8080</div>
            </div>
            <div class="workflow-step">
                <div class="step-number">2</div>
                <div class="step-title">Extract Payloads</div>
                <div class="step-desc">Fetch real findings from ZAP alerts</div>
            </div>
            <div class="workflow-step">
                <div class="step-number">3</div>
                <div class="step-title">Normalize</div>
                <div class="step-desc">Standardize category names (XSS, SQL, CSRF)</div>
            </div>
            <div class="workflow-step">
                <div class="step-number">4</div>
                <div class="step-title">Store</div>
                <div class="step-desc">Save to payload repository database</div>
            </div>
            <div class="workflow-step">
                <div class="step-number">5</div>
                <div class="step-title">Update Scanners</div>
                <div class="step-desc">Reload all scanner instances live</div>
            </div>
            <div class="workflow-step">
                <div class="step-number">6</div>
                <div class="step-title">Ready</div>
                <div class="step-desc">New payloads active (no restart needed!)</div>
            </div>
        </div>
    </div>

    <!-- Action Buttons -->
    <div class="phase2-section">
        <h3>🎯 Quick Actions</h3>
        <div class="action-buttons">
            <button class="btn-action btn-import" onclick="importFromZAP()">
                <span>📥</span> Import from ZAP
            </button>
            <button class="btn-action btn-reload" onclick="reloadPayloads()">
                <span>🔄</span> Reload Payloads
            </button>
            <button class="btn-action btn-scanners" onclick="reloadScanners()">
                <span>⚡</span> Reload Scanners
            </button>
            <button class="btn-action btn-refresh" onclick="refreshStatus()">
                <span>🔍</span> Refresh Status
            </button>
        </div>

        <div id="status-message" class="status-message"></div>
        <div id="loading" class="loading">
            <div class="loading-spinner"></div>
            <div id="loading-text">Processing...</div>
        </div>
    </div>

    <!-- Detailed Information -->
    <div class="phase2-section">
        <h3>ℹ️ How It Works</h3>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div>
                <h4>🔄 Dynamic Reload (No Restart)</h4>
                <p>After importing payloads from ZAP, they're immediately active without restarting the proxy. Scanners automatically load new payloads.</p>
                <p style="font-size: 12px; color: #6b7280;"><strong>Why this matters:</strong> Faster TTW (Time-to-Web), scanning can start immediately.</p>
            </div>
            <div>
                <h4>🎯 Real Payloads Only</h4>
                <p>Every payload comes from actual ZAP findings - no synthetic test data. This means higher effectiveness and relevance for your Moodle instance.</p>
                <p style="font-size: 12px; color: #6b7280;"><strong>Why this matters:</strong> Payloads tested on your real app, better coverage.</p>
            </div>
            <div>
                <h4>📊 Smart Scoring</h4>
                <p>Each payload gets an effectiveness score based on success rate (60%) and severity (40%). Top payloads are prioritized in scans.</p>
                <p style="font-size: 12px; color: #6b7280;"><strong>Why this matters:</strong> Faster vulnerability discovery using proven payloads.</p>
            </div>
            <div>
                <h4>🚀 Automated Workflow</h4>
                <p>Just click "Import from ZAP", and the entire workflow executes automatically: fetch → normalize → store → reload scanners.</p>
                <p style="font-size: 12px; color: #6b7280;"><strong>Why this matters:</strong> Zero manual steps, fully integrated with UI.</p>
            </div>
        </div>
    </div>

</div>

<script type="text/javascript">
const BASE_URL = '<?php echo get_config('local_security_dashboard', 'proxy_url') ?: 'http://localhost:8999'; ?>';
const SESSKEY = '<?php echo sesskey(); ?>';

function showLoading(show, text = 'Processing...') {
    const loading = document.getElementById('loading');
    const loadingText = document.getElementById('loading-text');
    if (show) {
        loadingText.textContent = text;
        loading.classList.add('active');
    } else {
        loading.classList.remove('active');
    }
}

function showMessage(type, text) {
    const msg = document.getElementById('status-message');
    msg.className = 'status-message show ' + type;
    msg.textContent = text;
    setTimeout(() => msg.classList.remove('show'), 5000);
}

async function callProxyAPI(endpoint, method = 'POST') {
    try {
        const url = BASE_URL + endpoint;
        const response = await fetch(url, { method });
        return await response.json();
    } catch (error) {
        showMessage('error', '❌ Connection error: ' + error.message);
        return null;
    }
}

async function importFromZAP() {
    showLoading(true, '🔗 Connecting to ZAP...');
    
    const result = await callProxyAPI('/api/payloads/import-from-zap', 'POST');
    showLoading(false);
    
    if (!result) return;
    
    const importRes = result.import_result;
    if (importRes.status === 'success') {
        showMessage('success', `✅ Imported ${importRes.payloads_imported} payloads from ${importRes.alerts_fetched} ZAP alerts!`);
        setTimeout(refreshStatus, 1000);
    } else {
        showMessage('error', '❌ Import failed: ' + importRes.message);
    }
}

async function reloadPayloads() {
    showLoading(true, '🔄 Reloading payloads...');
    
    const result = await callProxyAPI('/api/payloads/reload', 'POST');
    showLoading(false);
    
    if (result && result.status === 'success') {
        showMessage('success', '✅ Payloads reloaded successfully!');
        setTimeout(refreshStatus, 500);
    } else {
        showMessage('error', '❌ Reload failed');
    }
}

async function reloadScanners() {
    showLoading(true, '⚡ Reloading scanners...');
    
    const result = await callProxyAPI('/api/scanners/reload-payloads', 'POST');
    showLoading(false);
    
    if (result && result.status === 'success') {
        showMessage('success', '✅ Scanners reloaded with new payloads!');
    } else {
        showMessage('error', '❌ Scanner reload failed');
    }
}

async function refreshStatus() {
    showLoading(true, '🔍 Fetching status...');
    
    const result = await callProxyAPI('/api/payloads/import-status', 'GET');
    showLoading(false);
    
    if (!result) return;
    
    const repo = result.repository;
    document.getElementById('total-payloads').textContent = repo.total_payloads || '0';
    document.getElementById('vulnerable-payloads').textContent = repo.vulnerable_payloads || '0';
    document.getElementById('total-categories').textContent = Object.keys(repo.by_category || {}).length;
    document.getElementById('scanner-status').textContent = result.scanner_status === 'active' ? '✅ Active' : '⚠️ Inactive';
    
    // Update categories
    const categoriesDiv = document.getElementById('categories-display');
    const categories = repo.by_category || {};
    let html = '<h4 style="margin-top: 16px;">Payloads by Category:</h4><div class="payload-categories">';
    
    for (const [cat, info] of Object.entries(categories)) {
        const percent = repo.total_payloads > 0 ? Math.round(info.count / repo.total_payloads * 100) : 0;
        html += `
            <div class="category-badge">
                <div class="category-name">${cat}</div>
                <div class="category-count">${info.count}</div>
                <div class="category-percent">${percent}% of total</div>
            </div>
        `;
    }
    html += '</div>';
    categoriesDiv.innerHTML = html;
    
    showMessage('info', '✓ Status updated');
}

// Load status on page load
window.addEventListener('load', () => {
    setTimeout(refreshStatus, 500);
});
</script>

<?php
echo $OUTPUT->footer();
?>
