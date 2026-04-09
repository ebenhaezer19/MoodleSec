<?php
/**
 * Advanced Payload Management UI
 * 
 * Features:
 * - View/Edit/Delete payloads from database
 * - Import from ZAP history
 * - Custom payload creation
 * - Bulk operations (reset, delete)
 * - Auto-reuse configuration
 * 
 * @package    local_security_dashboard
 * @copyright  2025 Krisopras & Nathanael
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php');
require_once($CFG->libdir . '/adminlib.php');
require_once($CFG->libdir . '/tablelib.php');

require_login();
require_capability('local/security_dashboard:manage', context_system::instance());

$PAGE->set_url(new moodle_url('/local/security_dashboard/payload_manager_ui.php'));
$PAGE->set_context(context_system::instance());
$PAGE->set_title('Payload Management');
$PAGE->set_heading('Payload Management');
$PAGE->set_pagelayout('admin');

// Add CSS and JS
$PAGE->requires->css(new moodle_url('/local/security_dashboard/styles.css'));
$PAGE->requires->js(new moodle_url('/local/security_dashboard/js/payload_manager.js'));

echo $OUTPUT->header();

// Get action from URL
$action = optional_param('action', 'list', PARAM_ALPHA);
$id = optional_param('id', 0, PARAM_INT);

// Get proxy URL from config
$proxy_url = get_config('local_security_dashboard', 'proxy_url');
if (empty($proxy_url)) {
    echo $OUTPUT->notification('Proxy URL not configured. Please configure it in Settings.', 'error');
    echo $OUTPUT->footer();
    exit;
}

?>
<div class="payload-manager-container">
    <div class="row mb-3">
        <div class="col-md-12">
            <ul class="nav nav-tabs">
                <li class="nav-item">
                    <a class="nav-link <?php echo ($action === 'list') ? 'active' : ''; ?>" 
                       href="?action=list">
                        <i class="fa fa-list"></i> Repository
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link <?php echo ($action === 'import') ? 'active' : ''; ?>" 
                       href="?action=import">
                        <i class="fa fa-download"></i> Import from ZAP
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link <?php echo ($action === 'custom') ? 'active' : ''; ?>" 
                       href="?action=custom">
                        <i class="fa fa-plus"></i> Add Custom
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link <?php echo ($action === 'config') ? 'active' : ''; ?>" 
                       href="?action=config">
                        <i class="fa fa-cog"></i> Configuration
                    </a>
                </li>
            </ul>
        </div>
    </div>

    <?php if ($action === 'list'): ?>
        <!-- PAYLOAD REPOSITORY LIST -->
        <div class="payload-list-section">
            <div class="card">
                <div class="card-header">
                    <h5>Payload Repository
                        <button class="btn btn-sm btn-info float-right" id="btn-refresh-stats">
                            <i class="fa fa-refresh"></i> Refresh Stats
                        </button>
                        <button class="btn btn-sm btn-danger float-right mr-2" id="btn-reset-all">
                            <i class="fa fa-trash"></i> Reset All
                        </button>
                    </h5>
                </div>
                <div class="card-body">
                    <div id="payload-stats" class="alert alert-info">
                        Loading statistics...
                    </div>

                    <!-- Category Filter -->
                    <div class="form-group mb-3">
                        <label for="filter-category">Filter by Category:</label>
                        <select id="filter-category" class="form-control" style="max-width: 300px;">
                            <option value="">All Categories</option>
                            <option value="XSS">XSS (Cross-Site Scripting)</option>
                            <option value="SQLi">SQLi (SQL Injection)</option>
                            <option value="CSRF">CSRF (Cross-Site Request Forgery)</option>
                            <option value="RFI">RFI (Remote File Inclusion)</option>
                            <option value="XXE">XXE (XML External Entity)</option>
                            <option value="LFI">LFI (Local File Inclusion)</option>
                            <option value="SSRF">SSRF (Server-Side Request Forgery)</option>
                            <option value="COMMAND_INJECTION">Command Injection</option>
                            <option value="PATH_TRAVERSAL">Path Traversal</option>
                            <option value="BROKEN_AUTH">Broken Authentication</option>
                        </select>
                    </div>

                    <!-- Payloads Table -->
                    <div class="table-responsive">
                        <table class="table table-striped table-hover" id="payloads-table">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Category</th>
                                    <th>Payload Preview</th>
                                    <th>Effectiveness</th>
                                    <th>Success Rate</th>
                                    <th>Used Count</th>
                                    <th>Last Used</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="payloads-tbody">
                                <tr>
                                    <td colspan="8" class="text-center">Loading payloads...</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>

                    <!-- Pagination -->
                    <nav aria-label="Pagination">
                        <ul class="pagination" id="payloads-pagination">
                        </ul>
                    </nav>
                </div>
            </div>
        </div>

    <?php elseif ($action === 'import'): ?>
        <!-- IMPORT FROM ZAP -->
        <div class="import-section">
            <div class="card">
                <div class="card-header">
                    <h5>Import Payloads from ZAP</h5>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6">
                            <h6>ZAP API Configuration</h6>
                            <div class="form-group">
                                <label for="zap-host">ZAP Host:</label>
                                <input type="text" id="zap-host" class="form-control" 
                                       placeholder="localhost" value="localhost">
                            </div>
                            <div class="form-group">
                                <label for="zap-port">ZAP Port:</label>
                                <input type="number" id="zap-port" class="form-control" 
                                       placeholder="8080" value="8080">
                            </div>
                            <div class="form-group">
                                <label for="zap-api-key">ZAP API Key (optional):</label>
                                <input type="password" id="zap-api-key" class="form-control"
                                       placeholder="Leave empty if not required">
                            </div>
                            <button class="btn btn-primary" id="btn-import-zap">
                                <i class="fa fa-download"></i> Import from ZAP
                            </button>
                        </div>
                        <div class="col-md-6">
                            <div id="import-status" class="alert alert-info" style="display:none;">
                                <div id="import-message">Starting import...</div>
                                <div class="progress mt-2">
                                    <div id="import-progress" class="progress-bar" role="progressbar" 
                                         style="width: 0%">0%</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <hr>

                    <h6>Recent ZAP Scans</h6>
                    <div id="zap-scans-list" class="table-responsive">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Scan Date</th>
                                    <th>URL</th>
                                    <th>Alerts</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody id="zap-scans-tbody">
                                <tr><td colspan="4" class="text-center">Loading scans...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

    <?php elseif ($action === 'custom'): ?>
        <!-- ADD CUSTOM PAYLOAD -->
        <div class="custom-payload-section">
            <div class="card">
                <div class="card-header">
                    <h5>Add Custom Payload</h5>
                </div>
                <div class="card-body">
                    <form id="custom-payload-form">
                        <div class="row">
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label for="custom-category">Category:</label>
                                    <select id="custom-category" class="form-control" required>
                                        <option value="">Select category</option>
                                        <option value="XSS">XSS</option>
                                        <option value="SQLi">SQL Injection</option>
                                        <option value="CSRF">CSRF</option>
                                        <option value="RFI">RFI</option>
                                        <option value="XXE">XXE</option>
                                        <option value="LFI">LFI</option>
                                        <option value="SSRF">SSRF</option>
                                        <option value="COMMAND_INJECTION">Command Injection</option>
                                        <option value="PATH_TRAVERSAL">Path Traversal</option>
                                        <option value="BROKEN_AUTH">Broken Auth</option>
                                        <option value="CUSTOM">Custom</option>
                                    </select>
                                </div>

                                <div class="form-group">
                                    <label for="custom-description">Description:</label>
                                    <input type="text" id="custom-description" class="form-control"
                                           placeholder="e.g., Advanced XSS payload for Angular apps">
                                </div>

                                <div class="form-group">
                                    <label for="custom-tags">Tags (comma-separated):</label>
                                    <input type="text" id="custom-tags" class="form-control"
                                           placeholder="e.g., angular, modern, bypass">
                                </div>
                            </div>
                            <div class="col-md-6">
                                <div class="form-group">
                                    <label for="custom-payload">Payload:</label>
                                    <textarea id="custom-payload" class="form-control" rows="5"
                                              placeholder="Enter your payload here..." required></textarea>
                                </div>

                                <div class="form-group">
                                    <label for="custom-priority">Priority:</label>
                                    <select id="custom-priority" class="form-control">
                                        <option value="1">Low</option>
                                        <option value="2">Medium</option>
                                        <option value="3" selected>High</option>
                                    </select>
                                </div>
                            </div>
                        </div>

                        <div class="row">
                            <div class="col-md-12">
                                <button type="submit" class="btn btn-success">
                                    <i class="fa fa-save"></i> Add Payload
                                </button>
                                <button type="reset" class="btn btn-secondary">Clear</button>
                            </div>
                        </div>
                    </form>

                    <hr>

                    <h6 class="mt-4">Custom Payloads List</h6>
                    <div id="custom-payloads-list" class="table-responsive">
                        <table class="table table-striped">
                            <thead>
                                <tr>
                                    <th>Category</th>
                                    <th>Description</th>
                                    <th>Tags</th>
                                    <th>Priority</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="custom-payloads-tbody">
                                <tr><td colspan="5" class="text-center">Loading custom payloads...</td></tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

    <?php elseif ($action === 'config'): ?>
        <!-- CONFIGURATION -->
        <div class="config-section">
            <div class="card">
                <div class="card-header">
                    <h5>Auto-Reuse Configuration</h5>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-check mb-3">
                                <input type="checkbox" id="enable-auto-reuse" class="form-check-input">
                                <label class="form-check-label" for="enable-auto-reuse">
                                    <strong>Enable Auto-Reuse of Successful Payloads</strong>
                                </label>
                            </div>

                            <div class="form-group">
                                <label for="config-success-rate">Minimum Success Rate (%):</label>
                                <input type="number" id="config-success-rate" class="form-control"
                                       min="0" max="100" value="60">
                                <small class="form-text text-muted">
                                    Only payloads with success rate >= this value will be auto-reused
                                </small>
                            </div>

                            <div class="form-group">
                                <label for="config-effectiveness">Minimum Effectiveness Score:</label>
                                <input type="number" id="config-effectiveness" class="form-control"
                                       min="0" max="100" value="70" step="5">
                                <small class="form-text text-muted">
                                    0-100 scale based on payload complexity and coverage
                                </small>
                            </div>

                            <div class="form-group">
                                <label for="config-max-payloads">Max Payloads per Category:</label>
                                <input type="number" id="config-max-payloads" class="form-control"
                                       min="1" max="100" value="20">
                                <small class="form-text text-muted">
                                    Limit to prevent excessive payloads in single category
                                </small>
                            </div>

                            <div class="form-check mb-3">
                                <input type="checkbox" id="config-import-zap-auto" class="form-check-input" checked>
                                <label class="form-check-label" for="config-import-zap-auto">
                                    Auto-import from ZAP on scan completion
                                </label>
                            </div>

                            <div class="form-check mb-3">
                                <input type="checkbox" id="config-deduplicate" class="form-check-input" checked>
                                <label class="form-check-label" for="config-deduplicate">
                                    Auto-deduplicate similar payloads
                                </label>
                            </div>
                        </div>

                        <div class="col-md-6">
                            <div class="alert alert-info">
                                <h6>Smart Reuse Strategy</h6>
                                <p>The system will:</p>
                                <ol>
                                    <li>Track all payloads used in scans</li>
                                    <li>Record success rate for each payload</li>
                                    <li>Auto-select top payloads for auto-reuse</li>
                                    <li>Rotate payloads to avoid detection</li>
                                    <li>Learn from ZAP findings</li>
                                </ol>
                            </div>

                            <div class="card bg-light">
                                <div class="card-body">
                                    <h6>Current Statistics</h6>
                                    <div id="config-stats">
                                        <p>Loading...</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <hr>

                    <div class="row">
                        <div class="col-md-12">
                            <button class="btn btn-success" id="btn-save-config">
                                <i class="fa fa-save"></i> Save Configuration
                            </button>
                            <button class="btn btn-warning" id="btn-reload-payloads">
                                <i class="fa fa-refresh"></i> Reload All Payloads
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

    <?php endif; ?>

</div>

<!-- Modal untuk view/edit payload -->
<div class="modal fade" id="payload-modal" tabindex="-1">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="payload-modal-title">Payload Details</h5>
                <button type="button" class="close" data-dismiss="modal">
                    <span>&times;</span>
                </button>
            </div>
            <div class="modal-body">
                <div class="row">
                    <div class="col-md-6">
                        <p><strong>Category:</strong> <span id="modal-category"></span></p>
                        <p><strong>Effectiveness:</strong> <span id="modal-effectiveness"></span></p>
                        <p><strong>Success Rate:</strong> <span id="modal-success-rate"></span></p>
                    </div>
                    <div class="col-md-6">
                        <p><strong>Used Count:</strong> <span id="modal-used-count"></span></p>
                        <p><strong>Last Used:</strong> <span id="modal-last-used"></span></p>
                    </div>
                </div>
                <div class="form-group">
                    <label><strong>Payload:</strong></label>
                    <textarea id="modal-payload" class="form-control" rows="6" readonly></textarea>
                </div>
                <div id="modal-tags" class="form-group">
                    <label><strong>Tags:</strong></label>
                    <p id="modal-tags-content"></p>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-dismiss="modal">Close</button>
                <button type="button" class="btn btn-danger" id="btn-modal-delete">Delete</button>
            </div>
        </div>
    </div>
</div>

<script>
// Configuration
const PROXY_URL = '<?php echo $proxy_url; ?>';
const API_PAYLOADS = PROXY_URL + '/api/payloads';
const API_SCANNERS = PROXY_URL + '/api/scanners';
const ITEMS_PER_PAGE = 20;

// Global variables
let currentPayloads = [];
let currentPage = 1;
let currentFilter = '';
let allPayloads = [];
let selectedPayloadId = null;

// Load payloads on page load
document.addEventListener('DOMContentLoaded', function() {
    const action = '<?php echo $action; ?>';
    
    if (action === 'list') {
        loadPayloadStats();
        loadPayloads();
    } else if (action === 'import') {
        loadZAPScans();
    } else if (action === 'custom') {
        loadCustomPayloads();
    } else if (action === 'config') {
        loadConfiguration();
    }

    // Event listeners
    document.getElementById('filter-category')?.addEventListener('change', function() {
        currentFilter = this.value;
        currentPage = 1;
        loadPayloads();
    });

    document.getElementById('btn-refresh-stats')?.addEventListener('click', loadPayloadStats);
    document.getElementById('btn-reset-all')?.addEventListener('click', resetAllPayloads);
    document.getElementById('btn-import-zap')?.addEventListener('click', importFromZAP);
    document.getElementById('custom-payload-form')?.addEventListener('submit', saveCustomPayload);
    document.getElementById('btn-save-config')?.addEventListener('click', saveConfiguration);
    document.getElementById('btn-reload-payloads')?.addEventListener('click', reloadPayloads);
});

// Load payload statistics
async function loadPayloadStats() {
    try {
        const response = await fetch(API_PAYLOADS + '/stats');
        const data = await response.json();
        
        if (data.status === 'success') {
            const stats = data.data;
            const html = `
                <div class="row">
                    <div class="col-md-3">
                        <strong>Total Payloads:</strong> ${stats.total_payloads || 0}
                    </div>
                    <div class="col-md-3">
                        <strong>Avg Effectiveness:</strong> ${(stats.avg_effectiveness || 0).toFixed(2)}%
                    </div>
                    <div class="col-md-3">
                        <strong>Avg Success Rate:</strong> ${(stats.avg_success_rate || 0).toFixed(2)}%
                    </div>
                    <div class="col-md-3">
                        <strong>Categories:</strong> ${stats.category_count || 0}
                    </div>
                </div>
            `;
            document.getElementById('payload-stats').innerHTML = html;
        }
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

// Load payloads from API
async function loadPayloads() {
    try {
        const response = await fetch(API_PAYLOADS + '/stats');
        const data = await response.json();
        
        if (data.status === 'success') {
            allPayloads = data.data.payloads || [];
            
            // Filter by category
            let filteredPayloads = allPayloads;
            if (currentFilter) {
                filteredPayloads = allPayloads.filter(p => p.category === currentFilter);
            }
            
            currentPayloads = filteredPayloads;
            renderPayloadsTable();
            renderPagination();
        }
    } catch (error) {
        console.error('Error loading payloads:', error);
        document.getElementById('payloads-tbody').innerHTML = 
            '<tr><td colspan="8" class="text-danger">Error loading payloads</td></tr>';
    }
}

// Render payloads table
function renderPayloadsTable() {
    const startIdx = (currentPage - 1) * ITEMS_PER_PAGE;
    const endIdx = startIdx + ITEMS_PER_PAGE;
    const pagePayloads = currentPayloads.slice(startIdx, endIdx);
    
    let html = '';
    pagePayloads.forEach(payload => {
        const preview = payload.payload.substring(0, 50) + (payload.payload.length > 50 ? '...' : '');
        html += `
            <tr>
                <td>${payload.id || '-'}</td>
                <td><span class="badge badge-info">${payload.category || '-'}</span></td>
                <td><code>${preview}</code></td>
                <td>${(payload.effectiveness || 0).toFixed(1)}%</td>
                <td>${(payload.success_rate || 0).toFixed(1)}%</td>
                <td>${payload.used_count || 0}</td>
                <td>${payload.last_used || 'Never'}</td>
                <td>
                    <button class="btn btn-sm btn-info" onclick="viewPayload(${payload.id})">
                        View
                    </button>
                    <button class="btn btn-sm btn-danger" onclick="deletePayload(${payload.id})">
                        Delete
                    </button>
                </td>
            </tr>
        `;
    });
    
    document.getElementById('payloads-tbody').innerHTML = html || 
        '<tr><td colspan="8" class="text-center">No payloads found</td></tr>';
}

// View payload details
function viewPayload(id) {
    const payload = allPayloads.find(p => p.id === id);
    if (payload) {
        selectedPayloadId = id;
        document.getElementById('payload-modal-title').textContent = `Payload #${id}`;
        document.getElementById('modal-category').textContent = payload.category || '-';
        document.getElementById('modal-effectiveness').textContent = (payload.effectiveness || 0).toFixed(1) + '%';
        document.getElementById('modal-success-rate').textContent = (payload.success_rate || 0).toFixed(1) + '%';
        document.getElementById('modal-used-count').textContent = payload.used_count || 0;
        document.getElementById('modal-last-used').textContent = payload.last_used || 'Never';
        document.getElementById('modal-payload').textContent = payload.payload;
        document.getElementById('modal-tags-content').textContent = (payload.tags || []).join(', ') || 'None';
        
        jQuery('#payload-modal').modal('show');
    }
}

// Delete payload
async function deletePayload(id) {
    if (confirm('Are you sure you want to delete this payload?')) {
        try {
            const response = await fetch(API_PAYLOADS + `/${id}`, {
                method: 'DELETE'
            });
            if (response.ok) {
                alert('Payload deleted');
                loadPayloads();
            }
        } catch (error) {
            alert('Error deleting payload: ' + error);
        }
    }
}

// Reset all payloads
async function resetAllPayloads() {
    if (confirm('This will delete ALL payloads and reset the repository. Continue?')) {
        try {
            const response = await fetch(API_PAYLOADS + '/reset', {
                method: 'POST'
            });
            if (response.ok) {
                alert('Payload repository reset');
                loadPayloads();
            }
        } catch (error) {
            alert('Error resetting payloads: ' + error);
        }
    }
}

// Import from ZAP
async function importFromZAP() {
    const host = document.getElementById('zap-host').value;
    const port = document.getElementById('zap-port').value;
    const apiKey = document.getElementById('zap-api-key').value;
    
    const statusDiv = document.getElementById('import-status');
    statusDiv.style.display = 'block';
    
    try {
        const response = await fetch(API_PAYLOADS + '/import-from-zap', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                zap_host: host,
                zap_port: parseInt(port),
                zap_api_key: apiKey
            })
        });
        
        const data = await response.json();
        if (data.status === 'success') {
            document.getElementById('import-message').textContent = 'Import completed!';
            document.getElementById('import-progress').style.width = '100%';
            loadPayloads();
        }
    } catch (error) {
        document.getElementById('import-message').textContent = 'Error: ' + error;
    }
}

// Load ZAP scans
async function loadZAPScans() {
    // TODO: Implement ZAP scan history loading
}

// Save custom payload
async function saveCustomPayload(e) {
    e.preventDefault();
    
    const payload = {
        category: document.getElementById('custom-category').value,
        payload: document.getElementById('custom-payload').value,
        description: document.getElementById('custom-description').value,
        tags: document.getElementById('custom-tags').value.split(',').map(t => t.trim()),
        priority: document.getElementById('custom-priority').value
    };
    
    try {
        const response = await fetch(API_PAYLOADS + '/custom', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        
        if (response.ok) {
            alert('Custom payload saved');
            document.getElementById('custom-payload-form').reset();
            loadCustomPayloads();
        }
    } catch (error) {
        alert('Error saving payload: ' + error);
    }
}

// Load custom payloads
async function loadCustomPayloads() {
    // TODO: Load custom payloads from API
}

// Save configuration
async function saveConfiguration() {
    const config = {
        enable_auto_reuse: document.getElementById('enable-auto-reuse').checked,
        min_success_rate: parseInt(document.getElementById('config-success-rate').value),
        min_effectiveness: parseInt(document.getElementById('config-effectiveness').value),
        max_payloads_per_category: parseInt(document.getElementById('config-max-payloads').value),
        auto_import_zap: document.getElementById('config-import-zap-auto').checked,
        deduplicate: document.getElementById('config-deduplicate').checked
    };
    
    try {
        const response = await fetch(API_PAYLOADS + '/config', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(config)
        });
        
        if (response.ok) {
            alert('Configuration saved');
        }
    } catch (error) {
        alert('Error saving configuration: ' + error);
    }
}

// Load configuration
async function loadConfiguration() {
    // TODO: Load configuration from API
}

// Reload payloads
async function reloadPayloads() {
    try {
        const response = await fetch(API_PAYLOADS + '/reload', {
            method: 'POST'
        });
        
        if (response.ok) {
            alert('Payloads reloaded');
            loadPayloadStats();
        }
    } catch (error) {
        alert('Error reloading payloads: ' + error);
    }
}

// Render pagination
function renderPagination() {
    const totalPages = Math.ceil(currentPayloads.length / ITEMS_PER_PAGE);
    const paginationEl = document.getElementById('payloads-pagination');
    let html = '';
    
    for (let i = 1; i <= totalPages; i++) {
        html += `
            <li class="page-item ${i === currentPage ? 'active' : ''}">
                <a class="page-link" href="#" onclick="currentPage=${i}; loadPayloads();">${i}</a>
            </li>
        `;
    }
    
    paginationEl.innerHTML = html;
}
</script>

<style>
.payload-manager-container {
    padding: 20px 0;
}

.payload-manager-container .nav-tabs {
    margin-bottom: 20px;
    border-bottom: 2px solid #ddd;
}

.payload-manager-container .card {
    margin-bottom: 20px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.payload-manager-container code {
    background-color: #f5f5f5;
    padding: 2px 6px;
    border-radius: 3px;
    color: #d63384;
}

.payload-manager-container .table-responsive {
    overflow-x: auto;
}

#payload-stats, #import-status {
    padding: 15px;
    border-radius: 5px;
}
</style>

<?php echo $OUTPUT->footer();
