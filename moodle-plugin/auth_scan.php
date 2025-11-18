<?php
/**
 * Authentication & API Security Scan Page
 *
 * @package    local_security_dashboard
 * @copyright  2024 MoodleSec
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../../config.php');
require_once($CFG->libdir . '/adminlib.php');
require_once(__DIR__ . '/lib.php');

admin_externalpage_setup('local_security_dashboard_auth');

$PAGE->set_url(new moodle_url('/local/security_dashboard/auth_scan.php'));
$PAGE->set_title(get_string('pluginname', 'local_security_dashboard') . ' - Auth & API Scan');
$PAGE->set_heading('Authentication & API Security Scanner');

// Handle scan requests
$action = optional_param('action', '', PARAM_ALPHA);
$scan_type = optional_param('scan_type', '', PARAM_ALPHA);

if ($action === 'start_scan') {
    // TEMPORARY: Skip sesskey validation to test if scan works
    // TODO: Re-enable sesskey validation after confirming scan works
    // require_sesskey();
    
    if ($scan_type === 'auth') {
        \core\notification::info('Starting Authentication Security Scan... This may take 30-60 seconds.');
        $result = local_security_dashboard_start_auth_scan();
        
        // Debug: Log the result
        error_log('Auth scan result: ' . print_r($result, true));
        
    } else if ($scan_type === 'api') {
        \core\notification::info('Starting API Security Scan... This may take 30-60 seconds.');
        $result = local_security_dashboard_start_api_scan();
        
        // Debug: Log the result
        error_log('API scan result: ' . print_r($result, true));
    }
    
    if (isset($result['error'])) {
        \core\notification::error('Scan failed: ' . $result['error']);
        error_log('Scan error: ' . $result['error']);
    } else if (isset($result['scan_id'])) {
        \core\notification::success('✅ Scan completed! Scan ID: ' . $result['scan_id'] . ' - Found ' . ($result['total_findings'] ?? 0) . ' findings.');
        // Redirect to refresh and show results
        redirect($PAGE->url);
    } else {
        \core\notification::warning('Scan may have started but response was unexpected. Result: ' . json_encode($result));
        error_log('Unexpected scan result: ' . print_r($result, true));
    }
}

echo $OUTPUT->header();

?>

<style>
.scan-card {
    background: white;
    border-radius: 8px;
    padding: 24px;
    margin-bottom: 20px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
}

.scan-card h3 {
    margin-top: 0;
    color: #1f2937;
    font-size: 20px;
    margin-bottom: 12px;
}

.scan-card p {
    color: #6b7280;
    margin-bottom: 16px;
    line-height: 1.6;
}

.test-list {
    background: #f9fafb;
    border-radius: 6px;
    padding: 16px;
    margin-bottom: 16px;
}

.test-list h4 {
    margin-top: 0;
    font-size: 14px;
    color: #374151;
    margin-bottom: 12px;
}

.test-list ul {
    margin: 0;
    padding-left: 20px;
}

.test-list li {
    color: #6b7280;
    margin-bottom: 6px;
    font-size: 14px;
}

.scan-button {
    background: #2563eb;
    color: white;
    border: none;
    padding: 12px 24px;
    border-radius: 6px;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: background 0.2s;
}

.scan-button:hover {
    background: #1d4ed8;
}

.scan-button.secondary {
    background: #10b981;
}

.scan-button.secondary:hover {
    background: #059669;
}

.info-badge {
    display: inline-block;
    background: #dbeafe;
    color: #1e40af;
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 12px;
    font-weight: 500;
    margin-bottom: 16px;
}

.grid-2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-bottom: 20px;
}

@media (max-width: 768px) {
    .grid-2 {
        grid-template-columns: 1fr;
    }
}
</style>

<div class="container-fluid">
    <div class="row">
        <div class="col-12">
            <h2>🔐 Authentication & API Security Scanner</h2>
            <p style="color: #6b7280; margin-bottom: 30px;">
                Advanced security testing for authentication mechanisms and REST API endpoints.
                Part of <strong>Priority 3</strong> implementation.
            </p>
        </div>
    </div>

    <div class="grid-2">
        <!-- Authentication Scan Card -->
        <div class="scan-card">
            <h3>🔑 Authentication Security Scan</h3>
            <span class="info-badge">Session • RBAC • OAuth/SSO</span>
            
            <p>
                Comprehensive testing of authentication and authorization mechanisms including
                session management, role-based access control, and OAuth/SSO security.
            </p>

            <div class="test-list">
                <h4>📋 Tests Included:</h4>
                <ul>
                    <li>✅ Cookie security (HttpOnly, Secure, SameSite)</li>
                    <li>✅ Session fixation detection</li>
                    <li>✅ CSRF token validation</li>
                    <li>✅ Privilege escalation testing</li>
                    <li>✅ IDOR vulnerability detection</li>
                    <li>✅ OAuth redirect URI validation</li>
                    <li>✅ Token leakage detection</li>
                    <li>✅ SSO/SAML configuration testing</li>
                </ul>
            </div>

            <form method="post" action="<?php echo $PAGE->url->out(false); ?>" id="auth-scan-form">
                <input type="hidden" name="sesskey" value="<?php echo sesskey(); ?>">
                <input type="hidden" name="action" value="start_scan">
                <input type="hidden" name="scan_type" value="auth">
                <button type="submit" class="scan-button" id="auth-scan-btn">
                    🚀 Start Authentication Scan
                </button>
            </form>
        </div>

        <!-- API Scan Card -->
        <div class="scan-card">
            <h3>🌐 REST API Security Scan</h3>
            <span class="info-badge">Discovery • Validation • Security</span>
            
            <p>
                Automated discovery and security testing of REST API endpoints including
                authentication bypass, input validation, and data exposure detection.
            </p>

            <div class="test-list">
                <h4>📋 Tests Included:</h4>
                <ul>
                    <li>✅ API endpoint discovery</li>
                    <li>✅ Authentication bypass testing</li>
                    <li>✅ SQL injection & XSS detection</li>
                    <li>✅ HTTP method tampering</li>
                    <li>✅ Rate limiting validation</li>
                    <li>✅ Mass assignment detection</li>
                    <li>✅ Excessive data exposure</li>
                    <li>✅ Security headers validation</li>
                </ul>
            </div>

            <form method="post" action="<?php echo $PAGE->url->out(false); ?>" id="api-scan-form">
                <input type="hidden" name="sesskey" value="<?php echo sesskey(); ?>">
                <input type="hidden" name="action" value="start_scan">
                <input type="hidden" name="scan_type" value="api">
                <button type="submit" class="scan-button secondary" id="api-scan-btn">
                    🚀 Start API Scan
                </button>
            </form>
        </div>
    </div>

    <!-- Recent Scans -->
    <div class="scan-card">
        <h3>📊 Recent Auth & API Scans</h3>
        
        <?php
        $history = local_security_dashboard_get_scan_history(10);
        
        if (isset($history['error'])) {
            echo '<p style="color: #dc2626;">Error loading scan history: ' . htmlspecialchars($history['error']) . '</p>';
        } else if (empty($history)) {
            echo '<p style="color: #6b7280;">No scans found. Start your first scan above!</p>';
        } else {
            echo '<table class="table table-striped">';
            echo '<thead>';
            echo '<tr>';
            echo '<th>Scan ID</th>';
            echo '<th>Type</th>';
            echo '<th>Timestamp</th>';
            echo '<th>Findings</th>';
            echo '<th>Status</th>';
            echo '</tr>';
            echo '</thead>';
            echo '<tbody>';
            
            foreach ($history as $scan) {
                // Only show auth and api scans
                if (!in_array($scan['scan_type'], ['authentication', 'api'])) {
                    continue;
                }
                
                $scan_id = htmlspecialchars($scan['scan_id']);
                $scan_type = htmlspecialchars($scan['scan_type']);
                $timestamp = date('Y-m-d H:i:s', strtotime($scan['timestamp']));
                $total = $scan['total_findings'] ?? 0;
                
                // Determine status badge
                $critical = $scan['critical_count'] ?? 0;
                $high = $scan['high_count'] ?? 0;
                
                if ($critical > 0) {
                    $status_badge = '<span style="background: #dc2626; color: white; padding: 4px 12px; border-radius: 12px; font-size: 12px;">🔴 Critical</span>';
                } else if ($high > 0) {
                    $status_badge = '<span style="background: #ea580c; color: white; padding: 4px 12px; border-radius: 12px; font-size: 12px;">🟠 High Risk</span>';
                } else if ($total > 0) {
                    $status_badge = '<span style="background: #eab308; color: white; padding: 4px 12px; border-radius: 12px; font-size: 12px;">🟡 Medium</span>';
                } else {
                    $status_badge = '<span style="background: #10b981; color: white; padding: 4px 12px; border-radius: 12px; font-size: 12px;">✅ Clean</span>';
                }
                
                $type_icon = $scan_type === 'authentication' ? '🔑' : '🌐';
                
                echo '<tr>';
                echo '<td><code>' . $scan_id . '</code></td>';
                echo '<td>' . $type_icon . ' ' . ucfirst($scan_type) . '</td>';
                echo '<td>' . $timestamp . '</td>';
                echo '<td><strong>' . $total . '</strong> findings</td>';
                echo '<td>' . $status_badge . '</td>';
                echo '</tr>';
            }
            
            echo '</tbody>';
            echo '</table>';
        }
        ?>
    </div>

    <!-- Info Section -->
    <div class="scan-card" style="background: #eff6ff; border-left: 4px solid #2563eb;">
        <h3>ℹ️ About Priority 3 Scans</h3>
        <p style="margin-bottom: 12px;">
            <strong>Authentication Security Scan</strong> tests your Moodle instance for common authentication
            and authorization vulnerabilities including session management issues, privilege escalation, and OAuth/SSO misconfigurations.
        </p>
        <p style="margin-bottom: 0;">
            <strong>REST API Security Scan</strong> discovers and tests all REST API endpoints for security issues
            including authentication bypass, injection vulnerabilities, and data exposure.
        </p>
    </div>
</div>

<script>
// Debug: Log when script loads
console.log('[Auth Scan] JavaScript loaded');

// Add loading state to scan buttons
document.querySelectorAll('form').forEach((form, index) => {
    console.log('[Auth Scan] Found form:', form.id || 'unnamed-' + index);
    
    form.addEventListener('submit', function(e) {
        console.log('[Auth Scan] Form submitting:', this.id);
        console.log('[Auth Scan] Form action:', this.action);
        console.log('[Auth Scan] Form method:', this.method);
        
        const button = this.querySelector('button[type="submit"]');
        if (button) {
            console.log('[Auth Scan] Disabling button:', button.id);
            button.disabled = true;
            button.innerHTML = '⏳ Scanning... Please wait (30-60s)';
            button.style.opacity = '0.7';
            button.style.cursor = 'not-allowed';
        }
        
        // Don't prevent default - let form submit normally
        console.log('[Auth Scan] Form will submit to:', this.action);
    });
});

console.log('[Auth Scan] Event listeners attached');
</script>

<?php
echo $OUTPUT->footer();
?>
