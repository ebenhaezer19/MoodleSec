<?php
/**
 * Security Dashboard main page
 *
 * @package    local_security_dashboard
 * @copyright  2025 Krisopras & Nathanael
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php');
require_once($CFG->libdir . '/adminlib.php');

require_login();
require_capability('local/security_dashboard:view', context_system::instance());

$PAGE->set_url(new moodle_url('/local/security_dashboard/index.php'));
$PAGE->set_context(context_system::instance());
$PAGE->set_title(get_string('security_dashboard', 'local_security_dashboard'));
$PAGE->set_heading(get_string('security_dashboard', 'local_security_dashboard'));
$PAGE->set_pagelayout('admin');

echo $OUTPUT->header();

// Check service health
$health = local_security_dashboard_check_health();

// Display health status
echo html_writer::start_div('alert alert-' . ($health['proxy'] && $health['cvss'] ? 'success' : 'warning'));
echo html_writer::tag('h4', 'Service Status');
echo html_writer::tag('p', 'Proxy Service: ' . ($health['proxy'] ? '✅ Online' : '❌ Offline'));
echo html_writer::tag('p', 'CVSS Engine: ' . ($health['cvss'] ? '✅ Online' : '❌ Offline'));
echo html_writer::end_div();

// Get recent logs
$logs_data = local_security_dashboard_get_logs(10);

error_log('[index.php] Logs data received: ' . print_r($logs_data, true));
error_log('[index.php] isset error: ' . (isset($logs_data['error']) ? 'yes' : 'no'));
error_log('[index.php] logs count: ' . (isset($logs_data['logs']) ? count($logs_data['logs']) : '0'));

if (isset($logs_data['error'])) {
    echo html_writer::div($logs_data['error'], 'alert alert-danger');
} else {
    // Display summary
    echo html_writer::start_div('row');

    // Scan buttons
    echo html_writer::start_div('col-md-12 mb-3');
    echo html_writer::link(
        new moodle_url('/local/security_dashboard/scan.php'),
        '<i class="fa fa-search"></i> ' . get_string('scan_now', 'local_security_dashboard'),
        ['class' => 'btn btn-primary mr-2']
    );
    echo html_writer::link(
        new moodle_url('/local/security_dashboard/fullscan.php'),
        '<i class="fa fa-globe"></i> Unauthenticated Full Site Scan',
        ['class' => 'btn btn-success mr-2']
    );
    echo html_writer::link(
        new moodle_url('/local/security_dashboard/native_auth_scan.php'),
        '<i class="fa fa-user-crown"></i> Admin Area Scan',
        ['class' => 'btn btn-info mr-2']
    );
    
    // Reload Scanner button
    echo html_writer::tag('button',
        '<i class="fa fa-cogs"></i> Reload Scanner',
        ['class' => 'btn btn-warning mr-2', 'id' => 'btn-reload-scanner-dashboard', 
         'onclick' => 'reloadScannerDashboard()', 'type' => 'button',
         'title' => 'Reload scanner with latest payloads (without proxy restart)']
    );
    
    echo html_writer::link(
        new moodle_url('/local/security_dashboard/scheduler.php'),
        '<i class="fa fa-clock-o"></i> Scheduler',
        ['class' => 'btn btn-info mr-2']
    );
    echo html_writer::link(
        new moodle_url('/local/security_dashboard/reports.php'),
        '<i class="fa fa-file-pdf-o"></i> Reports',
        ['class' => 'btn btn-warning mr-2']
    );
    echo html_writer::link(
        new moodle_url('/local/security_dashboard/ml_dashboard.php'),
        '<i class="fa fa-brain"></i> ML Dashboard',
        ['class' => 'btn btn-info mr-2']
    );
    echo html_writer::link(
        new moodle_url('/local/security_dashboard/scan_phishing_content.php'),
        '<i class="fa fa-shield"></i> Phishing Scanner',
        ['class' => 'btn btn-danger mr-2']
    );
    echo html_writer::link(
        new moodle_url('/local/security_dashboard/login_monitor.php'),
        '<i class="fa fa-user-shield"></i> Login Monitor',
        ['class' => 'btn btn-info mr-2']
    );
    echo html_writer::end_div();

    echo html_writer::end_div();

    // Display recent logs
    echo html_writer::tag('h3', get_string('recent_scans', 'local_security_dashboard'));

    if (empty($logs_data['logs'])) {
        echo html_writer::div(get_string('no_scans', 'local_security_dashboard'), 'alert alert-info');
    } else {
        $table = new html_table();
        $table->head = ['Type', 'Timestamp', 'Details'];
        $table->attributes['class'] = 'generaltable';

        foreach ($logs_data['logs'] as $log) {
            $row = [];

            // Format type with badge for ZAP scans
            $type_display = s($log['type'] ?? 'N/A');
            if ($log['source'] === 'zap') {
                $type_display = '<span class="badge badge-info">ZAP</span> ' . $type_display;
            } else {
                $type_display = '<span class="badge badge-secondary">Proxy</span> ' . $type_display;
            }
            $row[] = $type_display;
            
            // Timestamp
            $row[] = s($log['timestamp'] ?? 'N/A');

            // Format details
            $details = '';
            
            // For ZAP scans - show findings summary
            if ($log['source'] === 'zap') {
                $details .= 'URL: ' . s($log['url']) . '<br>';
                $details .= 'Findings: ' . intval($log['findings'] ?? 0);
                
                if ($log['findings'] > 0) {
                    $summary_parts = [];
                    if ($log['critical'] > 0) $summary_parts[] = 'Critical: ' . intval($log['critical']);
                    if ($log['high'] > 0) $summary_parts[] = 'High: ' . intval($log['high']);
                    if ($log['medium'] > 0) $summary_parts[] = 'Medium: ' . intval($log['medium']);
                    if ($log['low'] > 0) $summary_parts[] = 'Low: ' . intval($log['low']);
                    
                    if (!empty($summary_parts)) {
                        $details .= '<br>' . implode(' | ', $summary_parts);
                    }
                }
                
                // Add link to view results
                if (!empty($log['db_id']) && $log['source'] === 'zap') {
                    $details .= '<br>' . html_writer::link(
                        new moodle_url('/local/security_dashboard/zap_results.php', 
                            ['scan_id' => $log['db_id']]),
                        'View Results →',
                        ['class' => 'small', 'style' => 'margin-top: 5px; display: inline-block;']
                    );
                }
            } else {
                // For proxy logs - show details with ML stats
                $details = s($log['details'] ?? 'N/A');
                if (!empty($log['url'])) {
                    $details .= '<br>URL: ' . s($log['url']);
                }
                
                // Add ML filtering statistics if available
                if ($log['source'] === 'proxy' && isset($log['original_count'])) {
                    $original = intval($log['original_count'] ?? 0);
                    $filtered = intval($log['fp_filtered'] ?? 0);
                    $final = intval($log['final_count'] ?? 0);
                    
                    $details .= '<br><strong>ML Filtering:</strong> ';
                    $details .= $original . ' raw → ' . $filtered . ' FP removed → ' . $final . ' actual vulns';
                }
                
                if ($log['findings'] > 0) {
                    $summary_parts = [];
                    if ($log['critical'] > 0) $summary_parts[] = 'Critical: ' . intval($log['critical']);
                    if ($log['high'] > 0) $summary_parts[] = 'High: ' . intval($log['high']);
                    if ($log['medium'] > 0) $summary_parts[] = 'Medium: ' . intval($log['medium']);
                    if ($log['low'] > 0) $summary_parts[] = 'Low: ' . intval($log['low']);
                    
                    if (!empty($summary_parts)) {
                        $details .= '<br>' . implode(' | ', $summary_parts);
                    }
                }
            }

            $row[] = $details ?: 'N/A';
            $table->data[] = $row;
        }

        echo html_writer::table($table);
    }
}

// ZAP INTEGRATION SECTION (Phase 2)
echo html_writer::start_div('', ['style' => 'margin-top: 30px;']);
echo html_writer::tag('h3', 'ZAP Vulnerability Scanning');

echo html_writer::start_div('', ['style' => 'margin-top: 15px;']);

echo html_writer::link(
    new moodle_url('/admin/settings.php?section=local_security_dashboard_zap'),
    '⚙️ ZAP Settings',
    ['class' => 'btn btn-secondary', 'style' => 'margin-right: 10px;']
);

echo html_writer::link(
    new moodle_url('/local/security_dashboard/zap_scan.php'),
    '🔍 Trigger Scan',
    ['class' => 'btn btn-primary', 'style' => 'margin-right: 10px;']
);

echo html_writer::link(
    new moodle_url('/local/security_dashboard/zap_results.php'),
    '📊 Scan Results',
    ['class' => 'btn btn-info', 'style' => 'margin-right: 10px;']
);

echo html_writer::link(
    new moodle_url('/local/security_dashboard/zap_trends.php'),
    '📈 Trends',
    ['class' => 'btn btn-warning', 'style' => 'margin-right: 10px;']
);

echo html_writer::link(
    new moodle_url('/local/security_dashboard/zap_compliance.php'),
    '✅ Compliance',
    ['class' => 'btn btn-danger']
);

echo html_writer::end_div();
echo html_writer::end_div();

// =========================================================================
// SOC OPERATIONS CENTER — Lightweight awareness panel with live polling
// =========================================================================
$proxy_url_val = get_config('local_security_dashboard', 'proxy_url') ?: 'http://localhost:8999';

echo <<<HTML
<div id="soc-ops-panel" style="margin-top: 30px; border: 1px solid #dee2e6; border-radius: 8px; overflow: hidden;">
  <!-- Header -->
  <div style="background: linear-gradient(135deg, #1b2a4a 0%, #243b5e 100%); padding: 14px 20px; display: flex; align-items: center; justify-content: space-between;">
    <div style="display: flex; align-items: center; gap: 10px;">
      <span style="font-size: 1.4em;">🛡️</span>
      <h3 style="margin: 0; color: #fff; font-size: 1.15em; font-weight: 600;">SOC Operations Center</h3>
    </div>
    <span id="soc-last-update" style="color: rgba(255,255,255,0.5); font-size: 0.75em;">—</span>
  </div>

  <!-- Status Indicators -->
  <div style="display: flex; flex-wrap: wrap; gap: 0; border-bottom: 1px solid #dee2e6;">

    <!-- Backend Health -->
    <div style="flex: 1; min-width: 160px; padding: 16px 20px; border-right: 1px solid #dee2e6;">
      <div style="font-size: 0.75em; text-transform: uppercase; letter-spacing: 0.5px; color: #6c757d; margin-bottom: 6px;">Backend Health</div>
      <span id="soc-health-badge" class="badge badge-secondary" style="font-size: 0.95em; padding: 5px 12px;">⏳ Checking…</span>
    </div>

    <!-- SOC Mode -->
    <div style="flex: 1; min-width: 160px; padding: 16px 20px; border-right: 1px solid #dee2e6;">
      <div style="font-size: 0.75em; text-transform: uppercase; letter-spacing: 0.5px; color: #6c757d; margin-bottom: 6px;">SOC Mode</div>
      <span id="soc-mode-badge" class="badge badge-secondary" style="font-size: 0.95em; padding: 5px 12px;">⏳ Checking…</span>
    </div>

    <!-- Active Alerts -->
    <div style="flex: 1; min-width: 160px; padding: 16px 20px;">
      <div style="font-size: 0.75em; text-transform: uppercase; letter-spacing: 0.5px; color: #6c757d; margin-bottom: 6px;">Active Alerts</div>
      <span id="soc-alerts-badge" class="badge badge-secondary" style="font-size: 0.95em; padding: 5px 12px;">⏳ Checking…</span>
    </div>

  </div>

  <!-- Action Bar -->
  <div style="padding: 14px 20px; background: #f8f9fa; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px;">
    <a href="{$proxy_url_val}/dashboard/"
       target="_blank" rel="noopener"
       id="btn-open-soc-dashboard"
       class="btn btn-primary"
       title="Open the full SOC War Room in a new tab"
       style="font-weight: 600;">
      <i class="fa fa-external-link"></i> Open SOC Dashboard
    </a>
    <span style="font-size: 0.8em; color: #6c757d;">Real-time incident response &amp; ML monitoring</span>
  </div>
</div>
HTML;

// Add JavaScript for reload scanner + SOC polling
echo html_writer::script(<<<JS
var SOC_PROXY_URL = '{$proxy_url_val}';

// --- Reload Scanner ---
function reloadScannerDashboard() {
    var btn = document.getElementById('btn-reload-scanner-dashboard');
    btn.disabled = true;
    var originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Reloading...';

    fetch(SOC_PROXY_URL + '/api/payloads/reload', { method: 'POST' })
    .then(function(r) { return r.json(); })
    .then(function() {
        btn.innerHTML = '<i class="fa fa-check"></i> Reloaded!';
        setTimeout(function() {
            btn.innerHTML = originalText;
            btn.disabled = false;
            alert('Scanner reloaded successfully! All payloads are now available.');
        }, 1500);
    })
    .catch(function(err) {
        btn.innerHTML = originalText;
        btn.disabled = false;
        alert('Error reloading scanner: ' + err.message);
    });
}

// --- SOC Operations Center: Lightweight Polling ---
(function() {
    var healthBadge = document.getElementById('soc-health-badge');
    var modeBadge   = document.getElementById('soc-mode-badge');
    var alertsBadge = document.getElementById('soc-alerts-badge');
    var lastUpdate  = document.getElementById('soc-last-update');

    function setBadge(el, text, cls) {
        if (!el) return;
        el.textContent = text;
        el.className = 'badge badge-' + cls;
        el.style.cssText = 'font-size:0.95em;padding:5px 12px;';
    }

    function updateTimestamp() {
        if (!lastUpdate) return;
        var now = new Date();
        lastUpdate.textContent = 'Updated ' + now.toLocaleTimeString();
    }

    function pollSOC() {
        // 1. Backend Health
        fetch(SOC_PROXY_URL + '/health', { signal: AbortSignal.timeout(5000) })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            if (d && d.status === 'ok') {
                setBadge(healthBadge, '✅ Online', 'success');
            } else {
                setBadge(healthBadge, '⚠️ Degraded', 'warning');
            }
        })
        .catch(function() {
            setBadge(healthBadge, '❌ Offline', 'danger');
        });

        // 2. SOC Mode
        fetch(SOC_PROXY_URL + '/soc/status', { signal: AbortSignal.timeout(5000) })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            var mode = 'UNKNOWN';
            var cls  = 'secondary';
            if (d) {
                if (d.enforcement_mode === 'SOC' && d.active) {
                    mode = 'ACTIVE';  cls = 'success';
                } else if (d.demo_mode) {
                    mode = 'DEMO';    cls = 'info';
                } else if (d.enforcement_mode === 'ENFORCE') {
                    mode = 'ENFORCE'; cls = 'warning';
                } else {
                    mode = d.enforcement_mode || 'PASSIVE';
                    cls = 'secondary';
                }
            }
            setBadge(modeBadge, mode, cls);
        })
        .catch(function() {
            setBadge(modeBadge, '—', 'secondary');
        });

        // 3. Active Alerts
        fetch(SOC_PROXY_URL + '/soc/alerts/stats', { signal: AbortSignal.timeout(5000) })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            var pending = (d && typeof d.pending === 'number') ? d.pending : 0;
            if (pending > 0) {
                setBadge(alertsBadge, '🔔 ' + pending + ' Pending', 'danger');
            } else {
                setBadge(alertsBadge, '✅ 0 Pending', 'success');
            }
        })
        .catch(function() {
            setBadge(alertsBadge, '—', 'secondary');
        });

        updateTimestamp();
    }

    // Initial fetch on page load, then poll every 12 seconds
    pollSOC();
    setInterval(pollSOC, 12000);
})();
JS
);

// Display footer
echo $OUTPUT->footer();
?>