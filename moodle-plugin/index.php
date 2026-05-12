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

// ── VULNERABILITY TRENDS CHART ──────────────────────────────────────────────
if (!isset($logs_data['error']) && !empty($logs_data['logs'])) {
    // Build chart data from logs
    $chart_labels   = [];
    $chart_critical = [];
    $chart_high     = [];
    $chart_medium   = [];
    $chart_low      = [];

    // Take up to 10 most recent scans (logs are already DESC, reverse for chronological)
    $chart_logs = array_slice($logs_data['logs'], 0, 10);
    $chart_logs = array_reverse($chart_logs);

    foreach ($chart_logs as $i => $log) {
        $ts = $log['timestamp'] ?? '';
        // Short label: date + time only
        $label = strlen($ts) >= 10 ? substr($ts, 0, 10) . ' #' . ($i + 1) : ('Scan ' . ($i + 1));
        $chart_labels[]   = $label;
        $chart_critical[] = intval($log['critical'] ?? 0);
        $chart_high[]     = intval($log['high']     ?? 0);
        $chart_medium[]   = intval($log['medium']   ?? 0);
        $chart_low[]      = intval($log['low']      ?? 0);
    }

    $js_labels   = json_encode($chart_labels);
    $js_critical = json_encode($chart_critical);
    $js_high     = json_encode($chart_high);
    $js_medium   = json_encode($chart_medium);
    $js_low      = json_encode($chart_low);

    echo html_writer::start_div('card mt-4');
    echo html_writer::start_div('card-header');
    echo html_writer::tag('h5', '📊 Vulnerability Trends (Recent Scans)', ['class' => 'mb-0']);
    echo html_writer::end_div();
    echo html_writer::start_div('card-body');
    echo '<canvas id="trendChart" height="90"></canvas>';
    echo html_writer::end_div();
    echo html_writer::end_div();

    echo html_writer::script(<<<JS
(function() {
    // Lazy-load Chart.js from CDN then render
    var script = document.createElement('script');
    script.src = 'https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js';
    script.onload = function() {
        var ctx = document.getElementById('trendChart').getContext('2d');
        new Chart(ctx, {
            type: 'bar',
            data: {
                labels: $js_labels,
                datasets: [
                    { label: 'Critical', data: $js_critical, backgroundColor: '#c0392b' },
                    { label: 'High',     data: $js_high,     backgroundColor: '#e67e22' },
                    { label: 'Medium',   data: $js_medium,   backgroundColor: '#d4ac0d' },
                    { label: 'Low',      data: $js_low,      backgroundColor: '#27ae60' }
                ]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'top' },
                    tooltip: { mode: 'index', intersect: false }
                },
                scales: {
                    x: { stacked: true, grid: { display: false } },
                    y: { stacked: true, beginAtZero: true, ticks: { precision: 0 },
                         title: { display: true, text: 'Findings Count' } }
                }
            }
        });
    };
    document.head.appendChild(script);
})();
JS
    );
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

// Add JavaScript for reload scanner functionality
echo html_writer::script(<<<'JS'
function reloadScannerDashboard() {
    const btn = document.getElementById('btn-reload-scanner-dashboard');
    const proxyUrl = 'http://localhost:8999';
    
    btn.disabled = true;
    const originalText = btn.innerHTML;
    btn.innerHTML = '<i class="fa fa-spinner fa-spin"></i> Reloading...';
    
    fetch(proxyUrl + '/api/payloads/reload', {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        btn.innerHTML = '<i class="fa fa-check"></i> Reloaded!';
        setTimeout(() => {
            btn.innerHTML = originalText;
            btn.disabled = false;
            alert('Scanner reloaded successfully! All payloads are now available.');
        }, 1500);
    })
    .catch(error => {
        btn.innerHTML = originalText;
        btn.disabled = false;
        alert('Error reloading scanner: ' + error.message);
    });
}
JS
);

// Display footer
echo $OUTPUT->footer();
?>