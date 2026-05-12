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

// ── VULNERABILITY TRENDS CHART (pure PHP SVG — no JS/CDN required) ──────────
if (!isset($logs_data['error']) && !empty($logs_data['logs'])) {
    $chart_logs = array_reverse(array_slice($logs_data['logs'], 0, 10));

    $bars = [];
    foreach ($chart_logs as $i => $log) {
        $ts = $log['timestamp'] ?? '';
        $label = strlen($ts) >= 10 ? substr($ts, 5, 5) . ' #' . ($i + 1) : 'S' . ($i + 1);
        $bars[] = [
            'label'    => $label,
            'critical' => intval($log['critical'] ?? 0),
            'high'     => intval($log['high']     ?? 0),
            'medium'   => intval($log['medium']   ?? 0),
            'low'      => intval($log['low']      ?? 0),
        ];
    }

    $max_total = 1;
    foreach ($bars as $b) {
        $t = $b['critical'] + $b['high'] + $b['medium'] + $b['low'];
        if ($t > $max_total) $max_total = $t;
    }

    $n    = count($bars);
    $svgW = 600; $svgH = 240;
    $padL = 45;  $padR = 15; $padT = 25; $padB = 48;
    $plotW = $svgW - $padL - $padR;
    $plotH = $svgH - $padT - $padB;
    $barW  = max(18, (int)($plotW / ($n * 1.6)));
    $gap   = $n > 1 ? (int)(($plotW - $barW * $n) / ($n + 1)) : (int)(($plotW - $barW) / 2);

    $colors = ['critical'=>'#c0392b','high'=>'#e67e22','medium'=>'#d4ac0d','low'=>'#27ae60'];

    $svg  = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 {$svgW} {$svgH}' style='width:100%;font-family:Segoe UI,sans-serif;'>";
    $svg .= "<rect x='{$padL}' y='{$padT}' width='{$plotW}' height='{$plotH}' fill='#f9fafb' stroke='#d0dae6'/>";

    // Y gridlines
    $y_steps = min($max_total, 5);
    for ($g = 0; $g <= $y_steps; $g++) {
        $val = (int)round($max_total * $g / $y_steps);
        $gy  = round($padT + $plotH - ($val / $max_total * $plotH), 1);
        $svg .= "<line x1='{$padL}' y1='{$gy}' x2='" . ($padL+$plotW) . "' y2='{$gy}' stroke='#e2e8f0' stroke-width='1'/>";
        $svg .= "<text x='" . ($padL-4) . "' y='" . ($gy+4) . "' text-anchor='end' font-size='10' fill='#666'>{$val}</text>";
    }

    // Bars (stacked: low→medium→high→critical)
    foreach ($bars as $i => $b) {
        $bx       = $padL + $gap + $i * ($barW + $gap);
        $y_cursor = $padT + $plotH;
        foreach (['low','medium','high','critical'] as $sev) {
            $val = $b[$sev];
            if ($val <= 0) continue;
            $bh = max(1, round($val / $max_total * $plotH, 1));
            $y_cursor -= $bh;
            $label_sev = ucfirst($sev);
            $svg .= "<rect x='" . round($bx,1) . "' y='" . round($y_cursor,1) . "' width='{$barW}' height='{$bh}' fill='" . $colors[$sev] . "' rx='1'><title>{$label_sev}: {$val}</title></rect>";
        }
        $lx    = round($bx + $barW / 2, 1);
        $total = $b['critical'] + $b['high'] + $b['medium'] + $b['low'];
        $svg .= "<text x='{$lx}' y='" . ($padT+$plotH+13) . "' text-anchor='middle' font-size='9' fill='#555'>" . htmlspecialchars($b['label']) . "</text>";
        if ($total > 0) {
            $svg .= "<text x='{$lx}' y='" . ($padT+$plotH+24) . "' text-anchor='middle' font-size='9' fill='#999'>({$total})</text>";
        }
    }

    // Axes
    $svg .= "<line x1='{$padL}' y1='{$padT}' x2='{$padL}' y2='" . ($padT+$plotH) . "' stroke='#888' stroke-width='1.5'/>";
    $svg .= "<line x1='{$padL}' y1='" . ($padT+$plotH) . "' x2='" . ($padL+$plotW) . "' y2='" . ($padT+$plotH) . "' stroke='#888' stroke-width='1.5'/>";

    // Y-axis label
    $my = round($padT + $plotH / 2, 1);
    $svg .= "<text transform='rotate(-90)' x='-{$my}' y='13' text-anchor='middle' font-size='10' fill='#666'>Findings</text>";

    // Legend (top-left)
    $loffset = 0; $ly = $padT + 6;
    foreach (['Critical'=>'#c0392b','High'=>'#e67e22','Medium'=>'#d4ac0d','Low'=>'#27ae60'] as $lbl => $col) {
        $svg .= "<rect x='" . ($padL+8+$loffset) . "' y='{$ly}' width='10' height='10' fill='{$col}' rx='2'/>";
        $svg .= "<text x='" . ($padL+22+$loffset) . "' y='" . ($ly+9) . "' font-size='10' fill='#333'>{$lbl}</text>";
        $loffset += 66;
    }
    $svg .= "</svg>";

    echo html_writer::start_div('card mt-4');
    echo html_writer::start_div('card-header');
    echo html_writer::tag('h5', '📊 Vulnerability Trends (Recent Scans)', ['class' => 'mb-0']);
    echo html_writer::end_div();
    echo html_writer::start_div('card-body');
    echo $svg;
    echo html_writer::end_div();
    echo html_writer::end_div();
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