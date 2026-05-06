<?php
/**
 * Reports and Downloads page — L2-L7 Self-Healing Pipeline
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

$PAGE->set_url(new moodle_url('/local/security_dashboard/reports.php'));
$PAGE->set_context(context_system::instance());
$PAGE->set_title('Security Reports');
$PAGE->set_heading('Security Reports & Downloads');
$PAGE->set_pagelayout('admin');

$PAGE->requires->css('/local/security_dashboard/styles.css');

$logs_data = local_security_dashboard_get_logs(50);

// Proxy base URL
$proxy_base = 'http://localhost:8998';

// Check GPT status
$gpt_active = !empty(getenv('OPENAI_API_KEY'));

echo $OUTPUT->header();
?>

<!-- L1-L7 Pipeline Status Banner -->
<div class="alert alert-success">
    <h4><i class="fa fa-shield"></i> Self-Healing Security Pipeline (L1-L7)</h4>
    <div class="row">
        <div class="col-md-3"><span class="badge badge-success">L1</span> ML Detection</div>
        <div class="col-md-3"><span class="badge badge-info">L2</span> GPT Recommendation</div>
        <div class="col-md-3"><span class="badge badge-warning">L3</span> CVSS 3.1 Scoring</div>
        <div class="col-md-3"><span class="badge badge-primary">L4</span> Severity Predictor</div>
    </div>
    <div class="row mt-2">
        <div class="col-md-3"><span class="badge badge-secondary">L5</span> PoC Steps</div>
        <div class="col-md-3"><span class="badge badge-danger">L6</span> Config Fix</div>
        <div class="col-md-3"><span class="badge badge-dark">L7</span> Verify Fix</div>
        <div class="col-md-3 small text-muted">
            GPT: <strong><?php echo $gpt_active ? '✅ Active' : '⚠️ Static (set OPENAI_API_KEY)'; ?></strong>
        </div>
    </div>
</div>

<!-- Generate Report from Scan -->
<div class="card mt-4">
    <div class="card-header bg-primary text-white">
        <h5><i class="fa fa-file-pdf-o"></i> Generate Report from Scan</h5>
    </div>
    <div class="card-body">
        <?php if (empty($logs_data['logs'])): ?>
            <div class="alert alert-warning">No scans available. Please run a scan first.</div>
        <?php else: ?>
            <div class="table-responsive">
                <table class="table table-striped table-hover">
                    <thead class="thead-dark">
                        <tr>
                            <th>Scan ID</th>
                            <th>Date</th>
                            <th>Type</th>
                            <th>ML Filtering Stats</th>
                            <th>Findings Summary</th>
                            <th>L6 Config Fix</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach (array_slice($logs_data['logs'], 0, 20) as $log): ?>
                            <?php if (!isset($log['scan_id'])) continue; ?>
                            <?php
                                $scan_id   = $log['scan_id'];

                                // Fetch enriched data from proxy for L6 preview
                                $api_url   = $proxy_base . '/api/scan/' . urlencode($scan_id);
                                $ctx       = stream_context_create(['http' => ['timeout' => 3]]);
                                $scan_json = @file_get_contents($api_url, false, $ctx);
                                $scan_data = $scan_json ? json_decode($scan_json, true) : null;
                                $findings  = $scan_data['findings'] ?? [];

                                // Aggregate config_fix platforms (L6)
                                $config_platforms = [];
                                $cvss_scores      = [];
                                foreach ($findings as $f) {
                                    if (!empty($f['cvss_score'])) {
                                        $cvss_scores[] = floatval($f['cvss_score']);
                                    }
                                    $cf = $f['config_fix'] ?? '';
                                    if ($cf) {
                                        if (stripos($cf, 'apache')  !== false) $config_platforms['Apache']  = true;
                                        if (stripos($cf, 'nginx')   !== false) $config_platforms['Nginx']   = true;
                                        if (stripos($cf, 'moodle')  !== false ||
                                            stripos($cf, '$CFG')    !== false) $config_platforms['Moodle']  = true;
                                        if (stripos($cf, 'php')     !== false) $config_platforms['PHP']     = true;
                                    }
                                }
                                $max_cvss = count($cvss_scores) ? max($cvss_scores) : 0;
                            ?>
                            <tr>
                                <td><code style="font-size:11px"><?php echo htmlspecialchars($scan_id); ?></code></td>
                                <td><?php echo htmlspecialchars($log['timestamp'] ?? 'N/A'); ?></td>
                                <td><span class="badge badge-secondary"><?php echo htmlspecialchars($log['type'] ?? 'N/A'); ?></span></td>
                                <td>
                                    <?php if (isset($log['original_count'])): ?>
                                        <small>
                                            Original: <strong><?php echo intval($log['original_count']); ?></strong><br>
                                            FP Removed: <strong><?php echo intval($log['fp_filtered']); ?></strong><br>
                                            Final: <strong><?php echo intval($log['final_count']); ?></strong>
                                        </small>
                                    <?php else: ?>
                                        <small>N/A</small>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ($log['critical'] > 0): ?>
                                        <span class="badge badge-danger">Critical: <?php echo $log['critical']; ?></span><br>
                                    <?php endif; ?>
                                    <?php if ($log['high'] > 0): ?>
                                        <span class="badge badge-warning">High: <?php echo $log['high']; ?></span><br>
                                    <?php endif; ?>
                                    <?php if ($log['medium'] > 0): ?>
                                        <span class="badge badge-info">Medium: <?php echo $log['medium']; ?></span><br>
                                    <?php endif; ?>
                                    <?php if ($log['low'] > 0): ?>
                                        <span class="badge badge-secondary">Low: <?php echo $log['low']; ?></span>
                                    <?php endif; ?>
                                    <?php if ($max_cvss > 0): ?>
                                        <br><small class="text-muted">Max CVSS: <strong style="color:#e74c3c"><?php echo $max_cvss; ?></strong></small>
                                    <?php endif; ?>
                                </td>
                                <!-- L6: Config Fix platform badges -->
                                <td>
                                    <?php if (!empty($config_platforms)): ?>
                                        <?php foreach (array_keys($config_platforms) as $platform): ?>
                                            <span class="badge badge-light border text-dark"><?php echo $platform; ?></span>
                                        <?php endforeach; ?>
                                    <?php elseif (count($findings) > 0): ?>
                                        <small class="text-muted">No config fix</small>
                                    <?php else: ?>
                                        <small class="text-muted">—</small>
                                    <?php endif; ?>
                                </td>
                                <!-- Actions -->
                                <td>
                                    <!-- Findings Detail: L6 config fix + L7 verify fix inside -->
                                    <a href="scan_findings.php?scan_id=<?php echo urlencode($scan_id); ?>"
                                       class="btn btn-sm btn-info mb-1"
                                       title="View findings with L6 Config Fix & L7 Verify Fix">
                                        <i class="fa fa-search"></i> Findings (L6/L7)
                                    </a><br>
                                    <!-- PCI-DSS PDF: full evidence + config fix + PoC -->
                                    <a href="download_report.php?scan_id=<?php echo urlencode($scan_id); ?>&type=compliance&framework=PCI-DSS"
                                       class="btn btn-sm btn-primary mb-1" target="_blank"
                                       title="Download PCI-DSS PDF with full evidence">
                                        <i class="fa fa-download"></i> PCI-DSS PDF
                                    </a>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>
</div>

<!-- L1-L7 Feature Legend -->
<div class="card mt-4">
    <div class="card-header">
        <h5><i class="fa fa-info-circle"></i> Pipeline Feature Coverage per Layer</h5>
    </div>
    <div class="card-body">
        <div class="row">
            <div class="col-md-6">
                <table class="table table-sm">
                    <tr><td><span class="badge badge-success">L1</span></td><td>ML FP Reducer (XGBoost, 14 features, 87% acc.)</td></tr>
                    <tr><td><span class="badge badge-info">L2</span></td><td>GPT-4 recommendation + static template fallback</td></tr>
                    <tr><td><span class="badge badge-warning">L3</span></td><td>CVSS 3.1 context-aware (URL path multiplier)</td></tr>
                    <tr><td><span class="badge badge-primary">L4</span></td><td>SeverityPredictor heuristic / XGBoost (when trained)</td></tr>
                </table>
            </div>
            <div class="col-md-6">
                <table class="table table-sm">
                    <tr><td><span class="badge badge-secondary">L5</span></td><td>PoC reproduction steps (URL + parameter + payload)</td></tr>
                    <tr><td><span class="badge badge-danger">L6</span></td><td>Apache / Nginx / Moodle / PHP config suggestions</td></tr>
                    <tr><td><span class="badge badge-dark">L7</span></td><td>Verify Fix — automated re-scan via /api/verify-fix/</td></tr>
                    <tr><td><span class="badge badge-light border">PDF</span></td><td>PCI-DSS compliance report with full evidence</td></tr>
                </table>
            </div>
        </div>
    </div>
</div>

<!-- Trend Analysis -->
<div class="card mt-4">
    <div class="card-header">
        <h5>Vulnerability Trends</h5>
    </div>
    <div class="card-body">
        <div class="row">
            <div class="col-md-4">
                <a href="trends.php?days=30" class="btn btn-block btn-info">
                    <i class="fa fa-line-chart"></i> 30 Day Trends
                </a>
            </div>
            <div class="col-md-4">
                <a href="trends.php?days=60" class="btn btn-block btn-info">
                    <i class="fa fa-line-chart"></i> 60 Day Trends
                </a>
            </div>
            <div class="col-md-4">
                <a href="trends.php?days=90" class="btn btn-block btn-info">
                    <i class="fa fa-line-chart"></i> 90 Day Trends
                </a>
            </div>
        </div>
    </div>
</div>

<div class="mt-3">
    <a href="<?php echo new moodle_url('/local/security_dashboard/index.php'); ?>" class="btn btn-secondary">
        <i class="fa fa-arrow-left"></i> Back to Dashboard
    </a>
</div>

<?php
echo $OUTPUT->footer();
