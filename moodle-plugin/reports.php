<?php
/**
 * Reports and Downloads page
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

// Add custom CSS
$PAGE->requires->css('/local/security_dashboard/styles.css');

// Get recent scans for report generation
$logs_data = local_security_dashboard_get_logs(50);

echo $OUTPUT->header();

?>

<div class="alert alert-info">
    <h4><i class="fa fa-file-pdf-o"></i> Security Reports</h4>
    <p>Generate and download professional PCI-DSS compliance reports in PDF format.</p>
    <p><strong>Current Phase 1:</strong> All reports are generated in <strong>PCI-DSS</strong> format with CVSS-based risk scoring and ML false positive filtering included.</p>
</div>

<!-- Report Type: PCI-DSS -->
<div class="row">
    <div class="col-md-8 mx-auto">
        <div class="card mb-4">
            <div class="card-header bg-primary text-white">
                <h5><i class="fa fa-shield"></i> PCI-DSS Compliance Report (Phase 1)</h5>
            </div>
            <div class="card-body">
                <p><strong>Coverage:</strong> Payment Card Industry Data Security Standard Requirements</p>
                <ul>
                    <li>✅ CVSS 3.1 Risk Scoring</li>
                    <li>✅ ML False Positive Reduction (87% accuracy)</li>
                    <li>✅ Vulnerability Classification</li>
                    <li>✅ Remediation Priority</li>
                    <li>✅ Compliance Status per Requirement</li>
                    <li>✅ Evidence & References</li>
                </ul>
                <p><em>Phase 2 will add OWASP Top 10 and Executive Summary formats.</em></p>
            </div>
        </div>
    </div>
</div>

<!-- Recent Scans - Select for Report -->
<div class="card mt-4">
    <div class="card-header">
        <h5>Generate Report from Scan</h5>
    </div>
    <div class="card-body">
        <?php if (empty($logs_data['logs'])): ?>
            <div class="alert alert-warning">
                No scans available. Please run a scan first.
            </div>
        <?php else: ?>
            <div class="table-responsive">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>Scan ID</th>
                            <th>Date</th>
                            <th>Type</th>
                            <th>ML Filtering Stats</th>
                            <th>Findings Summary</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach (array_slice($logs_data['logs'], 0, 20) as $log): ?>
                            <?php if (isset($log['scan_id'])): ?>
                                <tr>
                                    <td><code><?php echo htmlspecialchars($log['scan_id']); ?></code></td>
                                    <td><?php echo htmlspecialchars($log['timestamp'] ?? 'N/A'); ?></td>
                                    <td><?php echo htmlspecialchars($log['type'] ?? 'N/A'); ?></td>
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
                                    </td>
                                    <td>
                                        <a href="download_report.php?scan_id=<?php echo urlencode($log['scan_id']); ?>&type=compliance&framework=PCI-DSS" 
                                           class="btn btn-sm btn-primary" target="_blank" title="Download PCI-DSS Report">
                                            <i class="fa fa-download"></i> PCI-DSS
                                        </a>
                                    </td>
                                </tr>
                            <?php endif; ?>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
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

<!-- Back to Dashboard -->
<div class="mt-3">
    <a href="<?php echo new moodle_url('/local/security_dashboard/index.php'); ?>" class="btn btn-secondary">
        <i class="fa fa-arrow-left"></i> Back to Dashboard
    </a>
</div>

<?php

echo $OUTPUT->footer();
