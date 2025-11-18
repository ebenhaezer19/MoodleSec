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
    <p>Generate and download professional security reports in PDF format.</p>
</div>

<!-- Report Types -->
<div class="row">
    <div class="col-md-4 mb-3">
        <div class="card">
            <div class="card-header">
                <h5><i class="fa fa-file-text"></i> Executive Summary</h5>
            </div>
            <div class="card-body">
                <p>High-level overview for management:</p>
                <ul>
                    <li>Vulnerability summary</li>
                    <li>Top 10 risks</li>
                    <li>Recommendations</li>
                    <li>Risk trends</li>
                </ul>
            </div>
        </div>
    </div>
    
    <div class="col-md-4 mb-3">
        <div class="card">
            <div class="card-header">
                <h5><i class="fa fa-shield"></i> Compliance Report</h5>
            </div>
            <div class="card-body">
                <p>Compliance framework mapping:</p>
                <ul>
                    <li>OWASP Top 10 2021</li>
                    <li>PCI-DSS v3.2.1</li>
                    <li>Control status</li>
                    <li>Pass/Fail indicators</li>
                </ul>
            </div>
        </div>
    </div>
    
    <div class="col-md-4 mb-3">
        <div class="card">
            <div class="card-header">
                <h5><i class="fa fa-bar-chart"></i> Trend Analysis</h5>
            </div>
            <div class="card-body">
                <p>Historical trend data:</p>
                <ul>
                    <li>30/60/90 day trends</li>
                    <li>Regression detection</li>
                    <li>Fix rate metrics</li>
                    <li>Progress tracking</li>
                </ul>
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
                            <th>Findings</th>
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
                                        <?php if (isset($log['findings_count'])): ?>
                                            <span class="badge badge-info"><?php echo $log['findings_count']; ?></span>
                                        <?php else: ?>
                                            N/A
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <div class="btn-group">
                                            <a href="download_report.php?scan_id=<?php echo urlencode($log['scan_id']); ?>&type=executive" 
                                               class="btn btn-sm btn-primary" target="_blank">
                                                <i class="fa fa-download"></i> Executive
                                            </a>
                                            <a href="download_report.php?scan_id=<?php echo urlencode($log['scan_id']); ?>&type=compliance&framework=OWASP" 
                                               class="btn btn-sm btn-success" target="_blank">
                                                <i class="fa fa-download"></i> OWASP
                                            </a>
                                            <a href="download_report.php?scan_id=<?php echo urlencode($log['scan_id']); ?>&type=compliance&framework=PCI-DSS" 
                                               class="btn btn-sm btn-warning" target="_blank">
                                                <i class="fa fa-download"></i> PCI-DSS
                                            </a>
                                        </div>
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
