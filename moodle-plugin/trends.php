<?php
/**
 * Vulnerability Trends page
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

$PAGE->set_url(new moodle_url('/local/security_dashboard/trends.php'));
$PAGE->set_context(context_system::instance());
$PAGE->set_title('Vulnerability Trends');
$PAGE->set_heading('Vulnerability Trends & Analytics');
$PAGE->set_pagelayout('admin');

// Add custom CSS
$PAGE->requires->css('/local/security_dashboard/styles.css');

// Get parameters
$days = optional_param('days', 30, PARAM_INT);

// Get trend data
$proxy_url = get_config('local_security_dashboard', 'proxy_url');
$trends_data = null;
$fix_rate_data = null;
$regressions_data = null;

if (!empty($proxy_url)) {
    try {
        // Get trends
        $curl = new curl();
        $response = $curl->get(rtrim($proxy_url, '/') . '/trends?days=' . $days);
        $trends_data = json_decode($response, true);
        
        // Get fix rate
        $response = $curl->get(rtrim($proxy_url, '/') . '/fix-rate?days=' . $days);
        $fix_rate_data = json_decode($response, true);
        
        // Get regressions
        $response = $curl->get(rtrim($proxy_url, '/') . '/regressions?lookback_scans=5');
        $regressions_data = json_decode($response, true);
        
    } catch (Exception $e) {
        // Error handling
    }
}

echo $OUTPUT->header();

?>

<div class="alert alert-info">
    <h4><i class="fa fa-line-chart"></i> Vulnerability Trends & Analytics</h4>
    <p>Track vulnerability trends over time and monitor fix rates.</p>
</div>

<!-- Period Selection -->
<div class="btn-group mb-4">
    <a href="?days=7" class="btn <?php echo $days == 7 ? 'btn-primary' : 'btn-secondary'; ?>">
        7 Days
    </a>
    <a href="?days=30" class="btn <?php echo $days == 30 ? 'btn-primary' : 'btn-secondary'; ?>">
        30 Days
    </a>
    <a href="?days=60" class="btn <?php echo $days == 60 ? 'btn-primary' : 'btn-secondary'; ?>">
        60 Days
    </a>
    <a href="?days=90" class="btn <?php echo $days == 90 ? 'btn-primary' : 'btn-secondary'; ?>">
        90 Days
    </a>
</div>

<!-- Fix Rate Statistics -->
<?php if ($fix_rate_data && !isset($fix_rate_data['detail'])): ?>
    <div class="card mb-4">
        <div class="card-header">
            <h5>Fix Rate Statistics (<?php echo $days; ?> Days)</h5>
        </div>
        <div class="card-body">
            <div class="row text-center">
                <div class="col-md-3">
                    <div class="stat-box">
                        <h3><?php echo $fix_rate_data['total_findings'] ?? 0; ?></h3>
                        <p>Total Findings</p>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-box">
                        <h3><?php echo $fix_rate_data['fixed'] ?? 0; ?></h3>
                        <p>Fixed</p>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-box">
                        <h3><?php echo $fix_rate_data['open'] ?? 0; ?></h3>
                        <p>Open</p>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="stat-box">
                        <h3><?php echo $fix_rate_data['fix_rate_percent'] ?? 0; ?>%</h3>
                        <p>Fix Rate</p>
                    </div>
                </div>
            </div>
            
            <?php if (isset($fix_rate_data['avg_time_to_fix_days'])): ?>
                <div class="mt-3 text-center">
                    <p><strong>Average Time to Fix:</strong> <?php echo number_format($fix_rate_data['avg_time_to_fix_days'], 1); ?> days</p>
                </div>
            <?php endif; ?>
        </div>
    </div>
<?php endif; ?>

<!-- Trend Data -->
<?php if ($trends_data && !isset($trends_data['detail']) && !empty($trends_data['data_points'])): ?>
    <div class="card mb-4">
        <div class="card-header">
            <h5>Vulnerability Trends</h5>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>Date</th>
                            <th>Critical</th>
                            <th>High</th>
                            <th>Medium</th>
                            <th>Low</th>
                            <th>Info</th>
                            <th>Total</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach (array_reverse($trends_data['data_points']) as $point): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($point['date'] ?? 'N/A'); ?></td>
                                <td><span class="badge badge-critical"><?php echo $point['critical'] ?? 0; ?></span></td>
                                <td><span class="badge badge-high"><?php echo $point['high'] ?? 0; ?></span></td>
                                <td><span class="badge badge-medium"><?php echo $point['medium'] ?? 0; ?></span></td>
                                <td><span class="badge badge-low"><?php echo $point['low'] ?? 0; ?></span></td>
                                <td><span class="badge badge-info"><?php echo $point['info'] ?? 0; ?></span></td>
                                <td><strong><?php echo $point['total'] ?? 0; ?></strong></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
<?php elseif ($trends_data && isset($trends_data['detail'])): ?>
    <div class="alert alert-warning">
        <?php echo htmlspecialchars($trends_data['detail']); ?>
    </div>
<?php else: ?>
    <div class="alert alert-info">
        No trend data available. Run some scans to see trends.
    </div>
<?php endif; ?>

<!-- Regressions -->
<?php if ($regressions_data && !isset($regressions_data['detail'])): ?>
    <div class="card mb-4">
        <div class="card-header">
            <h5>New Vulnerabilities (Regressions)</h5>
        </div>
        <div class="card-body">
            <?php if (empty($regressions_data['regressions'])): ?>
                <div class="alert alert-success">
                    <i class="fa fa-check-circle"></i> No new vulnerabilities detected!
                </div>
            <?php else: ?>
                <div class="alert alert-warning">
                    <strong><?php echo $regressions_data['regressions_count']; ?></strong> new vulnerabilities detected in recent scans.
                </div>
                
                <div class="table-responsive">
                    <table class="table table-striped">
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>Category</th>
                                <th>Description</th>
                                <th>First Seen</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach (array_slice($regressions_data['regressions'], 0, 10) as $regression): ?>
                                <tr>
                                    <td>
                                        <span class="badge badge-<?php echo strtolower($regression['severity'] ?? 'info'); ?>">
                                            <?php echo htmlspecialchars($regression['severity'] ?? 'N/A'); ?>
                                        </span>
                                    </td>
                                    <td><?php echo htmlspecialchars($regression['category'] ?? 'N/A'); ?></td>
                                    <td><?php echo htmlspecialchars($regression['description'] ?? 'N/A'); ?></td>
                                    <td><?php echo htmlspecialchars($regression['first_seen'] ?? 'N/A'); ?></td>
                                </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    </div>
<?php endif; ?>

<!-- Back to Dashboard -->
<div class="mt-3">
    <a href="<?php echo new moodle_url('/local/security_dashboard/index.php'); ?>" class="btn btn-secondary">
        <i class="fa fa-arrow-left"></i> Back to Dashboard
    </a>
    <a href="<?php echo new moodle_url('/local/security_dashboard/reports.php'); ?>" class="btn btn-primary">
        <i class="fa fa-file-pdf-o"></i> Generate Reports
    </a>
</div>

<?php

echo $OUTPUT->footer();
