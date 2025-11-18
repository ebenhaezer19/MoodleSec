<?php
/**
 * Scan Scheduler Management page
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

$PAGE->set_url(new moodle_url('/local/security_dashboard/scheduler.php'));
$PAGE->set_context(context_system::instance());
$PAGE->set_title('Scan Scheduler');
$PAGE->set_heading('Automated Scan Scheduler');
$PAGE->set_pagelayout('admin');

// Add custom CSS
$PAGE->requires->css('/local/security_dashboard/styles.css');

// Handle form submission
$schedule_created = false;
$schedule_result = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && confirm_sesskey()) {
    $action = optional_param('action', '', PARAM_TEXT);
    
    if ($action === 'create') {
        $target_url = required_param('target_url', PARAM_URL);
        $frequency = required_param('frequency', PARAM_TEXT);
        $scan_type = optional_param('scan_type', 'full', PARAM_TEXT);
        
        $schedule_result = local_security_dashboard_create_schedule($target_url, $frequency, $scan_type);
        $schedule_created = true;
    }
}

echo $OUTPUT->header();

?>

<div class="alert alert-info">
    <h4><i class="fa fa-clock-o"></i> Automated Scan Scheduler</h4>
    <p>Schedule recurring security scans to run automatically at specified intervals.</p>
    <ul>
        <li><strong>Hourly:</strong> Run scans every hour (for critical systems)</li>
        <li><strong>Daily:</strong> Run scans once per day (recommended)</li>
        <li><strong>Weekly:</strong> Run scans once per week</li>
        <li><strong>Monthly:</strong> Run scans once per month</li>
    </ul>
</div>

<?php if ($schedule_created && $schedule_result): ?>
    <?php if (isset($schedule_result['error'])): ?>
        <div class="alert alert-danger">
            <h4>Schedule Creation Failed</h4>
            <p><?php echo htmlspecialchars($schedule_result['error']); ?></p>
        </div>
    <?php else: ?>
        <div class="alert alert-success">
            <h4><i class="fa fa-check-circle"></i> Schedule Created Successfully!</h4>
            <p><strong>Schedule ID:</strong> <?php echo htmlspecialchars($schedule_result['schedule_id'] ?? 'N/A'); ?></p>
            <p><strong>Next Run:</strong> <?php echo htmlspecialchars($schedule_result['next_run'] ?? 'N/A'); ?></p>
        </div>
    <?php endif; ?>
<?php endif; ?>

<!-- Create New Schedule -->
<div class="card mb-4">
    <div class="card-header">
        <h5>Create New Schedule</h5>
    </div>
    <div class="card-body">
        <form method="post" action="" class="mform">
            <input type="hidden" name="sesskey" value="<?php echo sesskey(); ?>">
            <input type="hidden" name="action" value="create">
            
            <div class="form-group row">
                <label for="target_url" class="col-md-3 col-form-label">
                    Target URL
                </label>
                <div class="col-md-9">
                    <input type="url" name="target_url" id="target_url" class="form-control" 
                           value="<?php echo htmlspecialchars($CFG->wwwroot); ?>" required>
                    <small class="form-text text-muted">
                        The base URL to scan (usually your Moodle site URL)
                    </small>
                </div>
            </div>
            
            <div class="form-group row">
                <label for="frequency" class="col-md-3 col-form-label">
                    Frequency
                </label>
                <div class="col-md-9">
                    <select name="frequency" id="frequency" class="form-control" required>
                        <option value="hourly">Hourly (Every hour)</option>
                        <option value="daily" selected>Daily (Once per day)</option>
                        <option value="weekly">Weekly (Once per week)</option>
                        <option value="monthly">Monthly (Once per month)</option>
                    </select>
                    <small class="form-text text-muted">
                        How often the scan should run
                    </small>
                </div>
            </div>
            
            <div class="form-group row">
                <label for="scan_type" class="col-md-3 col-form-label">
                    Scan Type
                </label>
                <div class="col-md-9">
                    <select name="scan_type" id="scan_type" class="form-control" required>
                        <option value="full" selected>Full Site Scan (Comprehensive)</option>
                        <option value="quick">Quick Scan (Fast)</option>
                        <option value="targeted">Targeted Scan (Specific endpoints)</option>
                    </select>
                    <small class="form-text text-muted">
                        Type of scan to perform
                    </small>
                </div>
            </div>
            
            <div class="form-group row">
                <div class="col-md-9 offset-md-3">
                    <button type="submit" class="btn btn-primary">
                        <i class="fa fa-plus"></i> Create Schedule
                    </button>
                    <a href="<?php echo new moodle_url('/local/security_dashboard/index.php'); ?>" 
                       class="btn btn-secondary">
                        <i class="fa fa-arrow-left"></i> Back to Dashboard
                    </a>
                </div>
            </div>
        </form>
    </div>
</div>

<!-- Active Schedules -->
<div class="card">
    <div class="card-header">
        <h5>Active Schedules</h5>
    </div>
    <div class="card-body">
        <?php
        $schedules = local_security_dashboard_get_schedules();
        
        if (isset($schedules['error'])):
        ?>
            <div class="alert alert-warning">
                <?php echo htmlspecialchars($schedules['error']); ?>
            </div>
        <?php elseif (empty($schedules)): ?>
            <div class="alert alert-info">
                No active schedules. Create one above to get started.
            </div>
        <?php else: ?>
            <div class="table-responsive">
                <table class="table table-striped">
                    <thead>
                        <tr>
                            <th>Schedule ID</th>
                            <th>Target URL</th>
                            <th>Frequency</th>
                            <th>Scan Type</th>
                            <th>Next Run</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($schedules as $schedule): ?>
                            <tr>
                                <td><code><?php echo htmlspecialchars($schedule['schedule_id'] ?? 'N/A'); ?></code></td>
                                <td><?php echo htmlspecialchars($schedule['target_url'] ?? 'N/A'); ?></td>
                                <td>
                                    <span class="badge badge-info">
                                        <?php echo htmlspecialchars($schedule['cron_expression'] ?? 'N/A'); ?>
                                    </span>
                                </td>
                                <td><?php echo htmlspecialchars($schedule['scan_type'] ?? 'N/A'); ?></td>
                                <td><?php echo htmlspecialchars($schedule['next_run'] ?? 'N/A'); ?></td>
                                <td>
                                    <?php if ($schedule['enabled'] ?? false): ?>
                                        <span class="badge badge-success">Active</span>
                                    <?php else: ?>
                                        <span class="badge badge-secondary">Disabled</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <button class="btn btn-sm btn-danger" disabled>
                                        <i class="fa fa-trash"></i> Delete
                                    </button>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        <?php endif; ?>
    </div>
</div>

<!-- Scheduler Information -->
<div class="card mt-4">
    <div class="card-header">
        <h5>How Scheduling Works</h5>
    </div>
    <div class="card-body">
        <h6>Automated Scanning</h6>
        <p>The scheduler automatically runs scans at the specified intervals:</p>
        <ul>
            <li><strong>Hourly:</strong> Best for critical production systems requiring constant monitoring</li>
            <li><strong>Daily:</strong> Recommended for most applications - balances coverage and resource usage</li>
            <li><strong>Weekly:</strong> Suitable for stable systems with infrequent changes</li>
            <li><strong>Monthly:</strong> For compliance-driven periodic assessments</li>
        </ul>
        
        <h6 class="mt-3">Benefits</h6>
        <ul>
            <li>✅ Continuous security monitoring</li>
            <li>✅ Early vulnerability detection</li>
            <li>✅ Automated compliance reporting</li>
            <li>✅ Trend analysis and regression detection</li>
            <li>✅ No manual intervention required</li>
        </ul>
        
        <h6 class="mt-3">Best Practices</h6>
        <ul>
            <li>Schedule scans during low-traffic periods</li>
            <li>Start with daily scans and adjust based on needs</li>
            <li>Monitor scan results regularly</li>
            <li>Set up notifications for critical findings</li>
        </ul>
    </div>
</div>

<?php

echo $OUTPUT->footer();
