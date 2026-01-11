<?php
/**
 * Login Monitoring Dashboard
 * 
 * Displays login activity, geolocation, and suspicious patterns
 * 
 * @package    local_security_dashboard
 * @copyright  2026 Krisopras & Nathanael
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php');
require_once($CFG->libdir . '/adminlib.php');

require_login();
require_capability('moodle/site:config', context_system::instance());

$PAGE->set_url(new moodle_url('/local/security_dashboard/login_monitor.php'));
$PAGE->set_context(context_system::instance());
$PAGE->set_title('Login Activity Monitor');
$PAGE->set_heading('🔐 Login Activity Monitor');
$PAGE->set_pagelayout('admin');

// Get filter parameters
$filter_success = optional_param('success', '', PARAM_INT);
$filter_user = optional_param('user', '', PARAM_INT);
$filter_days = optional_param('days', 7, PARAM_INT);
$page = optional_param('page', 0, PARAM_INT);
$perpage = 50;

global $DB;

// Build query
$where = ['1=1'];
$params = [];

if ($filter_success !== '') {
    $where[] = 'success = :success';
    $params['success'] = $filter_success;
}

if ($filter_user) {
    $where[] = 'userid = :userid';
    $params['userid'] = $filter_user;
}

if ($filter_days > 0) {
    $where[] = 'timecreated > :timeago';
    $params['timeago'] = time() - ($filter_days * 24 * 3600);
}

// Get login logs
$sql = "SELECT * FROM {local_security_login_log}
        WHERE " . implode(' AND ', $where) . "
        ORDER BY timecreated DESC";

$logs = $DB->get_records_sql($sql, $params, $page * $perpage, $perpage);
$total = $DB->count_records_sql("SELECT COUNT(*) FROM {local_security_login_log} WHERE " . implode(' AND ', $where), $params);

// Get statistics
$stats = [
    'total' => $DB->count_records('local_security_login_log'),
    'success' => $DB->count_records('local_security_login_log', ['success' => 1]),
    'failed' => $DB->count_records('local_security_login_log', ['success' => 0]),
    'suspicious' => $DB->count_records('local_security_login_log', ['is_suspicious' => 1]),
    'blocked_ips' => $DB->count_records('local_security_ip_blocklist', ['is_active' => 1]),
];

// Get recent blocked IPs
$blocked_ips = $DB->get_records('local_security_ip_blocklist', ['is_active' => 1], 'timemodified DESC', '*', 0, 10);

// Get country distribution
$country_stats = $DB->get_records_sql("
    SELECT country, COUNT(*) as count
    FROM {local_security_login_log}
    WHERE country IS NOT NULL AND country != ''
    GROUP BY country
    ORDER BY count DESC
    LIMIT 10
");

echo $OUTPUT->header();
?>

<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.7.1/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.7.1/dist/leaflet.js"></script>

<style>
.stats-card {
    border-left: 4px solid #007bff;
    transition: all 0.3s;
}
.stats-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
}
.stats-card.success { border-left-color: #28a745; }
.stats-card.danger { border-left-color: #dc3545; }
.stats-card.warning { border-left-color: #ffc107; }
.stats-card.info { border-left-color: #17a2b8; }

#map {
    height: 400px;
    border-radius: 8px;
    box-shadow: 0 2px 8px rgba(0,0,0,0.1);
}

.login-row.suspicious {
    background-color: #fff3cd !important;
}
.login-row.failed {
    background-color: #f8d7da !important;
}
.login-row.success {
    background-color: #d4edda !important;
}
</style>

<div class="container-fluid">
    <!-- Statistics Cards -->
    <div class="row mb-4">
        <div class="col-md-3">
            <div class="card stats-card">
                <div class="card-body">
                    <h6 class="text-muted"><i class="fas fa-sign-in-alt"></i> Total Logins</h6>
                    <h2 class="mb-0"><?php echo number_format($stats['total']); ?></h2>
                    <small class="text-muted">All time</small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card stats-card success">
                <div class="card-body">
                    <h6 class="text-muted"><i class="fas fa-check-circle"></i> Successful</h6>
                    <h2 class="mb-0 text-success"><?php echo number_format($stats['success']); ?></h2>
                    <small class="text-muted"><?php echo $stats['total'] > 0 ? round(($stats['success'] / $stats['total']) * 100, 1) : 0; ?>% success rate</small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card stats-card danger">
                <div class="card-body">
                    <h6 class="text-muted"><i class="fas fa-times-circle"></i> Failed Attempts</h6>
                    <h2 class="mb-0 text-danger"><?php echo number_format($stats['failed']); ?></h2>
                    <small class="text-muted"><?php echo $stats['total'] > 0 ? round(($stats['failed'] / $stats['total']) * 100, 1) : 0; ?>% failure rate</small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card stats-card warning">
                <div class="card-body">
                    <h6 class="text-muted"><i class="fas fa-exclamation-triangle"></i> Suspicious</h6>
                    <h2 class="mb-0 text-warning"><?php echo number_format($stats['suspicious']); ?></h2>
                    <small class="text-muted"><?php echo number_format($stats['blocked_ips']); ?> blocked IPs</small>
                </div>
            </div>
        </div>
    </div>

    <!-- World Map -->
    <div class="row mb-4">
        <div class="col-md-12">
            <div class="card">
                <div class="card-header">
                    <h4><i class="fas fa-globe"></i> Login Locations (Last <?php echo $filter_days; ?> Days)</h4>
                </div>
                <div class="card-body">
                    <div id="map"></div>
                </div>
            </div>
        </div>
    </div>

    <div class="row">
        <!-- Login Activity Log -->
        <div class="col-md-8">
            <div class="card">
                <div class="card-header">
                    <h4><i class="fas fa-list"></i> Login Activity</h4>
                </div>
                <div class="card-body">
                    <!-- Filters -->
                    <form method="get" class="mb-3">
                        <div class="row">
                            <div class="col-md-3">
                                <select name="success" class="form-control" onchange="this.form.submit()">
                                    <option value="">All Status</option>
                                    <option value="1" <?php echo $filter_success === 1 ? 'selected' : ''; ?>>Success</option>
                                    <option value="0" <?php echo $filter_success === 0 ? 'selected' : ''; ?>>Failed</option>
                                </select>
                            </div>
                            <div class="col-md-3">
                                <select name="days" class="form-control" onchange="this.form.submit()">
                                    <option value="1" <?php echo $filter_days == 1 ? 'selected' : ''; ?>>Last 24 hours</option>
                                    <option value="7" <?php echo $filter_days == 7 ? 'selected' : ''; ?>>Last 7 days</option>
                                    <option value="30" <?php echo $filter_days == 30 ? 'selected' : ''; ?>>Last 30 days</option>
                                    <option value="0" <?php echo $filter_days == 0 ? 'selected' : ''; ?>>All time</option>
                                </select>
                            </div>
                            <div class="col-md-3">
                                <a href="<?php echo $PAGE->url; ?>" class="btn btn-secondary">Reset</a>
                            </div>
                        </div>
                    </form>

                    <!-- Login Table -->
                    <div class="table-responsive">
                        <table class="table table-sm table-hover">
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>User</th>
                                    <th>IP / Location</th>
                                    <th>Status</th>
                                    <th>Risk</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($logs as $log): ?>
                                    <?php 
                                        $row_class = '';
                                        if ($log->is_suspicious) $row_class = 'suspicious';
                                        if (!$log->success) $row_class = 'failed';
                                        if ($log->success && !$log->is_suspicious) $row_class = 'success';
                                    ?>
                                    <tr class="login-row <?php echo $row_class; ?>">
                                        <td><small><?php echo userdate($log->timecreated, '%d %b %H:%M'); ?></small></td>
                                        <td>
                                            <?php if ($log->userid): ?>
                                                <?php $user = $DB->get_record('user', ['id' => $log->userid]); ?>
                                                <?php echo $user ? fullname($user) : 'Unknown'; ?>
                                            <?php else: ?>
                                                <em><?php echo s($log->username); ?></em>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <small>
                                                <strong><?php echo s($log->ip_address); ?></strong><br>
                                                <?php if ($log->city || $log->country): ?>
                                                    <i class="fas fa-map-marker-alt"></i> <?php echo s($log->city); ?>, <?php echo s($log->country); ?>
                                                <?php endif; ?>
                                            </small>
                                        </td>
                                        <td>
                                            <?php if ($log->success): ?>
                                                <span class="badge badge-success"><i class="fas fa-check"></i> Success</span>
                                            <?php else: ?>
                                                <span class="badge badge-danger"><i class="fas fa-times"></i> Failed</span>
                                            <?php endif; ?>
                                            <?php if ($log->is_suspicious): ?>
                                                <span class="badge badge-warning"><i class="fas fa-exclamation-triangle"></i> Suspicious</span>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <small>
                                                <div class="progress" style="height: 20px;">
                                                    <div class="progress-bar <?php echo $log->risk_score > 70 ? 'bg-danger' : ($log->risk_score > 40 ? 'bg-warning' : 'bg-success'); ?>" 
                                                         style="width: <?php echo $log->risk_score; ?>%">
                                                        <?php echo $log->risk_score; ?>
                                                    </div>
                                                </div>
                                            </small>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>

                    <!-- Pagination -->
                    <?php if ($total > $perpage): ?>
                        <div class="text-center">
                            <?php echo $OUTPUT->paging_bar($total, $page, $perpage, $PAGE->url); ?>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <!-- Sidebar -->
        <div class="col-md-4">
            <!-- Blocked IPs -->
            <div class="card mb-3">
                <div class="card-header">
                    <h5><i class="fas fa-ban"></i> Blocked IPs (<?php echo count($blocked_ips); ?>)</h5>
                </div>
                <div class="card-body" style="max-height: 400px; overflow-y: auto;">
                    <?php if (empty($blocked_ips)): ?>
                        <p class="text-muted">No blocked IPs</p>
                    <?php else: ?>
                        <ul class="list-unstyled">
                            <?php foreach ($blocked_ips as $blocked): ?>
                                <li class="mb-2 p-2" style="background: #f8f9fa; border-radius: 4px;">
                                    <strong><?php echo s($blocked->ip_address); ?></strong>
                                    <span class="badge badge-danger float-right"><?php echo $blocked->fail_count; ?> fails</span>
                                    <br>
                                    <small class="text-muted"><?php echo s($blocked->reason); ?></small>
                                </li>
                            <?php endforeach; ?>
                        </ul>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Country Distribution -->
            <div class="card">
                <div class="card-header">
                    <h5><i class="fas fa-flag"></i> Top Countries</h5>
                </div>
                <div class="card-body">
                    <?php foreach ($country_stats as $stat): ?>
                        <div class="mb-2">
                            <div class="d-flex justify-content-between">
                                <span><?php echo s($stat->country); ?></span>
                                <span class="badge badge-primary"><?php echo $stat->count; ?></span>
                            </div>
                            <div class="progress" style="height: 10px;">
                                <div class="progress-bar" style="width: <?php echo ($stat->count / $stats['total']) * 100; ?>%"></div>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
// Initialize map
var map = L.map('map').setView([0, 0], 2);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '© OpenStreetMap contributors'
}).addTo(map);

// Add markers for login locations
<?php foreach ($logs as $log): ?>
    <?php if ($log->latitude && $log->longitude): ?>
        L.marker([<?php echo $log->latitude; ?>, <?php echo $log->longitude; ?>])
            .addTo(map)
            .bindPopup(`
                <strong><?php echo $log->success ? 'Login Success' : 'Login Failed'; ?></strong><br>
                User: <?php echo s($log->username); ?><br>
                IP: <?php echo s($log->ip_address); ?><br>
                Location: <?php echo s($log->city); ?>, <?php echo s($log->country); ?><br>
                Time: <?php echo userdate($log->timecreated); ?>
            `);
    <?php endif; ?>
<?php endforeach; ?>
</script>

<?php
echo $OUTPUT->footer();
