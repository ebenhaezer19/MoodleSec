<?php
/**
 * Vulnerability Trending and Analysis
 * 
 * @package    local_security_dashboard
 * @copyright  2026 Security Team
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

require_once(__DIR__ . '/../../config.php');
require_once($CFG->libdir . '/adminlib.php');

require_login();
require_capability('local/security_dashboard:view', context_system::instance());

$PAGE->set_url(new moodle_url('/local/security_dashboard/zap_trends.php'));
$PAGE->set_context(context_system::instance());
$PAGE->set_title(get_string('vulnerability_trends', 'local_security_dashboard'));
$PAGE->set_heading(get_string('vulnerability_trends', 'local_security_dashboard'));
$PAGE->set_pagelayout('admin');

// Get date range
$days = optional_param('days', 30, PARAM_INT);
$start_date = time() - ($days * 24 * 60 * 60);

require_once($CFG->dirroot . '/local/security_dashboard/lib/zap_integration.php');

// Get trend data
$trends = local_security_dashboard_get_vulnerability_trends($start_date, time());
$monthly_stats = local_security_dashboard_get_monthly_statistics($start_date, time());
$vulnerability_types = local_security_dashboard_get_vulnerability_types($start_date, time());

echo $OUTPUT->header();

// Overall Statistics
echo html_writer::start_div('card');
echo html_writer::start_div('card-header');
echo html_writer::tag('h4', "Vulnerability Trends (Last $days Days)");
echo html_writer::end_div();

echo html_writer::start_div('card-body');

$stats_html = <<<HTML
<div class="row mb-3">
    <div class="col-md-3">
        <div class="stat-box text-center">
            <h3 class="text-danger">{$trends['total_vulnerabilities']}</h3>
            <p>Total Vulnerabilities</p>
        </div>
    </div>
    <div class="col-md-3">
        <div class="stat-box text-center">
            <h3 class="text-danger">{$trends['high_count']}</h3>
            <p>High Risk</p>
        </div>
    </div>
    <div class="col-md-3">
        <div class="stat-box text-center">
            <h3 class="text-warning">{$trends['medium_count']}</h3>
            <p>Medium Risk</p>
        </div>
    </div>
    <div class="col-md-3">
        <div class="stat-box text-center">
            <h3 class="text-info">{$trends['low_count']}</h3>
            <p>Low Risk</p>
        </div>
    </div>
</div>

<div class="mb-3">
    <p class="text-muted">
        <strong>Trend:</strong> 
        {$trends['trend_direction']} 
        {$trends['trend_percentage']}% 
        from previous period
    </p>
</div>
HTML;

echo $stats_html;
echo html_writer::end_div();
echo html_writer::end_div();

// Trend Chart
echo html_writer::start_div('card mt-4');
echo html_writer::start_div('card-header');
echo html_writer::tag('h5', 'Vulnerability Over Time');
echo html_writer::end_div();
echo html_writer::start_div('card-body');

// Chart.js data
$dates = [];
$high_data = [];
$medium_data = [];
$low_data = [];

if (!empty($trends['daily_data'])) {
    foreach ($trends['daily_data'] as $day) {
        $dates[] = date('M d', (int)$day['date']);
        $high_data[] = (int)$day['high'];
        $medium_data[] = (int)$day['medium'];
        $low_data[] = (int)$day['low'];
    }
}

// Convert to JSON for JavaScript
$dates_json = json_encode($dates);
$high_json = json_encode($high_data);
$medium_json = json_encode($medium_data);
$low_json = json_encode($low_data);

$chart_html = <<<HTML
<canvas id="trendChart"></canvas>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
const ctx = document.getElementById('trendChart').getContext('2d');
const trendChart = new Chart(ctx, {
    type: 'line',
    data: {
        labels: $dates_json,
        datasets: [
            {
                label: 'High Risk',
                data: $high_json,
                borderColor: '#dc3545',
                backgroundColor: 'rgba(220, 53, 69, 0.1)',
                tension: 0.4
            },
            {
                label: 'Medium Risk',
                data: $medium_json,
                borderColor: '#ffc107',
                backgroundColor: 'rgba(255, 193, 7, 0.1)',
                tension: 0.4
            },
            {
                label: 'Low Risk',
                data: $low_json,
                borderColor: '#17a2b8',
                backgroundColor: 'rgba(23, 162, 184, 0.1)',
                tension: 0.4
            }
        ]
    },
    options: {
        responsive: true,
        plugins: {
            legend: { position: 'top' }
        },
        scales: {
            y: { beginAtZero: true }
        }
    }
});
</script>
HTML;

echo $chart_html;
echo html_writer::end_div();
echo html_writer::end_div();

// Top Vulnerabilities
echo html_writer::start_div('card mt-4');
echo html_writer::start_div('card-header');
echo html_writer::tag('h5', 'Top Vulnerability Types');
echo html_writer::end_div();
echo html_writer::start_div('card-body');

$table = new html_table();
$table->head = ['Vulnerability Type', 'Count', 'Severity', 'Action'];
$table->data = [];

foreach ($vulnerability_types as $vuln) {
    $severity_class = match($vuln['avg_severity']) {
        'High' => 'badge-danger',
        'Medium' => 'badge-warning',
        'Low' => 'badge-info',
        default => 'badge-secondary'
    };
    
    $actions = html_writer::link(
        new moodle_url('/local/security_dashboard/zap_vulnerability_detail.php', 
            ['vuln_type' => urlencode($vuln['type'])]),
        'View Details',
        ['class' => 'btn btn-sm btn-info']
    );
    
    $table->data[] = [
        $vuln['type'],
        $vuln['count'],
        "<span class='badge {$severity_class}'>{$vuln['avg_severity']}</span>",
        $actions
    ];
}

echo html_writer::table($table);
echo html_writer::end_div();
echo html_writer::end_div();

// Monthly Summary
echo html_writer::start_div('card mt-4');
echo html_writer::start_div('card-header');
echo html_writer::tag('h5', 'Monthly Summary');
echo html_writer::end_div();
echo html_writer::start_div('card-body');

$summary_table = new html_table();
$summary_table->head = ['Month', 'High', 'Medium', 'Low', 'Total', 'Status'];
$summary_table->data = [];

foreach ($monthly_stats as $month) {
    $status = $month['total'] === 0 ? 
        '<span class="badge badge-success">Clean</span>' :
        '<span class="badge badge-warning">Issues Found</span>';
    
    $summary_table->data[] = [
        date('F Y', $month['timestamp']),
        "<span class='text-danger'>{$month['high']}</span>",
        "<span class='text-warning'>{$month['medium']}</span>",
        "<span class='text-info'>{$month['low']}</span>",
        $month['total'],
        $status
    ];
}

echo html_writer::table($summary_table);
echo html_writer::end_div();
echo html_writer::end_div();

// Export options
echo html_writer::start_div('mt-4');
echo html_writer::link(
    new moodle_url('/local/security_dashboard/zap_trends_export.php', 
        ['days' => $days, 'format' => 'pdf']),
    '<i class="fa fa-pdf"></i> Export as PDF',
    ['class' => 'btn btn-secondary']
);
echo ' ';
echo html_writer::link(
    new moodle_url('/local/security_dashboard/zap_trends_export.php',
        ['days' => $days, 'format' => 'csv']),
    '<i class="fa fa-download"></i> Export as CSV',
    ['class' => 'btn btn-secondary']
);
echo html_writer::end_div();

echo $OUTPUT->footer();
