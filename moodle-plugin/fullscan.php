<?php
/**
 * Full Site Scan page - Crawl and scan entire site
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

$PAGE->set_url(new moodle_url('/local/security_dashboard/fullscan.php'));
$PAGE->set_context(context_system::instance());
$PAGE->set_title('Full Site Security Scan');
$PAGE->set_heading('Full Site Security Scan');
$PAGE->set_pagelayout('admin');

// Add custom CSS
$PAGE->requires->css('/local/security_dashboard/styles.css');

// Handle form submission
$scan_triggered = false;
$scan_result = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST' && confirm_sesskey()) {
    $max_depth = optional_param('max_depth', 2, PARAM_INT);
    $max_pages = optional_param('max_pages', 30, PARAM_INT);
    
    $scan_result = local_security_dashboard_trigger_full_scan($max_depth, $max_pages);
    $scan_triggered = true;
}

echo $OUTPUT->header();

?>

<div class="alert alert-info">
    <h4><i class="fa fa-info-circle"></i> Full Site Scan</h4>
    <p>This will automatically crawl your Moodle site to discover all endpoints and scan them for vulnerabilities.</p>
    <ul>
        <li><strong>Automatic Discovery:</strong> Finds all pages, forms, and parameters</li>
        <li><strong>Comprehensive Scanning:</strong> Tests all discovered endpoints</li>
        <li><strong>Risk Scoring:</strong> Calculates CVSS-based risk scores</li>
        <li><strong>Priority Ranking:</strong> Sorts findings by risk level</li>
    </ul>
    <p><strong>Note:</strong> This may take several minutes depending on site size.</p>
</div>

<!-- Scan Configuration Form -->
<form method="post" action="" class="mform">
    <input type="hidden" name="sesskey" value="<?php echo sesskey(); ?>">
    
    <div class="form-group row">
        <label for="max_depth" class="col-md-3 col-form-label">
            Maximum Crawl Depth
        </label>
        <div class="col-md-9">
            <input type="number" name="max_depth" id="max_depth" class="form-control" 
                   value="2" min="1" max="5">
            <small class="form-text text-muted">
                How deep to crawl (1-5). Deeper = more pages but slower.
            </small>
        </div>
    </div>
    
    <div class="form-group row">
        <label for="max_pages" class="col-md-3 col-form-label">
            Maximum Pages
        </label>
        <div class="col-md-9">
            <input type="number" name="max_pages" id="max_pages" class="form-control" 
                   value="30" min="10" max="100">
            <small class="form-text text-muted">
                Maximum number of pages to scan (10-100).
            </small>
        </div>
    </div>
    
    <div class="form-group row">
        <div class="col-md-9 offset-md-3">
            <button type="submit" class="btn btn-primary">
                <i class="fa fa-search"></i> Start Full Site Scan
            </button>
            <a href="<?php echo new moodle_url('/local/security_dashboard/index.php'); ?>" 
               class="btn btn-secondary">
                <i class="fa fa-arrow-left"></i> Back to Dashboard
            </a>
        </div>
    </div>
</form>

<?php

// Display scan results
if ($scan_triggered && $scan_result) {
    if (isset($scan_result['error'])) {
        echo '<div class="alert alert-danger">';
        echo '<h4>Scan Failed</h4>';
        echo '<p>' . htmlspecialchars($scan_result['error']) . '</p>';
        echo '</div>';
    } else {
        echo '<div class="alert alert-success">';
        echo '<h4><i class="fa fa-check-circle"></i> Scan completed successfully!</h4>';
        echo '</div>';
        
        // Crawl Statistics
        echo '<div class="card mb-3">';
        echo '<div class="card-header"><h5>Crawl Statistics</h5></div>';
        echo '<div class="card-body">';
        echo '<div class="row">';
        echo '<div class="col-md-3">';
        echo '<div class="stat-box">';
        echo '<h3>' . $scan_result['endpoints_discovered'] . '</h3>';
        echo '<p>Endpoints Discovered</p>';
        echo '</div>';
        echo '</div>';
        echo '<div class="col-md-3">';
        echo '<div class="stat-box">';
        echo '<h3>' . $scan_result['endpoints_scanned'] . '</h3>';
        echo '<p>Endpoints Scanned</p>';
        echo '</div>';
        echo '</div>';
        echo '<div class="col-md-3">';
        echo '<div class="stat-box">';
        echo '<h3>' . $scan_result['total_findings'] . '</h3>';
        echo '<p>Total Findings</p>';
        echo '</div>';
        echo '</div>';
        echo '<div class="col-md-3">';
        echo '<div class="stat-box">';
        echo '<h3>' . $scan_result['scan_id'] . '</h3>';
        echo '<p>Scan ID</p>';
        echo '</div>';
        echo '</div>';
        echo '</div>';
        echo '</div>';
        echo '</div>';
        
        // Vulnerability Summary
        $summary = $scan_result['summary'];
        echo '<div class="card mb-3">';
        echo '<div class="card-header"><h5>Vulnerability Summary</h5></div>';
        echo '<div class="card-body">';
        echo '<div class="row text-center">';
        
        echo '<div class="col">';
        echo '<span class="badge badge-critical" style="font-size: 1.5em; padding: 10px 20px;">' . $summary['critical'] . '</span>';
        echo '<p class="mt-2">Critical</p>';
        echo '</div>';
        
        echo '<div class="col">';
        echo '<span class="badge badge-high" style="font-size: 1.5em; padding: 10px 20px;">' . $summary['high'] . '</span>';
        echo '<p class="mt-2">High</p>';
        echo '</div>';
        
        echo '<div class="col">';
        echo '<span class="badge badge-medium" style="font-size: 1.5em; padding: 10px 20px;">' . $summary['medium'] . '</span>';
        echo '<p class="mt-2">Medium</p>';
        echo '</div>';
        
        echo '<div class="col">';
        echo '<span class="badge badge-low" style="font-size: 1.5em; padding: 10px 20px;">' . $summary['low'] . '</span>';
        echo '<p class="mt-2">Low</p>';
        echo '</div>';
        
        echo '<div class="col">';
        echo '<span class="badge badge-info" style="font-size: 1.5em; padding: 10px 20px;">' . $summary['info'] . '</span>';
        echo '<p class="mt-2">Info</p>';
        echo '</div>';
        
        echo '</div>';
        echo '</div>';
        echo '</div>';
        
        // Top 10 Risks
        if (!empty($scan_result['top_risks'])) {
            echo '<div class="card mb-3">';
            echo '<div class="card-header"><h5>Top 10 Highest Risk Findings</h5></div>';
            echo '<div class="card-body">';
            echo '<div class="table-responsive">';
            echo '<table class="table table-striped">';
            echo '<thead>';
            echo '<tr>';
            echo '<th>Priority</th>';
            echo '<th>Severity</th>';
            echo '<th>Category</th>';
            echo '<th>Description</th>';
            echo '<th>Risk Score</th>';
            echo '<th>CVSS</th>';
            echo '</tr>';
            echo '</thead>';
            echo '<tbody>';
            
            foreach ($scan_result['top_risks'] as $index => $finding) {
                $severity = $finding['severity'] ?? 'Info';
                $severity_lower = strtolower($severity);
                $badge_class = 'badge-' . $severity_lower;
                
                $risk_score = $finding['risk_score'] ?? 0;
                $cvss_score = $finding['cvss_score'] ?? 0;
                $priority = $finding['priority'] ?? 5;
                
                echo '<tr>';
                echo '<td><span class="badge badge-dark">' . $priority . '</span></td>';
                echo '<td><span class="badge ' . $badge_class . '">' . htmlspecialchars($severity) . '</span></td>';
                echo '<td>' . htmlspecialchars($finding['category'] ?? 'Unknown') . '</td>';
                echo '<td>' . htmlspecialchars($finding['description'] ?? '') . '</td>';
                echo '<td><strong>' . number_format($risk_score, 1) . '</strong></td>';
                echo '<td>' . number_format($cvss_score, 1) . '</td>';
                echo '</tr>';
            }
            
            echo '</tbody>';
            echo '</table>';
            echo '</div>';
            echo '</div>';
            echo '</div>';
        }
        
        // All Findings (limited to 50)
        if (!empty($scan_result['findings'])) {
            $findings_count = count($scan_result['findings']);
            echo '<div class="card">';
            echo '<div class="card-header">';
            echo '<h5>All Findings (Showing ' . min($findings_count, 50) . ' of ' . $scan_result['total_findings'] . ')</h5>';
            echo '</div>';
            echo '<div class="card-body">';
            echo '<div class="table-responsive">';
            echo '<table class="table table-striped">';
            echo '<thead>';
            echo '<tr>';
            echo '<th>Severity</th>';
            echo '<th>Category</th>';
            echo '<th>Description</th>';
            echo '<th>Evidence</th>';
            echo '<th>Risk</th>';
            echo '</tr>';
            echo '</thead>';
            echo '<tbody>';
            
            foreach (array_slice($scan_result['findings'], 0, 50) as $finding) {
                $severity = $finding['severity'] ?? 'Info';
                $severity_lower = strtolower($severity);
                $badge_class = 'badge-' . $severity_lower;
                $risk_score = $finding['risk_score'] ?? 0;
                
                echo '<tr>';
                echo '<td><span class="badge ' . $badge_class . '">' . htmlspecialchars($severity) . '</span></td>';
                echo '<td>' . htmlspecialchars($finding['category'] ?? 'Unknown') . '</td>';
                echo '<td>' . htmlspecialchars($finding['description'] ?? '') . '</td>';
                echo '<td><small>' . htmlspecialchars(substr($finding['evidence'] ?? '', 0, 100)) . '...</small></td>';
                echo '<td>' . number_format($risk_score, 1) . '</td>';
                echo '</tr>';
            }
            
            echo '</tbody>';
            echo '</table>';
            echo '</div>';
            echo '</div>';
            echo '</div>';
        }
    }
}

echo $OUTPUT->footer();
