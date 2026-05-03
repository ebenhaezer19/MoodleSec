<?php
/**
 * Admin Area Security Scan - Authenticated Access Scanning
 * 
 * Performs security scanning of admin areas in the Moodle installation.
 * Logs in with provided credentials and scans all accessible admin endpoints and areas.
 */

require_once('../../config.php');
require_once('lib.php');

// Require admin access
require_login();
$context = context_system::instance();
require_capability('moodle/site:config', $context);

// Page setup
$PAGE->set_context($context);
$PAGE->set_url(new moodle_url('/local/security_dashboard/native_auth_scan.php'));
$PAGE->set_title(get_string('pluginname', 'local_security_dashboard') . ' - Admin Area Scan');
$PAGE->set_heading('Admin Area Security Scan (Authenticated Access)');

echo $OUTPUT->header();

// Handle scan trigger
$scan_triggered = false;
$scan_result = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Get parameters from form
    $max_depth = intval($_POST['max_depth'] ?? 2);
    $max_pages = intval($_POST['max_pages'] ?? 50);
    $username = $_POST['username'] ?? 'admin';
    $password = $_POST['password'] ?? 'Admin@1234';
    
    // Trigger scan
    $scan_result = local_security_dashboard_trigger_native_auth_scan($max_depth, $max_pages, $username, $password);
    $scan_triggered = true;
}

// Display scan form
?>
<div class="card mb-4">
    <div class="card-header bg-primary text-white">
        <h3 class="mb-0">Admin Area Security Scan</h3>
    </div>
    <div class="card-body">
        <p class="lead">
            This scan performs <strong>authenticated</strong> vulnerability testing of your Moodle installation.
        </p>
        
        <div class="alert alert-info">
            <strong>How it works:</strong>
            <ol>
                <li>Logs in to Moodle as the specified user (default: admin)</li>
                <li>Crawls all pages accessible to that user (authenticated areas)</li>
                <li>Scans discovered endpoints for vulnerabilities</li>
                <li>Compares with unauthenticated crawl results to identify auth bypass issues</li>
                <li>Applies ML-based false positive filtering</li>
            </ol>
        </div>
        
        <h4>Benefits over unauthenticated scanning:</h4>
        <ul>
            <li><strong>More endpoints:</strong> Discovers pages only visible when logged in</li>
            <li><strong>Better coverage:</strong> Tests authenticated workflows and forms</li>
            <li><strong>Auth bypass detection:</strong> Identifies access control vulnerabilities</li>
            <li><strong>Session testing:</strong> Validates session management security</li>
        </ul>
    </div>
</div>

<!-- Scan Form -->
<div class="card mb-4">
    <div class="card-header bg-secondary text-white">
        <h4 class="mb-0">Scan Configuration</h4>
    </div>
    <div class="card-body">
        <form method="POST" class="form-horizontal">
            <div class="form-group row mb-3">
                <label for="max_depth" class="col-sm-3 col-form-label">Maximum Crawl Depth:</label>
                <div class="col-sm-9">
                    <input type="number" 
                           name="max_depth" 
                           id="max_depth" 
                           min="1" 
                           max="10" 
                           value="2" 
                           class="form-control" 
                           required>
                    <small class="form-text text-muted">How deep to follow links (higher = slower but more endpoints)</small>
                </div>
            </div>
            
            <div class="form-group row mb-3">
                <label for="max_pages" class="col-sm-3 col-form-label">Maximum Pages to Crawl:</label>
                <div class="col-sm-9">
                    <input type="number" 
                           name="max_pages" 
                           id="max_pages" 
                           min="10" 
                           max="200" 
                           value="50" 
                           class="form-control" 
                           required>
                    <small class="form-text text-muted">Limit on number of pages to crawl (prevents timeout)</small>
                </div>
            </div>
            
            <div class="form-group row mb-3">
                <label for="username" class="col-sm-3 col-form-label">Login Username:</label>
                <div class="col-sm-9">
                    <input type="text" 
                           name="username" 
                           id="username" 
                           value="admin" 
                           class="form-control" 
                           required>
                    <small class="form-text text-muted">Username to login with for scanning</small>
                </div>
            </div>
            
            <div class="form-group row mb-3">
                <label for="password" class="col-sm-3 col-form-label">Login Password:</label>
                <div class="col-sm-9">
                    <input type="password" 
                           name="password" 
                           id="password" 
                           value="Admin@1234" 
                           class="form-control" 
                           required>
                    <small class="form-text text-muted">Password for the user account</small>
                </div>
            </div>
            
            <div class="form-group row">
                <div class="col-sm-9 offset-sm-3">
                    <button type="submit" name="submit" value="scan" class="btn btn-primary btn-lg">
                        <i class="fa fa-play"></i> Start Authenticated Scan
                    </button>
                    <small class="form-text text-muted d-block mt-2">
                        ⏱️ Typical scan time: 5-15 minutes (depends on site size)
                    </small>
                </div>
            </div>
        </form>
    </div>
</div>

<?php

// Display scan results
if ($scan_triggered && $scan_result) {
    if (isset($scan_result['error'])) {
        echo '<div class="alert alert-danger" role="alert">
            <strong>Scan Error:</strong> ' . htmlspecialchars($scan_result['error']) . '
        </div>';
    } else {
        // Success - display results
        $scan_id = $scan_result['scan_id'] ?? 'unknown';
        $endpoints_discovered = $scan_result['endpoints_discovered'] ?? 0;
        $endpoints_scanned = $scan_result['endpoints_scanned'] ?? 0;
        $pages_visited = $scan_result['pages_visited'] ?? 0;
        $total_findings = $scan_result['total_findings'] ?? 0;
        $summary = $scan_result['summary'] ?? [];
        $username_used = $scan_result['username'] ?? $username;
        
        ?>
        <div class="card mb-4 border-success">
            <div class="card-header bg-success text-white">
                <h4 class="mb-0">✓ Scan Completed Successfully</h4>
            </div>
            <div class="card-body">
                <p class="lead">Authenticated scan completed with findings.</p>
                
                <div class="row mb-4">
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h5 class="card-title">Pages Visited</h5>
                                <h3 class="text-primary"><?php echo $pages_visited; ?></h3>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h5 class="card-title">Endpoints Discovered</h5>
                                <h3 class="text-info"><?php echo $endpoints_discovered; ?></h3>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h5 class="card-title">Endpoints Scanned</h5>
                                <h3 class="text-warning"><?php echo $endpoints_scanned; ?></h3>
                            </div>
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="card text-center">
                            <div class="card-body">
                                <h5 class="card-title">Total Findings</h5>
                                <h3 class="text-danger"><?php echo $total_findings; ?></h3>
                            </div>
                        </div>
                    </div>
                </div>
                
                <h5>Finding Summary by Severity:</h5>
                <div class="row">
                    <div class="col-md-6">
                        <table class="table table-sm">
                            <tr class="table-danger">
                                <td><strong>🔴 Critical:</strong></td>
                                <td><strong><?php echo $summary['critical'] ?? 0; ?></strong></td>
                            </tr>
                            <tr class="table-warning">
                                <td><strong>🟠 High:</strong></td>
                                <td><strong><?php echo $summary['high'] ?? 0; ?></strong></td>
                            </tr>
                            <tr class="table-warning">
                                <td><strong>🟡 Medium:</strong></td>
                                <td><strong><?php echo $summary['medium'] ?? 0; ?></strong></td>
                            </tr>
                        </table>
                    </div>
                    <div class="col-md-6">
                        <table class="table table-sm">
                            <tr class="table-info">
                                <td><strong>🟢 Low:</strong></td>
                                <td><strong><?php echo $summary['low'] ?? 0; ?></strong></td>
                            </tr>
                            <tr class="table-secondary">
                                <td><strong>⚪ Info:</strong></td>
                                <td><strong><?php echo $summary['info'] ?? 0; ?></strong></td>
                            </tr>
                            <tr class="table-light">
                                <td><strong>📊 Total:</strong></td>
                                <td><strong><?php echo $total_findings; ?></strong></td>
                            </tr>
                        </table>
                    </div>
                </div>
                
                <hr>
                <p class="text-muted mt-3"><small>
                    <strong>Scan ID:</strong> <?php echo htmlspecialchars($scan_id); ?><br>
                    <strong>Username:</strong> <?php echo htmlspecialchars($username_used); ?><br>
                    <strong>Status:</strong> Completed (Results saved to database)
                </small></p>
            </div>
        </div>
        
        <div class="card mt-4">
            <div class="card-header">
                <h5 class="mb-0">Next Steps</h5>
            </div>
            <div class="card-body">
                <ul>
                    <li>Review findings in the <a href="reports.php">Reports</a> page</li>
                    <li>Compare with unauthenticated scan results to identify auth bypass issues</li>
                    <li>See endpoint improvement with: Pages Visited / Endpoints Discovered metrics</li>
                    <li>Export detailed report for stakeholders</li>
                </ul>
                <!-- L2-L7: Direct links to detailed findings -->
                <div class="mt-3 d-flex gap-2" style="gap:10px;">
                    <a href="scan_findings.php?scan_id=<?php echo urlencode($scan_id); ?>"
                       class="btn btn-info">
                        📋 View Detailed Findings (PoC + Recommendations)
                    </a>
                    <a href="download_report.php?scan_id=<?php echo urlencode($scan_id); ?>&type=compliance&framework=PCI-DSS"
                       class="btn btn-primary" target="_blank">
                        📄 Download PDF Report
                    </a>
                </div>
            </div>
        </div>
        <?php
    }
}

echo $OUTPUT->footer();
?>
