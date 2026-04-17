<?php
/**
 * Download PDF report handler
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

// Get parameters
$scan_id = required_param('scan_id', PARAM_TEXT);
$type = optional_param('type', 'compliance', PARAM_TEXT); // Force compliance
$framework = optional_param('framework', 'PCI-DSS', PARAM_TEXT); // Force PCI-DSS

// Validate and enforce PCI-DSS only
if ($framework !== 'PCI-DSS') {
    $framework = 'PCI-DSS';
}
if ($type !== 'compliance') {
    $type = 'compliance';
}

// Get proxy URL
$proxy_url = get_config('local_security_dashboard', 'proxy_url');

if (empty($proxy_url)) {
    die('Proxy URL not configured');
}

try {
    // Build report URL - PCI-DSS compliance only
    $url = rtrim($proxy_url, '/') . '/reports/compliance?scan_id=' . urlencode($scan_id) . '&framework=' . urlencode($framework);
    $filename = 'PCI-DSS_compliance_' . $scan_id . '.pdf';
    
    // Fetch PDF from proxy
    $curl = new curl();
    $pdf_content = $curl->get($url);
    
    if ($curl->get_errno()) {
        die('Error fetching report: ' . $curl->error);
    }
    
    // Check if response is PDF
    $info = $curl->get_info();
    if (!isset($info['content_type']) || strpos($info['content_type'], 'application/pdf') === false) {
        // Not a PDF, might be an error message
        $error_data = json_decode($pdf_content, true);
        if (isset($error_data['detail'])) {
            die('Report generation failed: ' . $error_data['detail']);
        } else {
            die('Failed to generate report. Please ensure the scan exists and try again.');
        }
    }
    
    // Send PDF to browser
    header('Content-Type: application/pdf');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . strlen($pdf_content));
    header('Cache-Control: private, max-age=0, must-revalidate');
    header('Pragma: public');
    
    echo $pdf_content;
    exit;
    
} catch (Exception $e) {
    die('Error: ' . $e->getMessage());
}
