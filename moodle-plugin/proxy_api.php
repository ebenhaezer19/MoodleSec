<?php
/**
 * PHP-side proxy for scan proxy API calls (avoids CORS / port issues in browser)
 *
 * Actions:
 *   verify-fix   POST  ?action=verify-fix&finding_id=X&scan_id=Y
 *   scan-data    GET   ?action=scan-data&scan_id=Y
 *
 * @package    local_security_dashboard
 * @copyright  2024 Krisopras & Nathanael
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

define('AJAX_SCRIPT', true);

require_once('../../config.php');
require_once('lib.php');

require_login();
require_capability('local/security_dashboard:scan', context_system::instance());

header('Content-Type: application/json');

$action     = required_param('action', PARAM_ALPHANUMEXT);
$proxy_base = rtrim(get_config('local_security_dashboard', 'proxy_url') ?: 'http://localhost:8998', '/');

$curl = new curl();
$curl->setopt(['CURLOPT_TIMEOUT' => 30, 'CURLOPT_CONNECTTIMEOUT' => 5]);

switch ($action) {

    // ------------------------------------------------------------------
    // L7: Verify Fix — re-scan a specific finding
    // ------------------------------------------------------------------
    case 'verify-fix':
        $finding_id = required_param('finding_id', PARAM_TEXT);
        $scan_id    = optional_param('scan_id', '', PARAM_TEXT);

        $url = $proxy_base . '/api/verify-fix/' . urlencode($finding_id);
        if ($scan_id) {
            $url .= '?scan_id=' . urlencode($scan_id);
        }

        $curl->setopt(['CURLOPT_CUSTOMREQUEST' => 'POST']);
        $response = $curl->post($url, '');
        $info     = $curl->get_info();

        if ($curl->get_errno()) {
            echo json_encode([
                'status'  => 'error',
                'message' => 'Proxy unreachable: ' . $curl->error,
            ]);
        } else {
            // Pass through proxy response directly
            echo $response ?: json_encode(['status' => 'error', 'message' => 'Empty response from proxy']);
        }
        break;

    // ------------------------------------------------------------------
    // Get scan enriched data
    // ------------------------------------------------------------------
    case 'scan-data':
        $scan_id  = required_param('scan_id', PARAM_TEXT);
        $response = $curl->get($proxy_base . '/api/scan/' . urlencode($scan_id));
        echo $response ?: json_encode(['error' => 'Empty response']);
        break;

    // ------------------------------------------------------------------
    // Save OpenAI API key → send to proxy to apply immediately
    // ------------------------------------------------------------------
    case 'save-openai-key':
        require_sesskey();
        $api_key = required_param('api_key', PARAM_RAW);

        if (strlen($api_key) < 20 || !str_starts_with(trim($api_key), 'sk-')) {
            echo json_encode(['success' => false, 'error' => 'Invalid API key format (must start with sk-)']);
            break;
        }

        $api_key = trim($api_key);

        // Save to Moodle config
        set_config('openai_api_key', $api_key, 'local_security_dashboard');

        // Push to proxy via API so it takes effect immediately (no restart)
        $push_resp = $curl->post(
            $proxy_base . '/api/settings/openai-key',
            json_encode(['api_key' => $api_key]),
            ['CURLOPT_HTTPHEADER' => ['Content-Type: application/json']]
        );
        $push_data = json_decode($push_resp, true);

        echo json_encode([
            'success'     => true,
            'proxy_ack'   => $push_data['status'] ?? 'unknown',
            'message'     => 'API key saved. GPT mode will activate for new scans.',
        ]);
        break;

    // ------------------------------------------------------------------
    // Get current GPT status
    // ------------------------------------------------------------------
    case 'gpt-status':
        $response = $curl->get($proxy_base . '/api/settings/status');
        echo $response ?: json_encode(['gpt_active' => false]);
        break;

    default:
        echo json_encode(['error' => 'Unknown action: ' . $action]);
}
