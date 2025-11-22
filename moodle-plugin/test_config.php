<?php
/**
 * Test configuration and connectivity
 */

require_once(__DIR__ . '/../../../config.php');
require_once($CFG->libdir . '/filelib.php');

// Check proxy URL configuration
$proxy_url = get_config('local_security_dashboard', 'proxy_url');

echo "<h2>Configuration Test</h2>";
echo "<p><strong>Proxy URL:</strong> " . ($proxy_url ? htmlspecialchars($proxy_url) : '<span style="color:red;">NOT CONFIGURED</span>') . "</p>";

if (empty($proxy_url)) {
    echo "<p style='color:red;'><strong>ERROR:</strong> Proxy URL is not configured!</p>";
    echo "<p>Go to: Site administration → Plugins → Local plugins → Security Dashboard → Settings</p>";
    echo "<p>Set proxy_url to: <code>http://localhost:8999</code></p>";
    exit;
}

// Test connectivity
echo "<h3>Testing Connectivity...</h3>";

$test_url = rtrim($proxy_url, '/') . '/health';
echo "<p>Testing: <code>" . htmlspecialchars($test_url) . "</code></p>";

try {
    $curl = new curl();
    $response = $curl->get($test_url);
    
    if ($curl->get_errno()) {
        echo "<p style='color:red;'><strong>ERROR:</strong> " . htmlspecialchars($curl->error) . "</p>";
        echo "<p>Make sure proxy is running: <code>cd ~/TA/adaptive-moodle-security/MoodleSec/proxy && python app.py</code></p>";
    } else {
        echo "<p style='color:green;'><strong>SUCCESS:</strong> Connected to proxy!</p>";
        echo "<p>Response: <pre>" . htmlspecialchars($response) . "</pre></p>";
        
        // Test scan-auth endpoint
        echo "<h3>Testing /scan-auth endpoint...</h3>";
        $scan_url = rtrim($proxy_url, '/') . '/scan-auth';
        echo "<p>Testing: <code>" . htmlspecialchars($scan_url) . "</code></p>";
        
        $scan_response = $curl->post($scan_url, '');
        
        if ($curl->get_errno()) {
            echo "<p style='color:red;'><strong>ERROR:</strong> " . htmlspecialchars($curl->error) . "</p>";
        } else {
            echo "<p style='color:green;'><strong>SUCCESS:</strong> Scan endpoint accessible!</p>";
            echo "<p>Response preview: <pre>" . htmlspecialchars(substr($scan_response, 0, 500)) . "...</pre></p>";
        }
    }
} catch (Exception $e) {
    echo "<p style='color:red;'><strong>EXCEPTION:</strong> " . htmlspecialchars($e->getMessage()) . "</p>";
}

echo "<hr>";
echo "<p><a href='/local/security_dashboard/auth_scan.php'>← Back to Auth & API Scan</a></p>";
?>
