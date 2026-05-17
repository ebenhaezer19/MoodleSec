#!/bin/bash

# Create backup
cp /var/www/html/moodle/public/local/security_dashboard/lib.php /var/www/html/moodle/public/local/security_dashboard/lib.php.backup

# Apply the fix using sed
# Find the old function and replace with new one

cat > /tmp/new_get_logs.php << 'EOFNEW'
function local_security_dashboard_get_logs($limit = 100) {
    global $DB;
    
    $logs = [];
    
    // 1. Get logs from proxy service
    $proxy_url = get_config('local_security_dashboard', 'proxy_url');
    
    if (!empty($proxy_url)) {
        $url = rtrim($proxy_url, '/') . '/logs?limit=' . $limit;
        
        try {
            $curl = new curl();
            $response = $curl->get($url);
            
            if (!$curl->get_errno()) {
                $proxy_data = json_decode($response, true);
                if (isset($proxy_data['logs']) && is_array($proxy_data['logs'])) {
                    foreach ($proxy_data['logs'] as $log) {
                        $logs[] = [
                            'type' => $log['type'] ?? 'proxy_transaction',
                            'timestamp' => date('Y-m-d H:i:s', $log['timestamp'] ?? time()),
                            'details' => $log['details'] ?? '',
                            'url' => $log['url'] ?? '',
                            'scan_id' => null,
                            'findings' => 0,
                            'critical' => 0,
                            'high' => 0,
                            'medium' => 0,
                            'low' => 0,
                            'source' => 'proxy'
                        ];
                    }
                }
            }
        } catch (Exception $e) {
            // Continue even if proxy fails
        }
    }
    
    // 2. Get ZAP scans from database
    try {
        $zap_scans = $DB->get_records('local_security_scans', 
            [], 'timecreated DESC', '*', 0, $limit);
        
        foreach ($zap_scans as $scan) {
            $logs[] = [
                'type' => $scan->scan_type ?? 'full_site_scan',
                'timestamp' => date('Y-m-d H:i:s', $scan->timecreated),
                'details' => 'Scan ID: ' . $scan->scan_id . ' | Findings: ' . $scan->total_findings,
                'url' => $scan->target_url,
                'scan_id' => $scan->scan_id,
                'findings' => $scan->total_findings,
                'critical' => $scan->critical_count ?? 0,
                'high' => $scan->high_count ?? 0,
                'medium' => $scan->medium_count ?? 0,
                'low' => $scan->low_count ?? 0,
                'source' => 'zap'
            ];
        }
    } catch (Exception $e) {
        error_log('Error fetching ZAP scans: ' . $e->getMessage());
    }
    
    // 3. Sort by timestamp descending and limit results
    usort($logs, function($a, $b) {
        return strtotime($b['timestamp']) - strtotime($a['timestamp']);
    });
    
    $logs = array_slice($logs, 0, $limit);
    
    return ['logs' => $logs, 'total' => count($logs)];
}
EOFNEW

# Run PHP to do the replacement
php << 'EOFPHP'
<?php
$file = '/var/www/html/moodle/public/local/security_dashboard/lib.php';
$content = file_get_contents($file);

// Find and replace the function
$pattern = '/function local_security_dashboard_get_logs\(\$limit = 100\) \{.*?\n\}/s';

// Check how much we need to replace - find opening brace and count closing braces
$start = strpos($content, 'function local_security_dashboard_get_logs($limit = 100)');
if ($start === false) {
    echo "ERROR: Function not found!\n";
    exit(1);
}

// Find the closing brace of this function
$open_braces = 0;
$found_open = false;
$i = $start;
$end = -1;

while ($i < strlen($content)) {
    if ($content[$i] === '{') {
        $open_braces++;
        $found_open = true;
    } elseif ($content[$i] === '}') {
        $open_braces--;
        if ($found_open && $open_braces === 0) {
            $end = $i + 1;
            break;
        }
    }
    $i++;
}

if ($end === -1) {
    echo "ERROR: Could not find end of function!\n";
    exit(1);
}

// Get the new function
$new_function = file_get_contents('/tmp/new_get_logs.php');

// Replace
$new_content = substr_replace($content, $new_function, $start, $end - $start);

// Write back
if (file_put_contents($file, $new_content)) {
    echo "✅ Successfully updated lib.php\n";
    echo "   - Replaced old get_logs function\n";
    echo "   - Now queries both Proxy AND Database\n";
    echo "   - Backup saved to lib.php.backup\n";
} else {
    echo "ERROR: Could not write to file!\n";
    exit(1);
}
?>
EOFPHP
