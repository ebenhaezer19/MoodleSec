# ZAP Moodle Plugin Implementation Guide

## Quick Start

### 1. Install Plugin
```bash
# Copy plugin to Moodle data directory
cp -r moodle-plugin/ /path/to/moodle/local/security_dashboard/

# Navigate to Moodle admin > Notifications
# Click "Upgrade" to install plugin
```

### 2. Configure ZAP Server
```bash
# Start OWASP ZAP with API enabled
zaproxy -config api.disablekey=false -config api.key=1qlbij76v3j9c6ail8d0locm24 -port 8080
```

### 3. Configure Moodle Plugin
1. Go to Admin > Plugins > Local Plugins > Security Dashboard
2. Configure ZAP Settings:
   - ZAP Host: `localhost`
   - ZAP Port: `8080`
   - ZAP API Key: `1qlbij76v3j9c6ail8d0locm24`
3. Configure Scan Settings:
   - Spider Depth: `3` (adjust based on site size)
   - Policy: `medium`
4. Enable ML Filtering:
   - Check "Enable ML Filtering"
   - Set Confidence Threshold: `0.75`
5. Configure Notifications:
   - Enable "Email on High Risk Findings"
   - Add recipient emails (one per line)

## Admin Panel Access

### Access ZAP Features
1. Go to Admin > Security Dashboard > ZAP Scanner
2. Five main interfaces available:

#### Settings (settings_zap.php)
- URL: `/admin/settings.php?section=local_security_dashboard_zap`
- Configure ZAP connection and scan parameters
- Requires `local/security_dashboard:manage` capability

#### Scan Trigger (zap_scan.php)
- URL: `/local/security_dashboard/zap_scan.php`
- Start new vulnerability scans
- View recent scan history
- Requires `local/security_dashboard:scan` capability

#### Results (zap_results.php)
- URL: `/local/security_dashboard/zap_results.php`
- View detailed vulnerability findings
- Export to PDF/JSON
- Requires `local/security_dashboard:viewreports` capability

#### Trends (zap_trends.php)
- URL: `/local/security_dashboard/zap_trends.php`
- Analyze vulnerability trends over time
- Compare vulnerability types
- Export to CSV/PDF
- Requires `local/security_dashboard:viewreports` capability

#### Compliance (zap_compliance.php)
- URL: `/local/security_dashboard/zap_compliance.php`
- View compliance score and audit trail
- Track OWASP Top 10 coverage
- Export compliance certificate
- Requires `local/security_dashboard:viewreports` capability

## Development Integration

### Using Backend Functions

#### Check ZAP Connection
```php
require_once(__DIR__ . '/../../../config.php');
require_once(__DIR__ . '/../lib/zap_integration.php');

$status = local_security_dashboard_check_zap_status();

if ($status['connected']) {
    echo "ZAP is running version: " . $status['version'];
} else {
    echo "Cannot connect to ZAP at " . $status['host'] . ":" . $status['port'];
}
```

#### Trigger Scan
```php
$result = local_security_dashboard_trigger_zap_scan(
    'authenticated',  // scan type
    'http://localhost/course/view.php?id=1'  // target URL
);

if ($result['success']) {
    // Store results in database
    $scan_id = local_security_dashboard_store_scan($result);
    
    // Notify administrators
    local_security_dashboard_notify_findings($result);
    
    echo "Scan {$scan_id} completed";
    echo "Total findings: {$result['total_findings']}";
    echo "High risk: {$result['high_risk_findings']}";
} else {
    echo "Error: {$result['error']}";
}
```

#### Get Recent Scans
```php
$scans = local_security_dashboard_get_recent_scans(5);

foreach ($scans as $scan) {
    echo sprintf(
        "Scan %d: %s [%s] → %d findings",
        $scan->id,
        $scan->target_url,
        $scan->scan_type,
        $scan->total_findings
    );
}
```

#### Retrieve Findings
```php
$findings = local_security_dashboard_get_scan_findings($scan_id);

foreach ($findings as $finding) {
    echo sprintf(
        "%s (%s): %s",
        $finding->type,
        $finding->risk,
        $finding->url
    );
}
```

#### Analyze Trends
```php
$start = strtotime('-3 months');
$end = time();

$trends = local_security_dashboard_get_vulnerability_trends($start, $end);

echo "Total: {$trends['total_vulnerabilities']}";
echo "High: {$trends['high_count']}";
echo "Trend: {$trends['trend_direction']} ({$trends['trend_percentage']}%)";
```

#### Get Compliance Report
```php
$report = local_security_dashboard_get_compliance_report();

echo "Compliance Score: {$report['overall_score']}%";
echo "Framework: {$report['framework']}";
echo "Audit Status: {$report['audit_status']}";

// Access OWASP Top 10 coverage
foreach ($report['owasp_top10'] as $issue) {
    if ($issue['vulnerable']) {
        echo "⚠️  {$issue['name']}: {$issue['count']} findings";
    }
}
```

## Scheduling Automated Scans

### Using Moodle Web Cron
```php
// In your plugin's adhoc task class
class scan_moodle_task extends \core\task\adhoc_task {
    public function execute() {
        require_once(__DIR__ . '/../lib/zap_integration.php');
        
        // Trigger scan
        $result = local_security_dashboard_trigger_zap_scan(
            'unauthenticated',
            get_config('wwwroot')
        );
        
        if ($result['success']) {
            // Store and notify
            $scan_id = local_security_dashboard_store_scan($result);
            local_security_dashboard_notify_findings($result);
        }
    }
}

// Schedule task
$task = new \local_security_dashboard\task\scan_moodle_task();
\core\task\manager::queue_adhoc_task($task);
```

## API Examples

### Get Scan Status
```php
$status = local_security_dashboard_check_zap_status();
echo json_encode($status);

// Output:
// {
//   "connected": true,
//   "host": "localhost",
//   "port": 8080,
//   "version": "2.12.0"
// }
```

### Export Results to JSON
```php
$findings = local_security_dashboard_get_scan_findings($scan_id);
$data = [
    'scan_id' => $scan_id,
    'findings' => $findings,
    'exported_at' => date('Y-m-d H:i:s')
];

header('Content-Type: application/json');
echo json_encode($data);
```

### Generate CSV Report
```php
$types = local_security_dashboard_get_vulnerability_types($start, $end);

header('Content-Type: text/csv');
header('Content-Disposition: attachment; filename="vulnerabilities.csv"');

$fp = fopen('php://output', 'w');
fputcsv($fp, ['Vulnerability Type', 'Count', 'Severity']);

foreach ($types as $type) {
    fputcsv($fp, [
        $type['type'],
        $type['count'],
        $type['avg_severity']
    ]);
}
fclose($fp);
```

## Database Queries

### Find High-Risk Vulnerabilities
```php
global $DB;

$sql = "SELECT * FROM {local_security_dashboard_findings}
        WHERE risk = 'High' 
        AND is_false_positive = 0
        ORDER BY timecreated DESC";

$high_risk = $DB->get_records_sql($sql);
```

### Get Scan Duration Statistics
```php
$sql = "SELECT 
        AVG(duration) as avg_duration,
        MIN(duration) as min_duration,
        MAX(duration) as max_duration
        FROM {local_security_dashboard_scans}
        WHERE timecreated > ?";

$stats = $DB->get_record_sql($sql, [strtotime('-30 days')]);
```

### Track False Positives
```php
$sql = "SELECT COUNT(*) as fp_count
        FROM {local_security_dashboard_findings}
        WHERE is_false_positive = 1
        AND scan_id IN (
            SELECT id FROM {local_security_dashboard_scans}
            WHERE timecreated > ?
        )";

$fp_count = $DB->get_record_sql($sql, [strtotime('-7 days')]);
```

## Error Handling

### Catching Exceptions
```php
try {
    $result = local_security_dashboard_trigger_zap_scan('unauthenticated', $url);
    
    if (!$result['success']) {
        throw new Exception($result['error']);
    }
    
    $scan_id = local_security_dashboard_store_scan($result);
    
} catch (Exception $e) {
    echo "Scan failed: " . $e->getMessage();
    // Log error
    error_log("ZAP Scan Error: " . $e->getMessage());
}
```

### Handling Timeouts
```php
$timeout = 30; // seconds
set_time_limit($timeout + 60); // Add buffer

try {
    // Scan will auto-timeout after configured max_wait
    $result = local_security_dashboard_trigger_zap_scan(
        'unauthenticated',
        $target_url
    );
} catch (Exception $e) {
    if (strpos($e->getMessage(), 'timeout') !== false) {
        echo "Scan timed out - consider reducing spider depth";
    }
}
```

## Performance Optimization

### Batch Processing
```php
// Process multiple scans efficiently
$sites = ['site1.com', 'site2.com', 'site3.com'];

foreach ($sites as $site) {
    $result = local_security_dashboard_trigger_zap_scan('unauthenticated', $site);
    
    if ($result['success']) {
        local_security_dashboard_store_scan($result);
        // Wait to avoid overwhelming ZAP
        sleep(5);
    }
}
```

### Lazy Loading Results
```php
// Load findings in chunks for large result sets
$limit = 100;
$offset = 0;

while (true) {
    $findings = $DB->get_records('local_security_dashboard_findings',
        ['scan_id' => $scan_id],
        'sequence ASC',
        '*',
        $offset,
        $limit
    );
    
    if (empty($findings)) break;
    
    process_findings_batch($findings);
    $offset += $limit;
}
```

## Troubleshooting

### ZAP API Key Not Working
```
Fix:
1. Verify API key in /admin/settings.php
2. Check ZAP server was started with -config api.disablekey=false
3. Try restarting ZAP server
4. Check firewall allows connection
```

### Scans Timing Out
```
Reduce spider depth:
Settings → Scan Settings → Spider Depth = 2 (instead of 3)

Or increase max wait time in zap_integration.php:
$max_wait = 600; // 10 minutes
```

### No Findings Detected
```
Check:
1. Target URL is public and accessible
2. ZAP scanning policy includes relevant tests
3. Target has vulnerable code patterns
4. Try manual ZAP scan on target first
```

### Database Errors
```
Run upgrade:
1. Go to Admin → Notifications
2. Click "Upgrade" to re-run database migrations
3. Check error log for details
```

## Security Best Practices

1. **Restrict Access**
   - Only grant scan capability to trusted admins
   - Use Moodle roles and permissions

2. **Protect API Key**
   - Never hardcode API key in code
   - Use Moodle config() function
   - Rotate key regularly

3. **Audit Scanning**
   - Check audit trail in compliance report
   - Review who triggered scans
   - Monitor scan coverage

4. **Secure Results**
   - Store vulnerability evidence securely
   - Encrypt sensitive scan data
   - Regular backups

5. **Rate Limiting**
   - Don't run unlimited concurrent scans
   - Queue scans to avoid server overload
   - Implement scan throttling

## Support and Resources

- **Admin Panel**: Admin > Security Dashboard > ZAP Scanner
- **Settings**: Admin > Plugins > Security Dashboard Settings
- **Logs**: /moodle/var/log/ (enable debug mode)
- **Database**: Check `mdl_local_security_dashboard_*` tables
- **Documentation**: See PHASE2_ZAP_INTEGRATION.md

## Version Information

- **Plugin Version**: 2.0.0
- **Moodle Min Version**: 4.0
- **ZAP Min Version**: 2.10.0
- **PHP Min Version**: 7.4
