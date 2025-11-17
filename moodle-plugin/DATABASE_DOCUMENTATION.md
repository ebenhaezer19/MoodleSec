# Database Layer Documentation

## Overview

Database layer untuk Moodle Security Dashboard plugin yang menyediakan persistent storage untuk scan results, findings, logs, dan configurations.

## Database Schema

### 1. `mdl_local_security_scans`
Menyimpan informasi scan utama.

| Field | Type | Description |
|-------|------|-------------|
| id | INT | Primary key |
| scan_id | VARCHAR(100) | Unique scan identifier |
| target_url | TEXT | Full target URL |
| scan_path | VARCHAR(255) | Path yang di-scan |
| scan_method | VARCHAR(10) | HTTP method (GET, POST, etc) |
| scan_type | VARCHAR(50) | Type of scan (manual, scheduled, etc) |
| status | VARCHAR(20) | Scan status (pending, completed, failed) |
| total_findings | INT | Total vulnerabilities found |
| critical_count | INT | Number of critical findings |
| high_count | INT | Number of high findings |
| medium_count | INT | Number of medium findings |
| low_count | INT | Number of low findings |
| info_count | INT | Number of info findings |
| scan_duration | INT | Duration in seconds |
| triggered_by | INT | User ID who triggered |
| timecreated | INT | Unix timestamp |
| timemodified | INT | Unix timestamp |

**Indexes:**
- `scan_id` (UNIQUE)
- `status`
- `timecreated`

**Foreign Keys:**
- `triggered_by` → `mdl_user.id`

---

### 2. `mdl_local_security_findings`
Menyimpan detail individual vulnerabilities.

| Field | Type | Description |
|-------|------|-------------|
| id | INT | Primary key |
| scan_id | INT | Foreign key to scans table |
| severity | VARCHAR(20) | Critical, High, Medium, Low, Info |
| category | VARCHAR(100) | Vulnerability category (SQL Injection, XSS, etc) |
| title | VARCHAR(255) | Finding title |
| description | TEXT | Detailed description |
| evidence | TEXT | Proof/evidence |
| cvss_score | DECIMAL(3,1) | CVSS base score (0.0-10.0) |
| cvss_vector | VARCHAR(255) | CVSS vector string |
| cwe_id | VARCHAR(20) | CWE identifier |
| remediation | TEXT | Fix recommendations |
| status | VARCHAR(20) | open, fixed, false_positive, accepted |
| false_positive | TINYINT | 0 or 1 |
| timecreated | INT | Unix timestamp |
| timemodified | INT | Unix timestamp |

**Indexes:**
- `severity`
- `category`
- `status`

**Foreign Keys:**
- `scan_id` → `mdl_local_security_scans.id`

---

### 3. `mdl_local_security_logs`
Menyimpan activity logs dan audit trail.

| Field | Type | Description |
|-------|------|-------------|
| id | INT | Primary key |
| scan_id | INT | Related scan ID (nullable) |
| log_type | VARCHAR(50) | Type of log entry |
| log_level | VARCHAR(20) | info, warning, error |
| message | TEXT | Log message |
| data | TEXT | Additional data (JSON) |
| user_id | INT | User ID (nullable) |
| timecreated | INT | Unix timestamp |

**Indexes:**
- `log_type`
- `log_level`
- `timecreated`

**Foreign Keys:**
- `scan_id` → `mdl_local_security_scans.id`
- `user_id` → `mdl_user.id`

---

### 4. `mdl_local_security_config`
Menyimpan configuration dan scan profiles.

| Field | Type | Description |
|-------|------|-------------|
| id | INT | Primary key |
| name | VARCHAR(100) | Config name |
| value | TEXT | Config value |
| description | TEXT | Description |
| config_type | VARCHAR(50) | scan_profile, threshold, etc |
| is_active | TINYINT | 0 or 1 |
| timecreated | INT | Unix timestamp |
| timemodified | INT | Unix timestamp |

**Indexes:**
- `name` (UNIQUE)
- `config_type`

---

### 5. `mdl_local_security_schedules`
Menyimpan scheduled scan configurations.

| Field | Type | Description |
|-------|------|-------------|
| id | INT | Primary key |
| name | VARCHAR(255) | Schedule name |
| scan_path | VARCHAR(255) | Path to scan |
| scan_method | VARCHAR(10) | HTTP method |
| scan_type | VARCHAR(50) | Type of scan |
| frequency | VARCHAR(20) | daily, weekly, monthly |
| schedule_time | VARCHAR(10) | HH:MM format |
| is_enabled | TINYINT | 0 or 1 |
| last_run | INT | Unix timestamp |
| next_run | INT | Unix timestamp |
| created_by | INT | User ID |
| timecreated | INT | Unix timestamp |
| timemodified | INT | Unix timestamp |

**Indexes:**
- `is_enabled`
- `next_run`

**Foreign Keys:**
- `created_by` → `mdl_user.id`

---

## Database Manager Class

### Class: `local_security_dashboard\db_manager`

#### Core Methods

##### `save_scan($scan_data, $userid)`
Save scan result to database.

```php
$scan_id = db_manager::save_scan($scan_result, $USER->id);
```

**Parameters:**
- `$scan_data` (object): Scan data from API
- `$userid` (int): User ID who triggered

**Returns:** int - Scan record ID

---

##### `save_finding($scan_id, $finding)`
Save individual finding.

```php
$finding_id = db_manager::save_finding($scan_id, $finding_data);
```

**Parameters:**
- `$scan_id` (int): Scan record ID
- `$finding` (object): Finding data

**Returns:** int - Finding record ID

---

##### `get_scan($scan_id)`
Get scan by database ID.

```php
$scan = db_manager::get_scan(123);
```

**Returns:** object|false - Scan record or false

---

##### `get_recent_scans($limit, $offset)`
Get recent scans with pagination.

```php
$scans = db_manager::get_recent_scans(10, 0);
```

**Parameters:**
- `$limit` (int): Number of scans (default: 10)
- `$offset` (int): Offset for pagination (default: 0)

**Returns:** array - Array of scan records

---

##### `get_findings($scan_id, $severity)`
Get findings for a scan.

```php
// All findings
$findings = db_manager::get_findings($scan_id);

// Only critical
$critical = db_manager::get_findings($scan_id, 'Critical');
```

**Parameters:**
- `$scan_id` (int): Scan record ID
- `$severity` (string): Filter by severity (optional)

**Returns:** array - Array of finding records

---

##### `get_statistics($days)`
Get aggregated statistics.

```php
// Last 30 days
$stats = db_manager::get_statistics(30);

// All time
$stats = db_manager::get_statistics(0);
```

**Returns:** object with properties:
- `total_scans`
- `total_findings`
- `critical_findings`
- `high_findings`
- `medium_findings`
- `low_findings`
- `info_findings`
- `avg_findings_per_scan`
- `top_categories` (array)

---

##### `get_scan_history($days)`
Get daily scan statistics for charts.

```php
$history = db_manager::get_scan_history(7);
```

**Returns:** array of daily stats:
```php
[
    [
        'date' => '2024-11-17',
        'day_name' => 'Sun',
        'scan_count' => 5,
        'findings_count' => 23,
        'critical' => 2,
        'high' => 8
    ],
    ...
]
```

---

##### `update_finding_status($finding_id, $status)`
Update finding status.

```php
db_manager::update_finding_status(456, 'fixed');
```

**Valid statuses:**
- `open`
- `fixed`
- `false_positive`
- `accepted`

**Returns:** bool - Success

---

##### `add_log($scan_id, $log_type, $log_level, $message, $data, $userid)`
Add log entry.

```php
db_manager::add_log(
    $scan_id,
    'scan_completed',
    'info',
    'Scan finished successfully',
    json_encode(['duration' => 45]),
    $USER->id
);
```

**Parameters:**
- `$scan_id` (int): Scan ID (nullable)
- `$log_type` (string): Log type
- `$log_level` (string): info, warning, error
- `$message` (string): Log message
- `$data` (string): Additional data (JSON)
- `$userid` (int): User ID (nullable)

**Returns:** int - Log record ID

---

##### `get_logs($scan_id, $limit)`
Retrieve logs.

```php
// All logs
$logs = db_manager::get_logs(null, 100);

// Logs for specific scan
$logs = db_manager::get_logs($scan_id, 50);
```

**Returns:** array - Array of log records

---

##### `delete_scan($scan_id)`
Delete scan and all related data (findings, logs).

```php
$success = db_manager::delete_scan(123);
```

**Returns:** bool - Success

---

## API Client Class

### Class: `local_security_dashboard\api_client`

#### Methods

##### `trigger_scan($path, $method, $parameters)`
Trigger security scan via proxy service.

```php
$api = new api_client();
$result = $api->trigger_scan('/login/index.php', 'POST');
```

---

##### `get_proxy_logs($limit)`
Get logs from proxy service.

```php
$logs = $api->get_proxy_logs(100);
```

---

##### `calculate_cvss($vector)`
Calculate CVSS score.

```php
$result = $api->calculate_cvss('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
// Returns: {score: 9.8, severity: "Critical"}
```

---

##### `check_all_health()`
Check all services health.

```php
$health = $api->check_all_health();
// Returns: {proxy: true, cvss: true, overall: true}
```

---

## Usage Examples

### Example 1: Complete Scan Workflow

```php
use local_security_dashboard\api_client;
use local_security_dashboard\db_manager;

// 1. Trigger scan
$api = new api_client();
$scan_result = $api->trigger_scan('/admin/login.php', 'POST');

// 2. Save to database
if ($scan_result && !isset($scan_result->error)) {
    $scan_id = db_manager::save_scan($scan_result, $USER->id);
    
    // 3. Get saved findings
    $findings = db_manager::get_findings($scan_id);
    
    // 4. Process critical findings
    foreach ($findings as $finding) {
        if ($finding->severity === 'Critical') {
            // Send notification, create ticket, etc.
        }
    }
}
```

---

### Example 2: Dashboard Statistics

```php
// Get statistics
$stats = db_manager::get_statistics(30);

echo "Total Scans: {$stats->total_scans}";
echo "Critical Issues: {$stats->critical_findings}";
echo "Average per scan: {$stats->avg_findings_per_scan}";

// Get history for chart
$history = db_manager::get_scan_history(7);
$labels = array_column($history, 'day_name');
$data = array_column($history, 'findings_count');
```

---

### Example 3: Finding Management

```php
// Get all open critical findings
$scans = db_manager::get_recent_scans(100);

foreach ($scans as $scan) {
    $critical = db_manager::get_findings($scan->id, 'Critical');
    
    foreach ($critical as $finding) {
        if ($finding->status === 'open') {
            // Display or process
            echo "{$finding->category}: {$finding->description}";
        }
    }
}
```

---

## Installation

1. Copy plugin to `/local/security_dashboard/`
2. Visit **Site administration → Notifications**
3. Database tables will be created automatically
4. Configure service URLs in plugin settings

## Upgrade

Database schema changes are handled automatically via `db/upgrade.php`.

## Performance Considerations

- Indexes on frequently queried columns
- Pagination for large result sets
- Efficient aggregation queries
- Transaction support for data integrity

## Security

- Capability checks required
- User ID tracking for audit
- Sensitive data handling
- SQL injection prevention (using Moodle DML)

---

**Version:** 1.0.0  
**Last Updated:** 2024-11-17
