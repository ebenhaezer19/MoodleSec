# Debug Display Integration Guide

## Overview
The `debug_display.php` component provides real-time payload injection debugging for all scan types.

## How to Use

### Option 1: Display in Panel (Inline)
```php
<?php
require_once(__DIR__ . '/debug_display.php');
$scan_id = 'your-scan-id'; // from database or GET parameter
$proxy_url = 'http://localhost:8999'; // proxy URL
display_debug_panel($scan_id, $proxy_url);
?>
```

### Option 2: Display in Modal (Overlay)
```php
<?php
require_once(__DIR__ . '/debug_display.php');
$scan_id = 'your-scan-id';
display_debug_modal($scan_id);
?>

<!-- Button to trigger modal -->
<button onclick="showDebugModal()">View Debug Logs</button>
```

## Integration Points

### 1. **payload_management.php** (Dashboard)
Add to the main dashboard to show current/last scan debug status:

```php
<?php
require_once(__DIR__ . '/debug_display.php');

// Get latest scan ID from database
$db = new PDO('sqlite:' . __DIR__ . '/scan_results.db');
$latest_scan = $db->query("SELECT scan_id FROM scan_results ORDER BY id DESC LIMIT 1")->fetch();
$scan_id = $latest_scan['scan_id'] ?? null;

if ($scan_id) {
    echo '<h3>🔍 Payload Injection Debug Status</h3>';
    display_debug_panel($scan_id);
}
?>
```

### 2. **scan.php** (Scan Now)
Add while scan is running:

```php
<?php
$scan_id = $_REQUEST['scan_id'] ?? time();
require_once(__DIR__ . '/debug_display.php');
display_debug_panel($scan_id);
?>
```

### 3. **fullscan.php** (Unauthenticated)
```php
<?php
$scan_id = 'fullscan_' . time();
require_once(__DIR__ . '/debug_display.php');
display_debug_panel($scan_id);
?>
```

### 4. **auth_scan.php** (Auth Vulnerability)
```php
<?php
$scan_id = 'auth_' . time();
require_once(__DIR__ . '/debug_display.php');
display_debug_panel($scan_id);
?>
```

### 5. **native_auth_scan.php** (Admin Area)
```php
<?php
$scan_id = 'admin_auth_' . time();
require_once(__DIR__ . '/debug_display.php');
display_debug_panel($scan_id);
?>
```

### 6. **scheduler.php** (Scheduler)
Show debug logs for scheduled scans:

```php
<?php
// Display debug for last scheduled scan
$scheduled_scan_id = 'scheduled_' . date('Y-m-d-H-i-s');
require_once(__DIR__ . '/debug_display.php');
display_debug_panel($scheduled_scan_id);
?>
```

## Backend Integration (Proxy)

### In `scanner_engine.py` - When payloads load:
```python
debug_logger.log_payload_loaded(
    category='SQL',
    count=len(payloads),
    payload_list=payloads
)
```

### In scan endpoints (`app.py`) - When scan starts:
```python
@app.post("/api/scan/start")
async def start_scan(request: ScanRequest):
    scan_id = str(uuid.uuid4())
    debug_logger.log_scan_start(scan_id, 'SCAN_NOW', request.target_url)
    # ... rest of scan logic
```

### When scan completes:
```python
debug_logger.log_scan_complete(
    scan_id=scan_id,
    findings_count=len(findings),
    status='SUCCESS' if not error else 'FAILED'
)
```

### During payload injection:
```python
debug_logger.log_injection_attempt(
    scan_id=scan_id,
    target_url=target_url,
    category='SQL',
    payload_text=payload,
    injection_point='parameter:search',
    status='SUCCESS',
    error=None,
    response_code=200
)
```

## Features

### Automatic Features
✅ Real-time log refresh (2-second interval)  
✅ Event type color coding  
✅ Status badges (Success/Failed/Attempt)  
✅ Statistics calculation (success rate, error count)  
✅ Payload display with injection points  
✅ Error messages with details  

### Manual Controls
🔄 Refresh - Manual fetch latest logs  
⏸ Pause - Stop auto-refresh  
▶ Resume - Resume auto-refresh  
✕ Clear - Clear log display  

## API Endpoints Used

All endpoints described in the conversation:

```
GET /api/debug/scan/{scan_id}/logs
GET /api/debug/statistics
GET /api/debug/logs/recent
POST /api/debug/payload/loaded
POST /api/debug/payload/injected
POST /api/debug/scan/start
POST /api/debug/scan/complete
```

## Database Schema

Logs stored in `data/debug_logs.db`:

```
debug_logs table:
- id (INTEGER PRIMARY KEY)
- timestamp (DATETIME)
- scan_id (VARCHAR)
- event_type (VARCHAR): PAYLOAD_LOADED, PAYLOAD_INJECTED, SCAN_START, SCAN_COMPLETE, ERROR
- category (VARCHAR): SQL, XSS, CSRF, etc.
- payload_text (TEXT)
- injection_point (VARCHAR): parameter, header, cookie, body, url
- target_url (TEXT)
- status (VARCHAR): SUCCESS, FAILED, ATTEMPT
- error_message (TEXT)
- details (TEXT)
- response_code (INTEGER)
```

## Styling

Default styles included in component:
- **Colors**: Green (success), Red (error), Yellow (attempt), Blue (info)
- **Responsive**: Works on mobile and desktop
- **Animations**: Smooth transitions, spinning loader
- **Accessibility**: Clear contrast, readable fonts

## Troubleshooting

### Logs not showing?
1. Check proxy is running on `localhost:8999`
2. Verify `scan_id` is correct
3. Check browser console for fetch errors
4. Ensure `/api/debug/scan/{id}/logs` endpoint is available

### Auto-refresh not working?
1. Open browser console (F12)
2. Check for network errors
3. Verify `setInterval` is not overridden
4. Try manual refresh button

### Data not persisting?
1. Check proxy logs for debug logger initialization
2. Verify `data/debug_logs.db` exists in proxy directory
3. Check database write permissions

## Customization

### Change refresh interval:
```javascript
startAutoRefresh(5000); // 5 seconds instead of 2
```

### Change panel styling:
Edit the `<style>` section in `debug_display.php`

### Disable auto-refresh:
Don't call `startAutoRefresh()` at end of component

## Example Integration (Complete)

```php
<?php
// In your scan page
require_once(__DIR__ . '/debug_display.php');

$scan_id = isset($_GET['scan_id']) ? $_GET['scan_id'] : 'manual_' . time();
$proxy_url = 'http://localhost:8999';
?>

<html>
<head>
    <title>Scan Results</title>
</head>
<body>
    <h1>Running Security Scan</h1>
    
    <!-- Debug Panel -->
    <?php display_debug_panel($scan_id, $proxy_url); ?>
    
    <!-- Your scan results below -->
    <h2>Results</h2>
    <!-- ... -->
</body>
</html>
```

## Next Steps

1. Add `debug_display.php` include to each scan page
2. Integrate backend logging calls in `scanner_engine.py`
3. Test with actual scan to verify logs display
4. Customize styling to match your theme
5. Deploy to production

---

For questions or issues, refer to the proxy debug endpoints documentation in `PAYLOAD_DEBUG_LOGGER.md`
