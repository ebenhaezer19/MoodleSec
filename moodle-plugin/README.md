# Moodle Security Dashboard Plugin

Plugin dashboard untuk monitoring keamanan Moodle yang terintegrasi dengan Proxy Service dan CVSS Engine.

## Struktur Plugin

```
moodle-plugin/
├── version.php              # Plugin version info
├── settings.php             # Admin settings
├── lib.php                  # Core functions
├── index.php                # Dashboard page
├── scan.php                 # Scan trigger page
├── db/
│   └── access.php          # Capabilities
└── lang/
    └── en/
        └── local_security_dashboard.php  # Language strings
```

## Instalasi

### 1. Copy Plugin ke Moodle

```bash
# Copy folder ke Moodle local plugins directory
cp -r moodle-plugin /path/to/moodle/local/security_dashboard
```

### 2. Install via Moodle Admin

1. Login sebagai admin
2. Buka **Site administration → Notifications**
3. Moodle akan detect plugin baru
4. Klik **Upgrade Moodle database now**

### 3. Konfigurasi

1. Buka **Site administration → Plugins → Local plugins → Security Dashboard**
2. Set URL untuk services:
   - **Proxy Service URL**: `http://localhost:8999`
   - **CVSS Engine URL**: `http://localhost:8001`
3. Save changes

## Fitur

### 1. Dashboard (index.php)
- Service health check
- Recent scan logs
- Quick scan button

### 2. Scan Trigger (scan.php)
- Manual scan trigger
- Path dan method selection
- Real-time scan results
- Vulnerability summary
- Detailed findings table

### 3. Settings
- Configurable service URLs
- Admin-only access

## Capabilities

- `local/security_dashboard:view` - View dashboard
- `local/security_dashboard:scan` - Trigger scans

Default: Manager role only

## API Integration

Plugin menggunakan fungsi di `lib.php`:

```php
// Get logs
local_security_dashboard_get_logs($limit);

// Trigger scan
local_security_dashboard_trigger_scan($path, $method, $parameters);

// Calculate CVSS
local_security_dashboard_calculate_cvss($vector);

// Check health
local_security_dashboard_check_health();
```

## Requirements

- Moodle 4.0+
- PHP 7.4+
- Proxy Service running on configured URL
- CVSS Engine running on configured URL

## Development

Untuk development lebih lanjut:

1. **Add AJAX support** untuk real-time updates
2. **Add charts** untuk visualisasi (Chart.js)
3. **Add scheduling** untuk automated scans
4. **Add notifications** untuk critical findings
5. **Add export** untuk PDF/CSV reports

## Troubleshooting

### Plugin tidak muncul di menu
- Check capabilities: User harus punya role Manager
- Clear cache: **Site administration → Development → Purge all caches**

### Connection error
- Pastikan Proxy dan CVSS services running
- Check URL di settings
- Check firewall/network

### Permission denied
- Check user capabilities
- Assign `local/security_dashboard:view` capability

## License

GNU GPL v3 or later
