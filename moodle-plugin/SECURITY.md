# Security Features Documentation

## Overview
This document outlines the security measures implemented in the Security Dashboard plugin for Moodle.

## Security Measures Implemented

### 1. Input Validation ✅
- **Path Validation**: All scan paths are validated using `PARAM_PATH` and regex patterns
- **Method Validation**: HTTP methods are restricted to GET and POST only
- **Parameter Sanitization**: All user inputs are sanitized before processing

```php
// Example from scan.php
$path = required_param('path', PARAM_PATH);
$method = required_param('method', PARAM_ALPHA);

// Validate path format
if (!preg_match('#^/[a-zA-Z0-9/_\-\.]+$#', $path)) {
    // Reject invalid paths
}
```

### 2. XSS Prevention ✅
- **Output Sanitization**: All dynamic content is sanitized using Moodle's `s()` function
- **HTML Escaping**: User-generated content is escaped before display
- **Safe HTML Writing**: Using Moodle's `html_writer` class for all HTML generation

```php
// Example from scan.php
$scan_id = s($scan_result['scan_id'] ?? 'N/A');
$description = s($finding['description'] ?? 'N/A');
```

### 3. CSRF Protection ✅
- **Session Keys**: All forms include `sesskey()` tokens
- **Token Validation**: All POST requests validate session keys using `confirm_sesskey()`

```php
// Example from scan.php
if ($_SERVER['REQUEST_METHOD'] === 'POST' && confirm_sesskey()) {
    // Process form
}
```

### 4. SQL Injection Prevention ✅
- **Moodle DB API**: All database queries use Moodle's DB API
- **Parameterized Queries**: No direct SQL concatenation
- **Prepared Statements**: Automatic parameter binding

```php
// Example from lib.php
$DB->get_record('security_scans', ['id' => $id]);
// NOT: $DB->execute("SELECT * FROM security_scans WHERE id = $id");
```

### 5. Capability-Based Access Control ✅
- **Granular Permissions**: 5 different capabilities for different actions
- **Context Checks**: All pages check user capabilities before access
- **Role-Based Access**: Capabilities assigned to appropriate roles

```php
// Example from scan.php
require_capability('local/security_dashboard:scan', context_system::instance());
```

#### Capabilities:
- `local/security_dashboard:view` - View dashboard
- `local/security_dashboard:scan` - Trigger scans
- `local/security_dashboard:viewreports` - View reports
- `local/security_dashboard:downloadreports` - Download reports
- `local/security_dashboard:manageschedule` - Manage scheduled scans

### 6. Background Task Processing ✅
- **Scheduled Tasks**: Automatic scans run at configured times
- **Ad-hoc Tasks**: On-demand scans run in background
- **Non-Blocking**: UI remains responsive during scans

#### Scheduled Task:
- **Class**: `local_security_dashboard\task\scan_task`
- **Schedule**: Daily at 2 AM (configurable)
- **Purpose**: Automated security scanning

#### Ad-hoc Task:
- **Class**: `local_security_dashboard\task\scan_adhoc_task`
- **Trigger**: On-demand via UI
- **Purpose**: Background processing for user-initiated scans

### 7. Secure Configuration ✅
- **URL Validation**: Proxy and CVSS URLs validated as proper URLs
- **Admin-Only Settings**: Only site administrators can modify settings
- **Secure Defaults**: Safe default values for all settings

## Security Best Practices

### For Administrators:
1. **Restrict Capabilities**: Only grant scan permissions to trusted users
2. **Monitor Logs**: Regularly review scan logs for suspicious activity
3. **Update Regularly**: Keep the plugin updated with latest security patches
4. **Secure Proxy**: Ensure proxy service is properly secured and firewalled
5. **HTTPS Only**: Use HTTPS for all proxy and CVSS service URLs

### For Developers:
1. **Never Trust User Input**: Always validate and sanitize
2. **Use Moodle APIs**: Leverage Moodle's built-in security functions
3. **Check Capabilities**: Always verify user permissions
4. **Sanitize Output**: Use `s()` for all dynamic content
5. **Test Security**: Regularly test for vulnerabilities

## Threat Model

### Protected Against:
- ✅ SQL Injection
- ✅ Cross-Site Scripting (XSS)
- ✅ Cross-Site Request Forgery (CSRF)
- ✅ Path Traversal
- ✅ Command Injection
- ✅ Unauthorized Access

### Considerations:
- ⚠️ **Proxy Security**: The security of scans depends on the proxy service security
- ⚠️ **Network Security**: Ensure proxy communication is over secure channels
- ⚠️ **Rate Limiting**: Consider implementing rate limiting for scan requests

## Incident Response

If you discover a security vulnerability:
1. **Do NOT** create a public issue
2. Email security details to: [your-email@example.com]
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

## Compliance

This plugin follows:
- ✅ Moodle coding standards
- ✅ OWASP Top 10 security guidelines
- ✅ Moodle security best practices
- ✅ PHP security recommendations

## Audit Log

| Date | Version | Security Changes |
|------|---------|------------------|
| 2025-12-09 | v1.1.0-beta | Initial security hardening: Input validation, XSS prevention, enhanced capabilities, background tasks |
| 2025-11-16 | v1.0.0 | Initial release with basic security measures |

## References

- [Moodle Security](https://docs.moodle.org/dev/Security)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Moodle Coding Style](https://docs.moodle.org/dev/Coding_style)
- [PHP Security Best Practices](https://www.php.net/manual/en/security.php)
