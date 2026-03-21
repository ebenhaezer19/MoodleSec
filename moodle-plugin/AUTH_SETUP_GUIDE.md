# ZAP Authenticated Scanning Guide

## Overview
ZAP can perform authenticated scanning to test vulnerabilities in authenticated areas of Moodle. This guide explains the different authentication methods and how to set them up.

---

## 3 Authentication Methods

### 1. **Manual Credentials** (RECOMMENDED)
**Best for:** Reliable setup when you know admin credentials

**How it works:**
- Admin manually enters Moodle credentials in plugin settings
- Credentials are encrypted and stored in database
- ZAP uses these credentials to login during scan

**Setup Steps:**
1. Go to **Administration → Plugins → Local plugins → Security Dashboard → ZAP Configuration**
2. Set **Authentication Method** to: `Manual Credentials`
3. Enter **Scan Test Username**: `admin`
4. Enter **Scan Test Password**: `Admin@1234`
5. Click **Save changes**

**Test the configuration:**
1. Go to **http://localhost:8998/local/security_dashboard/auth_setup.php**
2. Under "Test Credentials" section, enter your username/password
3. Click "Test Authentication"
4. If successful, you'll see: ✓ Authentication test passed

**Pros:**
- ✓ Works reliably
- ✓ Simple to understand
- ✓ Passwords encrypted in database
- ✓ Credentials never sent to ZAP (ZAP handles login internally)

**Cons:**
- ✗ Requires manual entry for each Moodle instance
- ✗ If admin password changes, need to update settings

**For Multiple Moodle Instances:**
```
Moodle Instance 1 (admin@univ1.edu)
  ├─ auth_method: manual
  ├─ scan_test_user: admin
  └─ scan_test_password: [encrypted password 1]

Moodle Instance 2 (admin@univ2.edu)
  ├─ auth_method: manual
  ├─ scan_test_user: admin
  └─ scan_test_password: [encrypted password 2]
```

---

### 2. **Auto-Detect Admin User** (SEMI-AUTOMATIC)
**Best for:** Instances where you want automatic admin detection

**How it works:**
- Plugin automatically finds the admin user in Moodle
- Still requires manual password entry (for security)
- Uses auto-detected admin for scanning

**Current Status:** ⚠️ Requires manual password still (less useful than expected)

**Setup Steps:**
1. Set **Authentication Method** to: `Auto-Detect Admin User`
2. Enter **Scan Test Password**: `Admin@1234`
3. The username will auto-detect as: `admin` (ID 2 in Moodle)

**Pros:**
- + Automatic user detection
- + Don't need to manually enter username

**Cons:**
- ✗ Still needs manual password
- ✗ Assumes admin is ID 2 (might differ in custom Moodle)
- ✗ Only slightly better than manual method

---

### 3. **Session Token** (MOST SECURE - PLANNED)
**Best for:** High-security environments

**Status:** 🔄 Available but requires additional setup

**How it works:**
- Uses Moodle's session/API token mechanism
- No passwords stored in plugin settings
- ZAP uses session tokens for authentication
- More secure than plain password storage

**Pros:**
- + Most secure - no plain password needed
- + Uses Moodle's built-in auth mechanisms
- + Better for compliance/audit requirements

**Cons:**
- ✗ More complex setup
- ✗ Requires browser session capture or token generation
- ✗ May need custom plugin development

---

## Recommended Setup for Different Scenarios

### Scenario A: Single Moodle Instance (Most Common)
```
Use: Manual Credentials method
Reason: Simple, reliable, secure

Setup:
1. Set auth_method = manual
2. Enter the same admin credentials you use to manage Moodle  
3. Test in auth_setup.php page
4. Run authenticated scans
```

### Scenario B: Multiple Moodle Instances
```
Option 1: Manual setup per instance (EASIEST)
1. Each Moodle has its own plugin settings
2. Each has different encrypted credentials
3. Scales across 5-10 instances reasonably well

Option 2: Dedicated test user per instance (RECOMMENDED)
1. Create a "security_scanner" test user on each Moodle
2. Give it necessary permissions (no admin needed)
3. Use consistent password or different per instance
4. More auditable who runs scans

Option 3: Service account with API tokens (FUTURE)
1. Create service account: "security_bot"
2. Generate Moodle API tokens
3. Store tokens securely
4. Most scalable and auditable
```

### Scenario C: Automated/CI-CD Integration
```
For automated scanning in CI/CD pipelines:

Option "Moodle API + Service Account":
1. Create CI/CD service account in Moodle
2. Generate permanent API token
3. Store token in CI/CD secrets
4. ZAP plugin reads token from environment
5. Uses token for all authenticated scans

This prevents:
- Storing actual passwords
- Manual intervention needed
- Credentials visible in logs
```

---

## Testing Your Authentication

### Test via Auth Setup Page
```
URL: http://localhost:8998/local/security_dashboard/auth_setup.php

Steps:
1. Enter your test username (e.g., admin)
2. Enter your test password
3. Click "Test Authentication"
4. Result will show:
   ✓ Authentication test passed - means ZAP can login
   ✗ Login failed - means wrong credentials
```

### Test via Scanner
```
URL: http://localhost:8998/local/security_dashboard/zap_scan.php

1. Select "Authenticated - Scan as logged-in user"
2. Credentials should auto-populate from settings
3. Click "Scan"
4. Compare unauthenticated vs authenticated results
   - Authenticated should find more endpoints
   - Should have access to protected areas
```

---

## Troubleshooting

### "Credentials not configured"
**Problem:** Getting this error when setting up auth

**Solution:**
1. Check if login credentials are saved in settings
2. Go to: **Administration → Plugins → Local → Security Dashboard → ZAP Configuration**
3. Ensure **Scan Test Username** and **Scan Test Password** are filled
4. Click Save
5. Try again

### "Login failed - check credentials"
**Problem:** Test shows "✗ Login failed"

**Solution:**
1. Verify credentials work: Try logging in manually to Moodle
2. Check if account is active (not disabled)
3. Check if account has login capability
4. Ensure password doesn't have special characters that need escaping
5. If using ldap/sso: Manual method won't work - use API token approach

### ZAP scans not finding authenticated resources
**Problem:** Authenticated scans find same things as unauthenticated

**Solution:**
1. Verify test in auth_setup.php passes ✓
2. Check if test user has proper permissions to access resources
3. May need to create test user with specific roles (e.g., Teacher, Manager)
4. Check ZAP logs for authentication errors

---

## For Different Moodle Installations

### Installation on New Moodle Instance
```
BEFORE plugin installation:
1. Decide auth method (recommend Manual)
2. Note the credentials you'll use

DURING installation:
1. Activate plugin normally
2. Go to plugin settings
3. Set authentication method
4. Enter credentials
5. Test in auth_setup.php

AFTER installation:
1. Auto-detect will work for that instance
2. Credentials stored encrypted
3. No additional config per Admin
```

### AutomatedSetup with Script
```bash
#!/bin/bash
# Auto-setup script for new Moodle instance

MOODLE_url="https://moodle.example.com"
admin_user="admin"
admin_pass="YourSecurePassword"

# 1. Install plugin
wp plugin install security-dashboard --activate

# 2. Set config
wp config set local_security_dashboard auth_method "manual"
wp config set local_security_dashboard scan_test_user "$admin_user"
wp config set local_security_dashboard scan_test_password "$admin_pass" --encrypt

# 3. Test
curl "$MOODLE_URL/local/security_dashboard/auth_setup.php?action=test" \
  -d "test_user=$admin_user&test_pass=$admin_pass"

echo "Setup complete!"
```

---

## Best Practices

### Security
1. ✓ Use a dedicated test user (not main admin account)
2. ✓ Limit test user permissions (only what's needed to scan)
3. ✓ Use strong passwords
4. ✓ Rotate credentials regularly
5. ✓ Store credentials securely (Moodle encryption)
6. ✓ Audit who has access to settings

### Operationally
1. ✓ Document which credentials are used per instance
2. ✓ Create separate test users for automated scans
3. ✓ Make scanning audit-trackable (log which user account ran scan)
4. ✓ Test credentials before important scans
5. ✓ Have fallback unauth scans if auth fails

### For Scale (Multiple Instances)
1. ✓ Use API token approach for 10+ instances
2. ✓ Automate credential deployment if possible
3. ✓ Use CI/CD secrets for sensitive data
4. ✓ Regular audit of all instances' settings

---

## Implementation Status

| Feature | Status | Usage |
|---------|--------|-------|
| Manual Credentials | ✅ Ready | Test & configure in auth_setup.php |
| Auto-Detect Admin | ✅ Ready | Semi-automated, still needs password |
| Session Tokens | 🔄 Planned | For future high-security setups |
| SSOAuth | 🔄 Planned | OAuth2 support coming |
| Audit Logging | 🔄 Planned | Track who issued scans |

---

## Summary

**For your current setup:**
```
Method: Manual Credentials
Reason: Most reliable, works everywhere
Setup: admin / Admin@1234 in settings
Test: auth_setup.php page
Status: ✓ Ready to use

For other Moodle installs:
- Each gets same setup process
- Credentials are different per instance
- All methods available

For future automation:
- Plan to use API token method
- Will eliminate manual password entry
- More scalable for 10+ instances
```

---

## Quick Start

```
1. Go to: Administration → Plugins → Local → Security Dashboard
2. Find "ZAP Configuration" section
3. Set Auth Method = "Manual Credentials"
4. Enter Username: admin  
5. Enter Password: Admin@1234
6. Click Save
7. Test: Visit auth_setup.php and test credentials
8. Run scan: Go to ZAP Scan page, select Authenticated scan
9. Check results: Should have more findings than unauthenticated
```

