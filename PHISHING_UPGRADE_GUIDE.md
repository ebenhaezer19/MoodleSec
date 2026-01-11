# Phishing Scanner Upgrade Guide

## 🎯 What's New in v1.2.0

### ✨ High Priority Features Implemented

1. **Database Storage** - All phishing findings now saved to database
2. **Pagination** - Historical findings displayed with 20 items per page
3. **Email Notifications** - Automatic alerts for CRITICAL findings

---

## 📋 Upgrade Steps (Linux Server)

### Step 1: Pull Latest Code

```bash
cd ~/TA/adaptive-moodle-security/MoodleSec
git pull origin main
```

### Step 2: Update Proxy Service

The phishing detector now has improved detection logic:

```bash
# Stop current proxy service
pkill -f "uvicorn app:app"

# Start with updated code
cd ~/TA/adaptive-moodle-security/MoodleSec/proxy
uvicorn app:app --host 0.0.0.0 --port 8999 &
```

Or if using systemd:

```bash
sudo systemctl restart moodlesec-proxy
```

### Step 3: Copy Updated Moodle Plugin

```bash
cd ~/TA/adaptive-moodle-security/MoodleSec

# Copy updated plugin files
sudo cp -r moodle-plugin/* /var/www/html/moodle/public/local/security_dashboard/

# Set proper permissions
sudo chown -R www-data:www-data /var/www/html/moodle/public/local/security_dashboard/
sudo chmod -R 755 /var/www/html/moodle/public/local/security_dashboard/
```

### Step 4: Run Moodle Database Upgrade

**Important:** This will create the `mdl_local_security_phishing` table.

1. Navigate to: `https://your-moodle-site.com/admin/index.php`
2. Login as admin
3. Moodle will detect the plugin update and prompt for database upgrade
4. Click **"Upgrade Moodle database now"**
5. Wait for upgrade to complete

**Or via CLI:**

```bash
sudo -u www-data php /var/www/html/moodle/public/admin/cli/upgrade.php
```

### Step 5: Clear Moodle Cache

```bash
sudo -u www-data php /var/www/html/moodle/public/admin/cli/purge_caches.php
```

### Step 6: Test the New Features

1. **Test Phishing Detection:**
   - Create a test user
   - Add to profile bio: `Klik disini untuk hadiah: <a href="https://phishing-test.com">CLAIM NOW</a>`
   - Go to: Site Administration → Local plugins → Security Dashboard → Phishing Content Scanner
   - Click "Scan User Profiles (Bio)"
   - Should detect with HIGH/CRITICAL risk score

2. **Verify Database Storage:**
   ```bash
   mysql -u root -p moodle
   SELECT * FROM mdl_local_security_phishing ORDER BY timecreated DESC LIMIT 5;
   ```

3. **Check Email Notification:**
   - If finding is CRITICAL, admin should receive email
   - Check spam folder if not received
   - Verify email settings: Site Administration → Server → Email → Outgoing mail configuration

4. **Test Pagination:**
   - Create multiple test findings (>20)
   - Verify pagination controls appear
   - Test navigation between pages

5. **Test Finding Management:**
   - Click "Resolve" button on a finding
   - Verify status changes to "resolved"
   - Check "False Positive" button works

---

## 🗄️ Database Schema

New table: `mdl_local_security_phishing`

| Column | Type | Description |
|--------|------|-------------|
| id | INT | Primary key |
| content_type | VARCHAR(50) | user_profile, forum_post, comment |
| content_id | INT | ID of the content |
| user_id | INT | User who created content (foreign key) |
| risk_level | VARCHAR(20) | CRITICAL, HIGH, MEDIUM, LOW |
| risk_score | DECIMAL(4,2) | Score 0.00-10.00 |
| suspicious_url | TEXT | The suspicious URL detected |
| indicators | TEXT | JSON array of detection indicators |
| content_preview | TEXT | First 500 chars of content |
| recommendation | TEXT | Remediation advice |
| status | VARCHAR(20) | open, resolved, false_positive, whitelisted |
| notified | TINYINT | Email notification sent (0/1) |
| detected_by | INT | Admin who ran scan |
| resolved_by | INT | Admin who resolved (nullable) |
| resolved_at | INT | Unix timestamp (nullable) |
| timecreated | INT | Unix timestamp |
| timemodified | INT | Unix timestamp |

---

## 🔧 Configuration

### Email Notification Settings

Notifications are sent to all site admins when CRITICAL findings are detected.

**To configure email:**

1. Site Administration → Server → Email → Outgoing mail configuration
2. Set SMTP settings or use system mail
3. Test with: Site Administration → Server → Email → Test outgoing mail configuration

**To disable notifications:**

Edit `lib.php` and comment out line in `local_security_dashboard_save_phishing_finding()`:

```php
// Send notification if CRITICAL
// if ($record->risk_level === 'CRITICAL') {
//     local_security_dashboard_send_phishing_notification($record);
// }
```

### Pagination Settings

To change items per page, edit `scan_phishing_content.php` line 31:

```php
$perpage = optional_param('perpage', 20, PARAM_INT); // Change 20 to desired number
```

---

## 🎨 New UI Features

### Historical Findings Table

- Shows all past detections with filtering
- Color-coded risk badges (red=CRITICAL, orange=HIGH, blue=MEDIUM, gray=LOW)
- Status badges (green=resolved, blue=false_positive, gray=open)
- Expandable detail rows (click to see indicators)
- Pagination controls at bottom

### Action Buttons

- **Resolve** - Mark finding as fixed (status → resolved)
- **False Positive** - Mark as non-threat (status → false_positive)
- Actions only visible for "open" findings

### Scan Results

- Now shows "Saved to Database: X" count
- Real-time detection still displayed in table
- Historical view automatically updates after scan

---

## 🚀 API Changes

### Detection Improvements

**Enhanced generic link text detection:**

Now detects these suspicious texts:
- "klik disini", "klik di sini", "click here"
- "claim", "verify", "confirm", "update"
- "login", "sign in", "masuk"
- "download", "unduh", "get", "lihat"

**New unknown domain detection:**

- External domains not in legitimate list get +2.0 risk score
- Combined with generic link text = HIGH/CRITICAL

**Example:**

```html
<a href="https://unknown-site.com">Klik di sini</a>
```

**Risk Calculation:**
- External link: +1.0
- Unknown domain: +2.0
- Suspicious link text: +5.0
- **Total: 8.0 = CRITICAL** ✅

---

## 🐛 Troubleshooting

### Database Table Not Created

```bash
# Check if upgrade ran
sudo -u www-data php /var/www/html/moodle/public/admin/cli/upgrade.php

# Check table exists
mysql -u root -p moodle -e "SHOW TABLES LIKE 'mdl_local_security_phishing';"
```

### Email Not Sending

```bash
# Test PHP mail function
sudo -u www-data php -r "mail('your-email@example.com', 'Test', 'Test from Moodle server');"

# Check Moodle email logs
tail -f /var/log/apache2/error.log
```

### Proxy Service Not Running

```bash
# Check if proxy is running
ps aux | grep uvicorn

# Check proxy logs
cd ~/TA/adaptive-moodle-security/MoodleSec/proxy
tail -f nohup.out

# Restart proxy
pkill -f uvicorn
uvicorn app:app --host 0.0.0.0 --port 8999 &
```

### Pagination Not Working

Check Moodle version supports `$OUTPUT->paging_bar()`:
- Requires Moodle 3.9+
- Update Moodle if using older version

---

## 📊 Testing Checklist

- [ ] Git pull successful
- [ ] Proxy service restarted
- [ ] Plugin files copied
- [ ] Database upgrade completed
- [ ] Table `mdl_local_security_phishing` exists
- [ ] Cache cleared
- [ ] Test scan detects phishing link
- [ ] Finding saved to database (check with SQL)
- [ ] Email notification received (for CRITICAL)
- [ ] Historical findings table displays
- [ ] Pagination works (if >20 findings)
- [ ] Resolve button works
- [ ] False Positive button works
- [ ] Status updates in database

---

## 📝 Version Info

- **Version:** 2026011100 (v1.2.0-beta)
- **Previous:** 2025120902 (v1.1.2-beta)
- **Changes:** +453 lines, 5 files modified
- **Database:** +1 table (local_security_phishing)
- **New Functions:** 7 (lib.php)

---

## 🆘 Support

If you encounter issues:

1. Check Moodle debug mode: Site Administration → Development → Debugging
2. Set to DEVELOPER level to see detailed errors
3. Check logs: `/var/log/apache2/error.log`
4. Check proxy logs: `~/TA/adaptive-moodle-security/MoodleSec/proxy/nohup.out`
5. Verify all files copied: `ls -la /var/www/html/moodle/public/local/security_dashboard/`

---

**Upgrade completed!** 🎉

Your phishing scanner now has:
- ✅ Persistent findings storage
- ✅ Historical tracking with pagination
- ✅ Automatic email alerts for critical threats
- ✅ Finding management workflow
- ✅ Enhanced detection accuracy
