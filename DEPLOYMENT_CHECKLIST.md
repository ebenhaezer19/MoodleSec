# 📋 Phishing Detection Deployment Checklist

## 🎯 Overview

File yang perlu di-copy dari **development repo** ke **production Moodle**:

```
Development:  ~/TA/adaptive-moodle-security/MoodleSec/
Production:   /var/www/html/moodle/public/local/security_dashboard/
```

---

## ✅ File Deployment Checklist

### **1. Moodle Plugin Files (PHP)**

Copy dari: `~/TA/adaptive-moodle-security/MoodleSec/moodle-plugin/`  
Ke: `/var/www/html/moodle/public/local/security_dashboard/`

```bash
cd ~/TA/adaptive-moodle-security/MoodleSec

# Copy new phishing scanner page
sudo cp moodle-plugin/scan_phishing_content.php \
    /var/www/html/moodle/public/local/security_dashboard/

# Update dashboard (added button)
sudo cp moodle-plugin/index.php \
    /var/www/html/moodle/public/local/security_dashboard/

# Update settings (added menu item)
sudo cp moodle-plugin/settings.php \
    /var/www/html/moodle/public/local/security_dashboard/

# Fix permissions
sudo chown -R www-data:www-data \
    /var/www/html/moodle/public/local/security_dashboard/
sudo chmod -R 755 \
    /var/www/html/moodle/public/local/security_dashboard/
```

**Files to copy:**
- [x] `scan_phishing_content.php` (NEW FILE - phishing scanner page)
- [x] `index.php` (UPDATED - added phishing button)
- [x] `settings.php` (UPDATED - added menu item)

---

### **2. Proxy Backend Files (Python)**

Files already in correct location: `~/TA/adaptive-moodle-security/MoodleSec/proxy/`

**New files created:**
- [x] `proxy/scanners/phishing_detector.py` (450+ lines - detection engine)
- [x] `proxy/api/phishing_scan_api.py` (200+ lines - REST API)

**No need to copy** - proxy runs from repository directory!

---

### **3. Update proxy/app.py**

File: `~/TA/adaptive-moodle-security/MoodleSec/proxy/app.py`

**Add these lines:**

```python
# Near the top with other imports
from api.phishing_scan_api import phishing_api, init_phishing_detector

# After other blueprint registrations (search for "register_blueprint")
app.register_blueprint(phishing_api)

# After config is loaded (near end of file, before app.run())
# Initialize phishing detector with Moodle domain
MOODLE_BASE_DOMAIN = "localhost"  # Change to your domain
init_phishing_detector(MOODLE_BASE_DOMAIN)
```

**Location hints:**
```python
# Find this section:
# app.register_blueprint(xxx)
# app.register_blueprint(yyy)
# ADD HERE: app.register_blueprint(phishing_api)

# Find this section (near bottom):
# if __name__ == '__main__':
#     # ADD BEFORE THIS:
#     init_phishing_detector(MOODLE_BASE_DOMAIN)
#     app.run(...)
```

---

### **4. Install Dependencies**

```bash
cd ~/TA/adaptive-moodle-security/MoodleSec

# Activate virtual environment
source venv/bin/activate

# Install required package
pip install tldextract

# Verify installation
python3 -c "import tldextract; print('✅ tldextract installed')"
```

---

### **5. Restart Services**

```bash
cd ~/TA/adaptive-moodle-security/MoodleSec

# Restart Docker containers
docker-compose restart proxy

# OR if not using Docker:
# pkill -f "python.*app.py"
# python proxy/app.py &

# Verify proxy is running
curl http://localhost:8999/phishing/stats
```

Expected response:
```json
{
  "success": true,
  "moodle_domain": "localhost",
  "detector_ready": true,
  "detection_methods": [...]
}
```

---

### **6. Clear Moodle Cache**

```bash
# Clear cache so Moodle sees new menu items
sudo -u www-data php /var/www/html/moodle/public/admin/cli/purge_caches.php
```

---

## 🧪 Testing Checklist

### **Test 1: Check Files Exist**

```bash
# Moodle plugin files
ls -lh /var/www/html/moodle/public/local/security_dashboard/scan_phishing_content.php
ls -lh /var/www/html/moodle/public/local/security_dashboard/index.php
ls -lh /var/www/html/moodle/public/local/security_dashboard/settings.php

# Proxy files
ls -lh ~/TA/adaptive-moodle-security/MoodleSec/proxy/scanners/phishing_detector.py
ls -lh ~/TA/adaptive-moodle-security/MoodleSec/proxy/api/phishing_scan_api.py
```

### **Test 2: Verify Proxy API**

```bash
# Test phishing detection API
curl -X POST http://localhost:8999/phishing/scan/profile \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": 1,
    "bio_content": "Free prizes: http://bit.ly/xyz123"
  }'
```

Expected: JSON response with findings

### **Test 3: Access Moodle Dashboard**

1. **Login to Moodle** as admin
2. **Navigate:** Site Administration → Local plugins → Security Dashboard → Dashboard
3. **Look for button:** 🛡️ Phishing Scanner (red button, far right)
4. **Click button** → Should go to phishing scanner page

### **Test 4: Run Phishing Scan**

1. **On phishing scanner page**
2. **Click:** "Scan User Profiles (Bio)"
3. **Should see:** Summary + table of results
4. **If no users with content:** Create test user with bio containing URL

### **Test 5: Check Menu Navigation**

1. **Site Administration** → **Local plugins** → **Security Dashboard**
2. **Should see menu items:**
   - Dashboard
   - Auth & API Scan
   - Reports
   - Scheduler
   - **Phishing Content Scanner** ← NEW!
   - Trends
   - ML Dashboard

---

## 🐛 Troubleshooting

### **Problem: Button not showing on dashboard**

**Solution:**
```bash
# Clear cache
sudo -u www-data php /var/www/html/moodle/public/admin/cli/purge_caches.php

# Check file permissions
ls -l /var/www/html/moodle/public/local/security_dashboard/index.php

# Should be: -rwxr-xr-x www-data www-data
```

### **Problem: Menu item not showing**

**Solution:**
```bash
# Re-copy settings.php
sudo cp ~/TA/adaptive-moodle-security/MoodleSec/moodle-plugin/settings.php \
    /var/www/html/moodle/public/local/security_dashboard/

# Clear cache
sudo -u www-data php /var/www/html/moodle/public/admin/cli/purge_caches.php

# Logout and login again
```

### **Problem: "Service Unavailable" error**

**Solution:**
```bash
# Check proxy is running
curl http://localhost:8999/health

# If not running:
cd ~/TA/adaptive-moodle-security/MoodleSec
docker-compose up -d

# Check logs
docker-compose logs proxy
```

### **Problem: "Module 'tldextract' not found"**

**Solution:**
```bash
cd ~/TA/adaptive-moodle-security/MoodleSec
source venv/bin/activate
pip install tldextract

# Restart proxy
docker-compose restart proxy
```

### **Problem: Phishing API not working**

**Solution:**
```bash
# Check if phishing_scan_api.py is imported in app.py
grep -n "phishing" ~/TA/adaptive-moodle-security/MoodleSec/proxy/app.py

# If nothing found, manually add the imports (see Step 3 above)

# Restart proxy
docker-compose restart proxy
```

---

## 📝 Quick Copy-Paste Commands

**One-liner deployment:**
```bash
cd ~/TA/adaptive-moodle-security/MoodleSec && \
sudo cp moodle-plugin/scan_phishing_content.php /var/www/html/moodle/public/local/security_dashboard/ && \
sudo cp moodle-plugin/index.php /var/www/html/moodle/public/local/security_dashboard/ && \
sudo cp moodle-plugin/settings.php /var/www/html/moodle/public/local/security_dashboard/ && \
sudo chown -R www-data:www-data /var/www/html/moodle/public/local/security_dashboard/ && \
sudo chmod -R 755 /var/www/html/moodle/public/local/security_dashboard/ && \
sudo -u www-data php /var/www/html/moodle/public/admin/cli/purge_caches.php && \
source venv/bin/activate && \
pip install tldextract && \
docker-compose restart proxy && \
echo "✅ Deployment complete!"
```

---

## 📂 File Structure Summary

```
~/TA/adaptive-moodle-security/MoodleSec/  (DEVELOPMENT)
├── moodle-plugin/
│   ├── scan_phishing_content.php    ← Copy to production
│   ├── index.php                    ← Copy to production (updated)
│   └── settings.php                 ← Copy to production (updated)
├── proxy/
│   ├── app.py                       ← Need to update manually
│   ├── scanners/
│   │   └── phishing_detector.py     ← Already in correct location
│   └── api/
│       └── phishing_scan_api.py     ← Already in correct location
└── PHISHING_DETECTION_GUIDE.md      ← User guide

/var/www/html/moodle/public/local/security_dashboard/  (PRODUCTION)
├── scan_phishing_content.php        ← NEW FILE (copy from dev)
├── index.php                        ← UPDATE (copy from dev)
├── settings.php                     ← UPDATE (copy from dev)
└── [other existing files...]
```

---

## ✅ Final Verification

After deployment, verify:

- [ ] Phishing Scanner button visible on dashboard
- [ ] Phishing Content Scanner menu item visible
- [ ] Can access scan_phishing_content.php page
- [ ] Can scan user profiles (test scan)
- [ ] Proxy API responds: `curl http://localhost:8999/phishing/stats`
- [ ] No errors in Moodle error logs: `/var/log/apache2/error.log`
- [ ] No errors in proxy logs: `docker-compose logs proxy`

---

**Deployment Date:** _____________  
**Tested By:** _____________  
**Status:** ⬜ Success  ⬜ Issues  

**Notes:**
```
[Write any issues or observations here]
```
