# Moodle Security Dashboard Plugin - Installation & Configuration Guide

Complete step-by-step guide for installing and configuring the Moodle Security Dashboard plugin with backend services.

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Moodle Installation](#moodle-installation)
3. [Backend Services Setup](#backend-services-setup)
4. [Plugin Installation](#plugin-installation)
5. [Configuration](#configuration)
6. [Testing](#testing)
7. [Troubleshooting](#troubleshooting)

---

## 🔧 Prerequisites

### System Requirements
- **OS**: Ubuntu 24.04 LTS (WSL2 or native)
- **Web Server**: Apache 2.4+
- **Database**: MySQL 8.0+ or MariaDB 10.6+
- **PHP**: 8.1+ (8.3 recommended)
- **Python**: 3.10+ (for backend services)

### Required PHP Extensions
```bash
php-mysql php-xml php-mbstring php-curl php-zip php-gd 
php-intl php-xmlrpc php-soap php-ldap
```

---

## 📦 Moodle Installation

### Step 1: Install Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Apache, MySQL, PHP
sudo apt install -y apache2 mysql-server php php-mysql php-xml \
    php-mbstring php-curl php-zip php-gd php-intl php-xmlrpc \
    php-soap php-ldap git curl unzip
```

### Step 2: Configure PHP

Find your PHP version:
```bash
php -v
# Example output: PHP 8.3.6
```

Edit PHP configuration:
```bash
# For PHP 8.3 (adjust version as needed)
sudo nano /etc/php/8.3/apache2/php.ini
```

Update these values:
```ini
max_execution_time = 300
max_input_time = 300
memory_limit = 256M
post_max_size = 100M
upload_max_filesize = 100M
max_input_vars = 5000
```

**Important**: Remove semicolon (`;`) from `max_input_vars` line!

### Step 3: Configure MySQL

```bash
# Secure MySQL installation
sudo mysql_secure_installation

# Create Moodle database
sudo mysql -u root -p
```

In MySQL prompt:
```sql
CREATE DATABASE moodle DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'moodleuser'@'localhost' IDENTIFIED BY 'moodlepassword';
GRANT ALL PRIVILEGES ON moodle.* TO 'moodleuser'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### Step 4: Download Moodle

```bash
cd ~
# Download Moodle 5.1
wget https://download.moodle.org/download.php/direct/stable51/moodle-5.1.tgz
tar -xzf moodle-5.1.tgz

# Copy to web root
sudo cp -r moodle /var/www/html/
```

### Step 5: Create Moodle Data Directory

```bash
# Create data directory (outside web root)
sudo mkdir -p /var/www/moodledata
sudo chown -R www-data:www-data /var/www/moodledata
sudo chmod -R 0777 /var/www/moodledata

# Set Moodle permissions
sudo chown -R www-data:www-data /var/www/html/moodle
sudo chmod -R 0755 /var/www/html/moodle
```

### Step 6: Configure Apache

**Note**: Moodle 5.1 uses `/public` directory structure.

Edit Apache ports (if port 80 is in use):
```bash
sudo nano /etc/apache2/ports.conf
```

Change to:
```apache
Listen 8998
```

Create Moodle virtual host:
```bash
sudo nano /etc/apache2/sites-available/moodle.conf
```

Add configuration:
```apache
<VirtualHost *:8998>
    ServerAdmin admin@localhost
    DocumentRoot /var/www/html/moodle/public
    ServerName localhost

    <Directory /var/www/html/moodle/public>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/moodle_error.log
    CustomLog ${APACHE_LOG_DIR}/moodle_access.log combined
</VirtualHost>
```

Enable site and restart Apache:
```bash
sudo a2ensite moodle.conf
sudo a2dissite 000-default.conf
sudo a2enmod rewrite
sudo service apache2 restart
```

### Step 7: Install Moodle via Web

1. Open browser: `http://localhost:8998/`
2. Follow installation wizard
3. Use these database settings:
   - **Database type**: MariaDB/MySQL
   - **Database host**: localhost
   - **Database name**: moodle
   - **Database user**: moodleuser
   - **Database password**: moodlepassword
   - **Tables prefix**: mdl_

4. **Important**: If you get MySQL version error, edit environment check:
   ```bash
   sudo nano /var/www/html/moodle/public/admin/environment.xml
   ```
   
   Find and change MySQL version requirement from `8.4` to `8.0`:
   ```xml
   <version>8.0</version>
   ```

5. Complete installation (takes 5-10 minutes for database setup)

6. Create admin account:
   - **Username**: admin
   - **Password**: Admin@12345 (or your choice)
   - **Email**: admin@example.com

### Step 8: Verify Installation

```bash
# Check database tables (should be 490+)
mysql -u moodleuser -pmoodlepassword moodle -e "SHOW TABLES;" | wc -l
```

Access Moodle:
```
http://localhost:8998/
```

---

## 🚀 Backend Services Setup

### Step 1: Setup Python Environment

```bash
cd ~/TA/adaptive-moodle-security/MoodleSec

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Configure Proxy Service

Edit proxy configuration:
```bash
nano ~/TA/adaptive-moodle-security/MoodleSec/proxy/config.py
```

Update `MOODLE_URL`:
```python
MOODLE_URL: str = "http://localhost:8998"
LISTEN_PORT: int = 8999
```

### Step 3: Fix Proxy Content-Length Error

Edit proxy app:
```bash
nano ~/TA/adaptive-moodle-security/MoodleSec/proxy/app.py
```

Find the response section (around line 232) and update:
```python
# Return response (remove Content-Length to avoid conflicts)
response_headers = dict(response.headers)
response_headers.pop("content-length", None)
response_headers.pop("transfer-encoding", None)

return Response(
    content=response.content,
    status_code=response.status_code,
    headers=response_headers,
    media_type=response.headers.get("content-type")
)
```

### Step 4: Start Backend Services

Open **two separate terminals**:

**Terminal 1 - CVSS Engine:**
```bash
cd ~/TA/adaptive-moodle-security/MoodleSec/cvss-engine
source ../venv/bin/activate
python api.py
```

**Terminal 2 - Proxy Service:**
```bash
cd ~/TA/adaptive-moodle-security/MoodleSec/proxy
source ../venv/bin/activate
python app.py
```

### Step 5: Verify Services

```bash
# Test CVSS Engine
curl http://localhost:8001/
# Expected: {"name":"CVSS v3.1 Calculator API",...}

# Test Proxy
curl http://localhost:8999/health
# Expected: {"status":"ok"}
```

---

## 🔌 Plugin Installation

### Step 1: Copy Plugin Files

```bash
# Copy plugin to Moodle
sudo cp -r ~/TA/adaptive-moodle-security/MoodleSec/moodle-plugin \
    /var/www/html/moodle/public/local/security_dashboard

# Set permissions
sudo chown -R www-data:www-data /var/www/html/moodle/public/local/security_dashboard
sudo chmod -R 0755 /var/www/html/moodle/public/local/security_dashboard
```

### Step 2: Trigger Plugin Installation

1. Go to: `http://localhost:8998/admin/index.php`
2. Moodle will detect the new plugin
3. Click **"Upgrade Moodle database now"**
4. Click **"Continue"**
5. Wait for database tables to be created

### Step 3: Verify Plugin Tables

```bash
mysql -u moodleuser -pmoodlepassword moodle -e "SHOW TABLES LIKE 'mdl_local_security_%';"
```

Expected output:
```
mdl_local_security_config
mdl_local_security_findings
mdl_local_security_logs
mdl_local_security_scans
mdl_local_security_schedules
```

---

## ⚙️ Configuration

### Step 1: Configure Service URLs

**Method 1: Via Database (Quick)**

```bash
# Set Proxy URL
mysql -u moodleuser -pmoodlepassword moodle -e \
"INSERT INTO mdl_config_plugins (plugin, name, value) 
VALUES ('local_security_dashboard', 'proxy_url', 'http://localhost:8999') 
ON DUPLICATE KEY UPDATE value='http://localhost:8999';"

# Set CVSS URL
mysql -u moodleuser -pmoodlepassword moodle -e \
"INSERT INTO mdl_config_plugins (plugin, name, value) 
VALUES ('local_security_dashboard', 'cvss_url', 'http://localhost:8001') 
ON DUPLICATE KEY UPDATE value='http://localhost:8001';"

# Verify
mysql -u moodleuser -pmoodlepassword moodle -e \
"SELECT * FROM mdl_config_plugins WHERE plugin='local_security_dashboard';"
```

**Method 2: Via Web Interface**

1. Go to: Site administration → Plugins → Local plugins → Security Dashboard
2. Or direct URL: `http://localhost:8998/admin/settings.php?section=local_security_dashboard`
3. Set:
   - **Proxy Service URL**: `http://localhost:8999`
   - **CVSS Engine URL**: `http://localhost:8001`
4. Click **Save changes**

### Step 2: Configure Moodle cURL Security

**Critical**: Moodle blocks localhost URLs by default for security.

**Method 1: Via Web Interface (Recommended)**

1. Go to: Site administration → Security → HTTP security
2. Or direct URL: `http://localhost:8998/admin/settings.php?section=httpsecurity`
3. Edit **cURL blocked hosts list**:
   - Remove `localhost` and `127.0.0.0/8` from the list
   - Or clear the entire list for development
4. Edit **cURL allowed ports list**:
   ```
   443
   80
   8999
   8001
   ```
5. Click **Save changes**

**Method 2: Via Database (Quick)**

```bash
# Clear blocked hosts (allow localhost)
mysql -u moodleuser -pmoodlepassword moodle -e \
"UPDATE mdl_config SET value='' WHERE name='curlsecurityblockedhosts';"

# Add allowed ports
mysql -u moodleuser -pmoodlepassword moodle -e \
"UPDATE mdl_config SET value='443
80
8999
8001' WHERE name='curlsecurityallowedport';"

# Verify
mysql -u moodleuser -pmoodlepassword moodle -e \
"SELECT name, value FROM mdl_config WHERE name LIKE 'curl%';"
```

### Step 3: Verify Configuration

Create test script:
```bash
sudo tee /var/www/html/moodle/test_config.php > /dev/null << 'EOF'
<?php
define('CLI_SCRIPT', true);
require_once(__DIR__ . '/config.php');
require_once($CFG->libdir . '/clilib.php');
require_once($CFG->libdir . '/filelib.php');

$proxy_url = get_config('local_security_dashboard', 'proxy_url');
$cvss_url = get_config('local_security_dashboard', 'cvss_url');

echo "Proxy URL: " . ($proxy_url ?: 'NOT SET') . "\n";
echo "CVSS URL: " . ($cvss_url ?: 'NOT SET') . "\n";

if (!empty($proxy_url)) {
    echo "\nTesting Proxy Health:\n";
    $curl = new curl();
    $response = $curl->get($proxy_url . '/health');
    echo "Response: " . $response . "\n";
    echo "Error: " . ($curl->get_errno() ? $curl->error : 'None') . "\n";
}

if (!empty($cvss_url)) {
    echo "\nTesting CVSS Health:\n";
    $curl2 = new curl();
    $response2 = $curl2->get($cvss_url . '/health');
    echo "Response: " . $response2 . "\n";
    echo "Error: " . ($curl2->get_errno() ? $curl2->error : 'None') . "\n";
}
EOF

# Run test
sudo -u www-data php /var/www/html/moodle/test_config.php
```

Expected output:
```
Proxy URL: http://localhost:8999
CVSS URL: http://localhost:8001

Testing Proxy Health:
Response: {"status":"ok"}
Error: None

Testing CVSS Health:
Response: {"status":"ok"}
Error: None
```

---

## ✅ Testing

### Step 1: Access Security Dashboard

Open browser:
```
http://localhost:8998/local/security_dashboard/index.php
```

### Step 2: Verify Service Status

You should see:
```
Service Status
Proxy Service: ✅ Online
CVSS Engine: ✅ Online
```

### Step 3: Test Scan Functionality

1. Click **"Scan Now"** button
2. You will be redirected to scan configuration page
3. Enter scan parameters:
   - **Path**: `/login/index.php`
   - **Method**: GET
4. Click **"Start Scan"**
5. View scan results with findings and CVSS scores

### Step 4: Verify Database Logging

```bash
# Check scan records
mysql -u moodleuser -pmoodlepassword moodle -e \
"SELECT * FROM mdl_local_security_scans ORDER BY timecreated DESC LIMIT 5;"

# Check findings
mysql -u moodleuser -pmoodlepassword moodle -e \
"SELECT * FROM mdl_local_security_findings ORDER BY timecreated DESC LIMIT 5;"
```

---

## 🔍 Troubleshooting

### Issue 1: Services Show Offline

**Symptoms**: Dashboard shows "❌ Offline" for both services

**Solutions**:

1. **Check if services are running**:
   ```bash
   curl http://localhost:8999/health
   curl http://localhost:8001/health
   ```

2. **Verify Moodle config**:
   ```bash
   mysql -u moodleuser -pmoodlepassword moodle -e \
   "SELECT * FROM mdl_config_plugins WHERE plugin='local_security_dashboard';"
   ```

3. **Check cURL security settings**:
   ```bash
   mysql -u moodleuser -pmoodlepassword moodle -e \
   "SELECT * FROM mdl_config WHERE name LIKE 'curl%';"
   ```

4. **Run test script** (see Configuration Step 3)

### Issue 2: Proxy Content-Length Error

**Symptoms**: `curl: (18) transfer closed with bytes remaining to read`

**Solution**: Update proxy `app.py` to remove Content-Length header (see Backend Services Setup Step 3)

### Issue 3: MySQL Version Warning

**Symptoms**: "version 8.4 is required and you are running 8.0.43"

**Solution**: Edit environment.xml to change required version from 8.4 to 8.0 (see Moodle Installation Step 7)

### Issue 4: max_input_vars Error

**Symptoms**: "PHP setting max_input_vars must be at least 5000"

**Solution**:
```bash
# Edit PHP config
sudo nano /etc/php/8.3/apache2/php.ini

# Find and uncomment (remove ;)
max_input_vars = 5000

# Restart Apache
sudo service apache2 restart
```

### Issue 5: Permission Denied

**Symptoms**: Cannot write to moodledata or plugin directory

**Solution**:
```bash
# Fix moodledata permissions
sudo chown -R www-data:www-data /var/www/moodledata
sudo chmod -R 0777 /var/www/moodledata

# Fix plugin permissions
sudo chown -R www-data:www-data /var/www/html/moodle/public/local/security_dashboard
sudo chmod -R 0755 /var/www/html/moodle/public/local/security_dashboard
```

### Issue 6: Port Already in Use

**Symptoms**: Apache fails to start on port 8998

**Solution**:
```bash
# Check what's using the port
sudo lsof -i :8998

# Kill the process or change Apache port
sudo nano /etc/apache2/ports.conf
# Change to different port (e.g., 8080)

# Update Moodle config
sudo nano /var/www/html/moodle/config.php
# Update $CFG->wwwroot
```

---

## 📊 Summary

### Installed Components

1. ✅ **Moodle 5.1** - Running on `http://localhost:8998`
2. ✅ **Security Dashboard Plugin** - Installed in `/local/security_dashboard`
3. ✅ **CVSS Engine** - Running on `http://localhost:8001`
4. ✅ **Proxy Service** - Running on `http://localhost:8999`

### Key Configuration Files

- **Moodle Config**: `/var/www/html/moodle/config.php`
- **Apache Config**: `/etc/apache2/sites-available/moodle.conf`
- **PHP Config**: `/etc/php/8.3/apache2/php.ini`
- **Proxy Config**: `~/TA/adaptive-moodle-security/MoodleSec/proxy/config.py`

### Database Tables

- `mdl_local_security_config` - Plugin configuration
- `mdl_local_security_scans` - Scan records
- `mdl_local_security_findings` - Security findings
- `mdl_local_security_logs` - Activity logs
- `mdl_local_security_schedules` - Scheduled scans

### Important URLs

- **Moodle**: `http://localhost:8998/`
- **Security Dashboard**: `http://localhost:8998/local/security_dashboard/index.php`
- **Plugin Settings**: `http://localhost:8998/admin/settings.php?section=local_security_dashboard`
- **HTTP Security**: `http://localhost:8998/admin/settings.php?section=httpsecurity`
- **CVSS API**: `http://localhost:8001/`
- **Proxy API**: `http://localhost:8999/`

---

## 🎯 Next Steps

1. **Configure scheduled scans** via plugin settings
2. **Set up email notifications** for critical findings
3. **Customize scan rules** in proxy service
4. **Add more CVSS vectors** for different vulnerability types
5. **Integrate with external DAST tools** (OWASP ZAP, Burp Suite)
6. **Set up production environment** with HTTPS and proper security

---

## 📝 Notes

- This setup is for **development/testing only**
- For **production**, enable HTTPS, use strong passwords, and restrict localhost access
- Keep all services updated regularly
- Monitor logs for security issues
- Backup database regularly

---

## 📚 References

- [Moodle Documentation](https://docs.moodle.org/)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Moodle Plugin Development](https://moodledev.io/)

---

**Installation Complete! 🎉**

For issues or questions, refer to the Troubleshooting section or check the project repository.
