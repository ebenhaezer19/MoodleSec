# Moodle Installation Guide - WSL/Ubuntu

## Prerequisites

- WSL2 with Ubuntu installed
- At least 4GB RAM
- 10GB free disk space

---

## Step 1: Update System & Install Dependencies

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Apache, MySQL, PHP and required extensions
sudo apt install -y apache2 mysql-server php php-mysql php-xml php-mbstring \
    php-curl php-zip php-gd php-intl php-xmlrpc php-soap php-ldap \
    git curl unzip
```

---

## Step 2: Configure PHP

```bash
# Edit php.ini
sudo nano /etc/php/8.1/apache2/php.ini
```

Find and modify these values:
```ini
max_execution_time = 300
max_input_time = 300
memory_limit = 256M
post_max_size = 100M
upload_max_filesize = 100M
```

Save: `Ctrl+O`, Enter, `Ctrl+X`

---

## Step 3: Start Services

```bash
# Start Apache
sudo service apache2 start

# Start MySQL
sudo service mysql start

# Verify services
sudo service apache2 status
sudo service mysql status
```

---

## Step 4: Configure MySQL

```bash
# Secure MySQL installation
sudo mysql_secure_installation
```

Answer prompts:
- Set root password: **Yes** (choose a password)
- Remove anonymous users: **Yes**
- Disallow root login remotely: **Yes**
- Remove test database: **Yes**
- Reload privilege tables: **Yes**

```bash
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

---

## Step 5: Download Moodle

```bash
# Go to web root
cd /var/www/html

# Download Moodle (latest stable - 4.3)
sudo git clone -b MOODLE_403_STABLE git://git.moodle.org/moodle.git moodle

# Create moodledata directory (outside web root)
sudo mkdir /var/moodledata
sudo chown -R www-data:www-data /var/moodledata
sudo chmod -R 0777 /var/moodledata

# Set permissions
sudo chown -R www-data:www-data /var/www/html/moodle
sudo chmod -R 0755 /var/www/html/moodle
```

---

## Step 6: Configure Apache

```bash
# Create Moodle site configuration
sudo nano /etc/apache2/sites-available/moodle.conf
```

Add this content:
```apache
<VirtualHost *:80>
    ServerAdmin admin@localhost
    DocumentRoot /var/www/html/moodle
    ServerName localhost

    <Directory /var/www/html/moodle>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog ${APACHE_LOG_DIR}/moodle_error.log
    CustomLog ${APACHE_LOG_DIR}/moodle_access.log combined
</VirtualHost>
```

Save and enable:
```bash
# Enable site and rewrite module
sudo a2ensite moodle.conf
sudo a2enmod rewrite
sudo systemctl restart apache2
```

---

## Step 7: Install Moodle via Web Interface

1. **Open browser** and go to:
   ```
   http://localhost/moodle
   ```

2. **Choose language**: English → Next

3. **Data directories**:
   - Web address: `http://localhost/moodle`
   - Moodle directory: `/var/www/html/moodle`
   - Data directory: `/var/moodledata`
   → Next

4. **Database driver**: 
   - Choose: **MariaDB (native/mariadb)**
   → Next

5. **Database settings**:
   - Database host: `localhost`
   - Database name: `moodle`
   - Database user: `moodleuser`
   - Database password: `moodlepassword`
   - Tables prefix: `mdl_`
   → Next

6. **Copyright notice**: 
   - Read and click **Continue**

7. **Server checks**: 
   - All should be green ✅
   - If any red, install missing PHP extensions
   → Continue

8. **Installation**:
   - Wait for installation (5-10 minutes)
   - Click **Continue**

9. **Admin account**:
   - Username: `admin`
   - Password: (choose strong password)
   - Email: your email
   - City: your city
   - Country: your country
   → Update profile

10. **Front page settings**:
    - Site name: `Moodle Security Test`
    - Short name: `MST`
    → Save changes

---

## Step 8: Verify Installation

```bash
# Check Moodle is running
curl http://localhost/moodle

# Check database tables
mysql -u moodleuser -p moodle -e "SHOW TABLES;" | wc -l
# Should show ~400+ tables
```

---

## Step 9: Install Security Dashboard Plugin

```bash
# Copy plugin to Moodle
cd ~/TA/adaptive-moodle-security/MoodleSec
sudo cp -r moodle-plugin /var/www/html/moodle/local/security_dashboard

# Set permissions
sudo chown -R www-data:www-data /var/www/html/moodle/local/security_dashboard
sudo chmod -R 0755 /var/www/html/moodle/local/security_dashboard
```

---

## Step 10: Install Plugin via Web

1. **Go to**: `http://localhost/moodle/admin/index.php`

2. **Login as admin**

3. **Moodle will detect new plugin**:
   ```
   New plugin detected: Security Dashboard (local_security_dashboard)
   ```

4. **Click "Upgrade Moodle database now"**

5. **Scroll down** and click **"Continue"**

6. **Verify tables created**:
   ```bash
   mysql -u moodleuser -p moodle -e "SHOW TABLES LIKE 'mdl_local_security_%';"
   ```
   Should show 5 tables

---

## Step 11: Configure Plugin

1. **Go to**: Site administration → Plugins → Local plugins → Security Dashboard

2. **Set URLs**:
   - Proxy Service URL: `http://localhost:8999`
   - CVSS Engine URL: `http://localhost:8001`

3. **Save changes**

---

## Step 12: Test Plugin

1. **Access Dashboard**:
   ```
   http://localhost/moodle/local/security_dashboard/index.php
   ```

2. **Expected**:
   - Service health status
   - Recent scans (empty initially)
   - Scan button

3. **Trigger Test Scan**:
   ```
   http://localhost/moodle/local/security_dashboard/scan.php
   ```
   - Path: `/login/index.php`
   - Method: `POST`
   - Click "Trigger Scan"

---

## Quick Start Commands (All-in-One)

```bash
# Start services
sudo service apache2 start
sudo service mysql start

# Check status
sudo service apache2 status
sudo service mysql status

# View logs
sudo tail -f /var/log/apache2/moodle_error.log
sudo tail -f /var/www/html/moodle/moodledata/error.log
```

---

## Troubleshooting

### Issue 1: Apache won't start
```bash
# Check what's using port 80
sudo lsof -i :80

# Kill process if needed
sudo kill -9 <PID>

# Restart Apache
sudo service apache2 restart
```

### Issue 2: MySQL connection error
```bash
# Check MySQL is running
sudo service mysql status

# Reset MySQL password
sudo mysql -u root
ALTER USER 'moodleuser'@'localhost' IDENTIFIED BY 'moodlepassword';
FLUSH PRIVILEGES;
EXIT;
```

### Issue 3: Permission denied
```bash
# Fix permissions
sudo chown -R www-data:www-data /var/www/html/moodle
sudo chown -R www-data:www-data /var/moodledata
sudo chmod -R 0755 /var/www/html/moodle
sudo chmod -R 0777 /var/moodledata
```

### Issue 4: PHP extensions missing
```bash
# Install missing extensions
sudo apt install php-<extension-name>
sudo service apache2 restart
```

### Issue 5: Can't access from Windows browser
```bash
# Get WSL IP address
ip addr show eth0 | grep inet

# Access via: http://<WSL-IP>/moodle
# Or setup port forwarding in Windows
```

---

## Useful Commands

```bash
# Restart services
sudo service apache2 restart
sudo service mysql restart

# Clear Moodle cache
sudo -u www-data php /var/www/html/moodle/admin/cli/purge_caches.php

# Upgrade Moodle
cd /var/www/html/moodle
sudo -u www-data git pull
sudo -u www-data php admin/cli/upgrade.php

# Backup database
mysqldump -u moodleuser -p moodle > moodle_backup.sql

# Check Moodle version
cat /var/www/html/moodle/version.php | grep release
```

---

## Security Notes

⚠️ **For Production:**
- Change default passwords
- Enable SSL/HTTPS
- Configure firewall
- Regular backups
- Update regularly
- Disable debug mode

---

## Estimated Time

- System setup: 10 minutes
- Moodle download: 5 minutes
- Web installation: 10 minutes
- Plugin installation: 5 minutes
- **Total: ~30 minutes**

---

**Last Updated:** 2024-11-17
