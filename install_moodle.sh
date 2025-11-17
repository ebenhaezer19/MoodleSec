#!/bin/bash

# Automated Moodle Installation Script for WSL/Ubuntu
# Usage: ./install_moodle.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
MOODLE_DB="moodle"
MOODLE_USER="moodleuser"
MOODLE_PASS="moodlepassword"
MOODLE_DIR="/var/www/html/moodle"
MOODLE_DATA="/var/moodledata"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Moodle Installation Script${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
    echo -e "${RED}Please do not run as root. Use sudo when needed.${NC}"
    exit 1
fi

# Step 1: Update system
echo -e "${YELLOW}Step 1: Updating system...${NC}"
sudo apt update && sudo apt upgrade -y
echo -e "${GREEN}✅ System updated${NC}\n"

# Step 2: Install dependencies
echo -e "${YELLOW}Step 2: Installing dependencies...${NC}"
sudo apt install -y apache2 mysql-server php php-mysql php-xml php-mbstring \
    php-curl php-zip php-gd php-intl php-xmlrpc php-soap php-ldap \
    git curl unzip
echo -e "${GREEN}✅ Dependencies installed${NC}\n"

# Step 3: Configure PHP
echo -e "${YELLOW}Step 3: Configuring PHP...${NC}"
PHP_INI="/etc/php/8.1/apache2/php.ini"
if [ ! -f "$PHP_INI" ]; then
    PHP_INI=$(find /etc/php -name php.ini | grep apache2 | head -1)
fi

sudo sed -i 's/max_execution_time = .*/max_execution_time = 300/' "$PHP_INI"
sudo sed -i 's/max_input_time = .*/max_input_time = 300/' "$PHP_INI"
sudo sed -i 's/memory_limit = .*/memory_limit = 256M/' "$PHP_INI"
sudo sed -i 's/post_max_size = .*/post_max_size = 100M/' "$PHP_INI"
sudo sed -i 's/upload_max_filesize = .*/upload_max_filesize = 100M/' "$PHP_INI"
echo -e "${GREEN}✅ PHP configured${NC}\n"

# Step 4: Start services
echo -e "${YELLOW}Step 4: Starting services...${NC}"
sudo service apache2 start
sudo service mysql start
echo -e "${GREEN}✅ Services started${NC}\n"

# Step 5: Configure MySQL
echo -e "${YELLOW}Step 5: Configuring MySQL...${NC}"
echo -e "${BLUE}Creating database and user...${NC}"

sudo mysql -e "CREATE DATABASE IF NOT EXISTS $MOODLE_DB DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
sudo mysql -e "CREATE USER IF NOT EXISTS '$MOODLE_USER'@'localhost' IDENTIFIED BY '$MOODLE_PASS';"
sudo mysql -e "GRANT ALL PRIVILEGES ON $MOODLE_DB.* TO '$MOODLE_USER'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

echo -e "${GREEN}✅ MySQL configured${NC}"
echo -e "${BLUE}Database: $MOODLE_DB${NC}"
echo -e "${BLUE}User: $MOODLE_USER${NC}"
echo -e "${BLUE}Password: $MOODLE_PASS${NC}\n"

# Step 6: Download Moodle
echo -e "${YELLOW}Step 6: Downloading Moodle...${NC}"
if [ -d "$MOODLE_DIR" ]; then
    echo -e "${YELLOW}Moodle directory exists. Backing up...${NC}"
    sudo mv "$MOODLE_DIR" "${MOODLE_DIR}_backup_$(date +%Y%m%d_%H%M%S)"
fi

cd /var/www/html
sudo git clone -b MOODLE_403_STABLE git://git.moodle.org/moodle.git moodle
echo -e "${GREEN}✅ Moodle downloaded${NC}\n"

# Step 7: Create data directory
echo -e "${YELLOW}Step 7: Creating data directory...${NC}"
if [ ! -d "$MOODLE_DATA" ]; then
    sudo mkdir -p "$MOODLE_DATA"
fi
sudo chown -R www-data:www-data "$MOODLE_DATA"
sudo chmod -R 0777 "$MOODLE_DATA"
echo -e "${GREEN}✅ Data directory created${NC}\n"

# Step 8: Set permissions
echo -e "${YELLOW}Step 8: Setting permissions...${NC}"
sudo chown -R www-data:www-data "$MOODLE_DIR"
sudo chmod -R 0755 "$MOODLE_DIR"
echo -e "${GREEN}✅ Permissions set${NC}\n"

# Step 9: Configure Apache
echo -e "${YELLOW}Step 9: Configuring Apache...${NC}"
sudo tee /etc/apache2/sites-available/moodle.conf > /dev/null <<EOF
<VirtualHost *:80>
    ServerAdmin admin@localhost
    DocumentRoot $MOODLE_DIR
    ServerName localhost

    <Directory $MOODLE_DIR>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/moodle_error.log
    CustomLog \${APACHE_LOG_DIR}/moodle_access.log combined
</VirtualHost>
EOF

sudo a2ensite moodle.conf
sudo a2enmod rewrite
sudo systemctl restart apache2
echo -e "${GREEN}✅ Apache configured${NC}\n"

# Step 10: Create config.php for CLI installation
echo -e "${YELLOW}Step 10: Installing Moodle via CLI...${NC}"
sudo -u www-data php "$MOODLE_DIR/admin/cli/install.php" \
    --lang=en \
    --wwwroot=http://localhost/moodle \
    --dataroot="$MOODLE_DATA" \
    --dbtype=mariadb \
    --dbhost=localhost \
    --dbname="$MOODLE_DB" \
    --dbuser="$MOODLE_USER" \
    --dbpass="$MOODLE_PASS" \
    --fullname="Moodle Security Test" \
    --shortname="MST" \
    --adminuser=admin \
    --adminpass=Admin@123 \
    --adminemail=admin@localhost \
    --non-interactive \
    --agree-license

echo -e "${GREEN}✅ Moodle installed${NC}\n"

# Step 11: Verify installation
echo -e "${YELLOW}Step 11: Verifying installation...${NC}"
TABLE_COUNT=$(mysql -u "$MOODLE_USER" -p"$MOODLE_PASS" "$MOODLE_DB" -e "SHOW TABLES;" | wc -l)
echo -e "${BLUE}Database tables created: $TABLE_COUNT${NC}"

if [ "$TABLE_COUNT" -gt 400 ]; then
    echo -e "${GREEN}✅ Installation verified${NC}\n"
else
    echo -e "${RED}⚠️  Warning: Expected 400+ tables, found $TABLE_COUNT${NC}\n"
fi

# Summary
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Installation Complete!${NC}"
echo -e "${BLUE}========================================${NC}\n"

echo -e "${GREEN}Moodle URL:${NC} http://localhost/moodle"
echo -e "${GREEN}Admin Username:${NC} admin"
echo -e "${GREEN}Admin Password:${NC} Admin@123"
echo -e ""
echo -e "${GREEN}Database:${NC} $MOODLE_DB"
echo -e "${GREEN}DB User:${NC} $MOODLE_USER"
echo -e "${GREEN}DB Password:${NC} $MOODLE_PASS"
echo -e ""
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "1. Open browser: http://localhost/moodle"
echo -e "2. Login with admin credentials"
echo -e "3. Install Security Dashboard plugin:"
echo -e "   sudo cp -r ~/TA/adaptive-moodle-security/MoodleSec/moodle-plugin $MOODLE_DIR/local/security_dashboard"
echo -e "   sudo chown -R www-data:www-data $MOODLE_DIR/local/security_dashboard"
echo -e "4. Go to: http://localhost/moodle/admin/index.php"
echo -e ""
echo -e "${GREEN}✅ All done!${NC}\n"
