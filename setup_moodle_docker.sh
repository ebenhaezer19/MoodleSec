#!/bin/bash
# Setup Vulnerable Moodle 3.9.0 for CVE Testing
# Use with Git Bash on Windows or WSL

echo "========================================"
echo "Moodle 3.9.0 Vulnerable Setup (Docker)"
echo "========================================"

# Check if Docker is installed
if ! command -v docker &> /dev/null
then
    echo "❌ Docker not found. Please install Docker Desktop first:"
    echo "   https://www.docker.com/products/docker-desktop"
    exit 1
fi

echo "✅ Docker found"

# Create docker-compose.yml
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  mariadb:
    image: mariadb:10.5
    container_name: moodle-db
    environment:
      MYSQL_ROOT_PASSWORD: rootpass
      MYSQL_DATABASE: moodle
      MYSQL_USER: moodleuser
      MYSQL_PASSWORD: moodlepass
    volumes:
      - mariadb_data:/var/lib/mysql
    networks:
      - moodle-network

  moodle:
    image: moodlehq/moodle-php-apache:3.9
    container_name: moodle-vuln
    ports:
      - "8080:80"
    environment:
      MOODLE_DATABASE_TYPE: mariadb
      MOODLE_DATABASE_HOST: mariadb
      MOODLE_DATABASE_NAME: moodle
      MOODLE_DATABASE_USER: moodleuser
      MOODLE_DATABASE_PASSWORD: moodlepass
      MOODLE_ADMIN_USER: admin
      MOODLE_ADMIN_PASSWORD: Admin123!
      MOODLE_ADMIN_EMAIL: admin@localhost.com
      MOODLE_WWWROOT: http://localhost:8080
    volumes:
      - moodle_data:/var/www/html
      - moodledata_data:/var/moodledata
    depends_on:
      - mariadb
    networks:
      - moodle-network

volumes:
  mariadb_data:
  moodle_data:
  moodledata_data:

networks:
  moodle-network:
    driver: bridge
EOF

echo ""
echo "📝 docker-compose.yml created"
echo ""
echo "🚀 Starting Moodle 3.9.0..."
echo "   This may take 3-5 minutes on first run..."
echo ""

# Check if docker-compose (v1) or docker compose (v2) is available
if command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
elif docker compose version &> /dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
else
    echo "❌ Neither 'docker-compose' nor 'docker compose' found"
    echo "Install Docker Compose: https://docs.docker.com/compose/install/"
    exit 1
fi

echo "Using: $DOCKER_COMPOSE"
echo ""

# Start containers (try with sudo if permission denied)
if ! $DOCKER_COMPOSE up -d 2>&1; then
    echo ""
    echo "⚠️  Permission denied. Trying with sudo..."
    sudo $DOCKER_COMPOSE up -d
fi

echo ""
echo "⏳ Waiting for Moodle to initialize..."
sleep 30

# Check if running
if sudo docker ps | grep -q moodle-vuln 2>/dev/null || docker ps | grep -q moodle-vuln 2>/dev/null; then
    echo ""
    echo "✅ Moodle 3.9.0 is running!"
    echo ""
    echo "📊 Access Information:"
    echo "   URL: http://localhost:8080"
    echo "   Username: admin"
    echo "   Password: Admin123!"
    echo ""
    echo "🔍 Check logs:"
    echo "   docker logs moodle-vuln -f"
    echo "   (or: sudo docker logs moodle-vuln -f)"
    echo ""
    echo "🛑 Stop Moodle:"
    echo "   docker compose down (or: docker-compose down)"
    echo ""
    echo "🗑️ Remove everything (including data):"
    echo "   docker compose down -v"
    echo ""
else
    echo "❌ Failed to start Moodle"
    echo "Check logs: sudo docker logs moodle-vuln"
    echo ""
    echo "💡 Common fixes:"
    echo "   1. Add user to docker group: sudo usermod -aG docker \$USER"
    echo "   2. Then logout and login again"
    echo "   3. Or always use: sudo docker compose up -d"
    echo ""
fi
EOF

chmod +x setup_moodle_docker.sh
echo "✅ Setup script created: setup_moodle_docker.sh"
echo ""
echo "Run: bash setup_moodle_docker.sh"
