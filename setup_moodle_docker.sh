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
    image: bitnami/moodle:3.9.0
    container_name: moodle-vuln
    ports:
      - "8080:8080"
      - "8443:8443"
    environment:
      MOODLE_DATABASE_HOST: mariadb
      MOODLE_DATABASE_PORT_NUMBER: 3306
      MOODLE_DATABASE_NAME: moodle
      MOODLE_DATABASE_USER: moodleuser
      MOODLE_DATABASE_PASSWORD: moodlepass
      MOODLE_USERNAME: admin
      MOODLE_PASSWORD: Admin123!
      MOODLE_EMAIL: admin@localhost.com
      MOODLE_SITE_NAME: "MoodleSec Test Lab"
      ALLOW_EMPTY_PASSWORD: 'yes'
    volumes:
      - moodle_data:/bitnami/moodle
      - moodledata_data:/bitnami/moodledata
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

# Start containers
docker-compose up -d

echo ""
echo "⏳ Waiting for Moodle to initialize..."
sleep 30

# Check if running
if docker ps | grep -q moodle-vuln; then
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
    echo ""
    echo "🛑 Stop Moodle:"
    echo "   docker-compose down"
    echo ""
    echo "🗑️ Remove everything (including data):"
    echo "   docker-compose down -v"
    echo ""
else
    echo "❌ Failed to start Moodle"
    echo "Check logs: docker logs moodle-vuln"
fi
EOF

chmod +x setup_moodle_docker.sh
echo "✅ Setup script created: setup_moodle_docker.sh"
echo ""
echo "Run: bash setup_moodle_docker.sh"
