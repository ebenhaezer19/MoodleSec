# Setup Vulnerable Moodle 3.9.0 for CVE Testing (PowerShell)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Moodle 3.9.0 Vulnerable Setup (Docker)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if Docker is installed
$dockerInstalled = Get-Command docker -ErrorAction SilentlyContinue
if (-not $dockerInstalled) {
    Write-Host "❌ Docker not found. Please install Docker Desktop first:" -ForegroundColor Red
    Write-Host "   https://www.docker.com/products/docker-desktop" -ForegroundColor Yellow
    exit 1
}

Write-Host "✅ Docker found" -ForegroundColor Green
Write-Host ""

# Create docker-compose.yml
$dockerCompose = @"
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
"@

$dockerCompose | Out-File -FilePath "docker-compose.yml" -Encoding UTF8
Write-Host "📝 docker-compose.yml created" -ForegroundColor Green
Write-Host ""

Write-Host "🚀 Starting Moodle 3.9.0..." -ForegroundColor Cyan
Write-Host "   This may take 3-5 minutes on first run..." -ForegroundColor Yellow
Write-Host ""

# Start containers
docker-compose up -d

Write-Host ""
Write-Host "⏳ Waiting for Moodle to initialize (30 seconds)..." -ForegroundColor Yellow
Start-Sleep -Seconds 30

# Check if running
$running = docker ps | Select-String "moodle-vuln"
if ($running) {
    Write-Host ""
    Write-Host "✅ Moodle 3.9.0 is running!" -ForegroundColor Green
    Write-Host ""
    Write-Host "📊 Access Information:" -ForegroundColor Cyan
    Write-Host "   URL: http://localhost:8080" -ForegroundColor White
    Write-Host "   Username: admin" -ForegroundColor White
    Write-Host "   Password: Admin123!" -ForegroundColor White
    Write-Host ""
    Write-Host "🔍 Useful Commands:" -ForegroundColor Cyan
    Write-Host "   Check logs: docker logs moodle-vuln -f" -ForegroundColor White
    Write-Host "   Stop: docker-compose down" -ForegroundColor White
    Write-Host "   Remove all: docker-compose down -v" -ForegroundColor White
    Write-Host ""
    Write-Host "🎯 Next: Open browser to http://localhost:8080" -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Host "❌ Failed to start Moodle" -ForegroundColor Red
    Write-Host "Check logs: docker logs moodle-vuln" -ForegroundColor Yellow
}
