# 🚀 MoodleSec Proxy Service Management

## Setup Systemd Service (Auto-start on Boot)

### **1. Install Service File**

```bash
# Copy service file to systemd
sudo cp ~/TA/adaptive-moodle-security/MoodleSec/moodlesec-proxy.service \
    /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable service (auto-start on boot)
sudo systemctl enable moodlesec-proxy.service

# Start service now
sudo systemctl start moodlesec-proxy.service
```

---

### **2. Service Management Commands**

```bash
# Start service
sudo systemctl start moodlesec-proxy

# Stop service
sudo systemctl stop moodlesec-proxy

# Restart service
sudo systemctl restart moodlesec-proxy

# Check status
sudo systemctl status moodlesec-proxy

# View logs (real-time)
sudo journalctl -u moodlesec-proxy -f

# View logs (last 100 lines)
sudo journalctl -u moodlesec-proxy -n 100
```

---

### **3. Verify Service is Running**

```bash
# Check process
ps aux | grep uvicorn

# Check port
sudo netstat -tlnp | grep 8999

# Test API
curl http://localhost:8999/health

# Test phishing API
curl http://localhost:8999/phishing/stats
```

---

## 🔧 Manual Start (Without Systemd)

### **Option 1: Using uvicorn (Recommended)**

```bash
cd ~/TA/adaptive-moodle-security/MoodleSec

# Activate venv
source venv/bin/activate

# Start in background
cd proxy
nohup uvicorn app:app --host 0.0.0.0 --port 8999 > ../logs/proxy.log 2>&1 &

# Check logs
tail -f ~/TA/adaptive-moodle-security/MoodleSec/logs/proxy.log
```

### **Option 2: Using Python directly**

```bash
cd ~/TA/adaptive-moodle-security/MoodleSec

# Activate venv
source venv/bin/activate

# Start in background
cd proxy
nohup python3 app.py > ../logs/proxy.log 2>&1 &

# Get process ID
echo $!
```

---

## 🛑 Stop Proxy Service

### **If Using Systemd:**
```bash
sudo systemctl stop moodlesec-proxy
```

### **If Running Manually:**
```bash
# Find process
ps aux | grep -E "(uvicorn|app.py)"

# Kill by pattern
pkill -f "uvicorn.*app:app"
# OR
pkill -f "python.*app.py"

# Kill by PID
kill -9 <PID>
```

---

## 📊 Check Service Status

```bash
# Systemd status
sudo systemctl status moodlesec-proxy

# Process status
ps aux | grep -E "(uvicorn|app.py)"

# Port status
sudo netstat -tlnp | grep 8999
# OR
sudo ss -tlnp | grep 8999

# Test API response
curl -v http://localhost:8999/health
```

---

## 🐛 Troubleshooting

### **Problem: Port 8999 already in use**

```bash
# Find what's using port
sudo lsof -i :8999

# Kill process
sudo kill -9 <PID>

# Restart service
sudo systemctl restart moodlesec-proxy
```

### **Problem: Service won't start**

```bash
# Check logs
sudo journalctl -u moodlesec-proxy -n 50

# Check Python syntax
cd ~/TA/adaptive-moodle-security/MoodleSec/proxy
python3 -m py_compile app.py

# Test manually
source ../venv/bin/activate
python3 app.py
```

### **Problem: Import errors**

```bash
# Install missing packages
cd ~/TA/adaptive-moodle-security/MoodleSec
source venv/bin/activate
pip install -r requirements.txt
pip install tldextract

# Restart service
sudo systemctl restart moodlesec-proxy
```

---

## 📝 Service Configuration

Edit service file:
```bash
sudo nano /etc/systemd/system/moodlesec-proxy.service
```

After changes:
```bash
# Reload systemd
sudo systemctl daemon-reload

# Restart service
sudo systemctl restart moodlesec-proxy
```

---

## ✅ Health Check Script

Create monitoring script:

```bash
#!/bin/bash
# health_check.sh

PROXY_URL="http://localhost:8999/health"

if curl -s -f "$PROXY_URL" > /dev/null 2>&1; then
    echo "✅ Proxy service is healthy"
    exit 0
else
    echo "❌ Proxy service is down!"
    echo "Attempting restart..."
    sudo systemctl restart moodlesec-proxy
    sleep 5
    
    if curl -s -f "$PROXY_URL" > /dev/null 2>&1; then
        echo "✅ Proxy service restarted successfully"
        exit 0
    else
        echo "❌ Failed to restart proxy service"
        exit 1
    fi
fi
```

Run every 5 minutes with cron:
```bash
crontab -e

# Add this line:
*/5 * * * * /path/to/health_check.sh >> /var/log/moodlesec-health.log 2>&1
```

---

## 📌 Quick Reference

| Command | Purpose |
|---------|---------|
| `sudo systemctl start moodlesec-proxy` | Start service |
| `sudo systemctl stop moodlesec-proxy` | Stop service |
| `sudo systemctl restart moodlesec-proxy` | Restart service |
| `sudo systemctl status moodlesec-proxy` | Check status |
| `sudo journalctl -u moodlesec-proxy -f` | View logs (follow) |
| `curl http://localhost:8999/health` | Test API |
| `curl http://localhost:8999/phishing/stats` | Test phishing detection |
| `ps aux | grep uvicorn` | Find process |
| `sudo netstat -tlnp | grep 8999` | Check port |

---

**Last Updated:** January 2026  
**Service Type:** Systemd (Native, No Docker)
