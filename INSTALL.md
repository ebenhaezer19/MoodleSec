# MoodleSec Installation Guide

## Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Virtual environment (recommended)

## Installation Steps

### 1. Clone or Extract the Project

```bash
# If from Git
git clone https://github.com/ebenhaezer19/MoodleSec.git
cd MoodleSec

# If from ZIP
# Extract moodlesec_plugin.zip to a folder
cd MoodleSec
```

### 2. Create Virtual Environment

**Windows:**
```cmd
python -m venv venv
venv\Scripts\activate
```

**Linux/Mac/WSL:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

**If you encounter errors, try upgrading pip first:**
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Navigate to Proxy Directory

```bash
cd proxy
```

### 5. Run the Application

```bash
python app.py
```

The server will start on `http://localhost:8080`

## Verification

Open your browser and navigate to:
- Dashboard: `http://localhost:8080`
- Health check: `http://localhost:8080/health`

## Common Issues

### Issue 1: Module not found

**Solution:**
```bash
# Make sure virtual environment is activated
# Windows: venv\Scripts\activate
# Linux: source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

### Issue 2: Port 8080 already in use

**Solution:**
```bash
# Check what's using port 8080
# Windows:
netstat -ano | findstr :8080

# Linux:
lsof -i :8080

# Kill the process or change port in config.py
```

### Issue 3: Permission denied (Linux/Mac)

**Solution:**
```bash
# Make sure you have write permissions
chmod +x app.py

# Or run with sudo (not recommended)
sudo python app.py
```

### Issue 4: SSL/TLS errors

**Solution:**
```bash
# Update certifi
pip install --upgrade certifi

# Or disable SSL verification (development only)
# Set in config.py: VERIFY_SSL = False
```

## Running in Production

For production deployment, use a production ASGI server:

```bash
# Install gunicorn (Linux/Mac)
pip install gunicorn

# Run with gunicorn
gunicorn -w 4 -k uvicorn.workers.UvicornWorker app:app --bind 0.0.0.0:8080

# Or use uvicorn with more workers
uvicorn app:app --host 0.0.0.0 --port 8080 --workers 4
```

## Docker Installation (Optional)

If you prefer Docker:

```bash
# Build image
docker build -t moodlesec .

# Run container
docker run -p 8080:8080 moodlesec
```

## Configuration

Edit `config.py` to customize:
- Target Moodle URL
- Scan settings
- ML model parameters
- Database location

## Next Steps

1. Configure target Moodle instance
2. Run your first scan
3. Review findings in dashboard
4. Train ML models with real data

## Support

For issues or questions:
- Check logs in `logs/` directory
- Review documentation in `README.md`
- For TA/research purposes only

## System Requirements

**Minimum:**
- CPU: 2 cores
- RAM: 2GB
- Disk: 1GB free space

**Recommended:**
- CPU: 4+ cores
- RAM: 4GB+
- Disk: 5GB+ free space
- SSD for better performance
