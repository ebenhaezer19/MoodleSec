@echo off
REM Start Mock ZAP Server for Moodle Plugin Testing

echo.
echo ==========================================
echo Starting Mock ZAP Server
echo ==========================================
echo.
echo Requirements:
echo   pip install flask
echo.

cd /d "%~dp0"

REM Check if Flask is installed
python -c "import flask" 2>nul
if errorlevel 1 (
    echo Flask not found. Installing...
    pip install flask
)

echo Starting server on http://localhost:5000
echo Health check: http://localhost:5000/health
echo.
echo Press Ctrl+C to stop the server
echo.

python mock_zap_server.py

pause
