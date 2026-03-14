#!/usr/bin/env python3
"""
Mock ZAP Server for Testing Moodle Plugin
Simulates ZAP API responses without needing real ZAP running
Perfect for development and testing the plugin UI
"""

from flask import Flask, request, jsonify
import json
import time
from datetime import datetime
import threading

app = Flask(__name__)

# Store scan data in memory
scans = {
    'spider': {},
    'ascan': {},
    'alerts': {}
}

scan_counter = 1

@app.route('/JSON/core/view/version', methods=['GET'])
def view_version():
    """Return ZAP version info"""
    return jsonify({
        'version': '2.17.0'
    })

@app.route('/JSON/core/view/alerts', methods=['GET'])
def view_alerts():
    """Return vulnerability alerts"""
    baseurl = request.args.get('baseurl', 'http://localhost')
    
    # Mock alerts for testing
    mock_alerts = [
        {
            'id': '1',
            'type': 'Cross Site Scripting (Reflected)',
            'name': 'Cross Site Scripting (Reflected)',
            'risk': 'High',
            'confidence': 'Medium',
            'url': f'{baseurl}/form.php?search=<script>',
            'method': 'GET',
            'description': 'Cross-site Scripting (XSS) is an attack...',
            'solution': 'Escape user input and output encode...',
            'reference': 'https://owasp.org/www-community/attacks/xss/',
            'evidence': '<script>alert(1)</script>',
            'cwe_id': '79',
            'wascid': '8'
        },
        {
            'id': '2',
            'type': 'SQL Injection',
            'name': 'SQL Injection',
            'risk': 'High',
            'confidence': 'High',
            'url': f'{baseurl}/search.php?id=1',
            'method': 'GET',
            'description': 'SQL injection is a code injection...',
            'solution': 'Use parameterized queries or prepared statements...',
            'reference': 'https://owasp.org/www-community/attacks/SQL_Injection',
            'evidence': "' OR '1'='1",
            'cwe_id': '89',
            'wascid': '19'
        },
        {
            'id': '3',
            'type': 'Missing Security Header',
            'name': 'X-Frame-Options Header Missing',
            'risk': 'Medium',
            'confidence': 'High',
            'url': f'{baseurl}/index.php',
            'method': 'GET',
            'description': 'X-Frame-Options header is not set...',
            'solution': 'Set X-Frame-Options header to DENY or SAMEORIGIN...',
            'reference': 'https://owasp.org/www-community/attacks/Clickjacking',
            'evidence': 'Header not found',
            'cwe_id': '1021',
            'wascid': '15'
        },
        {
            'id': '4',
            'type': 'Insecure Cookie Flag',
            'name': 'Cookie without Secure Flag',
            'risk': 'Low',
            'confidence': 'Medium',
            'url': f'{baseurl}/index.php',
            'method': 'GET',
            'description': 'Cookie set without Secure flag...',
            'solution': 'Set Secure flag on all cookies...',
            'reference': 'https://owasp.org/www-community/controls/Cookie_Security',
            'evidence': 'sessionid=abc123',
            'cwe_id': '614',
            'wascid': '8'
        }
    ]
    
    return jsonify({'alerts': mock_alerts})

@app.route('/JSON/spider/action/scan', methods=['GET'])
def spider_scan():
    """Start spider scan"""
    global scan_counter
    
    scan_id = str(scan_counter)
    scan_counter += 1
    
    scans['spider'][scan_id] = {
        'startTime': time.time(),
        'status': 0
    }
    
    # Simulate scan progress in background
    def progress_scan():
        for progress in range(0, 101, 20):
            scans['spider'][scan_id]['status'] = progress
            time.sleep(1)
    
    thread = threading.Thread(target=progress_scan, daemon=True)
    thread.start()
    
    return jsonify({'scan': scan_id})

@app.route('/JSON/spider/view/status', methods=['GET'])
def spider_status():
    """Get spider scan status"""
    scan_id = request.args.get('scanid', '0')
    
    if scan_id in scans['spider']:
        status = scans['spider'][scan_id]['status']
    else:
        status = 100
    
    return jsonify({'status': status})

@app.route('/JSON/ascan/action/scan', methods=['GET'])
def ascan_scan():
    """Start active scan"""
    global scan_counter
    
    scan_id = str(scan_counter)
    scan_counter += 1
    
    scans['ascan'][scan_id] = {
        'startTime': time.time(),
        'status': 0
    }
    
    # Simulate scan progress in background
    def progress_scan():
        for progress in range(0, 101, 25):
            scans['ascan'][scan_id]['status'] = progress
            time.sleep(2)
    
    thread = threading.Thread(target=progress_scan, daemon=True)
    thread.start()
    
    return jsonify({'scan': scan_id})

@app.route('/JSON/ascan/view/status', methods=['GET'])
def ascan_status():
    """Get active scan status"""
    scan_id = request.args.get('scanid', '0')
    
    if scan_id in scans['ascan']:
        status = scans['ascan'][scan_id]['status']
    else:
        status = 100
    
    return jsonify({'status': status})

@app.route('/JSON/core/action/accessUrl', methods=['GET'])
def access_url():
    """Access a URL (for spidering)"""
    url = request.args.get('url', '')
    return jsonify({'message': f'URL accessed: {url}'})

@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'service': 'Mock ZAP Server'})

if __name__ == '__main__':
    print("""
    ╔════════════════════════════════════════════════════════╗
    ║         Mock ZAP Server - Testing & Development       ║
    ║                                                        ║
    ║  This server simulates ZAP API for Moodle plugin      ║
    ║  testing without needing real ZAP running.            ║
    ║                                                        ║
    ║  Configure Moodle plugin with:                        ║
    ║    Host: localhost (or 0.0.0.0 to allow all)          ║
    ║    Port: 5000 (or change below)                       ║
    ║    API Key: test (not required for mock)              ║
    ║                                                        ║
    ║  Endpoints:                                            ║
    ║    /JSON/core/view/version                            ║
    ║    /JSON/spider/action/scan                           ║
    ║    /JSON/ascan/action/scan                            ║
    ║    /JSON/core/view/alerts                             ║
    ║    /health                                             ║
    ╚════════════════════════════════════════════════════════╝
    """)
    
    # Run on 0.0.0.0 to allow external connections (like from WSL)
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
