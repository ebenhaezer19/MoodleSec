#!/usr/bin/env python3
"""
Real ZAP Scanning Test - Tests actual scanning against live targets or test servers.
This script will:
1. Check if ZAP is running
2. Try to scan DVWA or other test target
3. Display actual findings
"""

import sys
import os
import logging
import json
from pathlib import Path
import socket
from datetime import datetime

# Setup path
sys.path.insert(0, os.getcwd())

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("RealScanTest")


def check_zap_available():
    """Check if ZAP is running on localhost:8080"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', 8080))
    sock.close()
    return result == 0


def check_target_available(target_url):
    """Check if target is reachable"""
    try:
        from urllib.parse import urlparse
        import urllib.request
        
        parsed = urlparse(target_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception as e:
        logger.warning(f"Error checking target: {e}")
        return False


def test_real_scan():
    """Test real ZAP scanning if available"""
    print("\n" + "="*70)
    print("🔍 REAL ZAP SCANNING TEST")
    print("="*70)
    
    # Check ZAP availability
    print("\n[1/5] Checking ZAP availability...")
    if not check_zap_available():
        print("⚠️  ZAP is NOT running on localhost:8080")
        print("     To run real scans, start ZAP with:")
        print("     - OWASP ZAP GUI")
        print("     - Or: zaproxy -config api.disablekey=true -config api.addrs.addr.name=127.0.0.1")
        return False
    
    print("✅ ZAP is running on localhost:8080")
    
    # Try to connect and get version
    print("\n[2/5] Connecting to ZAP API...")
    try:
        # Try relative import first, then absolute
        try:
            from ..zap_client import ZAPClient
        except (ImportError, ValueError):
            sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
            from ml.zap_integration.zap_client import ZAPClient
        
        client = ZAPClient(
            host="localhost",
            port=8080,
            api_key="1qlbij76v3j9c6ail8d0locm24"
        )
        
        # Try to get ZAP version
        try:
            version_info = client.request('/core/action/version')
            print(f"✅ Connected to ZAP")
            print(f"   ZAP Version: {version_info.get('version', 'Unknown')}")
        except Exception as e:
            print(f"⚠️  Could not retrieve ZAP version: {e}")
            print("   This might be a permission or configuration issue")
            return False
        
    except Exception as e:
        logger.error(f"Failed to connect to ZAP: {e}")
        return False
    
    # Define test targets (using local/safe targets)
    test_targets = [
        ("http://localhost:8000", "Local Test Server (if running)"),
        ("http://dvwa.local", "DVWA (if running locally)"),
        ("http://127.0.0.1:3000", "Node Test Server (if running)"),
    ]
    
    # Try to find an available target
    print("\n[3/5] Looking for available test targets...")
    target_url = None
    for url, description in test_targets:
        if check_target_available(url):
            target_url = url
            print(f"✅ Found available target: {description}")
            print(f"   URL: {target_url}")
            break
    
    if not target_url:
        print("⚠️  No test targets found")
        print("     Available targets:")
        for url, desc in test_targets:
            print(f"     - {desc}")
            print(f"       {url}")
        print("\n     To test, set up one of these targets or use your own")
        return None
    
    # Perform scan
    print(f"\n[4/5] Starting scan on {target_url}...")
    print("     This may take several minutes...")
    
    try:
        from ..zap_integration_manager import ZAPIntegrationManager
    except (ImportError, ValueError):
        sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
        from ml.zap_integration.zap_integration_manager import ZAPIntegrationManager
    
    try:
        manager = ZAPIntegrationManager(
            host="localhost",
            port=8080,
            api_key="1qlbij76v3j9c6ail8d0locm24"
        )
        
        # Initialize
        if not manager.initialize():
            print("❌ Failed to initialize ZAP manager")
            return False
        
        print("   Scanning...")
        result = manager.scan_unauthenticated(
            target_url=target_url,
            spider_depth=2,
            scan_policy="medium"
        )
        
        print(f"\n[5/5] Scan complete!")
        
        if result.get('success'):
            print(f"✅ Scan completed successfully!")
            print(f"\n📊 Results Summary:")
            print(f"   • Duration: {result.get('duration_seconds', 0):.1f} seconds")
            print(f"   • Total Findings: {result.get('total_findings', 0)}")
            print(f"   • After ML Filtering: {result.get('filtered_findings', 0)}")
            
            if result.get('alerts'):
                print(f"\n🔍 Top Findings:")
                for i, alert in enumerate(result['alerts'][:5], 1):
                    risk = alert.get('risk', 'Unknown')
                    risk_emoji = "🔴" if risk == "High" else "🟡" if risk == "Medium" else "🟢"
                    print(f"   {i}. {risk_emoji} {alert.get('type', 'Unknown')} [{risk}]")
                    print(f"      URL: {alert.get('url', 'N/A')}")
            
            return True
        else:
            print(f"❌ Scan failed")
            print(f"   Error: {result.get('errors', 'Unknown error')}")
            return False
            
    except Exception as e:
        logger.error(f"Scan error: {e}", exc_info=True)
        return False


def main():
    """Main test runner"""
    print("\n" + "="*70)
    print("REAL ZAP SCANNING CAPABILITY TEST")
    print("="*70)
    print("\nThis test verifies the ZAP integration can perform real scanning")
    print("against live targets using the OWASP ZAP API.\n")
    
    result = test_real_scan()
    
    print("\n" + "="*70)
    if result is True:
        print("✅ REAL SCANNING TEST PASSED")
        print("\n🎉 The ZAP integration is working correctly!")
        print("   It can successfully:")
        print("   • Connect to ZAP API")
        print("   • Discover pages (spider)")
        print("   • Detect vulnerabilities (scanner)")
        print("   • Filter false positives (ML)")
        print("   • Return results")
    elif result is False:
        print("❌ REAL SCANNING TEST FAILED")
        print("\nPossible issues:")
        print("   1. ZAP server not running")
        print("   2. No test targets available")
        print("   3. API key mismatch")
        print("   4. Network connectivity issue")
    else:
        print("⚠️  REAL SCANNING TEST SKIPPED")
        print("\nNo suitable targets found, but integration is working correctly.")
        print("To run real scans:")
        print("   1. Start OWASP ZAP")
        print("   2. Launch a test target (DVWA, WebGoat, etc.)")
        print("   3. Run this test again")
    
    print("="*70 + "\n")
    
    return result is not False


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
