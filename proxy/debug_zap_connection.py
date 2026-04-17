#!/usr/bin/env python3
"""
Debug ZAP Connection Issues
"""

import httpx
import socket
import sys
import time

def check_port_open(host: str, port: int) -> bool:
    """Check if port is open"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0

def debug_zap_connection():
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                    DEBUG ZAP CONNECTION                                   ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Test 1: Port connectivity
    print("[1] Checking if port 8080 is open...")
    hosts = ["localhost", "127.0.0.1", "0.0.0.0"]
    
    for host in hosts:
        if check_port_open(host, 8080):
            print(f"    ✅ {host}:8080 - OPEN")
        else:
            print(f"    ❌ {host}:8080 - CLOSED/UNREACHABLE")
    
    # Test 2: HTTP connection
    print("\n[2] Testing HTTP connections...")
    urls = [
        "http://localhost:8080",
        "http://127.0.0.1:8080",
        "http://localhost:8080/JSON/core/action/version",
    ]
    
    for url in urls:
        try:
            print(f"\n    Testing: {url}")
            response = httpx.get(url, timeout=5.0)
            print(f"    ✅ Status: {response.status_code}")
            print(f"    Response length: {len(response.content)} bytes")
            if response.status_code == 200:
                print(f"    ✅ ZAP API ACCESSIBLE!")
                return True
        except httpx.ConnectError as e:
            print(f"    ❌ Connection Error: {e}")
        except httpx.TimeoutException:
            print(f"    ❌ Timeout (may be firewalled)")
        except Exception as e:
            print(f"    ❌ Error: {type(e).__name__}: {e}")
    
    # Test 3: Check ZAP process
    print("\n[3] Checking ZAP process...")
    try:
        import psutil
        zap_running = False
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if 'zap' in proc.name().lower() or (proc.cmdline() and 'zap' in str(proc.cmdline()).lower()):
                    print(f"    ✅ ZAP Process Found: PID {proc.pid}")
                    zap_running = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        if not zap_running:
            print(f"    ⚠️  ZAP process NOT found")
    except ImportError:
        print("    ⚠️  psutil not available (skip process check)")
    
    # Test 4: Network interfaces
    print("\n[4] Network Interfaces...")
    try:
        interfaces = socket.gethostbyname_ex('localhost')
        print(f"    localhost resolves to: {interfaces[2]}")
    except Exception as e:
        print(f"    ❌ Error resolving localhost: {e}")
    
    print("\n[5] Solutions if ZAP not accessible:")
    print("""
    Option A: ZAP not started
      → sudo /opt/zapproxy/ZAP_2.14.0/zap.sh
      → Wait for startup (30-60 seconds)
    
    Option B: ZAP running but port not exposed
      → Check ZAP settings
      → Enable API: Settings → API → Enable (if disabled)
      → Check port: Usually 8080, might be different
    
    Option C: Firewall blocking
      → WSL firewall: ufw allow 8080
      → Windows firewall: Allow port 8080
    
    Option D: ZAP listening on 127.0.0.1 only
      → Might need: docker / network configuration
    
    Option E: API Key required
      → ZAP Settings → API → Set API key
      → Then use: import_zap_payloads.py --api-key YOUR_KEY
    """)
    
    return False

if __name__ == "__main__":
    debug_zap_connection()
