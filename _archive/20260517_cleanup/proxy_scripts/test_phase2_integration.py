#!/usr/bin/env python3
"""
Phase 2 Integration Test - Payload Management Endpoints
Test ZAP import, reload, and scanner integration
"""

import requests
import json
import time
from datetime import datetime

BASE_URL = "http://localhost:8999"
HEADERS = {"Content-Type": "application/json"}

def print_section(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")

def print_result(test_name, success, details=""):
    status = "✅ PASS" if success else "❌ FAIL"
    print(f"{status}: {test_name}")
    if details:
        print(f"   → {details}")

def test_payload_stats():
    """Test GET /api/payload-stats"""
    print_section("TEST 1: Get Payload Statistics")
    
    try:
        resp = requests.get(f"{BASE_URL}/api/payload-stats", timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            repo = data.get('repository', {})
            total = repo.get('total_payloads', 0)
            vulnr = repo.get('vulnerable_payloads', 0)
            
            print(f"Total Payloads: {total}")
            print(f"Vulnerable: {vulnr}")
            print(f"Categories: {list(repo.get('by_category', {}).keys())}")
            
            print_result("payload-stats", total > 0, f"{total} payloads in repo")
            return True
        else:
            print_result("payload-stats", False, f"Status {resp.status_code}")
            return False
    except Exception as e:
        print_result("payload-stats", False, str(e))
        return False

def test_payload_top_payloads():
    """Test GET /api/payload-top/{category}"""
    print_section("TEST 2: Get Top Payloads by Category")
    
    try:
        # Try XSS category
        resp = requests.get(f"{BASE_URL}/api/payload-top/XSS?limit=5", timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            payloads = data.get('payloads', [])
            count = data.get('count', 0)
            
            print(f"Retrieved {count} XSS payloads")
            if payloads and len(payloads) > 0:
                first = payloads[0]
                print(f"Top payload effectiveness: {first.get('effectiveness_score', 'N/A')}")
            
            print_result("payload-top", count > 0, f"{count} payloads retrieved")
            return True
        else:
            print_result("payload-top", False, f"Status {resp.status_code}")
            return False
    except Exception as e:
        print_result("payload-top", False, str(e))
        return False

def test_reload_payloads():
    """Test POST /api/payloads/reload"""
    print_section("TEST 3: Reload All Payloads")
    
    try:
        resp = requests.post(f"{BASE_URL}/api/payloads/reload", timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            by_cat = data.get('by_category', {})
            
            print(f"Reloaded categories: {list(by_cat.keys())}")
            for cat, info in by_cat.items():
                total = info.get('total', 0)
                vulnr = info.get('vulnerable', 0)
                print(f"  {cat}: {total} total, {vulnr} vulnerable")
            
            print_result("reload-payloads", len(by_cat) > 0)
            return True
        else:
            print_result("reload-payloads", False, f"Status {resp.status_code}")
            return False
    except Exception as e:
        print_result("reload-payloads", False, str(e))
        return False

def test_reload_category():
    """Test POST /api/payloads/reload?category=XSS"""
    print_section("TEST 4: Reload Specific Category")
    
    try:
        resp = requests.post(f"{BASE_URL}/api/payloads/reload?category=XSS", timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            result = data.get('result', {})
            total = result.get('total', 0)
            high_eff = result.get('high_effectiveness', 0)
            
            print(f"XSS Category Reloaded:")
            print(f"  Total: {total}")
            print(f"  High Effectiveness (≥0.7): {high_eff}")
            
            print_result("reload-category", total > 0, f"{total} XSS payloads")
            return True
        else:
            print_result("reload-category", False, f"Status {resp.status_code}")
            return False
    except Exception as e:
        print_result("reload-category", False, str(e))
        return False

def test_import_from_zap():
    """Test POST /api/payloads/import-from-zap"""
    print_section("TEST 5: Import Payloads from ZAP")
    
    try:
        payload = {
            "zap_host": "localhost",
            "zap_port": 8080,
            "limit": 100,
            "reload_scanners": True
        }
        
        resp = requests.post(
            f"{BASE_URL}/api/payloads/import-from-zap",
            json=payload,
            timeout=30
        )
        
        if resp.status_code == 200:
            data = resp.json()
            import_res = data.get('import_result', {})
            status = import_res.get('status', 'unknown')
            imported = import_res.get('payloads_imported', 0)
            alerts = import_res.get('alerts_fetched', 0)
            scanner_reload = data.get('scanners_reloaded', False)
            
            print(f"Import Status: {status}")
            print(f"Alerts Fetched: {alerts}")
            print(f"Payloads Imported: {imported}")
            print(f"Scanners Reloaded: {scanner_reload}")
            
            by_cat = import_res.get('by_category', {})
            if by_cat:
                print(f"Imported by Category:")
                for cat, count in by_cat.items():
                    print(f"  {cat}: {count}")
            
            print_result("import-from-zap", status == "success", f"{imported} payloads imported")
            return status == "success"
        else:
            print_result("import-from-zap", False, f"Status {resp.status_code}: {resp.text[:200]}")
            return False
    except Exception as e:
        print_result("import-from-zap", False, str(e))
        return False

def test_reload_scanners():
    """Test POST /api/scanners/reload-payloads"""
    print_section("TEST 6: Reload Scanner Payloads")
    
    try:
        resp = requests.post(f"{BASE_URL}/api/scanners/reload-payloads", timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            status = data.get('status', 'unknown')
            components = data.get('reloaded_components', {})
            
            print(f"Status: {status}")
            print(f"Reloaded Components: {list(components.keys())}")
            
            print_result("reload-scanners", status == "success")
            return True
        else:
            print_result("reload-scanners", False, f"Status {resp.status_code}")
            return False
    except Exception as e:
        print_result("reload-scanners", False, str(e))
        return False

def test_import_status():
    """Test GET /api/payloads/import-status"""
    print_section("TEST 7: Get Import Status")
    
    try:
        resp = requests.get(f"{BASE_URL}/api/payloads/import-status", timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            status = data.get('status', 'unknown')
            repo = data.get('repository', {})
            total = repo.get('total_payloads', 0)
            scanner_status = data.get('scanner_status', 'unknown')
            
            print(f"Overall Status: {status}")
            print(f"Total Payloads: {total}")
            print(f"Scanner Status: {scanner_status}")
            print(f"Repository Health: {list(repo.get('by_category', {}).keys())}")
            
            print_result("import-status", status == "ok", f"{total} payloads ready")
            return True
        else:
            print_result("import-status", False, f"Status {resp.status_code}")
            return False
    except Exception as e:
        print_result("import-status", False, str(e))
        return False

def main():
    """Run all integration tests"""
    print("\n" + "="*70)
    print("   PHASE 2 INTEGRATION TEST SUITE")
    print("   Payload Management & ZAP Import")
    print("="*70)
    
    # Pre-flight check
    try:
        resp = requests.get(f"{BASE_URL}/health", timeout=5)
        if resp.status_code != 200:
            print("\n❌ FATAL: Proxy not responding properly")
            return
    except:
        print("\n❌ FATAL: Cannot connect to proxy at {BASE_URL}")
        return
    
    results = []
    
    # Run tests
    results.append(("Payload Stats", test_payload_stats()))
    results.append(("Top Payloads", test_payload_top_payloads()))
    results.append(("Reload All", test_reload_payloads()))
    results.append(("Reload Category", test_reload_category()))
    results.append(("Import from ZAP", test_import_from_zap()))
    results.append(("Reload Scanners", test_reload_scanners()))
    results.append(("Import Status", test_import_status()))
    
    # Summary
    print_section("TEST SUMMARY")
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "✅" if result else "❌"
        print(f"{status} {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed ({passed*100//total}%)")
    
    if passed == total:
        print("\n🎉 ALL TESTS PASSED!")
    else:
        print(f"\n⚠️  {total-passed} test(s) failed")

if __name__ == "__main__":
    main()
