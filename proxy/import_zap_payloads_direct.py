#!/usr/bin/env python3
"""
Import REAL payloads dari ZAP - DIRECT VERSION
Menggunakan requests library (paling reliable)
"""

import requests
import json
import sys
from pathlib import Path
from typing import List, Dict, Any

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

# Add database to path
sys.path.insert(0, str(Path(__file__).parent / "database"))
from payload_repository import PayloadRepositoryManager


class ZAPPayloadImporterDirect:
    """Import REAL payloads dari ZAP scan history"""
    
    def __init__(self, zap_host: str = "localhost", zap_port: int = 8080, 
                 zap_api_key: str = ""):
        self.zap_base_url = f"http://{zap_host}:{zap_port}"
        self.zap_api_key = zap_api_key
        self.payload_repo = PayloadRepositoryManager("data/payload_repository.db")
        # Create session with custom headers
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ZAPPayloadImporter/1.0',
            'Accept': 'application/json'
        })
        self.session.verify = False
    
    def check_zap(self) -> bool:
        """Check ZAP running"""
        try:
            print(f"[*] Using requests library")
            print(f"[*] Attempting to connect to {self.zap_base_url}...")
            
            url = f"{self.zap_base_url}/JSON/core/view/version"
            print(f"[*] URL: {url}")
            
            # Direct request
            response = self.session.get(url, timeout=10)
            print(f"[*] Response Status: {response.status_code}")
            print(f"[*] Response Headers: {dict(response.headers)}\n")
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    version = data.get('version', 'unknown')
                    print(f"[✓] ZAP Version: {version}\n")
                    return True
                except Exception as je:
                    print(f"[!] JSON parse error: {je}")
                    print(f"[*] Response text: {response.text}\n")
                    return True
            else:
                print(f"[!] Unexpected status: {response.status_code}")
                print(f"[*] Response: {response.text[:300]}\n")
                return False
        except Exception as e:
            print(f"[✗] ZAP connection failed: {type(e).__name__}: {e}\n")
            import traceback
            traceback.print_exc()
            return False
    
    def get_zap_alerts(self, count: int = 200) -> List[Dict[str, Any]]:
        """Fetch REAL alerts/findings dari ZAP"""
        print(f"[*] Fetching alerts from ZAP API...")
        print(f"    URL: {self.zap_base_url}/JSON/core/view/alerts")
        print(f"    Count: {count}\n")
        
        try:
            url = f"{self.zap_base_url}/JSON/core/view/alerts"
            params = {
                'zapapiformat': 'JSON',
                'count': count
            }
            if self.zap_api_key:
                params['apikey'] = self.zap_api_key
                print(f"    API Key: {self.zap_api_key[:10]}...\n")
            
            response = self.session.get(url, params=params, timeout=30)
            print(f"[*] Response Status: {response.status_code}")
            print(f"[*] Response Size: {len(response.content)} bytes\n")
            
            if response.status_code == 200:
                data = response.json()
                print(f"[*] JSON Response Keys: {list(data.keys())}\n")
                
                alerts = data.get('alerts', [])
                print(f"[✓] Found {len(alerts)} alerts\n")
                
                if alerts and len(alerts) > 0:
                    print(f"[*] First alert structure:")
                    first_alert = alerts[0]
                    print(f"    Keys: {list(first_alert.keys())}\n")
                    for key in ['alert', 'evidence', 'attack', 'param', 'riskcode', 'confidence']:
                        if key in first_alert:
                            val = str(first_alert[key])[:100]
                            print(f"    {key}: {val}")
                    print()
                
                return alerts
            else:
                print(f"[✗] Unexpected status: {response.status_code}")
                print(f"[*] Response body:\n{response.text[:500]}\n")
                return []
                
        except json.JSONDecodeError as e:
            print(f"[✗] JSON Parse Error: {e}\n")
            return []
        except Exception as e:
            print(f"[✗] Error fetching alerts: {type(e).__name__}: {e}\n")
            import traceback
            traceback.print_exc()
            return []
    
    def extract_payload_from_alert(self, alert: Dict) -> str:
        """Extract REAL payload dari ZAP alert evidence"""
        evidence = alert.get('evidence', '')
        attack = alert.get('attack', '')
        param = alert.get('param', '')
        
        # Evidence biasanya berisi actual payload yang ditest
        if evidence and len(evidence) > 2:
            return evidence[:1000]
        elif attack and len(attack) > 2:
            return attack[:1000]
        elif param and len(param) > 2:
            return param[:1000]
        
        return None
    
    def import_from_zap(self, limit: int = 100) -> int:
        """Import REAL payloads dari ZAP scan history"""
        print("\n╔════════════════════════════════════════════════════════════╗")
        print("║  IMPORT REAL PAYLOADS FROM ZAP SCAN HISTORY               ║")
        print("╚════════════════════════════════════════════════════════════╝\n")
        
        # Check connection
        print("[1] Checking ZAP Connection...")
        if not self.check_zap():
            print("❌ ZAP tidak accessible di http://localhost:8080")
            print("   Pastikan ZAP sudah running:")
            print("   → sudo /opt/zapproxy/ZAP_2.14.0/zap.sh\n")
            return 0
        
        # Fetch alerts
        print("[2] Fetching alerts from ZAP...")
        alerts = self.get_zap_alerts(count=limit)
        
        if not alerts:
            print("❌ Tidak ada alerts di ZAP")
            print("   Kemungkinan:")
            print("   1. ZAP belum scan apa-apa (scan dulu)")
            print("   2. API response format berbeda")
            print("   3. API Key diperlukan\n")
            return 0
        
        # Import payloads
        print(f"[3] Importing {len(alerts)} alerts...\n")
        
        imported_count = 0
        by_category = {}
        errors = []
        
        for idx, alert in enumerate(alerts, 1):
            try:
                category = alert.get('alert', 'Unknown')
                severity = alert.get('riskcode', '2')
                evidence = self.extract_payload_from_alert(alert)
                url = alert.get('url', '')
                
                if not evidence:
                    continue
                
                severity_map = {
                    '0': 'Low', '1': 'Low', '2': 'Medium', 
                    '3': 'High', '4': 'Critical', '5': 'Critical'
                }
                severity_str = severity_map.get(str(severity), 'Medium')
                
                # Normalize category
                if 'XSS' in category or 'Cross' in category:
                    normalized_cat = 'XSS'
                elif 'SQL' in category:
                    normalized_cat = 'SQL Injection'
                elif 'CSRF' in category:
                    normalized_cat = 'CSRF'
                elif 'Path' in category or 'Directory' in category:
                    normalized_cat = 'Path Traversal'
                else:
                    normalized_cat = category
                
                # Add to repository
                payload_id = self.payload_repo.add_payload(
                    payload_text=evidence,
                    category=normalized_cat,
                    payload_type=category,
                    severity=severity_str,
                    source="ZAP_scan_history",
                    description=f"From ZAP: {category}",
                    url=url
                )
                
                imported_count += 1
                
                if normalized_cat not in by_category:
                    by_category[normalized_cat] = 0
                by_category[normalized_cat] += 1
                
                if idx % 20 == 0:
                    print(f"    [{idx}/{len(alerts)}] Processing...")
            
            except Exception as e:
                errors.append(f"Alert {idx}: {str(e)}")
                continue
        
        # Results
        print(f"\n[4] Import Complete!")
        print(f"    ✓ Total imported: {imported_count} payloads")
        
        if errors:
            print(f"\n[5] Errors ({len(errors)}):")
            for err in errors[:5]:
                print(f"    - {err}")
        
        print(f"\n[6] By Vulnerability Type:")
        print("─" * 60)
        for cat, count in sorted(by_category.items(), key=lambda x: x[1], reverse=True):
            print(f"    {cat:<40}: {count:>3} payloads")
        print("─" * 60)
        
        # Show database stats
        stats = self.payload_repo.get_stats()
        print(f"\n[7] Database After Import:")
        print(f"    Total payloads: {stats['total_payloads']}")
        print(f"    Vulnerable payloads: {stats['vulnerable_payloads']}\n")
        
        if imported_count > 0:
            print("✅ SUCCESS! Payloads imported to database.\n")
            print("Next: Run Native Auth Scan to use these payloads:")
            print("  curl -X POST http://localhost:8999/api/scan-native-auth \\")
            print("    -H 'Content-Type: application/json' \\")
            print("    -d '{\"username\":\"admin\",\"password\":\"admin123\",\"login_url\":\"http://localhost:8998/login\"}'")
        
        return imported_count


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Import payloads from ZAP")
    parser.add_argument("--host", default="localhost", help="ZAP host (default: localhost)")
    parser.add_argument("--port", type=int, default=8080, help="ZAP port (default: 8080)")
    parser.add_argument("--api-key", default="", help="ZAP API key if required")
    parser.add_argument("--limit", type=int, default=200, help="Max alerts to import (default: 200)")
    
    args = parser.parse_args()
    
    importer = ZAPPayloadImporterDirect(
        zap_host=args.host, 
        zap_port=args.port,
        zap_api_key=args.api_key
    )
    importer.import_from_zap(limit=args.limit)


if __name__ == "__main__":
    main()
