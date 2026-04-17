#!/usr/bin/env python3
"""
Import REAL payloads dari ZAP scan history
(Bukan generate - extract dari findings yang sebenarnya)
"""

import httpx
import json
import sys
from pathlib import Path
from typing import List, Dict, Any

# Add database to path
sys.path.insert(0, str(Path(__file__).parent / "database"))
from payload_repository import PayloadRepositoryManager


class ZAPPayloadImporter:
    """Import REAL payloads dari ZAP scan history"""
    
    def __init__(self, zap_host: str = "localhost", zap_port: int = 8080, 
                 zap_api_key: str = ""):
        self.zap_base_url = f"http://{zap_host}:{zap_port}"
        self.zap_api_key = zap_api_key
        self.payload_repo = PayloadRepositoryManager("data/payload_repository.db")
    
    def check_zap(self) -> bool:
        """Check ZAP running"""
        try:
            response = httpx.get(f"{self.zap_base_url}/JSON/core/action/version", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def get_zap_alerts(self, count: int = 200) -> List[Dict[str, Any]]:
        """Fetch REAL alerts/findings dari ZAP"""
        try:
            params = {
                'zapapiformat': 'JSON',
                'count': count
            }
            if self.zap_api_key:
                params['apikey'] = self.zap_api_key
            
            response = httpx.get(
                f"{self.zap_base_url}/JSON/core/view/alerts",
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                return data.get('alerts', [])
            return []
        except Exception as e:
            print(f"[Error] Fetch ZAP alerts: {e}")
            return []
    
    def extract_payload_from_alert(self, alert: Dict) -> str:
        """Extract REAL payload dari ZAP alert evidence"""
        evidence = alert.get('evidence', '')
        attack = alert.get('attack', '')
        param = alert.get('param', '')
        
        # Evidence biasanya berisi actual payload yang ditest
        if evidence and len(evidence) > 2:
            return evidence
        elif attack and len(attack) > 2:
            return attack
        
        return None
    
    def import_from_zap(self, limit: int = 100) -> int:
        """Import REAL payloads dari ZAP scan history"""
        print("\n╔════════════════════════════════════════════════════════════╗")
        print("║  IMPORT REAL PAYLOADS FROM ZAP SCAN HISTORY               ║")
        print("╚════════════════════════════════════════════════════════════╝\n")
        
        if not self.check_zap():
            print("❌ ZAP tidak accessible di http://localhost:8080")
            print("   Perlu jalankan ZAP dulu:")
            print("   → sudo /opt/zapproxy/ZAP_2.14.0/zap.sh\n")
            return 0
        
        print("✅ ZAP connected\n")
        
        alerts = self.get_zap_alerts(count=limit)
        
        if not alerts:
            print("❌ Tidak ada alerts di ZAP")
            print("   Perlu run ZAP scan dulu mendapatkan findings\n")
            return 0
        
        print(f"[1] Found {len(alerts)} alerts in ZAP scan history\n")
        
        imported_count = 0
        by_category = {}
        
        for idx, alert in enumerate(alerts, 1):
            try:
                category = alert.get('alert', 'Unknown')
                severity = alert.get('riskcode', '2')  # 1=low, 2=med, 3=high, 4=critical
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
                    payload_text=evidence[:1000],  # Limit length
                    category=normalized_cat,
                    payload_type=category,
                    severity=severity_str,
                    source="ZAP_scan_history",
                    description=f"From ZAP: {category}",
                    url=url,
                    ml_confidence=None,
                    created_method="zap_scan_history",
                    source_metadata=f'{{"zap_alert": "{category}", "severity": "{severity_str}"}}'
                )
                
                imported_count += 1
                
                if normalized_cat not in by_category:
                    by_category[normalized_cat] = 0
                by_category[normalized_cat] += 1
                
                if idx % 10 == 0:
                    print(f"    [{idx}/{len(alerts)}] Imported {imported_count} payloads...")
            
            except Exception as e:
                print(f"    [Error] Alert {idx}: {str(e)}")
                continue
        
        print(f"\n[2] Import completed!")
        print(f"    ✓ Total imported: {imported_count} REAL payloads from ZAP\n")
        
        print("[3] Breakdown by Vulnerability Type:")
        print("─" * 60)
        for cat, count in sorted(by_category.items(), key=lambda x: x[1], reverse=True):
            print(f"    {cat:<40}: {count:>3} payloads")
        print("─" * 60)
        
        # Show database stats
        stats = self.payload_repo.get_stats()
        print(f"\n[4] Database Status AFTER Import:")
        print(f"    Total payloads now: {stats['total_payloads']}")
        print(f"    Vulnerable payloads: {stats['vulnerable_payloads']}\n")
        
        return imported_count


def main():
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                  IMPORT REAL PAYLOADS FROM ZAP HISTORY                    ║
║                                                                            ║
║  Workflow:                                                                 ║
║  1. ZAP Run scan → Find vulnerabilities with payloads                     ║
║  2. Extract payloads from ZAP findings (REAL, not generated)              ║
║  3. Store to database                                                     ║
║  4. Native Auth Scanner uses these PROVEN payloads                        ║
║                                                                            ║
║  Why ZAP Payloads?                                                         ║
║  ✅ Proven effective (found actual vulnerabilities)                       ║
║  ✅ Critical/High severity (high confidence)                              ║
║  ✅ Real attack vectors (not speculation)                                 ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)
    
    importer = ZAPPayloadImporter()
    importer.import_from_zap(limit=200)


if __name__ == "__main__":
    main()
