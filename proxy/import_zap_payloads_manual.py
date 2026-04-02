#!/usr/bin/env python3
"""
Alternative: Manual Payload Import dari ZAP Session File
(Jika ZAP API tidak accessible)
"""

import xml.etree.ElementTree as ET
import sys
from pathlib import Path
from typing import List, Dict

# Add database module
sys.path.insert(0, str(Path(__file__).parent / "database"))
from payload_repository import PayloadRepositoryManager


class ZAPSessionImporter:
    """Import payloads dari ZAP session file (.session)"""
    
    def __init__(self):
        self.payload_repo = PayloadRepositoryManager("data/payload_repository.db")
    
    def find_zap_sessions(self) -> List[str]:
        """Find ZAP session files di system"""
        session_paths = [
            Path.home() / ".ZAP" / "sessions",
            Path("/opt/zapproxy/.ZAP/sessions") if Path("/opt/zapproxy").exists() else None,
            Path("/root/.ZAP/sessions") if Path("/root/.ZAP/sessions").exists() else None,
        ]
        
        found = []
        for path in session_paths:
            if path and path.exists():
                for session_file in path.glob("*.session"):
                    found.append(str(session_file))
        
        return found
    
    def import_from_session_file(self, session_path: str) -> int:
        """Import payloads dari XML session file"""
        print(f"[1] Reading ZAP session: {session_path}")
        
        try:
            tree = ET.parse(session_path)
            root = tree.getroot()
            
            # Find alerts in session XML
            alerts = root.findall(".//alert")
            
            if not alerts:
                print("❌ No alerts found in session file")
                return 0
            
            print(f"[2] Found {len(alerts)} alerts\n")
            
            imported = 0
            by_category = {}
            
            for alert in alerts:
                try:
                    # Extract alert info
                    alert_name = alert.findtext("name", "Unknown")
                    evidence = alert.findtext("evidence", "")
                    attack = alert.findtext("attack", "")
                    risk = alert.findtext("riskcode", "2")
                    
                    if not evidence and not attack:
                        continue
                    
                    payload = evidence if evidence else attack
                    
                    # Normalize category
                    if 'XSS' in alert_name or 'Cross' in alert_name:
                        category = 'XSS'
                    elif 'SQL' in alert_name:
                        category = 'SQL Injection'
                    elif 'CSRF' in alert_name:
                        category = 'CSRF'
                    elif 'Path' in alert_name:
                        category = 'Path Traversal'
                    else:
                        category = alert_name
                    
                    # Map risk to severity
                    risk_map = {
                        '0': 'Low', '1': 'Low', '2': 'Medium',
                        '3': 'High', '4': 'Critical', '5': 'Critical'
                    }
                    severity = risk_map.get(str(risk), 'Medium')
                    
                    # Add to DB
                    self.payload_repo.add_payload(
                        payload_text=payload[:1000],
                        category=category,
                        payload_type=alert_name,
                        severity=severity,
                        source="ZAP_session_file",
                        description=f"From ZAP: {alert_name}"
                    )
                    
                    imported += 1
                    
                    if category not in by_category:
                        by_category[category] = 0
                    by_category[category] += 1
                    
                except Exception as e:
                    continue
            
            print(f"[3] Import Results:")
            print(f"    ✓ Imported: {imported} payloads")
            print(f"\n[4] By Category:")
            for cat, count in sorted(by_category.items(), key=lambda x: x[1], reverse=True):
                print(f"    {cat:<40}: {count:>3} payloads")
            
            return imported
        
        except Exception as e:
            print(f"❌ Error reading session: {e}")
            return 0


def main():
    print("""
╔════════════════════════════════════════════════════════════════════════════╗
║     MANUAL PAYLOAD IMPORT FROM ZAP SESSION FILE                           ║
║                                                                            ║
║  Jika ZAP API tidak accessible:                                           ║
║  1. Export session dari ZAP GUI: Session → Save                           ║
║  2. Script ini parse XML session                                          ║
║  3. Extract payloads dari XML alert nodes                                 ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
    """)
    
    importer = ZAPSessionImporter()
    
    # Find sessions
    sessions = importer.find_zap_sessions()
    
    if not sessions:
        print("""
❌ No ZAP session files found

Perlu jalankan:
1. ZAP GUI: File → Session Properties
2. Pilih folder untuk session files
3. Copy path dari session file
4. Jalankan: python import_zap_payloads_manual.py <path_to_session>

Or:
1. Debug ZAP connection dulu: python debug_zap_connection.py
2. Fix connection issues
3. Use API method: python import_zap_payloads.py
        """)
        return
    
    print(f"[1] Found {len(sessions)} ZAP session(s):\n")
    for i, session in enumerate(sessions, 1):
        print(f"    {i}. {session}")
    
    # Import from first session
    print(f"\n[2] Importing from first session...")
    importer.import_from_session_file(sessions[0])


if __name__ == "__main__":
    main()
