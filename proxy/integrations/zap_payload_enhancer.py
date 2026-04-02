"""
ZAP Payload Enhancer

Extracts payloads from ZAP OWASP scans and feeds them into the custom scanner's
payload repository for intelligent reuse. Enhances custom scanner accuracy by
leveraging ZAP's diverse payload dictionary.

Integration Flow:
1. Query ZAP for recent alerts/findings
2. Extract payloads from ZAP test results
3. Categorize by vulnerability type (XSS, SQLi, CSRF, etc.)
4. Save to payload repository with success metrics
5. Custom scanner loads these payloads for higher-success scanning
"""

import re
import httpx
from typing import List, Dict, Any, Optional
from datetime import datetime
import sys
from pathlib import Path

# Add database module to path
db_path = Path(__file__).parent.parent / "database"
if str(db_path) not in sys.path:
    sys.path.insert(0, str(db_path))

from payload_repository import PayloadRepositoryManager


class ZAPPayloadEnhancer:
    """Extract and manage payloads from ZAP OWASP integration."""
    
    def __init__(self, zap_host: str = "localhost", zap_port: int = 8080,
                 zap_api_key: Optional[str] = None, payload_repo: Optional[PayloadRepositoryManager] = None):
        """
        Initialize ZAP Payload Enhancer.
        
        Args:
            zap_host: ZAP server host
            zap_port: ZAP API port
            zap_api_key: ZAP API key (if required)
            payload_repo: Existing PayloadRepositoryManager or create new
        """
        self.zap_base_url = f"http://{zap_host}:{zap_port}"
        self.zap_api_key = zap_api_key
        self.timeout = 30.0
        
        # Initialize payload repository
        if payload_repo is None:
            try:
                self.payload_repo = PayloadRepositoryManager()
            except Exception as e:
                print(f"[ZAP Enhancer] Payload repository initialization failed: {e}")
                self.payload_repo = None
        else:
            self.payload_repo = payload_repo
        
        # Mapping of ZAP alert types to custom scanner categories
        self.category_mapping = {
            'Cross Site Scripting': 'XSS',
            'Cross-Site Scripting (XSS)': 'XSS',
            'Cross-Site Scripting': 'XSS',
            'XSS': 'XSS',
            'Reflected XSS': 'XSS',
            'Stored XSS': 'XSS',
            'SQL Injection': 'SQL Injection',
            'CSRF': 'CSRF',
            'Cross-Site Request Forgery (CSRF)': 'CSRF',
            'Cross-Site Request Forgery': 'CSRF',
            'Path Traversal': 'Path Traversal',
            'Directory Traversal': 'Path Traversal',
            'Remote Code Execution': 'RCE',
            'XXE': 'XXE',
            'LDAP Injection': 'LDAP Injection',
            'OS Injection': 'OS Command Injection',
            'OS Command Injection': 'OS Command Injection',
            'XML Injection': 'XML Injection',
        }
        
        # Common ZAP payload patterns for extraction
        self.payload_extraction_patterns = {
            'XSS': [
                r"<script[^>]*>.*?</script>",
                r'on\w+\s*=\s*["\']([^"\']*)["\']',
                r'javascript:\s*([^\s]+)',
            ],
            'SQL': [
                r"'?\s*(?:OR|AND)\s*'?[\w\s]*'?\s*=\s*'?",
                r"'\s*(?:UNION|SELECT|FROM)\s*",
                r"UNION\s+SELECT\s+.*?--",
            ],
            'LDAP': [
                r"\*.*?\(",
                r"\).*?\(",
            ]
        }
    
    def check_zap_connection(self) -> bool:
        """
        Verify ZAP API is accessible.
        
        Returns:
            True if ZAP is accessible, False otherwise
        """
        try:
            client = httpx.Client(timeout=5.0)
            response = client.get(f"{self.zap_base_url}/JSON/core/action/version")
            client.close()
            return response.status_code == 200
        except Exception as e:
            print(f"[ZAP Enhancer] Cannot connect to ZAP: {e}")
            return False
    
    async def get_zap_alerts(self, count: int = 100) -> List[Dict[str, Any]]:
        """
        Fetch recent alerts from ZAP.
        
        Args:
            count: Number of alerts to retrieve
            
        Returns:
            List of ZAP alerts
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                params = {
                    'zapapiformat': 'JSON',
                    'count': count
                }
                if self.zap_api_key:
                    params['apikey'] = self.zap_api_key
                
                response = await client.get(
                    f"{self.zap_base_url}/JSON/core/view/alerts",
                    params=params
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return data.get('alerts', [])
                else:
                    print(f"[ZAP Enhancer] Failed to get alerts: {response.status_code}")
                    return []
        except Exception as e:
            print(f"[ZAP Enhancer] Error fetching alerts: {e}")
            return []
    
    def extract_payloads_from_alert(self, alert: Dict[str, Any]) -> List[Dict[str, str]]:
        """
        Extract payloads from a single ZAP alert.
        
        Args:
            alert: ZAP alert dictionary
            
        Returns:
            List of extracted payloads with metadata
        """
        payloads = []
        
        try:
            alert_name = alert.get('name', '')
            description = alert.get('description', '')
            risk = alert.get('riskcode', '2')  # 0-3 scale
            
            # Map ZAP alert type to custom scanner category
            category = self._map_alert_to_category(alert_name)
            
            # Extract evidence/payload from alert
            evidence = alert.get('evidence', '')
            attack = alert.get('attack', '')
            
            # Try to extract actual payload from evidence or attack
            payload_text = None
            if attack:
                payload_text = attack
            elif evidence and len(evidence) > 3 and len(evidence) < 500:
                payload_text = evidence
            
            if payload_text:
                payloads.append({
                    'payload_text': payload_text,
                    'category': category,
                    'source': 'ZAP',
                    'severity': self._map_zap_risk_to_severity(risk),
                    'description': description[:200] if description else '',
                    'zap_alert_name': alert_name
                })
            
            # Try pattern-based extraction
            if category in self.payload_extraction_patterns:
                patterns = self.payload_extraction_patterns[category]
                for pattern in patterns:
                    matches = re.findall(pattern, evidence + attack, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0] if match else ''
                        if match and len(match) > 2 and len(match) < 500:
                            payloads.append({
                                'payload_text': match,
                                'category': category,
                                'source': 'ZAP',
                                'severity': self._map_zap_risk_to_severity(risk),
                                'description': f"Extracted from: {alert_name}",
                                'zap_alert_name': alert_name
                            })
        
        except Exception as e:
            print(f"[ZAP Enhancer] Error extracting payload: {e}")
        
        return payloads
    
    def _map_alert_to_category(self, zap_alert_name: str) -> str:
        """Map ZAP alert name to custom scanner category."""
        for key, value in self.category_mapping.items():
            if key.lower() in zap_alert_name.lower():
                return value
        
        # Fallback to generic categories
        if 'script' in zap_alert_name.lower() or 'xss' in zap_alert_name.lower():
            return 'XSS'
        elif 'sql' in zap_alert_name.lower() or 'injection' in zap_alert_name.lower():
            return 'SQL Injection'
        elif 'csrf' in zap_alert_name.lower():
            return 'CSRF'
        elif 'path' in zap_alert_name.lower() or 'traversal' in zap_alert_name.lower():
            return 'Path Traversal'
        
        return 'Other'
    
    def _map_zap_risk_to_severity(self, risk_code: str) -> str:
        """Map ZAP risk code to severity."""
        risk_map = {
            '0': 'Info',
            '1': 'Low',
            '2': 'Medium',
            '3': 'High'
        }
        return risk_map.get(str(risk_code), 'Medium')
    
    async def enhance_from_zap(self, count: int = 50, save_to_repo: bool = True) -> Dict[str, Any]:
        """
        Main method: Fetch payloads from ZAP and save to repository.
        
        Args:
            count: Number of ZAP alerts to process
            save_to_repo: Whether to save extracted payloads to repository
            
        Returns:
            Results dictionary with extraction statistics
        """
        results = {
            'status': 'pending',
            'alerts_fetched': 0,
            'payloads_extracted': 0,
            'payloads_added': 0,
            'by_category': {},
            'errors': []
        }
        
        try:
            # Check ZAP connection
            if not self.check_zap_connection():
                results['status'] = 'error'
                results['errors'].append('Cannot connect to ZAP server')
                print("[ZAP Enhancer] Cannot connect to ZAP")
                return results
            
            # Fetch alerts from ZAP
            print(f"[ZAP Enhancer] Fetching up to {count} alerts from ZAP...")
            alerts = await self.get_zap_alerts(count=count)
            results['alerts_fetched'] = len(alerts)
            
            if not alerts:
                results['status'] = 'no_data'
                print("[ZAP Enhancer] No alerts found in ZAP")
                return results
            
            print(f"[ZAP Enhancer] Processing {len(alerts)} alerts...")
            
            # Extract payloads from all alerts
            all_payloads = []
            for alert in alerts:
                extracted = self.extract_payloads_from_alert(alert)
                all_payloads.extend(extracted)
                
                # Track by category
                for payload in extracted:
                    category = payload['category']
                    if category not in results['by_category']:
                        results['by_category'][category] = 0
                    results['by_category'][category] += 1
            
            results['payloads_extracted'] = len(all_payloads)
            print(f"[ZAP Enhancer] Extracted {len(all_payloads)} payloads from ZAP alerts")
            
            # Save to repository
            if save_to_repo and self.payload_repo and all_payloads:
                print(f"[ZAP Enhancer] Saving payloads to repository...")
                for payload in all_payloads:
                    try:
                        self.payload_repo.add_payload(
                            payload_text=payload['payload_text'],
                            category=payload['category'],
                            payload_type='zap_extracted',
                            severity=payload['severity'],
                            source='ZAP',
                            description=payload['description']
                        )
                        results['payloads_added'] += 1
                    except Exception as e:
                        results['errors'].append(f"Failed to save payload: {str(e)}")
                
                print(f"[ZAP Enhancer] ✓ Added {results['payloads_added']} payloads to repository")
            
            results['status'] = 'success'
            
        except Exception as e:
            results['status'] = 'error'
            results['errors'].append(str(e))
            print(f"[ZAP Enhancer] Error during enhancement: {e}")
        
        return results
    
    async def sync_zap_payloads_periodic(self, interval_seconds: int = 3600):
        """
        Periodically sync ZAP payloads to repository.
        Run this as a background task.
        
        Args:
            interval_seconds: Sync interval in seconds (default 1 hour)
        """
        import asyncio
        
        while True:
            try:
                print(f"[ZAP Enhancer] Starting periodic payload sync...")
                results = await self.enhance_from_zap(count=50, save_to_repo=True)
                print(f"[ZAP Enhancer] Sync complete: {results}")
            except Exception as e:
                print(f"[ZAP Enhancer] Periodic sync failed: {e}")
            
            # Wait for next interval
            await asyncio.sleep(interval_seconds)
    
    def get_zap_integration_stats(self) -> Dict[str, Any]:
        """Get statistics about ZAP integration and payload repository."""
        stats = {
            'zap_connected': self.check_zap_connection(),
            'zap_url': self.zap_base_url,
            'payload_repo_available': self.payload_repo is not None,
            'repository_stats': {}
        }
        
        if self.payload_repo:
            try:
                stats['repository_stats'] = self.payload_repo.get_stats()
            except Exception as e:
                stats['repository_error'] = str(e)
        
        return stats
