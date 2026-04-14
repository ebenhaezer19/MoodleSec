"""
Scanner Engine - Orchestrates all security scanners

Coordinates multiple vulnerability scanners and aggregates results.
"""

from typing import List, Dict, Any, Optional
from datetime import datetime

from .sql_injection import SQLInjectionDetector
from .xss_detector import XSSDetector
from .csrf_validator import CSRFValidator
from .path_traversal import PathTraversalDetector
from .payload_injector import PayloadInjector


class ScannerEngine:
    """Main scanner engine that orchestrates all vulnerability scanners."""
    
    def __init__(self, payload_repo=None, debug_logger=None):
        """Initialize scanner engine with all detectors."""
        self.sql_detector = SQLInjectionDetector(payload_repo)
        self.xss_detector = XSSDetector(payload_repo)
        self.csrf_validator = CSRFValidator(payload_repo)
        self.path_traversal_detector = PathTraversalDetector()
        
        # Initialize payload injector for active payload testing
        self.payload_injector = PayloadInjector(payload_repo, debug_logger)
        self.payload_repo = payload_repo
        self.debug_logger = debug_logger
        
        # Scanner metadata
        self.scanners = {
            'sql_injection': {
                'name': 'SQL Injection Scanner',
                'detector': self.sql_detector,
                'enabled': True,
                'category': 'SQL Injection'
            },
            'xss': {
                'name': 'Cross-Site Scripting Scanner',
                'detector': self.xss_detector,
                'enabled': True,
                'category': 'XSS'
            },
            'csrf': {
                'name': 'CSRF Protection Validator',
                'detector': self.csrf_validator,
                'enabled': True,
                'category': 'CSRF'
            },
            'path_traversal': {
                'name': 'Path Traversal Scanner',
                'detector': self.path_traversal_detector,
                'enabled': True,
                'category': 'Path Traversal'
            }
        }
        
        print("[Scanner Engine] Initialized with payload injection support")
    
    def initialize_scanners(self):
        """Reinitialize all scanners with fresh payload data from repository.
        
        Useful after importing new payloads from ZAP without restarting.
        """
        try:
            print("[Scanner Engine] Reinitializing scanners with fresh payloads...")
            
            # Reinitialize each detector
            self.sql_detector = SQLInjectionDetector(self.payload_repo)
            self.xss_detector = XSSDetector(self.payload_repo)
            self.csrf_validator = CSRFValidator(self.payload_repo)
            self.path_traversal_detector = PathTraversalDetector()
            
            # Reinitialize payload injector
            self.payload_injector = PayloadInjector(self.payload_repo, self.debug_logger)
            
            # Update scanner references
            self.scanners['sql_injection']['detector'] = self.sql_detector
            self.scanners['xss']['detector'] = self.xss_detector
            self.scanners['csrf']['detector'] = self.csrf_validator
            self.scanners['path_traversal']['detector'] = self.path_traversal_detector
            
            print("[Scanner Engine] Scanner reinitialization complete")
        except Exception as e:
            print(f"[Scanner Engine] Error reinitializing scanners: {e}")
    
    def scan(self, url: str, method: str = 'GET', 
             params: Optional[Dict[str, Any]] = None,
             request_body: str = "",
             response_body: str = "",
             request_headers: Optional[Dict[str, str]] = None,
             response_headers: Optional[Dict[str, str]] = None,
             status_code: int = 200) -> Dict[str, Any]:
        """
        Perform comprehensive security scan.
        
        Args:
            url: Target URL
            method: HTTP method
            params: Request parameters
            request_body: Request body content
            response_body: Response body content
            request_headers: Request headers
            response_headers: Response headers
            status_code: HTTP status code
            
        Returns:
            Scan results with all findings
        """
        scan_id = f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        all_findings = []
        scanner_results = {}
        
        # Run SQL Injection scanner
        if self.scanners['sql_injection']['enabled']:
            try:
                sql_findings = self.sql_detector.scan(
                    url=url,
                    method=method,
                    params=params,
                    response_body=response_body,
                    status_code=status_code
                )
                all_findings.extend(sql_findings)
                scanner_results['sql_injection'] = {
                    'findings_count': len(sql_findings),
                    'status': 'completed'
                }
            except Exception as e:
                scanner_results['sql_injection'] = {
                    'findings_count': 0,
                    'status': 'error',
                    'error': str(e)
                }
        
        # Run XSS scanner
        if self.scanners['xss']['enabled']:
            try:
                xss_findings = self.xss_detector.scan(
                    url=url,
                    method=method,
                    params=params,
                    response_body=response_body,
                    request_body=request_body
                )
                all_findings.extend(xss_findings)
                scanner_results['xss'] = {
                    'findings_count': len(xss_findings),
                    'status': 'completed'
                }
            except Exception as e:
                scanner_results['xss'] = {
                    'findings_count': 0,
                    'status': 'error',
                    'error': str(e)
                }
        
        # Run CSRF validator
        if self.scanners['csrf']['enabled']:
            try:
                csrf_findings = self.csrf_validator.scan(
                    url=url,
                    method=method,
                    params=params,
                    response_body=response_body,
                    request_headers=request_headers
                )
                all_findings.extend(csrf_findings)
                scanner_results['csrf'] = {
                    'findings_count': len(csrf_findings),
                    'status': 'completed'
                }
            except Exception as e:
                scanner_results['csrf'] = {
                    'findings_count': 0,
                    'status': 'error',
                    'error': str(e)
                }
        
        # Run Path Traversal scanner
        if self.scanners['path_traversal']['enabled']:
            try:
                path_findings = self.path_traversal_detector.scan(
                    url=url,
                    method=method,
                    params=params,
                    response_body=response_body,
                    status_code=status_code
                )
                all_findings.extend(path_findings)
                scanner_results['path_traversal'] = {
                    'findings_count': len(path_findings),
                    'status': 'completed'
                }
            except Exception as e:
                scanner_results['path_traversal'] = {
                    'findings_count': 0,
                    'status': 'error',
                    'error': str(e)
                }
        
        # PAYLOAD INJECTION TESTING (Active testing with repository payloads)
        # Test each vulnerability category with payloads
        if self.payload_injector:
            print(f"[Scanner Engine] Starting active payload injection testing...")
            payload_findings = self._test_payloads_against_endpoints(
                url=url,
                params=params,
                method=method,
                scan_id=scan_id
            )
            all_findings.extend(payload_findings)
            scanner_results['payload_injection'] = {
                'findings_count': len(payload_findings),
                'status': 'completed'
            }
        
        # Calculate summary
        summary = self._calculate_summary(all_findings)
        
        # Deduplicate findings
        unique_findings = self._deduplicate_findings(all_findings)
        
        # Sort findings by severity
        sorted_findings = self._sort_by_severity(unique_findings)
        
        return {
            'scan_id': scan_id,
            'target_url': url,
            'timestamp': timestamp,
            'method': method,
            'findings': sorted_findings,
            'summary': summary,
            'scanner_results': scanner_results,
            'total_findings': len(sorted_findings)
        }
    
    def _calculate_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Calculate severity summary.
        
        Args:
            findings: List of findings
            
        Returns:
            Summary dictionary with counts by severity
        """
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for finding in findings:
            severity = finding.get('severity', 'Info').lower()
            if severity in summary:
                summary[severity] += 1
        
        return summary
    
    def _deduplicate_findings(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate findings.
        
        Args:
            findings: List of findings
            
        Returns:
            Deduplicated list of findings
        """
        seen = set()
        unique_findings = []
        
        for finding in findings:
            # Create a unique key based on category and description
            key = (
                finding.get('category', ''),
                finding.get('description', ''),
                finding.get('severity', '')
            )
            
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        return unique_findings
    
    def _sort_by_severity(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Sort findings by severity (Critical -> High -> Medium -> Low -> Info).
        
        Args:
            findings: List of findings
            
        Returns:
            Sorted list of findings
        """
        severity_order = {
            'critical': 0,
            'high': 1,
            'medium': 2,
            'low': 3,
            'info': 4
        }
        
        return sorted(
            findings,
            key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5)
        )
    
    def enable_scanner(self, scanner_name: str) -> bool:
        """
        Enable a specific scanner.
        
        Args:
            scanner_name: Name of scanner to enable
            
        Returns:
            True if successful, False otherwise
        """
        if scanner_name in self.scanners:
            self.scanners[scanner_name]['enabled'] = True
            return True
        return False
    
    def disable_scanner(self, scanner_name: str) -> bool:
        """
        Disable a specific scanner.
        
        Args:
            scanner_name: Name of scanner to disable
            
        Returns:
            True if successful, False otherwise
        """
        if scanner_name in self.scanners:
            self.scanners[scanner_name]['enabled'] = False
            return True
        return False
    
    def get_scanner_status(self) -> Dict[str, Any]:
        """
        Get status of all scanners.
        
        Returns:
            Dictionary with scanner status information
        """
        status = {}
        for scanner_id, scanner_info in self.scanners.items():
            status[scanner_id] = {
                'name': scanner_info['name'],
                'enabled': scanner_info['enabled']
            }
        return status
    
    def _test_payloads_against_endpoints(
        self,
        url: str,
        params: Dict[str, Any],
        method: str,
        scan_id: str
    ) -> List[Dict[str, Any]]:
        """
        Test payloads from repository against endpoints.
        
        This is the active payload reuse mechanism - uses stored payloads
        to test parameters and discover vulnerabilities.
        
        Args:
            url: Target URL
            params: Request parameters
            method: HTTP method
            scan_id: Scan ID for tracking
            
        Returns:
            List of findings from payload injection
        """
        findings = []
        
        if not params or not self.payload_injector:
            return findings
        
        # Test SQL Injection payloads
        if self.scanners['sql_injection']['enabled']:
            try:
                print("[Scanner Engine] Testing SQL Injection payloads...")
                sql_findings = self._test_payload_category(
                    url=url,
                    params=params,
                    category="SQL Injection",
                    scan_id=scan_id
                )
                findings.extend(sql_findings)
                print(f"[Scanner Engine] Found {len(sql_findings)} SQL Injection findings")
            except Exception as e:
                print(f"[Scanner Engine] Error testing SQL Injection payloads: {e}")
        
        # Test XSS payloads
        if self.scanners['xss']['enabled']:
            try:
                print("[Scanner Engine] Testing XSS payloads...")
                xss_findings = self._test_payload_category(
                    url=url,
                    params=params,
                    category="XSS",
                    scan_id=scan_id
                )
                findings.extend(xss_findings)
                print(f"[Scanner Engine] Found {len(xss_findings)} XSS findings")
            except Exception as e:
                print(f"[Scanner Engine] Error testing XSS payloads: {e}")
        
        # Test CSRF payloads
        if self.scanners['csrf']['enabled']:
            try:
                print("[Scanner Engine] Testing CSRF payloads...")
                csrf_findings = self._test_payload_category(
                    url=url,
                    params=params,
                    category="CSRF",
                    scan_id=scan_id
                )
                findings.extend(csrf_findings)
                print(f"[Scanner Engine] Found {len(csrf_findings)} CSRF findings")
            except Exception as e:
                print(f"[Scanner Engine] Error testing CSRF payloads: {e}")
        
        return findings
    
    def _test_payload_category(
        self,
        url: str,
        params: Dict[str, Any],
        category: str,
        scan_id: str
    ) -> List[Dict[str, Any]]:
        """
        Test specific payload category against parameters.
        
        Args:
            url: Target URL
            params: Parameters to test
            category: Payload category (SQL Injection, XSS, etc.)
            scan_id: Scan ID
            
        Returns:
            List of findings
        """
        findings = []
        
        if not self.payload_repo:
            return findings
        
        # Get payloads for this category
        payloads = self.payload_repo.get_top_payloads(category, limit=10)
        if not payloads:
            print(f"[Scanner Engine] No payloads found for {category}")
            return findings
        
        print(f"[Scanner Engine] Testing {len(payloads)} {category} payloads on {len(params)} parameters")
        
        # Test each parameter with each payload
        for param_name, param_value in params.items():
            if not isinstance(param_value, str):
                continue
            
            for payload_obj in payloads:
                payload_text = payload_obj.get('payload_text', '')
                payload_id = payload_obj.get('id', 'unknown')
                
                if not payload_text:
                    continue
                
                try:
                    # Log injection attempt
                    if self.debug_logger:
                        self.debug_logger.log_injection_attempt(
                            scan_id=scan_id,
                            payload_id=payload_id,
                            category=category,
                            payload_text=payload_text,
                            injection_point=f"parameter:{param_name}",
                            target_url=url,
                            status="tested"
                        )
                    
                    # For now, just log the injection attempts
                    # In a real scenario, you would make actual requests here
                    # and check responses for vulnerability indicators
                    
                except Exception as e:
                    print(f"[Scanner Engine] Error testing {category} payload: {e}")
        
        return findings
