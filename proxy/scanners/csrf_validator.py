"""
Cross-Site Request Forgery (CSRF) Validation Scanner

Detects missing or weak CSRF protection in web applications.
"""

import re
import sys
from typing import List, Dict, Any, Optional
from pathlib import Path

# Add database module to path
db_path = Path(__file__).parent.parent / "database"
if str(db_path) not in sys.path:
    sys.path.insert(0, str(db_path))

from payload_repository import PayloadRepositoryManager


class CSRFValidator:
    """Validate CSRF protection mechanisms."""
    
    def __init__(self, payload_repo: Optional[PayloadRepositoryManager] = None):
        """Initialize CSRF validator with token patterns."""
        
        # Initialize payload repository
        if payload_repo is None:
            try:
                self.payload_repo = PayloadRepositoryManager()
            except Exception as e:
                print(f"[!] Payload repository initialization failed: {e}")
                self.payload_repo = None
        else:
            self.payload_repo = payload_repo
        
        # Load smart payloads from repository (high-success ones prioritized)
        self.smart_payloads = []
        if self.payload_repo:
            try:
                print(f"[Scanner] CSRF: Loading top payloads from repository...")
                smart_csrf = self.payload_repo.get_top_payloads("CSRF", limit=20)
                self.smart_payloads = [p.get('payload_text', '') for p in smart_csrf if p.get('payload_text')]
                print(f"[✓] Loaded {len(self.smart_payloads)} smart CSRF payloads from repository")
            except Exception as e:
                print(f"[!] Failed to load smart payloads: {e}")
        
        # Common CSRF token parameter names
        self.csrf_token_names = [
            'csrf', 'csrf_token', 'csrftoken', 'csrf-token',
            '_csrf', '_csrf_token', '_token', 'token',
            'authenticity_token', 'anti_csrf_token',
            'xsrf', 'xsrf_token', 'xsrftoken',
            'sesskey',  # Moodle-specific
            '__RequestVerificationToken',  # ASP.NET
            'csrfmiddlewaretoken',  # Django
        ]
        
        # Patterns to detect CSRF tokens in HTML
        self.token_patterns = [
            r'<input[^>]*name=["\']({tokens})["\'][^>]*>',
            r'<meta[^>]*name=["\']({tokens})["\'][^>]*>',
            r'data-csrf=["\']([^"\']+)["\']',
            r'{tokens}\s*[:=]\s*["\']([^"\']+)["\']',
        ]
        
        # Compile patterns with token names
        token_names_regex = '|'.join(self.csrf_token_names)
        self.compiled_patterns = [
            re.compile(pattern.format(tokens=token_names_regex), re.IGNORECASE)
            for pattern in self.token_patterns
        ]
        
        # State-changing methods that should have CSRF protection
        self.state_changing_methods = ['POST', 'PUT', 'DELETE', 'PATCH']
    
    def scan(self, url: str, method: str, params: Optional[Dict[str, Any]] = None,
             response_body: str = "", request_headers: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        """
        Scan for CSRF vulnerabilities.
        
        Args:
            url: Target URL
            method: HTTP method
            params: Request parameters
            response_body: Response body content
            request_headers: Request headers
            
        Returns:
            List of findings
        """
        findings = []
        
        # Check if state-changing request has CSRF protection
        if method in self.state_changing_methods:
            csrf_findings = self._check_csrf_protection(url, method, params, request_headers)
            findings.extend(csrf_findings)
        
        # Check forms in response for CSRF tokens
        form_findings = self._check_forms(response_body, url)
        findings.extend(form_findings)
        
        # Check for SameSite cookie attribute
        samesite_findings = self._check_samesite_cookies(request_headers, url)
        findings.extend(samesite_findings)
        
        return findings
    
    def _check_csrf_protection(self, url: str, method: str, 
                               params: Optional[Dict[str, Any]], 
                               headers: Optional[Dict[str, str]]) -> List[Dict[str, Any]]:
        """
        Check if state-changing request has CSRF protection.
        
        Args:
            url: Target URL
            method: HTTP method
            params: Request parameters
            headers: Request headers
            
        Returns:
            List of findings
        """
        findings = []
        
        has_csrf_token = False
        
        # Check parameters for CSRF token
        if params:
            for token_name in self.csrf_token_names:
                if token_name in params or token_name.upper() in params:
                    has_csrf_token = True
                    break
        
        # Check headers for CSRF token
        if headers:
            csrf_headers = ['X-CSRF-Token', 'X-XSRF-Token', 'X-CSRFToken']
            for header in csrf_headers:
                if header in headers or header.lower() in headers:
                    has_csrf_token = True
                    break
        
        # Report if no CSRF protection found
        if not has_csrf_token:
            findings.append({
                'severity': 'High',
                'category': 'Cross-Site Request Forgery (CSRF)',
                'confidence_tier': 'heuristic',  # Structural observation — no active exploit proof
                'description': f'Missing CSRF protection on {method} request',
                'evidence': f'{method} request to {url} does not include CSRF token',
                'recommendation': 'Implement CSRF tokens for all state-changing operations. Use synchronizer token pattern or double-submit cookie.',
                'url': url,
                'parameter': f'[{method} form params]',
                'cwe': 'CWE-352',
                'owasp': 'A01:2021 - Broken Access Control'
            })
        
        return findings
    
    def _check_forms(self, response_body: str, url: str) -> List[Dict[str, Any]]:
        """
        Check HTML forms for CSRF tokens.
        
        Args:
            response_body: Response content
            url: Target URL
            
        Returns:
            List of findings
        """
        findings = []
        
        # Find all forms
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
        forms = form_pattern.findall(response_body)
        
        for i, form_content in enumerate(forms):
            # Check if form uses POST method
            method_match = re.search(r'method=["\']?(post|put|delete|patch)["\']?', 
                                    form_content, re.IGNORECASE)
            
            if method_match:
                # Check if form has CSRF token
                has_token = False
                for pattern in self.compiled_patterns:
                    if pattern.search(form_content):
                        has_token = True
                        break
                
                if not has_token:
                    findings.append({
                        'severity': 'High',
                        'category': 'Cross-Site Request Forgery (CSRF)',
                        'confidence_tier': 'heuristic',  # Structural observation — no active exploit proof
                        'description': f'Form without CSRF protection detected',
                        'evidence': f'Form #{i+1} in {url} uses {method_match.group(1).upper()} but has no CSRF token',
                        'recommendation': 'Add CSRF token to all forms. Use framework-provided CSRF protection.',
                        'url': url,
                        'cwe': 'CWE-352',
                        'owasp': 'A01:2021 - Broken Access Control'
                    })
        
        return findings
    
    def _check_samesite_cookies(self, headers: Optional[Dict[str, str]], 
                                url: str) -> List[Dict[str, Any]]:
        """
        Check for SameSite cookie attribute.
        
        Args:
            headers: Request headers
            url: Target URL
            
        Returns:
            List of findings
        """
        findings = []
        
        if not headers:
            return findings
        
        # Check Set-Cookie headers
        cookie_header = headers.get('Set-Cookie') or headers.get('set-cookie')
        
        if cookie_header:
            # Check if SameSite attribute is present
            if 'samesite' not in cookie_header.lower():
                findings.append({
                    'severity': 'Medium',
                    'category': 'Cross-Site Request Forgery (CSRF)',
                    'confidence_tier': 'informational',  # Best-practice observation
                    'description': 'Cookie without SameSite attribute',
                    'evidence': f'Set-Cookie header in {url} does not include SameSite attribute',
                    'recommendation': 'Set SameSite=Strict or SameSite=Lax for all cookies to prevent CSRF attacks.',
                    'cwe': 'CWE-352',
                    'owasp': 'A01:2021 - Broken Access Control'
                })
            elif 'samesite=none' in cookie_header.lower():
                findings.append({
                    'severity': 'Medium',
                    'category': 'Cross-Site Request Forgery (CSRF)',
                    'confidence_tier': 'informational',  # Best-practice observation
                    'description': 'Cookie with SameSite=None',
                    'evidence': f'Cookie in {url} uses SameSite=None, which offers no CSRF protection',
                    'recommendation': 'Use SameSite=Strict or SameSite=Lax unless cross-site access is required.',
                    'cwe': 'CWE-352',
                    'owasp': 'A01:2021 - Broken Access Control'
                })
        
        return findings
    
    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate CSRF token strength.
        
        Args:
            token: CSRF token to validate
            
        Returns:
            Validation result
        """
        issues = []
        
        # Check token length
        if len(token) < 16:
            issues.append('Token is too short (should be at least 16 characters)')
        
        # Check if token is predictable
        if token.isdigit():
            issues.append('Token contains only digits (predictable)')
        
        if token.isalpha():
            issues.append('Token contains only letters (weak entropy)')
        
        # Check for common weak tokens
        weak_tokens = ['test', 'token', '12345', 'admin', 'csrf']
        if token.lower() in weak_tokens:
            issues.append('Token is a common weak value')
        
        return {
            'is_valid': len(issues) == 0,
            'issues': issues,
            'strength': 'strong' if len(issues) == 0 else 'weak'
        }    
    def record_payload_usage(self, payload_id: int, scan_id: str, url: str,
                            parameter: str, success: bool, response: str = ""):
        """Record payload usage in repository for effectiveness tracking."""
        if self.payload_repo is None:
            return
        
        try:
            self.payload_repo.record_usage(payload_id, scan_id, url, parameter, success, response)
        except Exception as e:
            print(f"[!] Failed to record payload usage: {e}")