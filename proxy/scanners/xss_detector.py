"""
Cross-Site Scripting (XSS) Detection Scanner

Detects XSS vulnerabilities including reflected, stored, and DOM-based XSS.
"""

import re
import sys
from typing import List, Dict, Any, Optional
from html import unescape
from urllib.parse import unquote
from pathlib import Path

# Add database module to path
db_path = Path(__file__).parent.parent / "database"
if str(db_path) not in sys.path:
    sys.path.insert(0, str(db_path))

from payload_repository import PayloadRepositoryManager


class XSSDetector:
    """Detect Cross-Site Scripting (XSS) vulnerabilities."""
    
    def __init__(self, payload_repo: Optional[PayloadRepositoryManager] = None):
        """Initialize XSS detector with patterns and payloads."""
        
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
                print(f"[Scanner] XSS: Loading top payloads from repository...")
                smart_xss = self.payload_repo.get_top_payloads("XSS", limit=20)
                self.smart_payloads = [p.get('payload_text', '') for p in smart_xss if p.get('payload_text')]
                print(f"[✓] Loaded {len(self.smart_payloads)} smart XSS payloads from repository")
            except Exception as e:
                print(f"[!] Failed to load smart payloads: {e}")
        
        # XSS patterns in HTML context
        self.html_patterns = [
            r'<script[^>]*>.*?</script>',
            r'<iframe[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>',
            r'<applet[^>]*>',
            r'javascript:',
            r'on\w+\s*=',  # Event handlers like onclick, onload, etc.
        ]
        
        # Compile patterns
        self.compiled_html_patterns = [re.compile(pattern, re.IGNORECASE | re.DOTALL) 
                                       for pattern in self.html_patterns]
        
        # Dangerous HTML tags
        self.dangerous_tags = [
            'script', 'iframe', 'object', 'embed', 'applet', 
            'meta', 'link', 'style', 'base', 'form'
        ]
        
        # Event handlers that can execute JavaScript
        self.event_handlers = [
            'onload', 'onerror', 'onclick', 'onmouseover', 'onmouseout',
            'onmousemove', 'onmousedown', 'onmouseup', 'onfocus', 'onblur',
            'onchange', 'onsubmit', 'onkeydown', 'onkeyup', 'onkeypress',
            'onabort', 'onbeforeunload', 'onhashchange', 'onpageshow',
            'onpagehide', 'onresize', 'onscroll', 'onunload'
        ]
        
        # XSS test payloads
        self.test_payloads = [
            # Basic XSS
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            
            # Event handler XSS
            '" onclick="alert(1)"',
            "' onclick='alert(1)'",
            
            # JavaScript protocol
            'javascript:alert(1)',
            'javascript:alert(String.fromCharCode(88,83,83))',
            
            # HTML entity encoding
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            
            # Attribute breaking
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            
            # Filter bypass
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            '<img src="x" onerror="alert(1)">',
            '<svg/onload=alert(1)>',
            
            # DOM-based XSS
            '#<script>alert(1)</script>',
            
            # Template injection
            '{{constructor.constructor("alert(1)")()}}',
            '${alert(1)}',
        ]
        
        # Context-specific patterns
        self.context_patterns = {
            'html': r'<[^>]*>',
            'attribute': r'["\']',
            'javascript': r'<script[^>]*>',
            'url': r'javascript:|data:text/html',
        }
    
    def scan(self, url: str, method: str, params: Optional[Dict[str, Any]] = None,
             response_body: str = "", request_body: str = "") -> List[Dict[str, Any]]:
        """
        Scan for XSS vulnerabilities.
        
        Args:
            url: Target URL
            method: HTTP method
            params: Request parameters
            response_body: Response body content
            request_body: Request body content
            
        Returns:
            List of findings
        """
        findings = []
        
        # Check for reflected XSS
        if params:
            reflected_findings = self._check_reflected_xss(url, params, response_body)
            findings.extend(reflected_findings)
        
        # Check for XSS in response
        response_findings = self._check_response_xss(response_body, url)
        findings.extend(response_findings)
        
        # Check for DOM-based XSS indicators
        dom_findings = self._check_dom_xss(response_body, url)
        findings.extend(dom_findings)
        
        # Check input fields for XSS protection
        input_findings = self._check_input_sanitization(response_body, url)
        findings.extend(input_findings)
        
        return findings
    
    def _check_reflected_xss(self, url: str, params: Dict[str, Any], 
                            response_body: str) -> List[Dict[str, Any]]:
        """
        Check for reflected XSS vulnerabilities.
        
        Args:
            url: Target URL
            params: Request parameters
            response_body: Response content
            
        Returns:
            List of findings
        """
        findings = []
        
        for param_name, param_value in params.items():
            if not isinstance(param_value, str):
                continue
            
            # Check if parameter value appears in response unescaped
            # Decode HTML entities and URL encoding
            decoded_response = unescape(response_body)
            decoded_value = unquote(str(param_value))
            
            if decoded_value in decoded_response:
                # Check if it appears in a dangerous context
                for pattern in self.compiled_html_patterns:
                    if pattern.search(decoded_response):
                        findings.append({
                            'severity': 'High',
                            'category': 'Cross-Site Scripting (XSS)',
                            'confidence_tier': 'heuristic',  # Passive pattern match — no active exploit proof
                            'description': f'Potential reflected XSS in parameter "{param_name}"',
                            'evidence': f'Parameter value "{param_value[:100]}" appears unescaped in response',
                            'recommendation': 'Encode all user input before displaying. Use Content-Security-Policy headers.',
                            'url': url,
                            'parameter': param_name,
                            'cwe': 'CWE-79',
                            'owasp': 'A03:2021 - Injection'
                        })
                        break
        
        return findings
    
    def _check_response_xss(self, response_body: str, url: str) -> List[Dict[str, Any]]:
        """
        Check response for XSS patterns.
        
        Args:
            response_body: Response content
            url: Target URL
            
        Returns:
            List of findings
        """
        findings = []
        
        # Check for dangerous tags
        for tag in self.dangerous_tags:
            pattern = re.compile(f'<{tag}[^>]*>', re.IGNORECASE)
            matches = pattern.findall(response_body)
            if matches:
                findings.append({
                    'severity': 'Medium',
                    'category': 'Cross-Site Scripting (XSS)',
                    'confidence_tier': 'informational',  # CMS-native HTML — not an exploit indicator
                    'description': f'Potentially dangerous HTML tag detected: <{tag}>',
                    'evidence': f'Found {len(matches)} instance(s) of <{tag}> tag in {url}',
                    'recommendation': 'Review usage of dangerous HTML tags. Implement Content-Security-Policy.',
                    'cwe': 'CWE-79',
                    'owasp': 'A03:2021 - Injection'
                })
        
        # Check for inline event handlers
        for handler in self.event_handlers:
            pattern = re.compile(f'{handler}\\s*=', re.IGNORECASE)
            if pattern.search(response_body):
                findings.append({
                    'severity': 'Medium',
                    'category': 'Cross-Site Scripting (XSS)',
                    'confidence_tier': 'heuristic',  # Passive pattern match — no active exploit proof
                    'description': f'Inline event handler detected: {handler}',
                    'evidence': f'Event handler "{handler}" found in response from {url}',
                    'recommendation': 'Avoid inline event handlers. Use addEventListener() instead.',
                    'cwe': 'CWE-79',
                    'owasp': 'A03:2021 - Injection'
                })
                break  # Only report once per response
        
        # Check for javascript: protocol
        if re.search(r'javascript:', response_body, re.IGNORECASE):
            findings.append({
                'severity': 'High',
                'category': 'Cross-Site Scripting (XSS)',
                'confidence_tier': 'heuristic',  # Passive pattern match — no active exploit proof
                'description': 'JavaScript protocol detected in response',
                'evidence': f'javascript: protocol found in {url}',
                'recommendation': 'Remove javascript: protocol usage. Use proper event handlers.',
                'cwe': 'CWE-79',
                'owasp': 'A03:2021 - Injection'
            })
        
        return findings
    
    def _check_dom_xss(self, response_body: str, url: str) -> List[Dict[str, Any]]:
        """
        Check for DOM-based XSS indicators.
        
        Args:
            response_body: Response content
            url: Target URL
            
        Returns:
            List of findings
        """
        findings = []
        
        # Dangerous JavaScript sinks
        dangerous_sinks = [
            'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
            'eval', 'setTimeout', 'setInterval', 'Function', 'location.href',
            'location.replace', 'location.assign'
        ]
        
        for sink in dangerous_sinks:
            if sink in response_body:
                findings.append({
                    'severity': 'Medium',
                    'category': 'Cross-Site Scripting (XSS)',
                    'confidence_tier': 'heuristic',  # Passive pattern match — no active exploit proof
                    'description': f'Dangerous JavaScript sink detected: {sink}',
                    'evidence': f'Potentially dangerous sink "{sink}" found in {url}',
                    'recommendation': 'Avoid using dangerous sinks with user input. Use safe alternatives like textContent.',
                    'cwe': 'CWE-79',
                    'owasp': 'A03:2021 - Injection'
                })
        
        # Check for unsafe DOM manipulation
        unsafe_patterns = [
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'document\.write\s*\(',
            r'eval\s*\(',
        ]
        
        for pattern in unsafe_patterns:
            if re.search(pattern, response_body):
                findings.append({
                    'severity': 'High',
                    'category': 'Cross-Site Scripting (XSS)',
                    'confidence_tier': 'heuristic',  # Passive pattern match — no active exploit proof
                    'description': 'Unsafe DOM manipulation detected',
                    'evidence': f'Unsafe DOM operation found in {url}',
                    'recommendation': 'Use safe DOM manipulation methods. Sanitize all user input.',
                    'cwe': 'CWE-79',
                    'owasp': 'A03:2021 - Injection'
                })
                break
        
        return findings
    
    def _check_input_sanitization(self, response_body: str, url: str) -> List[Dict[str, Any]]:
        """
        Check if input fields have proper XSS protection.
        
        Args:
            response_body: Response content
            url: Target URL
            
        Returns:
            List of findings
        """
        findings = []
        
        # Check for input/textarea fields
        input_pattern = re.compile(r'<(input|textarea)[^>]*>', re.IGNORECASE)
        inputs = input_pattern.findall(response_body)
        
        if inputs:
            # Check if Content-Security-Policy header should be present
            findings.append({
                'severity': 'Info',
                'category': 'Cross-Site Scripting (XSS)',
                'confidence_tier': 'informational',  # Observation only — not exploitable
                'description': f'Found {len(inputs)} input field(s) - verify XSS protection',
                'evidence': f'Input fields detected in {url}. Ensure proper output encoding.',
                'recommendation': 'Implement Content-Security-Policy header. Encode all output.',
                'cwe': 'CWE-79',
                'owasp': 'A03:2021 - Injection'
            })
        
        return findings    
    def record_payload_usage(self, payload_id: int, scan_id: str, url: str, 
                            parameter: str, success: bool, response: str = ""):
        """Record payload usage in repository for effectiveness tracking."""
        if self.payload_repo is None:
            return
        
        try:
            self.payload_repo.record_usage(payload_id, scan_id, url, parameter, success, response)
        except Exception as e:
            print(f"[!] Failed to record payload usage: {e}")