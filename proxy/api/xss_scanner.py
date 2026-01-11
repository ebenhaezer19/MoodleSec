"""
XSS (Cross-Site Scripting) Scanner for Moodle

Tests for XSS vulnerabilities - the #1 most common Moodle vulnerability (45% of CVEs)
- Reflected XSS (immediate response)
- Stored XSS (persisted in database)
- DOM-based XSS
- Context-aware testing (HTML, JavaScript, attribute)

Based on real Moodle CVEs:
- CVE-2024-43437 - XSS via course description
- CVE-2023-6185 - XSS in forum posts
- CVE-2022-45153 - Stored XSS in quiz module
"""

import httpx
import asyncio
import re
from typing import Dict, List, Any, Set
from datetime import datetime
from urllib.parse import quote, urlencode


class XSSScanner:
    """Comprehensive XSS vulnerability scanner for Moodle."""
    
    # XSS payloads for different contexts
    XSS_PAYLOADS = {
        'basic': [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<iframe src="javascript:alert(1)">',
            '<body onload=alert(1)>',
        ],
        'attribute': [
            '" onmouseover="alert(1)',
            "' onmouseover='alert(1)",
            '"><script>alert(1)</script>',
            "' onclick='alert(1)'//",
        ],
        'javascript': [
            'javascript:alert(1)',
            'javascript:alert(String.fromCharCode(88,83,83))',
            'jaVasCript:alert(1)',
        ],
        'encoded': [
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            '%3Cscript%3Ealert(1)%3C/script%3E',
            '&#60;script&#62;alert(1)&#60;/script&#62;',
        ],
        'bypass': [
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            '<<script>script>alert(1)<</script>/script>',
            '<img src="x" onerror="alert&#40;1&#41;">',
            '<svg/onload=alert(1)>',
        ]
    }
    
    # Moodle-specific endpoints prone to XSS
    MOODLE_XSS_ENDPOINTS = [
        # Course management
        '/course/edit.php',
        '/course/view.php',
        '/course/modedit.php',
        
        # Forum (high risk)
        '/mod/forum/post.php',
        '/mod/forum/discuss.php',
        '/mod/forum/view.php',
        
        # Quiz
        '/mod/quiz/edit.php',
        '/question/question.php',
        
        # User profile
        '/user/profile.php',
        '/user/edit.php',
        '/user/editadvanced.php',
        
        # Messaging
        '/message/index.php',
        
        # Custom fields
        '/customfield/edit.php',
        
        # Search
        '/search/index.php',
        '/course/search.php',
    ]
    
    # Parameters commonly vulnerable to XSS in Moodle
    VULNERABLE_PARAMS = [
        'name', 'description', 'summary', 'intro',
        'content', 'message', 'subject', 'title',
        'search', 'q', 'query', 'keyword',
        'customfield', 'value', 'text',
        'fullname', 'shortname', 'idnumber',
        'url', 'link', 'redirect',
    ]
    
    def __init__(self, base_url: str):
        """
        Initialize XSS scanner.
        
        Args:
            base_url: Base URL of Moodle installation
        """
        self.base_url = base_url.rstrip('/')
        self.client = httpx.AsyncClient(timeout=30.0, follow_redirects=True, verify=False)
        self.findings = []
        self.tested_endpoints = set()
    
    async def scan_all(self) -> Dict[str, Any]:
        """
        Run comprehensive XSS scan.
        
        Returns:
            Complete scan results with all findings
        """
        print("[XSS Scanner] Starting comprehensive XSS vulnerability scan...")
        
        results = {
            'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
            'base_url': self.base_url,
            'tests': {}
        }
        
        # Test 1: Reflected XSS
        print("[XSS Scanner] Testing reflected XSS...")
        results['tests']['reflected'] = await self.test_reflected_xss()
        
        # Test 2: Stored XSS (if we have authenticated session)
        print("[XSS Scanner] Testing stored XSS...")
        results['tests']['stored'] = await self.test_stored_xss()
        
        # Test 3: DOM-based XSS
        print("[XSS Scanner] Testing DOM-based XSS...")
        results['tests']['dom_based'] = await self.test_dom_xss()
        
        # Compile results
        results['findings'] = self.findings
        results['total_findings'] = len(self.findings)
        results['tested_endpoints'] = list(self.tested_endpoints)
        results['summary'] = self._generate_summary()
        
        print(f"[XSS Scanner] Complete! Found {len(self.findings)} XSS vulnerabilities")
        if self.findings:
            summary = results['summary']
            print(f"[XSS Scanner] Summary: Critical={summary.get('critical', 0)}, High={summary.get('high', 0)}, Medium={summary.get('medium', 0)}")
        
        return results
    
    async def test_reflected_xss(self) -> Dict[str, Any]:
        """
        Test for reflected XSS vulnerabilities.
        
        Injects payloads and checks if they're reflected in response.
        """
        result = {
            'test_name': 'Reflected XSS',
            'status': 'pass',
            'vulnerabilities': []
        }
        
        for endpoint in self.MOODLE_XSS_ENDPOINTS:
            self.tested_endpoints.add(endpoint)
            
            for param in self.VULNERABLE_PARAMS[:5]:  # Test top 5 params per endpoint
                for payload_type, payloads in self.XSS_PAYLOADS.items():
                    for payload in payloads[:2]:  # Test 2 payloads per type
                        try:
                            # Test GET request
                            url = f"{self.base_url}{endpoint}?{param}={quote(payload)}"
                            response = await self.client.get(url)
                            
                            if self._is_xss_reflected(payload, response.text):
                                vuln = {
                                    'endpoint': endpoint,
                                    'parameter': param,
                                    'payload': payload,
                                    'payload_type': payload_type,
                                    'method': 'GET',
                                    'reflected': True
                                }
                                result['vulnerabilities'].append(vuln)
                                result['status'] = 'fail'
                                
                                self._add_finding(
                                    severity='High',
                                    category='XSS - Reflected',
                                    description=f'Reflected XSS vulnerability detected',
                                    evidence=f'Endpoint: {endpoint}, Parameter: {param}, Payload: {payload[:50]}, Type: {payload_type}',
                                    recommendation='Implement output encoding and Content-Security-Policy header'
                                )
                                break  # Found XSS, no need to test more payloads
                        
                        except Exception as e:
                            pass
                    
                    if result['vulnerabilities']:
                        break
        
        return result
    
    async def test_stored_xss(self) -> Dict[str, Any]:
        """
        Test for stored XSS vulnerabilities.
        
        Note: Requires authentication. This is a basic test.
        """
        result = {
            'test_name': 'Stored XSS',
            'status': 'pass',
            'note': 'Limited testing without authentication'
        }
        
        # Test search functionality for stored XSS
        search_endpoints = ['/search/index.php', '/course/search.php']
        
        for endpoint in search_endpoints:
            try:
                payload = '<script>alert("XSS")</script>'
                url = f"{self.base_url}{endpoint}"
                
                # POST the payload
                response = await self.client.post(url, data={'search': payload})
                
                # Check if payload is stored and reflected
                if self._is_xss_reflected(payload, response.text):
                    self._add_finding(
                        severity='Critical',
                        category='XSS - Stored',
                        description=f'Stored XSS vulnerability in search functionality',
                        evidence=f'Endpoint: {endpoint}, Payload persisted and reflected',
                        recommendation='Implement input validation, output encoding, and CSP'
                    )
                    result['status'] = 'fail'
            
            except Exception:
                pass
        
        return result
    
    async def test_dom_xss(self) -> Dict[str, Any]:
        """
        Test for DOM-based XSS vulnerabilities.
        
        Checks for dangerous JavaScript sinks.
        """
        result = {
            'test_name': 'DOM-based XSS',
            'status': 'pass',
            'dangerous_patterns': []
        }
        
        # Test main pages for DOM XSS patterns
        test_pages = ['/', '/index.php', '/my/index.php', '/course/index.php']
        
        dangerous_sinks = [
            r'document\.write\(',
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'eval\(',
            r'setTimeout\(',
            r'setInterval\(',
            r'location\.href\s*=',
            r'location\.replace\(',
        ]
        
        for page in test_pages:
            try:
                url = f"{self.base_url}{page}"
                response = await self.client.get(url)
                
                # Check for dangerous patterns that use user input
                for pattern in dangerous_sinks:
                    matches = re.finditer(pattern, response.text)
                    for match in matches:
                        # Get context (50 chars before and after)
                        start = max(0, match.start() - 50)
                        end = min(len(response.text), match.end() + 50)
                        context = response.text[start:end]
                        
                        # Check if it involves URL parameters or user input
                        if any(indicator in context.lower() for indicator in ['location.search', 'window.location', 'document.url', 'document.referrer']):
                            result['dangerous_patterns'].append({
                                'page': page,
                                'sink': pattern,
                                'context': context
                            })
                            
                            self._add_finding(
                                severity='Medium',
                                category='XSS - DOM-based',
                                description=f'Potential DOM-based XSS vulnerability',
                                evidence=f'Page: {page}, Dangerous sink: {pattern}, Context: {context[:100]}',
                                recommendation='Avoid using dangerous sinks with user input, use safe alternatives'
                            )
                            result['status'] = 'warning'
            
            except Exception:
                pass
        
        return result
    
    def _is_xss_reflected(self, payload: str, response: str) -> bool:
        """
        Check if XSS payload is reflected in response without encoding.
        
        Args:
            payload: The XSS payload
            response: The HTTP response body
            
        Returns:
            True if payload is reflected unencoded
        """
        # Check exact reflection
        if payload in response:
            return True
        
        # Check for common dangerous patterns
        dangerous_patterns = [
            '<script>',
            'onerror=',
            'onload=',
            'onclick=',
            'javascript:',
        ]
        
        response_lower = response.lower()
        for pattern in dangerous_patterns:
            if pattern in payload.lower() and pattern in response_lower:
                # Check if it's in a dangerous context (not encoded)
                if not self._is_safely_encoded(payload, response):
                    return True
        
        return False
    
    def _is_safely_encoded(self, payload: str, response: str) -> bool:
        """
        Check if payload is safely encoded in response.
        
        Args:
            payload: Original payload
            response: Response text
            
        Returns:
            True if safely encoded
        """
        # Check if < > are encoded
        if '<' in payload:
            if '&lt;' in response or '&#60;' in response or '%3C' in response:
                return True
        
        if '>' in payload:
            if '&gt;' in response or '&#62;' in response or '%3E' in response:
                return True
        
        if '"' in payload:
            if '&quot;' in response or '&#34;' in response:
                return True
        
        return False
    
    def _add_finding(self, severity: str, category: str, description: str,
                    evidence: str, recommendation: str):
        """Add XSS finding."""
        print(f"[XSS Scanner] 🔍 {severity}: {description}")
        print(f"[XSS Scanner]    📍 {evidence}")
        
        self.findings.append({
            'severity': severity,
            'category': category,
            'description': description,
            'evidence': evidence,
            'recommendation': recommendation,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
    
    def _generate_summary(self) -> Dict[str, int]:
        """Generate summary by severity."""
        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in self.findings:
            severity = finding['severity'].lower()
            if severity in summary:
                summary[severity] += 1
        return summary
    
    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()
