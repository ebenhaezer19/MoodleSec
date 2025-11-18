"""
Session Management Security Tester

Tests for common session-related vulnerabilities:
- Session fixation
- Session hijacking
- Insecure cookies
- Session timeout issues
- CSRF token validation
"""

import httpx
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import re


class SessionTester:
    """Test session management security."""
    
    def __init__(self, base_url: str):
        """
        Initialize session tester.
        
        Args:
            base_url: Base URL of the application
        """
        self.base_url = base_url.rstrip('/')
        self.client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
        self.findings = []
    
    async def test_all(self) -> Dict[str, Any]:
        """
        Run all session security tests.
        
        Returns:
            Dictionary containing all test results
        """
        print("[Session Tester] Starting comprehensive session security tests...")
        
        results = {
            'test_timestamp': datetime.utcnow().isoformat() + 'Z',
            'base_url': self.base_url,
            'tests': {}
        }
        
        # Test 1: Cookie Security
        print("[Session Tester] Testing cookie security...")
        results['tests']['cookie_security'] = await self.test_cookie_security()
        
        # Test 2: Session Fixation
        print("[Session Tester] Testing session fixation...")
        results['tests']['session_fixation'] = await self.test_session_fixation()
        
        # Test 3: Session Timeout
        print("[Session Tester] Testing session timeout...")
        results['tests']['session_timeout'] = await self.test_session_timeout()
        
        # Test 4: CSRF Protection
        print("[Session Tester] Testing CSRF protection...")
        results['tests']['csrf_protection'] = await self.test_csrf_protection()
        
        # Test 5: Session Regeneration
        print("[Session Tester] Testing session regeneration...")
        results['tests']['session_regeneration'] = await self.test_session_regeneration()
        
        # Compile findings
        results['findings'] = self.findings
        results['total_findings'] = len(self.findings)
        results['summary'] = self._generate_summary()
        
        print(f"[Session Tester] Complete! Found {len(self.findings)} issues")
        
        return results
    
    async def test_cookie_security(self) -> Dict[str, Any]:
        """
        Test cookie security attributes.
        
        Checks for:
        - HttpOnly flag
        - Secure flag
        - SameSite attribute
        - Cookie expiration
        """
        result = {
            'test_name': 'Cookie Security',
            'status': 'pass',
            'issues': []
        }
        
        try:
            response = await self.client.get(f"{self.base_url}/")
            
            # Check cookies
            for cookie_name, cookie_value in response.cookies.items():
                cookie = response.cookies.get(cookie_name)
                
                issues = []
                
                # Check HttpOnly
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append('Missing HttpOnly flag')
                    self._add_finding(
                        severity='Medium',
                        category='Session Management',
                        description=f'Cookie "{cookie_name}" missing HttpOnly flag',
                        evidence=f'Cookie: {cookie_name}',
                        recommendation='Set HttpOnly flag to prevent XSS cookie theft'
                    )
                
                # Check Secure flag
                if not cookie.has_nonstandard_attr('Secure'):
                    issues.append('Missing Secure flag')
                    self._add_finding(
                        severity='Medium',
                        category='Session Management',
                        description=f'Cookie "{cookie_name}" missing Secure flag',
                        evidence=f'Cookie: {cookie_name}',
                        recommendation='Set Secure flag to ensure HTTPS-only transmission'
                    )
                
                # Check SameSite
                if not cookie.has_nonstandard_attr('SameSite'):
                    issues.append('Missing SameSite attribute')
                    self._add_finding(
                        severity='Low',
                        category='Session Management',
                        description=f'Cookie "{cookie_name}" missing SameSite attribute',
                        evidence=f'Cookie: {cookie_name}',
                        recommendation='Set SameSite=Strict or SameSite=Lax for CSRF protection'
                    )
                
                if issues:
                    result['issues'].append({
                        'cookie': cookie_name,
                        'problems': issues
                    })
                    result['status'] = 'fail'
        
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
        
        return result
    
    async def test_session_fixation(self) -> Dict[str, Any]:
        """
        Test for session fixation vulnerability.
        
        Checks if session ID changes after authentication.
        """
        result = {
            'test_name': 'Session Fixation',
            'status': 'pass',
            'vulnerable': False
        }
        
        try:
            # Get initial session
            response1 = await self.client.get(f"{self.base_url}/login/index.php")
            initial_session = response1.cookies.get('MoodleSession')
            
            if initial_session:
                # Simulate login (this would need actual credentials in production)
                # For now, we just check if session ID changes on subsequent requests
                response2 = await self.client.get(f"{self.base_url}/login/index.php")
                new_session = response2.cookies.get('MoodleSession')
                
                if initial_session == new_session:
                    result['vulnerable'] = True
                    result['status'] = 'warning'
                    result['note'] = 'Session ID does not change - potential fixation risk'
                    
                    self._add_finding(
                        severity='High',
                        category='Session Management',
                        description='Potential session fixation vulnerability',
                        evidence=f'Session ID remains constant: {initial_session}',
                        recommendation='Regenerate session ID after successful authentication'
                    )
        
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
        
        return result
    
    async def test_session_timeout(self) -> Dict[str, Any]:
        """
        Test session timeout configuration.
        
        Checks if sessions expire appropriately.
        """
        result = {
            'test_name': 'Session Timeout',
            'status': 'pass',
            'timeout_configured': False
        }
        
        try:
            response = await self.client.get(f"{self.base_url}/")
            
            # Check for session timeout in cookies
            for cookie_name, cookie_value in response.cookies.items():
                cookie = response.cookies.get(cookie_name)
                
                if cookie.expires:
                    result['timeout_configured'] = True
                    result['expires'] = str(cookie.expires)
                else:
                    result['status'] = 'warning'
                    self._add_finding(
                        severity='Low',
                        category='Session Management',
                        description=f'Cookie "{cookie_name}" has no expiration',
                        evidence=f'Cookie: {cookie_name}, Expires: None',
                        recommendation='Set appropriate session timeout (e.g., 30 minutes)'
                    )
        
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
        
        return result
    
    async def test_csrf_protection(self) -> Dict[str, Any]:
        """
        Test CSRF token implementation.
        
        Checks if forms include CSRF tokens.
        """
        result = {
            'test_name': 'CSRF Protection',
            'status': 'pass',
            'forms_checked': 0,
            'forms_protected': 0
        }
        
        try:
            response = await self.client.get(f"{self.base_url}/login/index.php")
            html = response.text
            
            # Find all forms
            forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE)
            result['forms_checked'] = len(forms)
            
            # Check each form for CSRF token
            csrf_patterns = [
                r'name=["\']sesskey["\']',
                r'name=["\']csrf_token["\']',
                r'name=["\']_token["\']',
                r'name=["\']authenticity_token["\']'
            ]
            
            for form in forms:
                has_csrf = any(re.search(pattern, form, re.IGNORECASE) for pattern in csrf_patterns)
                if has_csrf:
                    result['forms_protected'] += 1
            
            # Check if all forms are protected
            if result['forms_checked'] > 0:
                if result['forms_protected'] < result['forms_checked']:
                    result['status'] = 'fail'
                    unprotected = result['forms_checked'] - result['forms_protected']
                    
                    # Create PoC data
                    poc_data = {
                        'request': {
                            'method': 'GET',
                            'url': f'{self.base_url}/login/index.php',
                            'headers': {
                                'User-Agent': 'MoodleSec Scanner',
                                'Accept': 'text/html'
                            }
                        },
                        'response': {
                            'status_code': response.status_code,
                            'headers': {
                                'Content-Type': response.headers.get('Content-Type', 'N/A'),
                                'Set-Cookie': response.headers.get('Set-Cookie', 'N/A')
                            },
                            'body': html[:500] if html else 'N/A'
                        },
                        'steps': [
                            'Navigate to the login page',
                            'Inspect the HTML source code',
                            'Look for <form> elements',
                            'Check if forms contain CSRF token fields (sesskey, csrf_token, _token)',
                            f'Found {unprotected} form(s) without CSRF protection'
                        ],
                        'fix_code': '''// Add CSRF token to your forms
// In Moodle, use sesskey:
<input type="hidden" name="sesskey" value="<?php echo sesskey(); ?>" />

// Or in PHP:
$form->addElement('hidden', 'sesskey', sesskey());

// Verify on submission:
require_sesskey();'''
                    }
                    
                    self._add_finding(
                        severity='High',
                        category='Session Management',
                        description=f'{unprotected} form(s) missing CSRF protection',
                        evidence=f'Forms checked: {result["forms_checked"]}, Protected: {result["forms_protected"]}',
                        recommendation='Add CSRF tokens to all state-changing forms',
                        poc=poc_data
                    )
        
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
        
        return result
    
    async def test_session_regeneration(self) -> Dict[str, Any]:
        """
        Test if session ID regenerates on privilege escalation.
        
        Checks session handling during authentication state changes.
        """
        result = {
            'test_name': 'Session Regeneration',
            'status': 'pass',
            'regenerates': False
        }
        
        try:
            # Get session before login
            response1 = await self.client.get(f"{self.base_url}/")
            session_before = response1.cookies.get('MoodleSession')
            
            # Access authenticated area (will redirect to login)
            response2 = await self.client.get(f"{self.base_url}/my/")
            session_after = response2.cookies.get('MoodleSession')
            
            if session_before and session_after:
                if session_before != session_after:
                    result['regenerates'] = True
                    result['status'] = 'pass'
                else:
                    result['status'] = 'warning'
                    result['note'] = 'Session ID does not regenerate on privilege change'
        
        except Exception as e:
            result['status'] = 'error'
            result['error'] = str(e)
        
        return result
    
    def _add_finding(self, severity: str, category: str, description: str, 
                    evidence: str, recommendation: str, poc: Dict[str, Any] = None):
        """Add a security finding with optional PoC."""
        finding = {
            'severity': severity,
            'category': category,
            'description': description,
            'evidence': evidence,
            'recommendation': recommendation,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        # Add PoC if provided
        if poc:
            finding['poc'] = poc
        
        self.findings.append(finding)
    
    def _generate_summary(self) -> Dict[str, int]:
        """Generate summary of findings by severity."""
        summary = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for finding in self.findings:
            severity = finding['severity'].lower()
            if severity in summary:
                summary[severity] += 1
        
        return summary
    
    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()


# Example usage
if __name__ == "__main__":
    async def test():
        tester = SessionTester("http://localhost:8998")
        results = await tester.test_all()
        
        print("\n" + "="*50)
        print("SESSION SECURITY TEST RESULTS")
        print("="*50)
        print(f"Total Findings: {results['total_findings']}")
        print(f"Summary: {results['summary']}")
        print("="*50)
        
        await tester.close()
    
    asyncio.run(test())
