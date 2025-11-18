"""
OAuth/SSO Security Tester

Tests for OAuth and SSO vulnerabilities:
- OAuth token validation
- Redirect URI validation
- State parameter validation
- Token leakage
- SSO misconfiguration
- SAML vulnerabilities
"""

import httpx
import asyncio
from typing import Dict, List, Any, Optional
from datetime import datetime
import re
from urllib.parse import urlparse, parse_qs, urlencode


class OAuthTester:
    """Test OAuth and SSO security."""
    
    # Common OAuth/SSO endpoints in Moodle
    OAUTH_ENDPOINTS = [
        '/admin/oauth2callback.php',
        '/auth/oauth2/login.php',
        '/auth/oauth2/callback.php'
    ]
    
    # Common SSO/SAML endpoints
    SSO_ENDPOINTS = [
        '/auth/saml2/sp/saml2-acs.php',
        '/auth/saml2/sp/saml2-logout.php',
        '/auth/shibboleth/index.php'
    ]
    
    def __init__(self, base_url: str):
        """
        Initialize OAuth/SSO tester.
        
        Args:
            base_url: Base URL of the application
        """
        self.base_url = base_url.rstrip('/')
        self.client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)
        self.findings = []
    
    async def test_all(self) -> Dict[str, Any]:
        """
        Run all OAuth/SSO security tests.
        
        Returns:
            Dictionary containing all test results
        """
        print("[OAuth Tester] Starting OAuth/SSO security tests...")
        
        results = {
            'test_timestamp': datetime.utcnow().isoformat() + 'Z',
            'base_url': self.base_url,
            'tests': {}
        }
        
        # Test 1: OAuth Configuration
        print("[OAuth Tester] Testing OAuth configuration...")
        results['tests']['oauth_config'] = await self.test_oauth_configuration()
        
        # Test 2: Redirect URI Validation
        print("[OAuth Tester] Testing redirect URI validation...")
        results['tests']['redirect_uri'] = await self.test_redirect_uri_validation()
        
        # Test 3: State Parameter
        print("[OAuth Tester] Testing state parameter...")
        results['tests']['state_parameter'] = await self.test_state_parameter()
        
        # Test 4: Token Leakage
        print("[OAuth Tester] Testing token leakage...")
        results['tests']['token_leakage'] = await self.test_token_leakage()
        
        # Test 5: SSO Configuration
        print("[OAuth Tester] Testing SSO configuration...")
        results['tests']['sso_config'] = await self.test_sso_configuration()
        
        # Compile findings
        results['findings'] = self.findings
        results['total_findings'] = len(self.findings)
        results['summary'] = self._generate_summary()
        
        print(f"[OAuth Tester] Complete! Found {len(self.findings)} issues")
        
        return results
    
    async def test_oauth_configuration(self) -> Dict[str, Any]:
        """
        Test OAuth configuration and endpoint availability.
        """
        result = {
            'test_name': 'OAuth Configuration',
            'oauth_enabled': False,
            'endpoints_found': [],
            'status': 'pass'
        }
        
        for endpoint in self.OAUTH_ENDPOINTS:
            try:
                url = f"{self.base_url}{endpoint}"
                response = await self.client.get(url)
                
                if response.status_code != 404:
                    result['oauth_enabled'] = True
                    result['endpoints_found'].append({
                        'endpoint': endpoint,
                        'status_code': response.status_code
                    })
                    
                    # Check for common OAuth misconfigurations
                    if response.status_code == 200:
                        # Check if error messages expose sensitive info
                        if any(keyword in response.text.lower() for keyword in 
                               ['client_secret', 'access_token', 'refresh_token']):
                            result['status'] = 'fail'
                            self._add_finding(
                                severity='High',
                                category='OAuth Security',
                                description='OAuth endpoint exposes sensitive information',
                                evidence=f'Endpoint: {endpoint}',
                                recommendation='Remove sensitive data from error messages'
                            )
            
            except Exception as e:
                pass
        
        return result
    
    async def test_redirect_uri_validation(self) -> Dict[str, Any]:
        """
        Test redirect URI validation in OAuth flow.
        
        Checks if arbitrary redirect URIs are accepted.
        """
        result = {
            'test_name': 'Redirect URI Validation',
            'status': 'pass',
            'vulnerable': False
        }
        
        # Test with malicious redirect URIs
        malicious_uris = [
            'http://evil.com/callback',
            'https://attacker.com',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>'
        ]
        
        for endpoint in self.OAUTH_ENDPOINTS:
            for malicious_uri in malicious_uris:
                try:
                    url = f"{self.base_url}{endpoint}?redirect_uri={malicious_uri}"
                    response = await self.client.get(url)
                    
                    # Check if redirect is accepted
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if malicious_uri in location:
                            result['vulnerable'] = True
                            result['status'] = 'fail'
                            
                            self._add_finding(
                                severity='Critical',
                                category='OAuth Security',
                                description='Open redirect vulnerability in OAuth flow',
                                evidence=f'Accepted redirect to: {malicious_uri}',
                                recommendation='Implement strict redirect URI whitelist validation'
                            )
                            break
                
                except Exception as e:
                    pass
            
            if result['vulnerable']:
                break
        
        return result
    
    async def test_state_parameter(self) -> Dict[str, Any]:
        """
        Test state parameter validation for CSRF protection.
        
        Checks if state parameter is properly validated.
        """
        result = {
            'test_name': 'State Parameter Validation',
            'status': 'pass',
            'state_required': False
        }
        
        for endpoint in self.OAUTH_ENDPOINTS:
            try:
                # Test without state parameter
                url = f"{self.base_url}{endpoint}?code=test123"
                response = await self.client.get(url)
                
                # If request succeeds without state, it's vulnerable
                if response.status_code == 200:
                    if 'error' not in response.text.lower():
                        result['status'] = 'fail'
                        
                        self._add_finding(
                            severity='High',
                            category='OAuth Security',
                            description='Missing state parameter validation',
                            evidence=f'Endpoint: {endpoint} accepts requests without state',
                            recommendation='Require and validate state parameter for CSRF protection'
                        )
                else:
                    result['state_required'] = True
            
            except Exception as e:
                pass
        
        return result
    
    async def test_token_leakage(self) -> Dict[str, Any]:
        """
        Test for OAuth token leakage.
        
        Checks if tokens are exposed in URLs, logs, or error messages.
        """
        result = {
            'test_name': 'Token Leakage',
            'status': 'pass',
            'leakage_found': []
        }
        
        # Patterns that might indicate token leakage
        token_patterns = [
            r'access_token=([a-zA-Z0-9_-]+)',
            r'refresh_token=([a-zA-Z0-9_-]+)',
            r'bearer\s+([a-zA-Z0-9_-]+)',
            r'token["\']:\s*["\']([a-zA-Z0-9_-]+)'
        ]
        
        for endpoint in self.OAUTH_ENDPOINTS:
            try:
                url = f"{self.base_url}{endpoint}"
                response = await self.client.get(url)
                
                # Check response body for tokens
                for pattern in token_patterns:
                    matches = re.findall(pattern, response.text, re.IGNORECASE)
                    if matches:
                        result['leakage_found'].append({
                            'endpoint': endpoint,
                            'pattern': pattern,
                            'tokens_found': len(matches)
                        })
                        result['status'] = 'fail'
                
                # Check if tokens are in URL (fragment or query)
                if '#access_token=' in str(response.url) or '?access_token=' in str(response.url):
                    result['leakage_found'].append({
                        'endpoint': endpoint,
                        'location': 'URL',
                        'issue': 'Token in URL'
                    })
                    result['status'] = 'fail'
            
            except Exception as e:
                pass
        
        if result['leakage_found']:
            self._add_finding(
                severity='Critical',
                category='OAuth Security',
                description='OAuth token leakage detected',
                evidence=f'Found {len(result["leakage_found"])} instances of token exposure',
                recommendation='Use POST method and secure storage for tokens, avoid URL parameters'
            )
        
        return result
    
    async def test_sso_configuration(self) -> Dict[str, Any]:
        """
        Test SSO/SAML configuration.
        
        Checks for common SSO misconfigurations.
        """
        result = {
            'test_name': 'SSO Configuration',
            'sso_enabled': False,
            'endpoints_found': [],
            'status': 'pass'
        }
        
        for endpoint in self.SSO_ENDPOINTS:
            try:
                url = f"{self.base_url}{endpoint}"
                response = await self.client.get(url)
                
                if response.status_code != 404:
                    result['sso_enabled'] = True
                    result['endpoints_found'].append({
                        'endpoint': endpoint,
                        'status_code': response.status_code
                    })
                    
                    # Check for SAML metadata exposure
                    if 'saml' in endpoint.lower():
                        metadata_url = f"{self.base_url}/auth/saml2/sp/metadata.php"
                        try:
                            metadata_response = await self.client.get(metadata_url)
                            if metadata_response.status_code == 200:
                                if 'EntityDescriptor' in metadata_response.text:
                                    result['status'] = 'warning'
                                    self._add_finding(
                                        severity='Low',
                                        category='SSO Security',
                                        description='SAML metadata publicly accessible',
                                        evidence=f'Metadata URL: {metadata_url}',
                                        recommendation='Consider restricting access to SAML metadata'
                                    )
                        except:
                            pass
            
            except Exception as e:
                pass
        
        return result
    
    def _add_finding(self, severity: str, category: str, description: str,
                    evidence: str, recommendation: str):
        """Add a security finding."""
        self.findings.append({
            'severity': severity,
            'category': category,
            'description': description,
            'evidence': evidence,
            'recommendation': recommendation,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
    
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
        tester = OAuthTester("http://localhost:8998")
        results = await tester.test_all()
        
        print("\n" + "="*50)
        print("OAUTH/SSO SECURITY TEST RESULTS")
        print("="*50)
        print(f"Total Findings: {results['total_findings']}")
        print(f"Summary: {results['summary']}")
        print("="*50)
        
        await tester.close()
    
    asyncio.run(test())
