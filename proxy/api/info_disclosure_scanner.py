"""
Information Disclosure Scanner for Moodle

Tests for information disclosure vulnerabilities - 15-20% of Moodle CVEs
- User enumeration
- Email disclosure
- Private file access
- Debug information leakage
- Version disclosure
- Sensitive data in API responses

Based on real Moodle CVEs:
- CVE-2024-43434 - User email disclosure
- CVE-2023-5540 - User account enumeration
- CVE-2022-45154 - Access to private files
- CVE-2021-36394 - Course information disclosure
"""

import httpx
import asyncio
import re
import json
from typing import Dict, List, Any, Set
from datetime import datetime


class InfoDisclosureScanner:
    """Information disclosure vulnerability scanner for Moodle."""
    
    # Endpoints that may leak user information
    USER_ENUM_ENDPOINTS = [
        '/login/forgot_password.php',
        '/login/index.php',
        '/user/profile.php',
        '/user/view.php',
        '/message/index.php',
        '/user/index.php',
        '/enrol/index.php',
    ]
    
    # API endpoints that may expose sensitive data
    API_ENDPOINTS = [
        '/webservice/rest/server.php',
        '/lib/ajax/service.php',
        '/lib/ajax/service-nologin.php',
    ]
    
    # Files that may contain sensitive information
    SENSITIVE_FILES = [
        '/config.php',
        '/.env',
        '/composer.json',
        '/package.json',
        '/README.txt',
        '/CHANGELOG.txt',
        '/version.php',
        '/.git/config',
        '/.git/HEAD',
        '/phpinfo.php',
        '/info.php',
        '/.htaccess',
        '/web.config',
    ]
    
    # Debug/error pages
    DEBUG_ENDPOINTS = [
        '/error/index.php',
        '/admin/phpinfo.php',
        '/test.php',
    ]
    
    def __init__(self, base_url: str):
        """
        Initialize information disclosure scanner.
        
        Args:
            base_url: Base URL of Moodle installation
        """
        self.base_url = base_url.rstrip('/')
        self.client = httpx.AsyncClient(timeout=30.0, follow_redirects=True, verify=False)
        self.findings = []
        self.tested_endpoints = set()
    
    async def scan_all(self) -> Dict[str, Any]:
        """
        Run comprehensive information disclosure scan.
        
        Returns:
            Complete scan results
        """
        print("[Info Disclosure Scanner] Starting information disclosure scan...")
        
        results = {
            'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
            'base_url': self.base_url,
            'tests': {}
        }
        
        # Test 1: User enumeration
        print("[Info Disclosure Scanner] Testing user enumeration...")
        results['tests']['user_enumeration'] = await self.test_user_enumeration()
        
        # Test 2: Email disclosure
        print("[Info Disclosure Scanner] Testing email disclosure...")
        results['tests']['email_disclosure'] = await self.test_email_disclosure()
        
        # Test 3: Sensitive file access
        print("[Info Disclosure Scanner] Testing sensitive file access...")
        results['tests']['sensitive_files'] = await self.test_sensitive_files()
        
        # Test 4: Debug information leakage
        print("[Info Disclosure Scanner] Testing debug information leakage...")
        results['tests']['debug_leakage'] = await self.test_debug_leakage()
        
        # Test 5: Version disclosure
        print("[Info Disclosure Scanner] Testing version disclosure...")
        results['tests']['version_disclosure'] = await self.test_version_disclosure()
        
        # Test 6: API data exposure
        print("[Info Disclosure Scanner] Testing API data exposure...")
        results['tests']['api_exposure'] = await self.test_api_exposure()
        
        # Compile results
        results['findings'] = self.findings
        results['total_findings'] = len(self.findings)
        results['tested_endpoints'] = list(self.tested_endpoints)
        results['summary'] = self._generate_summary()
        
        print(f"[Info Disclosure Scanner] Complete! Found {len(self.findings)} information disclosure issues")
        if self.findings:
            summary = results['summary']
            print(f"[Info Disclosure Scanner] Summary: High={summary.get('high', 0)}, Medium={summary.get('medium', 0)}, Low={summary.get('low', 0)}")
        
        return results
    
    async def test_user_enumeration(self) -> Dict[str, Any]:
        """
        Test for user enumeration vulnerabilities.
        
        Checks if system reveals whether username exists.
        """
        result = {
            'test_name': 'User Enumeration',
            'status': 'pass',
            'enumerable_endpoints': []
        }
        
        test_users = ['admin', 'teacher', 'student', 'nonexistent_user_12345']
        
        for endpoint in self.USER_ENUM_ENDPOINTS:
            self.tested_endpoints.add(endpoint)
            
            responses = {}
            
            # Test different usernames
            for username in test_users:
                try:
                    url = f"{self.base_url}{endpoint}"
                    
                    # Test password reset (common enumeration vector)
                    if 'forgot_password' in endpoint:
                        data = {'username': username}
                    elif 'login' in endpoint:
                        data = {'username': username, 'password': 'wrongpassword123'}
                    else:
                        data = {'id': username}
                    
                    response = await self.client.post(url, data=data)
                    responses[username] = {
                        'status': response.status_code,
                        'length': len(response.text),
                        'text': response.text.lower()
                    }
                
                except Exception:
                    pass
            
            # Compare responses for existing vs non-existing users
            if len(responses) >= 2:
                # Check if responses differ significantly
                response_texts = [r['text'] for r in responses.values()]
                response_lengths = [r['length'] for r in responses.values()]
                
                # If responses are different, user enumeration is possible
                if len(set(response_lengths)) > 1:
                    # Check for telling error messages
                    telling_messages = [
                        'user not found', 'invalid user', 'no such user',
                        'user does not exist', 'account not found',
                        'email sent', 'check your email', 'password reset'
                    ]
                    
                    for username, resp in responses.items():
                        for message in telling_messages:
                            if message in resp['text']:
                                result['enumerable_endpoints'].append(endpoint)
                                result['status'] = 'fail'
                                
                                self._add_finding(
                                    severity='Medium',
                                    category='Information Disclosure',
                                    description=f'User enumeration vulnerability - different responses for valid/invalid users',
                                    evidence=f'Endpoint: {endpoint}, Revealing message: "{message}"',
                                    recommendation='Return generic error messages for both valid and invalid users'
                                )
                                break
        
        return result
    
    async def test_email_disclosure(self) -> Dict[str, Any]:
        """
        Test for email address disclosure.
        
        CVE-2024-43434, CVE-2023-5540
        """
        result = {
            'test_name': 'Email Disclosure',
            'status': 'pass',
            'exposed_emails': []
        }
        
        # Test user profile pages
        test_endpoints = [
            '/user/profile.php?id=1',
            '/user/profile.php?id=2',
            '/user/view.php?id=1',
            '/user/index.php',
            '/course/user.php',
        ]
        
        email_patterns = [
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            r'email["\s:]+([^"<>\s]+@[^"<>\s]+)',
            r'mailto:([^"\'<>\s]+)',
        ]
        
        for endpoint in test_endpoints:
            self.tested_endpoints.add(endpoint)
            
            try:
                url = f"{self.base_url}{endpoint}"
                response = await self.client.get(url)
                
                if response.status_code == 200:
                    # Search for email addresses
                    for pattern in email_patterns:
                        matches = re.findall(pattern, response.text, re.IGNORECASE)
                        if matches:
                            # Filter out common false positives
                            real_emails = [m for m in matches if '@' in m and not any(
                                fake in m.lower() for fake in ['example.com', 'test.com', 'placeholder']
                            )]
                            
                            if real_emails:
                                result['exposed_emails'].extend(real_emails)
                                result['status'] = 'fail'
                                
                                self._add_finding(
                                    severity='Medium',
                                    category='Information Disclosure',
                                    description=f'Email addresses exposed in page',
                                    evidence=f'Endpoint: {endpoint}, Found {len(real_emails)} email(s): {real_emails[0]}...',
                                    recommendation='Restrict email visibility to authorized users only'
                                )
                                break
            
            except Exception:
                pass
        
        return result
    
    async def test_sensitive_files(self) -> Dict[str, Any]:
        """
        Test access to sensitive configuration and system files.
        """
        result = {
            'test_name': 'Sensitive File Access',
            'status': 'pass',
            'accessible_files': []
        }
        
        for file_path in self.SENSITIVE_FILES:
            self.tested_endpoints.add(file_path)
            
            try:
                url = f"{self.base_url}{file_path}"
                response = await self.client.get(url)
                
                # File is accessible if status is 200 and not empty
                if response.status_code == 200 and len(response.text) > 0:
                    # Check if it's actual content, not error page
                    response_lower = response.text.lower()
                    
                    if not any(err in response_lower for err in ['not found', 'forbidden', 'access denied', 'error']):
                        result['accessible_files'].append(file_path)
                        result['status'] = 'fail'
                        
                        # Determine severity based on file type
                        severity = 'High' if any(s in file_path for s in ['config', '.env', '.git']) else 'Medium'
                        
                        self._add_finding(
                            severity=severity,
                            category='Information Disclosure',
                            description=f'Sensitive file accessible: {file_path}',
                            evidence=f'File: {file_path}, Size: {len(response.text)} bytes, Status: {response.status_code}',
                            recommendation='Restrict access to sensitive files and configuration files'
                        )
            
            except Exception:
                pass
        
        return result
    
    async def test_debug_leakage(self) -> Dict[str, Any]:
        """
        Test for debug information and error message leakage.
        """
        result = {
            'test_name': 'Debug Information Leakage',
            'status': 'pass',
            'debug_pages': []
        }
        
        # Test for debug mode
        test_pages = ['/', '/index.php', '/course/view.php?id=1']
        
        debug_indicators = [
            'debugging',
            'debug mode',
            'stack trace',
            'call stack',
            'error on line',
            'warning: ',
            'notice: ',
            'deprecated: ',
            'fatal error',
            'parse error',
            'mysql error',
            'sql error',
            '/home/',
            'c:\\',
            'php version',
        ]
        
        for page in test_pages:
            try:
                url = f"{self.base_url}{page}"
                response = await self.client.get(url)
                
                response_lower = response.text.lower()
                
                found_indicators = []
                for indicator in debug_indicators:
                    if indicator in response_lower:
                        found_indicators.append(indicator)
                
                if found_indicators:
                    result['debug_pages'].append({
                        'page': page,
                        'indicators': found_indicators
                    })
                    result['status'] = 'fail'
                    
                    self._add_finding(
                        severity='Low',
                        category='Information Disclosure',
                        description=f'Debug information exposed on page',
                        evidence=f'Page: {page}, Debug indicators: {", ".join(found_indicators[:3])}',
                        recommendation='Disable debug mode in production, configure error handling'
                    )
            
            except Exception:
                pass
        
        return result
    
    async def test_version_disclosure(self) -> Dict[str, Any]:
        """
        Test for Moodle version disclosure.
        """
        result = {
            'test_name': 'Version Disclosure',
            'status': 'pass',
            'version_info': {}
        }
        
        # Check common version disclosure locations
        version_endpoints = [
            '/admin/environment.xml',
            '/version.php',
            '/lib/upgrade.txt',
            '/',  # Check HTML comments and meta tags
        ]
        
        version_patterns = [
            r'moodle["\s]+version["\s:]+([0-9.]+)',
            r'release["\s:]+([0-9.]+\s*\([^)]+\))',
            r'<meta name="version" content="([^"]+)"',
            r'<!--.*moodle\s+([0-9.]+).*-->',
        ]
        
        for endpoint in version_endpoints:
            try:
                url = f"{self.base_url}{endpoint}"
                response = await self.client.get(url)
                
                if response.status_code == 200:
                    for pattern in version_patterns:
                        matches = re.findall(pattern, response.text, re.IGNORECASE)
                        if matches:
                            version = matches[0]
                            result['version_info'][endpoint] = version
                            result['status'] = 'warning'
                            
                            self._add_finding(
                                severity='Low',
                                category='Information Disclosure',
                                description=f'Moodle version disclosed',
                                evidence=f'Endpoint: {endpoint}, Version: {version}',
                                recommendation='Hide version information to prevent targeted attacks'
                            )
                            break
            
            except Exception:
                pass
        
        return result
    
    async def test_api_exposure(self) -> Dict[str, Any]:
        """
        Test for excessive data exposure in API responses.
        """
        result = {
            'test_name': 'API Data Exposure',
            'status': 'pass',
            'exposed_data': []
        }
        
        # Sensitive fields that shouldn't be exposed
        sensitive_fields = [
            'password', 'secret', 'token', 'api_key', 'private_key',
            'ssn', 'credit_card', 'auth', 'session', 'hash'
        ]
        
        for endpoint in self.API_ENDPOINTS:
            try:
                url = f"{self.base_url}{endpoint}"
                
                # Test without authentication
                response = await self.client.get(url)
                
                if response.status_code == 200:
                    try:
                        # Try to parse as JSON
                        data = response.json()
                        
                        # Check for sensitive fields
                        data_str = json.dumps(data).lower()
                        
                        found_sensitive = []
                        for field in sensitive_fields:
                            if field in data_str:
                                found_sensitive.append(field)
                        
                        if found_sensitive:
                            result['exposed_data'].append({
                                'endpoint': endpoint,
                                'sensitive_fields': found_sensitive
                            })
                            result['status'] = 'fail'
                            
                            self._add_finding(
                                severity='High',
                                category='Information Disclosure',
                                description=f'Sensitive data exposed in API response',
                                evidence=f'Endpoint: {endpoint}, Sensitive fields: {", ".join(found_sensitive)}',
                                recommendation='Filter sensitive fields from API responses, implement field-level access control'
                            )
                    
                    except:
                        pass
            
            except Exception:
                pass
        
        return result
    
    def _add_finding(self, severity: str, category: str, description: str,
                    evidence: str, recommendation: str):
        """Add information disclosure finding."""
        print(f"[Info Disclosure Scanner] 🔍 {severity}: {description}")
        print(f"[Info Disclosure Scanner]    📍 {evidence}")
        
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
