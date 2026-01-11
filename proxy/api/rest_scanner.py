"""
REST API Security Scanner

Comprehensive REST API security testing:
- API endpoint discovery
- Authentication bypass
- Input validation & fuzzing
- Rate limiting
- Mass assignment
- HTTP method tampering
- Excessive data exposure
- Security misconfiguration
"""

import httpx
import asyncio
import json
import re
from typing import Dict, List, Any, Optional, Set
from datetime import datetime
import random
import string


class RESTScanner:
    """Comprehensive REST API security scanner."""
    
    # Common API paths in Moodle
    API_PATHS = [
        '/webservice/rest/server.php',
        '/webservice/xmlrpc/server.php',
        '/webservice/soap/server.php',
        '/lib/ajax/service.php',
        '/lib/ajax/service-nologin.php'
    ]
    
    # Common API parameters
    COMMON_PARAMS = [
        'wstoken', 'wsfunction', 'moodlewsrestformat',
        'id', 'userid', 'courseid', 'cmid',
        'username', 'password', 'email'
    ]
    
    # HTTP methods to test
    HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']
    
    # Injection payloads for fuzzing
    INJECTION_PAYLOADS = [
        "' OR '1'='1",
        "1' OR '1'='1' --",
        "<script>alert(1)</script>",
        "../../../etc/passwd",
        "${7*7}",
        "{{7*7}}",
        "'; DROP TABLE users--",
        "1 UNION SELECT NULL--"
    ]
    
    def __init__(self, base_url: str):
        """
        Initialize REST API scanner.
        
        Args:
            base_url: Base URL of the application
        """
        self.base_url = base_url.rstrip('/')
        self.client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
        self.findings = []
        self.discovered_endpoints = set()
    
    async def scan_all(self) -> Dict[str, Any]:
        """
        Run comprehensive REST API security scan.
        
        Returns:
            Complete scan results
        """
        print("[REST Scanner] Starting comprehensive REST API security scan...")
        
        results = {
            'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
            'base_url': self.base_url,
            'tests': {}
        }
        
        # Test 1: API Discovery
        print("[REST Scanner] Discovering API endpoints...")
        results['tests']['discovery'] = await self.discover_apis()
        
        # Test 2: Authentication Bypass
        print("[REST Scanner] Testing authentication bypass...")
        results['tests']['auth_bypass'] = await self.test_authentication_bypass()
        
        # Test 3: Input Validation
        print("[REST Scanner] Testing input validation...")
        results['tests']['input_validation'] = await self.test_input_validation()
        
        # Test 4: HTTP Method Tampering
        print("[REST Scanner] Testing HTTP method tampering...")
        results['tests']['method_tampering'] = await self.test_method_tampering()
        
        # Test 5: Rate Limiting
        print("[REST Scanner] Testing rate limiting...")
        results['tests']['rate_limiting'] = await self.test_rate_limiting()
        
        # Test 6: Mass Assignment
        print("[REST Scanner] Testing mass assignment...")
        results['tests']['mass_assignment'] = await self.test_mass_assignment()
        
        # Test 7: Excessive Data Exposure
        print("[REST Scanner] Testing excessive data exposure...")
        results['tests']['data_exposure'] = await self.test_data_exposure()
        
        # Test 8: Security Headers
        print("[REST Scanner] Testing security headers...")
        results['tests']['security_headers'] = await self.test_security_headers()
        
        # Compile findings
        results['findings'] = self.findings
        results['total_findings'] = len(self.findings)
        results['discovered_endpoints'] = list(self.discovered_endpoints)
        results['summary'] = self._generate_summary()
        
        print(f"[REST Scanner] Complete! Found {len(self.findings)} issues")
        print(f"[REST Scanner] Discovered {len(self.discovered_endpoints)} API endpoints")
        
        # Print summary breakdown
        if self.findings:
            summary = results['summary']
            print(f"[REST Scanner] Summary: Critical={summary.get('critical', 0)}, High={summary.get('high', 0)}, Medium={summary.get('medium', 0)}, Low={summary.get('low', 0)}")
            print(f"[REST Scanner] Tested endpoints: {list(self.discovered_endpoints)}")
        
        return results
    
    async def discover_apis(self) -> Dict[str, Any]:
        """
        Discover API endpoints.
        
        Finds REST API endpoints and their capabilities.
        """
        result = {
            'test_name': 'API Discovery',
            'endpoints_found': [],
            'status': 'pass'
        }
        
        # Test known API paths
        for api_path in self.API_PATHS:
            try:
                url = f"{self.base_url}{api_path}"
                response = await self.client.get(url)
                
                if response.status_code != 404:
                    endpoint_info = {
                        'path': api_path,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('content-type', ''),
                        'accessible': response.status_code == 200
                    }
                    
                    result['endpoints_found'].append(endpoint_info)
                    self.discovered_endpoints.add(api_path)
                    
                    # Check if API is accessible without authentication
                    if response.status_code == 200:
                        if 'error' not in response.text.lower()[:200]:
                            result['status'] = 'warning'
                            self._add_finding(
                                severity='Medium',
                                category='API Security',
                                description=f'API endpoint accessible without authentication',
                                evidence=f'URL: {api_path}, Status: {response.status_code}',
                                recommendation='Implement authentication for API endpoints'
                            )
            
            except Exception as e:
                pass
        
        # Try to discover API documentation
        doc_paths = ['/api/docs', '/api/swagger', '/api/v1', '/api/v2']
        for doc_path in doc_paths:
            try:
                url = f"{self.base_url}{doc_path}"
                response = await self.client.get(url)
                
                if response.status_code == 200:
                    result['endpoints_found'].append({
                        'path': doc_path,
                        'type': 'documentation',
                        'accessible': True
                    })
                    
                    self._add_finding(
                        severity='Low',
                        category='Information Disclosure',
                        description='API documentation publicly accessible',
                        evidence=f'URL: {doc_path}',
                        recommendation='Restrict access to API documentation in production'
                    )
            except:
                pass
        
        return result
    
    async def test_authentication_bypass(self) -> Dict[str, Any]:
        """
        Test for authentication bypass vulnerabilities.
        
        Attempts to access API without proper authentication.
        """
        result = {
            'test_name': 'Authentication Bypass',
            'status': 'pass',
            'bypass_attempts': []
        }
        
        for endpoint in self.discovered_endpoints:
            # Test without token
            try:
                url = f"{self.base_url}{endpoint}"
                response = await self.client.get(url)
                
                if response.status_code == 200:
                    # Check if we got actual data (not error)
                    try:
                        data = response.json()
                        if not any(key in str(data).lower() for key in ['error', 'exception', 'invalid']):
                            result['bypass_attempts'].append({
                                'endpoint': endpoint,
                                'method': 'No authentication',
                                'successful': True
                            })
                            result['status'] = 'fail'
                            
                            self._add_finding(
                                severity='Critical',
                                category='API Security',
                                description='API authentication bypass - endpoint accessible without credentials',
                                evidence=f'Endpoint: {endpoint}',
                                recommendation='Implement mandatory authentication for all API endpoints'
                            )
                    except:
                        pass
            except:
                pass
            
            # Test with invalid token
            try:
                url = f"{self.base_url}{endpoint}?wstoken=invalid_token_12345"
                response = await self.client.get(url)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if not any(key in str(data).lower() for key in ['error', 'exception', 'invalid']):
                            result['bypass_attempts'].append({
                                'endpoint': endpoint,
                                'method': 'Invalid token',
                                'successful': True
                            })
                            result['status'] = 'fail'
                    except:
                        pass
            except:
                pass
        
        return result
    
    async def test_input_validation(self) -> Dict[str, Any]:
        """
        Test input validation with fuzzing.
        
        Tests API parameters with malicious payloads.
        """
        result = {
            'test_name': 'Input Validation',
            'status': 'pass',
            'vulnerabilities': []
        }
        
        for endpoint in self.discovered_endpoints:
            for param in self.COMMON_PARAMS:
                for payload in self.INJECTION_PAYLOADS[:5]:  # Test first 5 payloads
                    try:
                        url = f"{self.base_url}{endpoint}"
                        data = {param: payload}
                        
                        response = await self.client.post(url, data=data)
                        
                        # Check for ACTUAL SQL error messages (not just keywords)
                        # More specific patterns to reduce false positives
                        sql_error_patterns = [
                            'you have an error in your sql syntax',
                            'warning: mysql',
                            'unclosed quotation mark',
                            'quoted string not properly terminated',
                            'sql command not properly ended',
                            'sqlexception',
                            'pg_query()',
                            'mysql_fetch',
                            'ora-01756',  # Oracle error
                            'microsoft sql server'
                        ]
                        
                        response_lower = response.text.lower()
                        sql_error_found = False
                        matched_error = None
                        
                        for error_pattern in sql_error_patterns:
                            if error_pattern in response_lower:
                                sql_error_found = True
                                matched_error = error_pattern
                                break
                        
                        if sql_error_found:
                            result['vulnerabilities'].append({
                                'endpoint': endpoint,
                                'parameter': param,
                                'payload': payload,
                                'type': 'SQL Injection',
                                'error': matched_error
                            })
                            result['status'] = 'fail'
                            
                            self._add_finding(
                                severity='Critical',
                                category='Input Validation',
                                description=f'SQL injection detected - database error exposed',
                                evidence=f'Endpoint: {endpoint}, Parameter: {param}, Error: {matched_error}, Payload: {payload[:30]}',
                                recommendation='Implement parameterized queries and input validation'
                            )
                            break
                        
                        # Check for XSS reflection
                        if '<script>' in payload and payload in response.text:
                            result['vulnerabilities'].append({
                                'endpoint': endpoint,
                                'parameter': param,
                                'payload': payload,
                                'type': 'XSS'
                            })
                            result['status'] = 'fail'
                            
                            self._add_finding(
                                severity='High',
                                category='Input Validation',
                                description=f'Potential XSS in API response',
                                evidence=f'Endpoint: {endpoint}, Parameter: {param}',
                                recommendation='Implement output encoding and Content-Security-Policy'
                            )
                            break
                    
                    except:
                        pass
        
        return result
    
    async def test_method_tampering(self) -> Dict[str, Any]:
        """
        Test HTTP method tampering.
        
        Checks if endpoints accept unexpected HTTP methods.
        """
        result = {
            'test_name': 'HTTP Method Tampering',
            'status': 'pass',
            'unexpected_methods': []
        }
        
        for endpoint in self.discovered_endpoints:
            allowed_methods = set()
            
            for method in self.HTTP_METHODS:
                try:
                    url = f"{self.base_url}{endpoint}"
                    response = await self.client.request(method, url)
                    
                    # If method is allowed (not 405 Method Not Allowed)
                    if response.status_code != 405:
                        allowed_methods.add(method)
                        
                        # Check for dangerous methods - but only flag if successful (200-299)
                        if method in ['DELETE', 'PUT', 'PATCH']:
                            # Only flag as issue if method returns success code
                            if 200 <= response.status_code < 300:
                                # Check if response contains error or requires auth
                                response_lower = response.text.lower()
                                if not any(keyword in response_lower for keyword in ['error', 'exception', 'invalid', 'access denied', 'unauthorized', 'forbidden']):
                                    result['unexpected_methods'].append({
                                        'endpoint': endpoint,
                                        'method': method,
                                        'status_code': response.status_code
                                    })
                                    result['status'] = 'warning'
                                    
                                    self._add_finding(
                                        severity='Medium',
                                        category='API Security',
                                        description=f'Dangerous HTTP method allowed without authentication',
                                        evidence=f'Endpoint: {endpoint}, Method: {method}, Status: {response.status_code}',
                                        recommendation='Restrict HTTP methods to only those required and enforce authentication'
                                    )
                
                except:
                    pass
        
        return result
    
    async def test_rate_limiting(self) -> Dict[str, Any]:
        """
        Test rate limiting implementation.
        
        Sends multiple rapid requests to check for rate limiting.
        """
        result = {
            'test_name': 'Rate Limiting',
            'status': 'pass',
            'rate_limited': False
        }
        
        if self.discovered_endpoints:
            endpoint = list(self.discovered_endpoints)[0]
            url = f"{self.base_url}{endpoint}"
            
            # Send 20 rapid requests
            responses = []
            for i in range(20):
                try:
                    response = await self.client.get(url)
                    responses.append(response.status_code)
                except:
                    pass
            
            # Check if any request was rate limited (429 Too Many Requests)
            if 429 in responses:
                result['rate_limited'] = True
                result['status'] = 'pass'
            else:
                result['status'] = 'warning'
                result['requests_sent'] = len(responses)
                result['all_successful'] = all(s == 200 for s in responses)
                
                if result['all_successful']:
                    self._add_finding(
                        severity='Medium',
                        category='API Security',
                        description='No rate limiting detected on API endpoint',
                        evidence=f'Sent {len(responses)} requests without rate limiting',
                        recommendation='Implement rate limiting to prevent abuse'
                    )
        
        return result
    
    async def test_mass_assignment(self) -> Dict[str, Any]:
        """
        Test for mass assignment vulnerabilities.
        
        Attempts to modify unexpected parameters.
        """
        result = {
            'test_name': 'Mass Assignment',
            'status': 'pass',
            'vulnerable_endpoints': []
        }
        
        # Sensitive parameters that shouldn't be modifiable
        sensitive_params = ['role', 'admin', 'isadmin', 'is_admin', 'permissions', 'privileges']
        
        for endpoint in self.discovered_endpoints:
            for param in sensitive_params:
                try:
                    url = f"{self.base_url}{endpoint}"
                    data = {param: 'admin', 'id': '1'}
                    
                    response = await self.client.post(url, data=data)
                    
                    # Check if parameter was accepted (no error about unexpected parameter)
                    if response.status_code == 200:
                        if param not in response.text.lower() or 'error' not in response.text.lower():
                            result['vulnerable_endpoints'].append({
                                'endpoint': endpoint,
                                'parameter': param
                            })
                            result['status'] = 'warning'
                
                except:
                    pass
        
        if result['vulnerable_endpoints']:
            self._add_finding(
                severity='High',
                category='API Security',
                description='Potential mass assignment vulnerability',
                evidence=f'Found {len(result["vulnerable_endpoints"])} potentially vulnerable endpoints',
                recommendation='Implement parameter whitelisting and validation'
            )
        
        return result
    
    async def test_data_exposure(self) -> Dict[str, Any]:
        """
        Test for excessive data exposure.
        
        Checks if API returns more data than necessary.
        """
        result = {
            'test_name': 'Excessive Data Exposure',
            'status': 'pass',
            'exposed_data': []
        }
        
        # Sensitive fields that shouldn't be exposed
        sensitive_fields = [
            'password', 'passwd', 'pwd', 'secret', 'token',
            'api_key', 'apikey', 'private_key', 'privatekey',
            'ssn', 'credit_card', 'creditcard'
        ]
        
        for endpoint in self.discovered_endpoints:
            try:
                url = f"{self.base_url}{endpoint}"
                response = await self.client.get(url)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        data_str = json.dumps(data).lower()
                        
                        # Check for sensitive fields
                        for field in sensitive_fields:
                            if field in data_str:
                                result['exposed_data'].append({
                                    'endpoint': endpoint,
                                    'field': field
                                })
                                result['status'] = 'fail'
                                
                                self._add_finding(
                                    severity='High',
                                    category='Data Exposure',
                                    description=f'Sensitive field "{field}" exposed in API response',
                                    evidence=f'Endpoint: {endpoint}',
                                    recommendation='Remove sensitive fields from API responses'
                                )
                    except:
                        pass
            except:
                pass
        
        return result
    
    async def test_security_headers(self) -> Dict[str, Any]:
        """
        Test security headers in API responses.
        
        Checks for important security headers.
        """
        result = {
            'test_name': 'Security Headers',
            'status': 'pass',
            'missing_headers': []
        }
        
        # Important security headers
        required_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
            'Content-Security-Policy': None,
            'Strict-Transport-Security': None
        }
        
        if self.discovered_endpoints:
            endpoint = list(self.discovered_endpoints)[0]
            
            try:
                url = f"{self.base_url}{endpoint}"
                response = await self.client.get(url)
                
                for header, expected_value in required_headers.items():
                    if header not in response.headers:
                        result['missing_headers'].append(header)
                        result['status'] = 'warning'
                        
                        self._add_finding(
                            severity='Low',
                            category='Security Misconfiguration',
                            description=f'Missing security header: {header}',
                            evidence=f'Header not found in API response',
                            recommendation=f'Add {header} header to API responses'
                        )
            except:
                pass
        
        return result
    
    def _add_finding(self, severity: str, category: str, description: str,
                    evidence: str, recommendation: str):
        """Add a security finding."""
        # Log the finding with URL/endpoint details
        print(f"[REST Scanner] 🔍 {severity}: {description}")
        print(f"[REST Scanner]    📍 {evidence}")
        
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
        scanner = RESTScanner("http://localhost:8998")
        results = await scanner.scan_all()
        
        print("\n" + "="*50)
        print("REST API SECURITY SCAN RESULTS")
        print("="*50)
        print(f"Discovered Endpoints: {len(results['discovered_endpoints'])}")
        print(f"Total Findings: {results['total_findings']}")
        print(f"Summary: {results['summary']}")
        print("="*50)
        
        await scanner.close()
    
    asyncio.run(test())
