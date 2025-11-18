"""
Role-Based Access Control (RBAC) Security Tester

Tests for authorization vulnerabilities:
- Privilege escalation (vertical)
- Horizontal access control bypass
- Missing function-level access control
- Insecure direct object references (IDOR)
- Role enumeration
"""

import httpx
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import re


class RBACTester:
    """Test role-based access control security."""
    
    # Common Moodle roles
    MOODLE_ROLES = {
        'guest': {'id': 6, 'capabilities': []},
        'student': {'id': 5, 'capabilities': ['mod/forum:replypost']},
        'teacher': {'id': 4, 'capabilities': ['moodle/grade:edit']},
        'editingteacher': {'id': 3, 'capabilities': ['moodle/course:update']},
        'manager': {'id': 2, 'capabilities': ['moodle/site:config']},
        'admin': {'id': 1, 'capabilities': ['moodle/site:config', 'all']}
    }
    
    # Sensitive endpoints that should require authentication/authorization
    SENSITIVE_ENDPOINTS = [
        '/admin/',
        '/admin/index.php',
        '/admin/settings.php',
        '/user/edit.php',
        '/grade/edit/',
        '/course/edit.php',
        '/my/',
        '/my/index.php'
    ]
    
    def __init__(self, base_url: str):
        """
        Initialize RBAC tester.
        
        Args:
            base_url: Base URL of the application
        """
        self.base_url = base_url.rstrip('/')
        self.client = httpx.AsyncClient(timeout=30.0, follow_redirects=False)
        self.findings = []
    
    async def test_all(self) -> Dict[str, Any]:
        """
        Run all RBAC security tests.
        
        Returns:
            Dictionary containing all test results
        """
        print("[RBAC Tester] Starting comprehensive RBAC security tests...")
        
        results = {
            'test_timestamp': datetime.utcnow().isoformat() + 'Z',
            'base_url': self.base_url,
            'tests': {}
        }
        
        # Test 1: Unauthenticated Access
        print("[RBAC Tester] Testing unauthenticated access to sensitive endpoints...")
        results['tests']['unauth_access'] = await self.test_unauthenticated_access()
        
        # Test 2: Privilege Escalation
        print("[RBAC Tester] Testing privilege escalation...")
        results['tests']['privilege_escalation'] = await self.test_privilege_escalation()
        
        # Test 3: IDOR (Insecure Direct Object References)
        print("[RBAC Tester] Testing IDOR vulnerabilities...")
        results['tests']['idor'] = await self.test_idor()
        
        # Test 4: Function-Level Access Control
        print("[RBAC Tester] Testing function-level access control...")
        results['tests']['function_access'] = await self.test_function_level_access()
        
        # Test 5: Role Enumeration
        print("[RBAC Tester] Testing role enumeration...")
        results['tests']['role_enumeration'] = await self.test_role_enumeration()
        
        # Compile findings
        results['findings'] = self.findings
        results['total_findings'] = len(self.findings)
        results['summary'] = self._generate_summary()
        
        print(f"[RBAC Tester] Complete! Found {len(self.findings)} issues")
        
        return results
    
    async def test_unauthenticated_access(self) -> Dict[str, Any]:
        """
        Test if sensitive endpoints are accessible without authentication.
        """
        result = {
            'test_name': 'Unauthenticated Access Control',
            'endpoints_tested': 0,
            'accessible_endpoints': [],
            'status': 'pass'
        }
        
        for endpoint in self.SENSITIVE_ENDPOINTS:
            result['endpoints_tested'] += 1
            
            try:
                url = f"{self.base_url}{endpoint}"
                response = await self.client.get(url)
                
                # Check if endpoint is accessible (not redirected to login)
                if response.status_code == 200:
                    # Check if it's not a login page
                    if 'login' not in response.text.lower()[:500]:
                        result['accessible_endpoints'].append({
                            'endpoint': endpoint,
                            'status_code': response.status_code
                        })
                        result['status'] = 'fail'
                        
                        self._add_finding(
                            severity='High',
                            category='Access Control',
                            description=f'Sensitive endpoint accessible without authentication',
                            evidence=f'URL: {endpoint}, Status: {response.status_code}',
                            recommendation='Implement authentication check before allowing access'
                        )
            
            except Exception as e:
                print(f"[RBAC Tester] Error testing {endpoint}: {str(e)}")
        
        return result
    
    async def test_privilege_escalation(self) -> Dict[str, Any]:
        """
        Test for vertical privilege escalation.
        
        Attempts to access higher-privilege functions with lower-privilege credentials.
        """
        result = {
            'test_name': 'Privilege Escalation',
            'status': 'pass',
            'vulnerabilities': []
        }
        
        # Test accessing admin endpoints with different methods
        admin_endpoints = [
            '/admin/index.php',
            '/admin/settings.php',
            '/admin/user.php'
        ]
        
        for endpoint in admin_endpoints:
            try:
                url = f"{self.base_url}{endpoint}"
                
                # Test with different HTTP methods
                methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']
                
                for method in methods:
                    try:
                        response = await self.client.request(method, url)
                        
                        # If we get 200 OK instead of 401/403, it might be vulnerable
                        if response.status_code == 200:
                            if 'login' not in response.text.lower()[:500]:
                                result['vulnerabilities'].append({
                                    'endpoint': endpoint,
                                    'method': method,
                                    'status_code': response.status_code
                                })
                                result['status'] = 'warning'
                    
                    except:
                        pass
            
            except Exception as e:
                print(f"[RBAC Tester] Error testing privilege escalation: {str(e)}")
        
        if result['vulnerabilities']:
            self._add_finding(
                severity='Critical',
                category='Access Control',
                description='Potential privilege escalation vulnerability detected',
                evidence=f'Found {len(result["vulnerabilities"])} accessible admin endpoints',
                recommendation='Implement proper role-based access control checks'
            )
        
        return result
    
    async def test_idor(self) -> Dict[str, Any]:
        """
        Test for Insecure Direct Object References (IDOR).
        
        Checks if user IDs can be manipulated to access other users' data.
        """
        result = {
            'test_name': 'IDOR (Insecure Direct Object References)',
            'status': 'pass',
            'potential_idor': []
        }
        
        # Test user profile access with different IDs
        user_ids = [1, 2, 3, 100, 999]
        
        for user_id in user_ids:
            try:
                url = f"{self.base_url}/user/profile.php?id={user_id}"
                response = await self.client.get(url)
                
                # If we can access user profiles without authentication
                if response.status_code == 200:
                    if 'login' not in response.text.lower()[:500]:
                        result['potential_idor'].append({
                            'url': url,
                            'user_id': user_id,
                            'accessible': True
                        })
                        result['status'] = 'fail'
            
            except Exception as e:
                pass
        
        if result['potential_idor']:
            self._add_finding(
                severity='High',
                category='Access Control',
                description='Potential IDOR vulnerability - user data accessible',
                evidence=f'Accessible user IDs: {[item["user_id"] for item in result["potential_idor"]]}',
                recommendation='Implement authorization checks to verify user owns the resource'
            )
        
        return result
    
    async def test_function_level_access_control(self) -> Dict[str, Any]:
        """
        Test for missing function-level access control.
        
        Checks if administrative functions can be accessed directly.
        """
        result = {
            'test_name': 'Function-Level Access Control',
            'status': 'pass',
            'exposed_functions': []
        }
        
        # Test common administrative functions
        admin_functions = [
            '/admin/tool/installaddon/index.php',
            '/admin/roles/assign.php',
            '/admin/user/user_bulk.php',
            '/course/delete.php',
            '/user/editadvanced.php'
        ]
        
        for function in admin_functions:
            try:
                url = f"{self.base_url}{function}"
                response = await self.client.get(url)
                
                # Check if function is accessible
                if response.status_code == 200:
                    # Check if it's not redirecting to login
                    if 'login' not in response.text.lower()[:500]:
                        result['exposed_functions'].append({
                            'function': function,
                            'status_code': response.status_code
                        })
                        result['status'] = 'fail'
            
            except Exception as e:
                pass
        
        if result['exposed_functions']:
            self._add_finding(
                severity='Critical',
                category='Access Control',
                description='Missing function-level access control',
                evidence=f'Exposed functions: {[f["function"] for f in result["exposed_functions"]]}',
                recommendation='Add authorization checks to all administrative functions'
            )
        
        return result
    
    async def test_role_enumeration(self) -> Dict[str, Any]:
        """
        Test if user roles can be enumerated.
        
        Checks for information disclosure about user roles.
        """
        result = {
            'test_name': 'Role Enumeration',
            'status': 'pass',
            'enumerable': False
        }
        
        try:
            # Try to access role management page
            url = f"{self.base_url}/admin/roles/manage.php"
            response = await self.client.get(url)
            
            if response.status_code == 200:
                # Check if role information is exposed
                role_patterns = [
                    r'role.*?admin',
                    r'role.*?teacher',
                    r'role.*?student',
                    r'capability.*?moodle'
                ]
                
                for pattern in role_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        result['enumerable'] = True
                        result['status'] = 'warning'
                        break
            
            if result['enumerable']:
                self._add_finding(
                    severity='Low',
                    category='Information Disclosure',
                    description='User roles and capabilities may be enumerable',
                    evidence='Role information accessible without authentication',
                    recommendation='Restrict access to role management pages'
                )
        
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
        tester = RBACTester("http://localhost:8998")
        results = await tester.test_all()
        
        print("\n" + "="*50)
        print("RBAC SECURITY TEST RESULTS")
        print("="*50)
        print(f"Total Findings: {results['total_findings']}")
        print(f"Summary: {results['summary']}")
        print("="*50)
        
        await tester.close()
    
    asyncio.run(test())
