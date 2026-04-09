"""
SQL Injection Detection Scanner

Detects SQL injection vulnerabilities using pattern matching and payload testing.
"""

import re
import sys
from typing import List, Dict, Any, Optional
from urllib.parse import parse_qs, urlparse
from pathlib import Path

# Add database module to path
db_path = Path(__file__).parent.parent / "database"
if str(db_path) not in sys.path:
    sys.path.insert(0, str(db_path))

from payload_repository import PayloadRepositoryManager


class SQLInjectionDetector:
    """Detect SQL injection vulnerabilities in web applications."""
    
    def __init__(self, payload_repo: Optional[PayloadRepositoryManager] = None):
        """Initialize SQL injection detector with patterns and payloads."""
        
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
                print(f"[Scanner] SQLi: Loading top payloads from repository...")
                smart_sql = self.payload_repo.get_top_payloads("SQL Injection", limit=20)
                self.smart_payloads = [p.get('payload_text', '') for p in smart_sql if p.get('payload_text')]
                print(f"[✓] Loaded {len(self.smart_payloads)} smart SQL injection payloads from repository")
            except Exception as e:
                print(f"[!] Failed to load smart payloads: {e}")
        
        # SQL error patterns that indicate potential SQL injection
        self.error_patterns = [
            # MySQL errors
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySQL Query fail.*",
            r"SQL syntax.*MariaDB",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            
            # PostgreSQL errors
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            
            # Microsoft SQL Server errors
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"(\W|\A)SQL Server.*Driver",
            r"Warning.*mssql_.*",
            r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
            r"System\.Data\.SqlClient\.",
            
            # Oracle errors
            r"Warning.*\Woci_.*",
            r"Warning.*\Wora_.*",
            r"oracle\.jdbc",
            r"Oracle error",
            r"Oracle.*Driver",
            
            # Generic SQL errors
            r"SQL syntax error",
            r"syntax error.*SQL",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
            r"SQL command not properly ended",
        ]
        
        # Compile patterns for performance
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.error_patterns]
        
        # SQL injection test payloads
        self.test_payloads = [
            # Basic SQL injection
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR 1=1--",
            "\" OR 1=1--",
            
            # Union-based
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            
            # Time-based blind
            "' AND SLEEP(5)--",
            "'; WAITFOR DELAY '0:0:5'--",
            
            # Boolean-based blind
            "' AND 1=1--",
            "' AND 1=2--",
            
            # Comment injection
            "'--",
            "\"--",
            "'#",
            "\"#",
            
            # Stacked queries
            "'; DROP TABLE users--",
            
            # Special characters
            "\\",
            "%27",
            "%22",
        ]
        
        # SQL keywords that might indicate injection
        self.sql_keywords = [
            'SELECT', 'UNION', 'INSERT', 'UPDATE', 'DELETE', 'DROP',
            'CREATE', 'ALTER', 'EXEC', 'EXECUTE', 'SCRIPT', 'JAVASCRIPT',
            'WAITFOR', 'DELAY', 'SLEEP', 'BENCHMARK'
        ]
    
    def scan(self, url: str, method: str, params: Optional[Dict[str, Any]] = None, 
             response_body: str = "", status_code: int = 200) -> List[Dict[str, Any]]:
        """
        Scan for SQL injection vulnerabilities.
        
        Args:
            url: Target URL
            method: HTTP method (GET, POST, etc.)
            params: Request parameters
            response_body: Response body content
            status_code: HTTP status code
            
        Returns:
            List of findings
        """
        findings = []
        
        # Check for SQL errors in response
        error_finding = self._check_sql_errors(response_body, url)
        if error_finding:
            findings.append(error_finding)
        
        # Check parameters for SQL injection patterns
        if params:
            param_findings = self._check_parameters(url, params)
            findings.extend(param_findings)
        
        # Check URL for SQL injection patterns
        url_finding = self._check_url_patterns(url)
        if url_finding:
            findings.append(url_finding)
        
        return findings
    
    def _check_sql_errors(self, response_body: str, url: str) -> Optional[Dict[str, Any]]:
        """
        Check response body for SQL error messages.
        
        Args:
            response_body: Response content
            url: Target URL
            
        Returns:
            Finding dictionary if SQL error detected, None otherwise
        """
        for pattern in self.compiled_patterns:
            match = pattern.search(response_body)
            if match:
                return {
                    'severity': 'High',
                    'category': 'SQL Injection',
                    'description': 'SQL error message detected in response - indicates potential SQL injection vulnerability',
                    'evidence': f'SQL error pattern found: "{match.group()}" in response from {url}',
                    'recommendation': 'Use parameterized queries or prepared statements. Validate and sanitize all user inputs.',
                    'cwe': 'CWE-89',
                    'owasp': 'A03:2021 - Injection'
                }
        return None
    
    def _check_parameters(self, url: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check request parameters for SQL injection patterns.
        
        Args:
            url: Target URL
            params: Request parameters
            
        Returns:
            List of findings
        """
        findings = []
        
        for param_name, param_value in params.items():
            if not isinstance(param_value, str):
                continue
            
            # Check for SQL keywords
            param_upper = param_value.upper()
            for keyword in self.sql_keywords:
                if keyword in param_upper:
                    findings.append({
                        'severity': 'Medium',
                        'category': 'SQL Injection',
                        'description': f'SQL keyword detected in parameter "{param_name}"',
                        'evidence': f'Parameter "{param_name}" contains SQL keyword: {keyword}. Value: {param_value[:100]}',
                        'recommendation': 'Validate input to reject SQL keywords. Use allowlists for expected values.',
                        'cwe': 'CWE-89',
                        'owasp': 'A03:2021 - Injection'
                    })
                    break
            
            # Check for SQL injection characters
            suspicious_chars = ["'", '"', '--', '#', ';', '/*', '*/']
            for char in suspicious_chars:
                if char in param_value:
                    findings.append({
                        'severity': 'Medium',
                        'category': 'SQL Injection',
                        'description': f'Suspicious SQL character detected in parameter "{param_name}"',
                        'evidence': f'Parameter "{param_name}" contains "{char}". Value: {param_value[:100]}',
                        'recommendation': 'Escape special characters. Use parameterized queries.',
                        'cwe': 'CWE-89',
                        'owasp': 'A03:2021 - Injection'
                    })
                    break
        
        return findings
    
    def _check_url_patterns(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Check URL for SQL injection patterns.
        
        Args:
            url: Target URL
            
        Returns:
            Finding dictionary if pattern detected, None otherwise
        """
        # Parse URL and query string
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        for param_name, param_values in query_params.items():
            for param_value in param_values:
                # Check for SQL keywords in URL
                param_upper = param_value.upper()
                for keyword in self.sql_keywords:
                    if keyword in param_upper:
                        return {
                            'severity': 'Medium',
                            'category': 'SQL Injection',
                            'description': f'SQL keyword detected in URL parameter "{param_name}"',
                            'evidence': f'URL parameter "{param_name}" contains SQL keyword: {keyword}. URL: {url}',
                            'recommendation': 'Validate URL parameters. Use parameterized queries.',
                            'cwe': 'CWE-89',
                            'owasp': 'A03:2021 - Injection'
                        }
        
        return None
    
    def test_payload(self, base_url: str, param_name: str, original_value: str) -> List[Dict[str, Any]]:
        """
        Test a parameter with SQL injection payloads.
        
        Args:
            base_url: Base URL
            param_name: Parameter name to test
            original_value: Original parameter value
            
        Returns:
            List of findings from payload testing
        """
        findings = []
        
        for payload in self.test_payloads:
            # This would normally make actual HTTP requests
            # For now, we'll return potential vulnerabilities
            findings.append({
                'severity': 'Info',
                'category': 'SQL Injection',
                'description': f'SQL injection payload test for parameter "{param_name}"',
                'evidence': f'Testing payload: {payload}',
                'recommendation': 'Manual verification required. Test with actual requests.',
                'cwe': 'CWE-89',
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