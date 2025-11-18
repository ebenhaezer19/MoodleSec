"""
Path Traversal Detection Scanner

Detects path traversal and directory traversal vulnerabilities.
"""

import re
from typing import List, Dict, Any, Optional
from urllib.parse import unquote, urlparse


class PathTraversalDetector:
    """Detect path traversal vulnerabilities."""
    
    def __init__(self):
        """Initialize path traversal detector with patterns."""
        
        # Path traversal patterns
        self.traversal_patterns = [
            # Basic patterns
            r'\.\.',
            r'\.\./',
            r'\.\.\%2f',
            r'\.\.\%5c',
            
            # URL encoded
            r'%2e%2e',
            r'%2e%2e%2f',
            r'%2e%2e%5c',
            
            # Double encoding
            r'%252e%252e',
            r'%252e%252e%252f',
            
            # Unicode encoding
            r'\.\.%c0%af',
            r'\.\.%c1%9c',
            
            # Absolute paths
            r'/etc/passwd',
            r'/etc/shadow',
            r'c:\\windows',
            r'c:\\boot\.ini',
            
            # Windows paths
            r'\\\\',
            r'\.\.\\',
        ]
        
        # Compile patterns
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) 
                                 for pattern in self.traversal_patterns]
        
        # Sensitive file patterns
        self.sensitive_files = [
            # Unix/Linux
            '/etc/passwd', '/etc/shadow', '/etc/hosts', '/etc/group',
            '/proc/self/environ', '/proc/version', '/proc/cmdline',
            
            # Windows
            'c:\\windows\\system32\\config\\sam',
            'c:\\windows\\system32\\config\\system',
            'c:\\boot.ini', 'c:\\windows\\win.ini',
            
            # Application files
            'web.config', '.htaccess', '.env', 'config.php',
            'database.yml', 'settings.py',
        ]
        
        # File extension patterns that might indicate file access
        self.file_extensions = [
            '.txt', '.log', '.conf', '.config', '.ini', '.xml',
            '.json', '.yml', '.yaml', '.properties', '.env'
        ]
        
        # Parameters commonly used for file operations
        self.file_parameters = [
            'file', 'filename', 'path', 'filepath', 'dir', 'directory',
            'folder', 'document', 'doc', 'page', 'template', 'include',
            'load', 'read', 'download', 'upload', 'attachment'
        ]
    
    def scan(self, url: str, method: str, params: Optional[Dict[str, Any]] = None,
             response_body: str = "", status_code: int = 200) -> List[Dict[str, Any]]:
        """
        Scan for path traversal vulnerabilities.
        
        Args:
            url: Target URL
            method: HTTP method
            params: Request parameters
            response_body: Response body content
            status_code: HTTP status code
            
        Returns:
            List of findings
        """
        findings = []
        
        # Check URL for traversal patterns
        url_findings = self._check_url_patterns(url)
        findings.extend(url_findings)
        
        # Check parameters for traversal patterns
        if params:
            param_findings = self._check_parameters(url, params)
            findings.extend(param_findings)
        
        # Check response for sensitive file content
        file_findings = self._check_sensitive_files(response_body, url)
        findings.extend(file_findings)
        
        # Check for directory listing
        listing_findings = self._check_directory_listing(response_body, url)
        findings.extend(listing_findings)
        
        return findings
    
    def _check_url_patterns(self, url: str) -> List[Dict[str, Any]]:
        """
        Check URL for path traversal patterns.
        
        Args:
            url: Target URL
            
        Returns:
            List of findings
        """
        findings = []
        
        # Decode URL
        decoded_url = unquote(url)
        
        # Check for traversal patterns
        for pattern in self.compiled_patterns:
            if pattern.search(decoded_url):
                findings.append({
                    'severity': 'High',
                    'category': 'Path Traversal',
                    'description': 'Path traversal pattern detected in URL',
                    'evidence': f'URL contains path traversal pattern: {url}',
                    'recommendation': 'Validate and sanitize file paths. Use allowlist of permitted files.',
                    'cwe': 'CWE-22',
                    'owasp': 'A01:2021 - Broken Access Control'
                })
                break
        
        # Check for sensitive files in URL
        for sensitive_file in self.sensitive_files:
            if sensitive_file.lower() in decoded_url.lower():
                findings.append({
                    'severity': 'Critical',
                    'category': 'Path Traversal',
                    'description': f'Attempt to access sensitive file: {sensitive_file}',
                    'evidence': f'URL attempts to access: {sensitive_file}',
                    'recommendation': 'Block access to sensitive system files. Implement proper access controls.',
                    'cwe': 'CWE-22',
                    'owasp': 'A01:2021 - Broken Access Control'
                })
                break
        
        return findings
    
    def _check_parameters(self, url: str, params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Check parameters for path traversal patterns.
        
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
            
            # Check if parameter name suggests file operation
            is_file_param = any(fp in param_name.lower() for fp in self.file_parameters)
            
            # Decode parameter value
            decoded_value = unquote(str(param_value))
            
            # Check for traversal patterns
            for pattern in self.compiled_patterns:
                if pattern.search(decoded_value):
                    severity = 'High' if is_file_param else 'Medium'
                    findings.append({
                        'severity': severity,
                        'category': 'Path Traversal',
                        'description': f'Path traversal pattern in parameter "{param_name}"',
                        'evidence': f'Parameter "{param_name}" contains traversal pattern. Value: {param_value[:100]}',
                        'recommendation': 'Validate file paths. Use basename() to prevent directory traversal.',
                        'cwe': 'CWE-22',
                        'owasp': 'A01:2021 - Broken Access Control'
                    })
                    break
            
            # Check for sensitive files
            for sensitive_file in self.sensitive_files:
                if sensitive_file.lower() in decoded_value.lower():
                    findings.append({
                        'severity': 'Critical',
                        'category': 'Path Traversal',
                        'description': f'Attempt to access sensitive file via parameter "{param_name}"',
                        'evidence': f'Parameter "{param_name}" references: {sensitive_file}',
                        'recommendation': 'Block access to sensitive files. Implement file access controls.',
                        'cwe': 'CWE-22',
                        'owasp': 'A01:2021 - Broken Access Control'
                    })
                    break
            
            # Check for absolute paths
            if decoded_value.startswith('/') or re.match(r'[a-zA-Z]:\\', decoded_value):
                if is_file_param:
                    findings.append({
                        'severity': 'Medium',
                        'category': 'Path Traversal',
                        'description': f'Absolute path in parameter "{param_name}"',
                        'evidence': f'Parameter "{param_name}" contains absolute path: {param_value[:100]}',
                        'recommendation': 'Reject absolute paths. Only accept relative paths within allowed directory.',
                        'cwe': 'CWE-22',
                        'owasp': 'A01:2021 - Broken Access Control'
                    })
        
        return findings
    
    def _check_sensitive_files(self, response_body: str, url: str) -> List[Dict[str, Any]]:
        """
        Check if response contains sensitive file content.
        
        Args:
            response_body: Response content
            url: Target URL
            
        Returns:
            List of findings
        """
        findings = []
        
        # Patterns indicating sensitive file content
        sensitive_patterns = {
            '/etc/passwd': r'root:.*:0:0:',
            '/etc/shadow': r'root:\$[0-9]\$',
            'database config': r'(password|passwd|pwd)\s*[:=]\s*["\']?[\w@#$%^&*]+',
            'private key': r'-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----',
            'AWS credentials': r'AKIA[0-9A-Z]{16}',
        }
        
        for file_type, pattern in sensitive_patterns.items():
            if re.search(pattern, response_body, re.IGNORECASE):
                findings.append({
                    'severity': 'Critical',
                    'category': 'Path Traversal',
                    'description': f'Sensitive file content exposed: {file_type}',
                    'evidence': f'Response from {url} contains {file_type} content',
                    'recommendation': 'Immediately block access. Review file access controls. Change exposed credentials.',
                    'cwe': 'CWE-22',
                    'owasp': 'A01:2021 - Broken Access Control'
                })
        
        return findings
    
    def _check_directory_listing(self, response_body: str, url: str) -> List[Dict[str, Any]]:
        """
        Check if response shows directory listing.
        
        Args:
            response_body: Response content
            url: Target URL
            
        Returns:
            List of findings
        """
        findings = []
        
        # Patterns indicating directory listing
        listing_patterns = [
            r'Index of /',
            r'Directory listing for',
            r'<title>Index of',
            r'Parent Directory',
            r'\[To Parent Directory\]',
        ]
        
        for pattern in listing_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                findings.append({
                    'severity': 'Medium',
                    'category': 'Path Traversal',
                    'description': 'Directory listing enabled',
                    'evidence': f'Directory listing detected at {url}',
                    'recommendation': 'Disable directory listing. Configure web server to deny directory browsing.',
                    'cwe': 'CWE-548',
                    'owasp': 'A05:2021 - Security Misconfiguration'
                })
                break
        
        return findings
