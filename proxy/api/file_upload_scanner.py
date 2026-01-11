"""
File Upload Scanner for Moodle

Tests for file upload vulnerabilities - 10-15% of Moodle CVEs
- Unrestricted file upload (PHP shell, web shell)
- Zip slip / Path traversal in archive extraction
- File type bypass (double extension, MIME type)
- Arbitrary file overwrite

Based on real Moodle CVEs:
- CVE-2024-43433 - Unrestricted file upload
- CVE-2023-4733 - Path traversal in backup restore  
- CVE-2022-35654 - Zip slip vulnerability
- CVE-2021-36393 - File upload bypass
"""

import httpx
import asyncio
import os
import io
import zipfile
from typing import Dict, List, Any
from datetime import datetime


class FileUploadScanner:
    """File upload vulnerability scanner for Moodle."""
    
    # Moodle file upload endpoints
    UPLOAD_ENDPOINTS = [
        '/repository/repository_ajax.php',
        '/lib/ajax/service.php',
        '/files/index.php',
        '/mod/assign/view.php',
        '/mod/workshop/submission.php',
        '/user/edit.php',
        '/user/profile.php',
        '/course/edit.php',
        '/backup/restorefile.php',
    ]
    
    # Dangerous file extensions
    DANGEROUS_EXTENSIONS = [
        'php', 'php3', 'php4', 'php5', 'phtml', 'phar',
        'jsp', 'asp', 'aspx', 'cgi', 'pl',
        'exe', 'bat', 'sh', 'cmd',
        'htaccess', 'config'
    ]
    
    # PHP web shell payloads (harmless test versions)
    WEB_SHELL_TESTS = {
        'simple_php': b'<?php echo "MOODLESEC_UPLOAD_TEST"; ?>',
        'double_ext': b'<?php /* test */ ?>',
        'null_byte': b'<?php phpinfo(); ?>',
    }
    
    def __init__(self, base_url: str):
        """
        Initialize file upload scanner.
        
        Args:
            base_url: Base URL of Moodle installation
        """
        self.base_url = base_url.rstrip('/')
        self.client = httpx.AsyncClient(timeout=30.0, follow_redirects=True, verify=False)
        self.findings = []
        self.tested_endpoints = set()
    
    async def scan_all(self) -> Dict[str, Any]:
        """
        Run comprehensive file upload security scan.
        
        Returns:
            Complete scan results
        """
        print("[File Upload Scanner] Starting file upload vulnerability scan...")
        
        results = {
            'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
            'base_url': self.base_url,
            'tests': {}
        }
        
        # Test 1: Unrestricted file upload
        print("[File Upload Scanner] Testing unrestricted file upload...")
        results['tests']['unrestricted_upload'] = await self.test_unrestricted_upload()
        
        # Test 2: Zip slip vulnerability
        print("[File Upload Scanner] Testing zip slip vulnerability...")
        results['tests']['zip_slip'] = await self.test_zip_slip()
        
        # Test 3: File type bypass
        print("[File Upload Scanner] Testing file type bypass...")
        results['tests']['type_bypass'] = await self.test_file_type_bypass()
        
        # Test 4: Path traversal in uploads
        print("[File Upload Scanner] Testing path traversal...")
        results['tests']['path_traversal'] = await self.test_path_traversal()
        
        # Compile results
        results['findings'] = self.findings
        results['total_findings'] = len(self.findings)
        results['tested_endpoints'] = list(self.tested_endpoints)
        results['summary'] = self._generate_summary()
        
        print(f"[File Upload Scanner] Complete! Found {len(self.findings)} vulnerabilities")
        if self.findings:
            summary = results['summary']
            print(f"[File Upload Scanner] Summary: Critical={summary.get('critical', 0)}, High={summary.get('high', 0)}, Medium={summary.get('medium', 0)}")
        
        return results
    
    async def test_unrestricted_upload(self) -> Dict[str, Any]:
        """
        Test for unrestricted file upload vulnerabilities.
        
        Attempts to upload PHP files and web shells.
        """
        result = {
            'test_name': 'Unrestricted File Upload',
            'status': 'pass',
            'vulnerabilities': []
        }
        
        for endpoint in self.UPLOAD_ENDPOINTS[:5]:  # Test first 5 endpoints
            self.tested_endpoints.add(endpoint)
            
            for ext in ['php', 'phtml', 'php5']:
                try:
                    url = f"{self.base_url}{endpoint}"
                    
                    # Create test file
                    filename = f"test_upload.{ext}"
                    files = {
                        'file': (filename, self.WEB_SHELL_TESTS['simple_php'], 'application/x-php')
                    }
                    
                    response = await self.client.post(url, files=files)
                    
                    # Check if upload was accepted (200 status, no error message)
                    if response.status_code == 200:
                        response_lower = response.text.lower()
                        
                        # Check for success indicators
                        success_indicators = ['upload', 'success', 'file saved', 'completed']
                        error_indicators = ['error', 'invalid', 'not allowed', 'forbidden', 'denied', 'extension']
                        
                        has_success = any(ind in response_lower for ind in success_indicators)
                        has_error = any(ind in response_lower for ind in error_indicators)
                        
                        if has_success and not has_error:
                            result['vulnerabilities'].append({
                                'endpoint': endpoint,
                                'file_extension': ext,
                                'status': 'potentially vulnerable'
                            })
                            result['status'] = 'fail'
                            
                            self._add_finding(
                                severity='Critical',
                                category='File Upload',
                                description=f'Potentially unrestricted file upload - {ext} file accepted',
                                evidence=f'Endpoint: {endpoint}, Extension: {ext}, Status: {response.status_code}',
                                recommendation='Implement whitelist-based file extension validation and file type verification'
                            )
                
                except Exception:
                    pass
        
        return result
    
    async def test_zip_slip(self) -> Dict[str, Any]:
        """
        Test for Zip Slip vulnerability in archive extraction.
        
        CVE-2023-4733, CVE-2022-35654
        """
        result = {
            'test_name': 'Zip Slip Vulnerability',
            'status': 'pass',
            'note': 'Tests path traversal in zip extraction'
        }
        
        # Create malicious zip with path traversal
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            # Add file with path traversal
            zip_file.writestr('../../../test_zipslip.txt', 'MOODLESEC_ZIPSLIP_TEST')
            zip_file.writestr('../../../../../../tmp/test_zipslip.txt', 'TEST')
        
        zip_buffer.seek(0)
        
        # Test backup/restore endpoints (common zip slip targets)
        test_endpoints = [
            '/backup/restorefile.php',
            '/backup/restore.php',
            '/files/index.php',
        ]
        
        for endpoint in test_endpoints:
            self.tested_endpoints.add(endpoint)
            
            try:
                url = f"{self.base_url}{endpoint}"
                files = {
                    'file': ('malicious.zip', zip_buffer.getvalue(), 'application/zip')
                }
                
                response = await self.client.post(url, files=files)
                
                # Check if server processed zip without error
                if response.status_code == 200:
                    response_lower = response.text.lower()
                    
                    # If no error about path traversal, might be vulnerable
                    if 'path traversal' not in response_lower and 'invalid path' not in response_lower:
                        self._add_finding(
                            severity='High',
                            category='File Upload',
                            description=f'Potential Zip Slip vulnerability in archive extraction',
                            evidence=f'Endpoint: {endpoint}, Zip with path traversal accepted',
                            recommendation='Validate extracted file paths and prevent directory traversal'
                        )
                        result['status'] = 'warning'
            
            except Exception:
                pass
        
        return result
    
    async def test_file_type_bypass(self) -> Dict[str, Any]:
        """
        Test for file type validation bypass techniques.
        
        - Double extension (file.php.jpg)
        - Null byte injection (file.php%00.jpg)
        - MIME type spoofing
        """
        result = {
            'test_name': 'File Type Bypass',
            'status': 'pass',
            'bypass_attempts': []
        }
        
        bypass_techniques = [
            ('double_ext', 'test.php.jpg', 'image/jpeg'),
            ('null_byte', 'test.php\x00.jpg', 'image/jpeg'),
            ('mime_spoof', 'test.php', 'image/jpeg'),
            ('case_bypass', 'test.PhP', 'application/x-php'),
        ]
        
        for endpoint in self.UPLOAD_ENDPOINTS[:3]:
            for technique, filename, mime_type in bypass_techniques:
                try:
                    url = f"{self.base_url}{endpoint}"
                    files = {
                        'file': (filename, self.WEB_SHELL_TESTS['simple_php'], mime_type)
                    }
                    
                    response = await self.client.post(url, files=files)
                    
                    if response.status_code == 200:
                        response_lower = response.text.lower()
                        
                        if 'success' in response_lower and 'error' not in response_lower:
                            result['bypass_attempts'].append({
                                'endpoint': endpoint,
                                'technique': technique,
                                'filename': filename
                            })
                            
                            self._add_finding(
                                severity='High',
                                category='File Upload',
                                description=f'File type validation bypass using {technique}',
                                evidence=f'Endpoint: {endpoint}, Technique: {technique}, Filename: {filename}',
                                recommendation='Implement robust file type validation (magic numbers, not just extension/MIME)'
                            )
                            result['status'] = 'fail'
                
                except Exception:
                    pass
        
        return result
    
    async def test_path_traversal(self) -> Dict[str, Any]:
        """
        Test for path traversal in file upload paths.
        
        Attempts to upload files to arbitrary locations.
        """
        result = {
            'test_name': 'Path Traversal in Upload',
            'status': 'pass'
        }
        
        traversal_paths = [
            '../../../evil.txt',
            '..\\..\\..\\evil.txt',
            '/etc/passwd',
            'C:\\windows\\system32\\evil.txt',
        ]
        
        for endpoint in self.UPLOAD_ENDPOINTS[:3]:
            for path in traversal_paths:
                try:
                    url = f"{self.base_url}{endpoint}"
                    files = {
                        'file': (path, b'TEST', 'text/plain')
                    }
                    data = {
                        'filepath': path,
                        'destination': path,
                        'path': path,
                    }
                    
                    response = await self.client.post(url, files=files, data=data)
                    
                    if response.status_code == 200:
                        response_lower = response.text.lower()
                        
                        # Check if path traversal was blocked
                        if 'path traversal' not in response_lower and 'invalid path' not in response_lower:
                            self._add_finding(
                                severity='High',
                                category='File Upload',
                                description=f'Potential path traversal in file upload',
                                evidence=f'Endpoint: {endpoint}, Path: {path[:50]}',
                                recommendation='Validate and sanitize file paths, use whitelist-based path validation'
                            )
                            result['status'] = 'warning'
                            break
                
                except Exception:
                    pass
        
        return result
    
    def _add_finding(self, severity: str, category: str, description: str,
                    evidence: str, recommendation: str):
        """Add file upload finding."""
        print(f"[File Upload Scanner] 🔍 {severity}: {description}")
        print(f"[File Upload Scanner]    📍 {evidence}")
        
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
