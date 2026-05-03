"""
Payload Injector - Handles payload injection and reuse across all scanners

Responsible for:
- Loading payloads from repository for each category
- Injecting payloads into request parameters, headers, body
- Tracking injection attempts with debug logger
- Testing for vulnerabilities based on payload responses
"""

import asyncio
import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlencode, urlparse, parse_qs, quote
import logging

logger = logging.getLogger(__name__)

TRUSTED_SCANNER_HEADER_NAME = "X-MoodleSec-Scanner"
TRUSTED_SCANNER_HEADER_VALUE = "internal"


class PayloadInjector:
    """Handles payload injection and vulnerability detection through payload responses."""
    
    def __init__(self, payload_repo=None, debug_logger=None):
        """
        Initialize payload injector.
        
        Args:
            payload_repo: PayloadRepositoryManager instance
            debug_logger: PayloadDebugLogger instance for tracking injections
        """
        self.payload_repo = payload_repo
        self.debug_logger = debug_logger
        
        # Indicators for successful injection/vulnerability
        # Covers: MySQL, PostgreSQL, Oracle, MSSQL, SQLite, and Moodle DML errors
        self.sql_error_indicators = [
            r"sql syntax error",
            r"you have an error in your sql",
            r"warning.*mysql",
            r"postgresql.*error",
            r"oracle.*error",
            r"unclosed quotation mark",
            r"sqlexception",
            r"syntax error in sql",
            # Moodle-specific DML / mysqli error patterns
            r"error writing to database",
            r"error reading from database",
            r"data too long for column",
            r"INSERT INTO\s+\w+",
            r"SELECT .+FROM\s+\w+",
            r"UPDATE\s+\w+\s+SET",
            r"DELETE FROM\s+\w+",
            r"mysqli_native_moodle_database",
            r"moodle_database",
            r"dml_write_exception",
            r"dml_read_exception",
            r"/lib/dml/",
            # Generic DB error patterns
            r"SQLSTATE\[",
            r"ORA-\d{5}",
            r"PG::Error",
            r"sqlite3?\.OperationalError",
            r"database error",
            r"query_end\(\)",
            r"insert_record",
        ]
        
        self.xss_indicators = [
            r"<script.*?>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
        ]
        
        self.compiled_sql_patterns = [re.compile(p, re.IGNORECASE) for p in self.sql_error_indicators]
        self.compiled_xss_patterns = [re.compile(p, re.IGNORECASE) for p in self.xss_indicators]
        
        # Invalid characters for HTTP headers (RFC 7230)
        self.header_invalid_chars = ['\n', '\r', '\x00', '\t', '&']  # & causes httpx parsing issues
        
        print("[PayloadInjector] Initialized")
    
    def _is_header_safe_payload(self, payload_text: str) -> bool:
        """
        Check if a payload is safe to inject into HTTP headers.
        HTTP headers must comply with RFC 7230 (no control characters).
        
        Args:
            payload_text: Payload string to validate
            
        Returns:
            True if payload is header-safe, False otherwise
        """
        if not payload_text:
            return True
        
        # Check for invalid characters
        for invalid_char in self.header_invalid_chars:
            if invalid_char in payload_text:
                return False
        
        # Check for control characters (0x00-0x1F except tab/CRLF handled above)
        for char in payload_text:
            if ord(char) < 0x20 and char not in ['\t']:
                return False
            if ord(char) == 0x7F:  # DEL character
                return False
        
        return True
    
    def _sanitize_for_headers(self, payload_text: str) -> str:
        """
        Sanitize payload for HTTP header injection.
        Removes/replaces problematic characters while preserving payload intent.
        
        Args:
            payload_text: Original payload text
            
        Returns:
            Sanitized payload safe for headers
        """
        if not payload_text:
            return payload_text
        
        sanitized = payload_text
        
        # Replace newlines/carriage returns with spaces
        sanitized = sanitized.replace('\r', ' ').replace('\n', ' ')
        
        # Remove null bytes
        sanitized = sanitized.replace('\x00', '')
        
        # Remove ampersand which causes httpx header parsing issues
        sanitized = sanitized.replace('&', '%26')
        
        # Remove other control characters
        sanitized = ''.join(
            char if ord(char) >= 0x20 or char == '\t' else ' '
            for char in sanitized
        )
        
        return sanitized.strip()
    
    async def inject_payloads_to_parameters(
        self, 
        url: str,
        params: Dict[str, Any],
        client: Any,
        category: str,
        scan_id: str = "",
        max_payloads: int = 50,
        method: str = "GET"
    ) -> List[Dict[str, Any]]:
        """
        Inject payloads from repository to each parameter with proper URL encoding.
        
        For GET endpoints: payloads are injected as URL query parameters.
        For POST endpoints: payloads are injected as form-encoded body data
        (Content-Type: application/x-www-form-urlencoded), matching how real
        forms submit data (same as curl --data-urlencode).
        
        Args:
            url: Target URL
            params: Request parameters
            client: HTTP client (httpx.AsyncClient)
            category: Payload category (XSS, SQL Injection, etc.)
            scan_id: ID of current scan for tracking
            max_payloads: Max payloads to test per parameter (default 50 for comprehensive testing)
            method: HTTP method (GET or POST) - determines how params are sent
            
        Returns:
            List of findings from payload injection
        """
        findings = []
        
        if not self.payload_repo or not params:
            return findings
        
        # Get payloads for this category - use all available (up to max_payloads)
        available_payloads = self.payload_repo.get_top_payloads(category, limit=max_payloads)
        if not available_payloads:
            print(f"[PayloadInjector] No payloads found for category: {category}")
            return findings
        
        use_method = method.upper()
        print(f"[PayloadInjector] Testing {len(params)} parameters with {len(available_payloads)} {category} payloads (method={use_method})")
        
        # Detect time-based SQLi keywords in payloads
        _TIME_BASED_KEYWORDS = ['sleep', 'waitfor', 'delay', 'pg_sleep', 'benchmark']
        
        def _is_time_based_payload(payload: str) -> bool:
            pl = payload.lower()
            return any(kw in pl for kw in _TIME_BASED_KEYWORDS)
        
        # Test each parameter with each payload
        for param_name, param_value in params.items():
            print(f"[PayloadInjector] Injecting payloads to parameter: {param_name}")
            
            for payload_obj in available_payloads:
                payload_text = payload_obj.get('payload_text', '')
                payload_id = payload_obj.get('id', 'unknown')
                
                if not payload_text:
                    continue
                
                try:
                    # Create test request with injected payload
                    test_params = params.copy()
                    test_params[param_name] = payload_text
                    
                    # Log the payload being tested with URL-encoded preview
                    encoded_preview = quote(payload_text, safe='')
                    print(f"[PayloadInjector] Payload ID {payload_id} -> {param_name}={encoded_preview[:80]}{'...' if len(encoded_preview) > 80 else ''}")
                    
                    # Make request with injected payload
                    # POST: send as form data (Content-Type: application/x-www-form-urlencoded)
                    # GET:  send as URL query parameters
                    import time as _time
                    t0 = _time.monotonic()
                    if use_method == 'POST':
                        response = await self._make_request(
                            url, params=None, client=client,
                            method='POST', data=test_params
                        )
                    else:
                        response = await self._make_request(
                            url, params=test_params, client=client,
                            method='GET'
                        )
                    elapsed_ms = (_time.monotonic() - t0) * 1000
                    
                    # --- TIME-BASED BLIND SQLi DETECTION ---
                    # If the payload contains sleep/waitfor AND the request timed out
                    # or took abnormally long, that IS evidence of SQL injection.
                    if response is None and _is_time_based_payload(payload_text):
                        finding = {
                            'severity': 'Critical',
                            'category': 'SQL Injection',
                            'type': 'Time-Based Blind SQL Injection',
                            'description': f'Time-based blind SQL Injection detected in parameter "{param_name}"',
                            'evidence': f'Payload with sleep/delay caused request timeout ({elapsed_ms:.0f}ms). '
                                        f'Server executed the injected SQL sleep command.',
                            'payload': payload_text[:200],
                            'payload_id': payload_id,
                            'injection_point': 'parameter',
                            'target': url,
                            'cwe': 'CWE-89',
                            'owasp': 'A03:2021 - Injection'
                        }
                        findings.append(finding)
                        print(f"[PayloadInjector] ✓ CRITICAL: Time-based blind SQLi detected! "
                              f"Timeout on sleep payload in param '{param_name}'")
                        
                        if self.payload_repo and payload_id != "unknown":
                            self.payload_repo.update_payload_stats(
                                payload_id=int(payload_id) if isinstance(payload_id, (str, int)) else 0,
                                success=True,
                                severity='Critical'
                            )
                        continue
                    
                    if self.debug_logger:
                        self.debug_logger.log_injection_attempt(
                            scan_id=scan_id,
                            target_url=url,
                            category=category,
                            payload_text=payload_text,
                            injection_point=f"parameter:{param_name}",
                            status="success" if response else "failed",
                            response_code=response.status_code if response else None
                        )
                    
                    # Check if payload was reflected or caused error
                    if response:
                        finding = self._check_injection_result(
                            response=response,
                            payload_text=payload_text,
                            param_name=param_name,
                            url=url,
                            category=category,
                            payload_id=payload_id,
                            elapsed_ms=elapsed_ms
                        )
                        if finding:
                            findings.append(finding)
                            print(f"[PayloadInjector] ✓ Found vulnerability: {finding['description']}")
                            
                            # Update payload stats with successful injection
                            if self.payload_repo and payload_id != "unknown":
                                severity = finding.get('severity', 'High')
                                self.payload_repo.update_payload_stats(
                                    payload_id=int(payload_id) if isinstance(payload_id, (str, int)) else 0,
                                    success=True,
                                    severity=severity
                                )
                
                except Exception as e:
                    logger.error(f"Error injecting payload to {param_name}: {e}")
                    if self.debug_logger:
                        self.debug_logger.log_injection_attempt(
                            scan_id=scan_id,
                            target_url=url,
                            category=category,
                            payload_text=payload_text,
                            injection_point=f"parameter:{param_name}",
                            status="error",
                            error=str(e)
                        )
        
        return findings
    
    async def inject_payloads_to_headers(
        self,
        url: str,
        headers: Dict[str, str],
        client: Any,
        category: str,
        scan_id: str = "",
        max_payloads: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Inject payloads into request headers with RFC 7230 compliance.
        
        Args:
            url: Target URL
            headers: Request headers
            client: HTTP client
            category: Payload category
            scan_id: Scan ID for tracking
            max_payloads: Max payloads to test
            
        Returns:
            List of findings
        """
        findings = []
        
        if not self.payload_repo or not headers:
            return findings
        
        # Get payloads
        available_payloads = self.payload_repo.get_top_payloads(category, limit=max_payloads)
        if not available_payloads:
            return findings
        
        # Headers to test (security-related ones)
        test_headers = [
            'User-Agent',
            'Referer',
            'X-Forwarded-For',
            'X-Original-URL',
            'X-Rewrite-URL',
        ]
        
        # Sanitize ALL payloads for header injection (don't skip, sanitize instead)
        sanitized_payloads = []
        skipped_payloads = 0
        
        for payload_obj in available_payloads:
            payload_text = payload_obj.get('payload_text', '')
            if not payload_text:
                continue
            
            # Sanitize the payload for header use
            sanitized_text = self._sanitize_for_headers(payload_text)
            
            # Only skip if sanitization results in empty string
            if not sanitized_text or sanitized_text.isspace():
                skipped_payloads += 1
                continue
            
            # Create new payload object with sanitized text
            sanitized_obj = payload_obj.copy()
            sanitized_obj['original_payload_text'] = payload_text  # Keep original for logging
            sanitized_obj['payload_text'] = sanitized_text
            sanitized_payloads.append(sanitized_obj)
        
        if not sanitized_payloads:
            print(f"[PayloadInjector] No payloads available for {category} (all sanitization resulted in empty)")
            return findings
        
        if skipped_payloads > 0:
            print(f"[PayloadInjector] Sanitized {len(sanitized_payloads)} payloads for header injection ({skipped_payloads} became empty)")
        else:
            print(f"[PayloadInjector] Testing {len(test_headers)} headers with {len(sanitized_payloads)} sanitized payloads")
        
        for header_name in test_headers:
            for payload_obj in sanitized_payloads:
                payload_text = payload_obj.get('payload_text', '')
                original_payload = payload_obj.get('original_payload_text', payload_text)
                payload_id = payload_obj.get('id', 'unknown')
                
                if not payload_text:
                    continue
                
                # Sanitize payload for headers
                sanitized_payload = self._sanitize_for_headers(payload_text)
                
                if not sanitized_payload:
                    print(f"[PayloadInjector] Payload {payload_id} sanitized to empty, skipping")
                    continue
                
                try:
                    test_headers_dict = headers.copy()
                    test_headers_dict[header_name] = sanitized_payload
                    
                    response = await self._make_request(url, {}, client, headers=test_headers_dict)
                    
                    if self.debug_logger:
                        self.debug_logger.log_injection_attempt(
                            scan_id=scan_id,
                            target_url=url,
                            category=category,
                            payload_text=sanitized_payload,
                            injection_point=f"header:{header_name}",
                            status="success" if response else "failed",
                            response_code=response.status_code if response else None
                        )
                    
                    if response:
                        finding = self._check_injection_result(
                            response=response,
                            payload_text=sanitized_payload,
                            param_name=header_name,
                            url=url,
                            category=category,
                            payload_id=payload_id,
                            injection_point="header"
                        )
                        if finding:
                            findings.append(finding)
                            
                            # Update payload stats with successful injection
                            if self.payload_repo and payload_id != "unknown":
                                severity = finding.get('severity', 'High')
                                self.payload_repo.update_payload_stats(
                                    payload_id=int(payload_id) if isinstance(payload_id, (str, int)) else 0,
                                    success=True,
                                    severity=severity
                                )
                
                except Exception as e:
                    logger.error(f"Error injecting payload to header {header_name}: {e}")
                    if self.debug_logger:
                        self.debug_logger.log_injection_attempt(
                            scan_id=scan_id,
                            target_url=url,
                            category=category,
                            payload_text=sanitized_payload,
                            injection_point=f"header:{header_name}",
                            status="error",
                            error=str(e)
                        )
        
        return findings
    
    async def inject_payloads_to_body(
        self,
        url: str,
        body_content: str,
        client: Any,
        category: str,
        scan_id: str = "",
        max_payloads: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Inject payloads into request body.
        
        Args:
            url: Target URL
            body_content: Request body
            client: HTTP client
            category: Payload category
            scan_id: Scan ID
            max_payloads: Max payloads
            
        Returns:
            List of findings
        """
        findings = []
        
        if not self.payload_repo or not body_content:
            return findings
        
        available_payloads = self.payload_repo.get_top_payloads(category, limit=max_payloads)
        if not available_payloads:
            return findings
        
        print(f"[PayloadInjector] Testing request body with {len(available_payloads)} payloads")
        
        for payload_obj in available_payloads:
            payload_text = payload_obj.get('payload_text', '')
            payload_id = payload_obj.get('id', 'unknown')
            
            if not payload_text:
                continue
            
            try:
                # Replace first identifiable field with payload
                test_body = body_content.replace(
                    body_content.split('=')[0].split('&')[0],
                    payload_text,
                    1
                )
                
                response = await self._make_request(
                    url, 
                    {}, 
                    client, 
                    data=test_body,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                )
                
                if self.debug_logger:
                    self.debug_logger.log_injection_attempt(
                        scan_id=scan_id,
                        target_url=url,
                        category=category,
                        payload_text=payload_text,
                        injection_point="body",
                        status="success" if response else "failed",
                        response_code=response.status_code if response else None
                    )
                
                if response:
                    finding = self._check_injection_result(
                        response=response,
                        payload_text=payload_text,
                        param_name="body",
                        url=url,
                        category=category,
                        payload_id=payload_id,
                        injection_point="body"
                    )
                    if finding:
                        findings.append(finding)
                        
                        # Update payload stats with successful injection
                        if self.payload_repo and payload_id != "unknown":
                            severity = finding.get('severity', 'High')
                            self.payload_repo.update_payload_stats(
                                payload_id=int(payload_id) if isinstance(payload_id, (str, int)) else 0,
                                success=True,
                                severity=severity
                            )
            
            except Exception as e:
                logger.error(f"Error injecting payload to body: {e}")
                if self.debug_logger:
                    self.debug_logger.log_injection_attempt(
                        scan_id=scan_id,
                        target_url=url,
                        category=category,
                        payload_text=payload_text,
                        injection_point="body",
                        status="error",
                        error=str(e)
                    )
        
        return findings
    
    def _check_injection_result(
        self,
        response: Any,
        payload_text: str,
        param_name: str,
        url: str,
        category: str,
        payload_id: str = "unknown",
        injection_point: str = "parameter",
        elapsed_ms: float = 0
    ) -> Optional[Dict[str, Any]]:
        """
        Check if payload injection resulted in vulnerability.
        
        Detection methods:
        - SQL Injection: error patterns, HTTP 500, time-based (slow response)
        - XSS: payload reflection in response
        - CSRF: form accepted without valid token
        
        Args:
            response: Response from injected request
            payload_text: Payload that was injected
            param_name: Parameter/header name
            url: Target URL
            category: Payload category
            payload_id: ID of payload
            injection_point: Where payload was injected
            elapsed_ms: Response time in milliseconds
            
        Returns:
            Finding dict if vulnerability detected, None otherwise
        """
        response_text = response.text if hasattr(response, 'text') else str(response)
        status_code = response.status_code if hasattr(response, 'status_code') else 200
        
        # ======== SQL INJECTION DETECTION ========
        if category == "SQL Injection" or "sql" in category.lower():
            
            # Method 1: Error-based SQLi (SQL error messages in response)
            for pattern in self.compiled_sql_patterns:
                if pattern.search(response_text):
                    return {
                        'severity': 'Critical',
                        'category': 'SQL Injection',
                        'type': 'Error-Based SQL Injection',
                        'description': f'SQL Injection detected in {injection_point} "{param_name}" (error-based)',
                        'evidence': f'SQL error pattern detected after injecting payload',
                        'payload': payload_text[:200],
                        'payload_id': payload_id,
                        'injection_point': injection_point,
                        'target': url,
                        'cwe': 'CWE-89',
                        'owasp': 'A03:2021 - Injection'
                    }
            
            # Method 2: HTTP 500 error (server crashed processing SQL)
            if status_code >= 500:
                return {
                    'severity': 'High',
                    'category': 'SQL Injection',
                    'type': 'Error-Based SQL Injection (HTTP 500)',
                    'description': f'Potential SQL Injection in {injection_point} "{param_name}" - server error {status_code}',
                    'evidence': f'HTTP {status_code} returned after injecting SQL payload. '
                                f'Server may have failed processing the injected SQL.',
                    'payload': payload_text[:200],
                    'payload_id': payload_id,
                    'injection_point': injection_point,
                    'target': url,
                    'cwe': 'CWE-89',
                    'owasp': 'A03:2021 - Injection'
                }
            
            # Method 3: Time-based blind SQLi (abnormally slow response)
            _time_keywords = ['sleep', 'waitfor', 'delay', 'pg_sleep', 'benchmark']
            is_time_payload = any(kw in payload_text.lower() for kw in _time_keywords)
            if is_time_payload and elapsed_ms > 5000:
                return {
                    'severity': 'Critical',
                    'category': 'SQL Injection',
                    'type': 'Time-Based Blind SQL Injection',
                    'description': f'Time-based blind SQL Injection in {injection_point} "{param_name}"',
                    'evidence': f'Payload with sleep/delay caused {elapsed_ms:.0f}ms response time '
                                f'(normal < 2000ms). Server executed the injected SQL.',
                    'payload': payload_text[:200],
                    'payload_id': payload_id,
                    'injection_point': injection_point,
                    'target': url,
                    'cwe': 'CWE-89',
                    'owasp': 'A03:2021 - Injection'
                }
        
        # ======== XSS DETECTION ========
        if category == "XSS" or "xss" in category.lower():
            # Check if payload is reflected in response
            if payload_text in response_text:
                for pattern in self.compiled_xss_patterns:
                    if pattern.search(response_text):
                        return {
                            'severity': 'High',
                            'category': 'Cross-Site Scripting (XSS)',
                            'type': 'Reflected XSS via Payload',
                            'description': f'XSS detected in {injection_point} "{param_name}"',
                            'evidence': f'JavaScript code reflected in response: {payload_text[:100]}',
                            'payload': payload_text[:200],
                            'payload_id': payload_id,
                            'injection_point': injection_point,
                            'target': url,
                            'cwe': 'CWE-79',
                            'owasp': 'A03:2021 - Injection'
                        }
        
        # ======== CSRF DETECTION ========
        if category == "CSRF" or "csrf" in category.lower():
            # If the form accepted the request without a valid CSRF token
            # (status 200 when it should have been 403), that's a vulnerability.
            # Look for indicators that the action was processed successfully:
            # - HTTP 200 with no error message about sesskey/token
            # - Form submission was accepted (redirect to success page)
            response_lower = response_text.lower()
            
            # Check if the token payload was "missing_csrf_token" or empty
            is_csrf_test_payload = ('missing' in payload_text.lower() or 
                                   'csrf' in payload_text.lower() or
                                   payload_text.strip() == '')
            
            if is_csrf_test_payload and status_code == 200:
                # Check that the response doesn't contain CSRF rejection messages
                csrf_rejection_patterns = [
                    'sesskey', 'invalid session', 'session expired',
                    'invalid token', 'csrf token', 'form submission failed'
                ]
                was_rejected = any(p in response_lower for p in csrf_rejection_patterns)
                
                if not was_rejected:
                    return {
                        'severity': 'High',
                        'category': 'Cross-Site Request Forgery (CSRF)',
                        'type': 'CSRF Token Bypass',
                        'description': f'CSRF protection may be missing on {injection_point} "{param_name}"',
                        'evidence': f'Request with invalid/missing CSRF token was accepted (HTTP {status_code}). '
                                    f'Form may not validate CSRF tokens properly.',
                        'payload': payload_text[:200],
                        'payload_id': payload_id,
                        'injection_point': injection_point,
                        'target': url,
                        'cwe': 'CWE-352',
                        'owasp': 'A01:2021 - Broken Access Control'
                    }
        
        return None
    
    async def _make_request(
        self,
        url: str,
        params: Dict[str, Any] = None,
        client: Any = None,
        headers: Dict[str, str] = None,
        data: Any = None,
        timeout: int = 30,
        method: str = None
    ) -> Optional[Any]:
        """
        Make HTTP request with error handling.
        
        For POST requests with dict `data`, httpx automatically encodes as
        application/x-www-form-urlencoded (same as curl --data-urlencode).
        
        Args:
            url: Target URL
            params: URL query parameters (for GET)
            client: HTTP client (httpx.AsyncClient)
            headers: Request headers
            data: Request body data (dict for form data, str for raw)
            timeout: Request timeout in seconds (default 30 for time-based SQLi)
            method: HTTP method (GET/POST). If None, auto-detect from data.
            
        Returns:
            Response object or None on error
        """
        # Auto-detect method if not explicitly provided
        if method is None:
            method = 'POST' if data else 'GET'
        method = method.upper()

        effective_headers: Dict[str, str] = dict(headers or {})
        # Mark scanner-generated traffic so proxy enforcement can selectively
        # bypass blocking while still running classification and logging.
        effective_headers.setdefault(TRUSTED_SCANNER_HEADER_NAME, TRUSTED_SCANNER_HEADER_VALUE)
        
        try:
            if not client:
                # Create temporary httpx client if none provided
                import httpx
                async with httpx.AsyncClient(
                    timeout=timeout, follow_redirects=True, verify=False
                ) as temp_client:
                    response = await temp_client.request(
                        method=method,
                        url=url,
                        params=params,
                        headers=effective_headers,
                        data=data
                    )
                    return response
            else:
                # If client is httpx.AsyncClient
                if hasattr(client, 'request'):
                    response = await client.request(
                        method=method,
                        url=url,
                        params=params,
                        headers=effective_headers,
                        data=data,
                        timeout=timeout
                    )
                    return response
                # Fallback for other client types
                else:
                    return None
        
        except asyncio.TimeoutError:
            logger.warning(f"Request timeout to {url} (method={method}, timeout={timeout}s)")
            return None
        except Exception as e:
            # Catch httpx-specific timeouts too
            if 'ReadTimeout' in type(e).__name__ or 'TimeoutException' in type(e).__name__:
                logger.warning(f"Request timeout to {url} (method={method}, timeout={timeout}s)")
            else:
                logger.error(f"Request error to {url}: {e}")
                import traceback
                traceback.print_exc()
            return None

