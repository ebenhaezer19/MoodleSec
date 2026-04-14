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
from urllib.parse import urlencode, urlparse, parse_qs
import logging

logger = logging.getLogger(__name__)


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
        self.sql_error_indicators = [
            r"sql syntax error",
            r"you have an error",
            r"warning.*mysql",
            r"postgresql.*error",
            r"oracle.*error",
            r"unclosed quotation mark",
            r"sqlexception",
            r"syntax error in sql",
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
        max_payloads: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Inject payloads from repository to each parameter with proper encoding.
        
        Args:
            url: Target URL
            params: Request parameters
            client: HTTP client (aiohttp or requests)
            category: Payload category (XSS, SQL Injection, etc.)
            scan_id: ID of current scan for tracking
            max_payloads: Max payloads to test per parameter
            
        Returns:
            List of findings from payload injection
        """
        findings = []
        
        if not self.payload_repo or not params:
            return findings
        
        # Get payloads for this category
        available_payloads = self.payload_repo.get_top_payloads(category, limit=max_payloads)
        if not available_payloads:
            print(f"[PayloadInjector] No payloads found for category: {category}")
            return findings
        
        print(f"[PayloadInjector] Testing {len(params)} parameters with {len(available_payloads)} payloads")
        
        # Test each parameter with each payload
        for param_name, param_value in params.items():
            for payload_obj in available_payloads:
                payload_text = payload_obj.get('payload_text', '')
                payload_id = payload_obj.get('id', 'unknown')
                
                if not payload_text:
                    continue
                
                try:
                    # Create test request with injected payload
                    # URL encoding handles these automatically
                    test_params = params.copy()
                    test_params[param_name] = payload_text
                    
                    # Make request
                    response = await self._make_request(url, test_params, client)
                    
                    # Log injection attempt
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
                            payload_id=payload_id
                        )
                        if finding:
                            findings.append(finding)
                            print(f"[PayloadInjector] ✓ Found vulnerability: {finding['description']}")
                
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
        
        # Filter payloads for header safety
        header_safe_payloads = []
        header_unsafe_payloads = []
        
        for payload_obj in available_payloads:
            payload_text = payload_obj.get('payload_text', '')
            if not payload_text:
                continue
            
            if self._is_header_safe_payload(payload_text):
                header_safe_payloads.append(payload_obj)
            else:
                header_unsafe_payloads.append(payload_obj)
        
        if header_unsafe_payloads:
            print(f"[PayloadInjector] ⚠️  Skipping {len(header_unsafe_payloads)} payloads for header injection (contain invalid chars)")
            for p in header_unsafe_payloads[:3]:  # Show first 3 examples
                payload_preview = p.get('payload_text', '')[:50]
                print(f"    - {p.get('id', '?')}: {payload_preview}... (category: {p.get('category', '?')})")
        
        if not header_safe_payloads:
            print(f"[PayloadInjector] No header-safe payloads available for {category}")
            return findings
        
        print(f"[PayloadInjector] Testing {len(test_headers)} headers with {len(header_safe_payloads)} header-safe payloads")
        
        for header_name in test_headers:
            for payload_obj in header_safe_payloads:
                payload_text = payload_obj.get('payload_text', '')
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
        injection_point: str = "parameter"
    ) -> Optional[Dict[str, Any]]:
        """
        Check if payload injection resulted in vulnerability.
        
        Args:
            response: Response from injected request
            payload_text: Payload that was injected
            param_name: Parameter/header name
            url: Target URL
            category: Payload category
            payload_id: ID of payload
            injection_point: Where payload was injected
            
        Returns:
            Finding dict if vulnerability detected, None otherwise
        """
        response_text = response.text if hasattr(response, 'text') else str(response)
        
        # Check for SQL injection indicators
        if category == "SQL Injection" or "sql" in category.lower():
            for pattern in self.compiled_sql_patterns:
                if pattern.search(response_text):
                    return {
                        'severity': 'Critical',
                        'category': 'SQL Injection',
                        'type': 'SQL Injection via Payload',
                        'description': f'SQL Injection detected in {injection_point} "{param_name}"',
                        'evidence': f'SQL error pattern detected after injecting payload',
                        'payload': payload_text[:200],
                        'payload_id': payload_id,
                        'injection_point': injection_point,
                        'target': url,
                        'cwe': 'CWE-89',
                        'owasp': 'A03:2021 - Injection'
                    }
        
        # Check for XSS indicators
        if category == "XSS" or "xss" in category.lower():
            # Check if payload is reflected in response
            if payload_text in response_text:
                for pattern in self.compiled_xss_patterns:
                    if pattern.search(response_text):
                        return {
                            'severity': 'High',
                            'category': 'Cross-Site Scripting (XSS)',
                            'type': 'XSS via Payload',
                            'description': f'XSS detected in {injection_point} "{param_name}"',
                            'evidence': f'JavaScript code reflected: {payload_text[:100]}',
                            'payload': payload_text[:200],
                            'payload_id': payload_id,
                            'injection_point': injection_point,
                            'target': url,
                            'cwe': 'CWE-79',
                            'owasp': 'A03:2021 - Injection'
                        }
        
        return None
    
    async def _make_request(
        self,
        url: str,
        params: Dict[str, Any] = None,
        client: Any = None,
        headers: Dict[str, str] = None,
        data: str = None,
        timeout: int = 10
    ) -> Optional[Any]:
        """
        Make HTTP request with error handling.
        
        Args:
            url: Target URL
            params: Query parameters
            client: HTTP client (httpx.AsyncClient or aiohttp.ClientSession)
            headers: Request headers
            data: Request body
            timeout: Request timeout
            
        Returns:
            Response object or None on error
        """
        try:
            if not client:
                # Create temporary aiohttp client if none provided
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    method = 'POST' if data else 'GET'
                    async with session.request(
                        method,
                        url,
                        params=params,
                        headers=headers,
                        data=data,
                        timeout=aiohttp.ClientTimeout(total=timeout),
                        ssl=False
                    ) as response:
                        # Read response text to keep it alive
                        text = await response.text()
                        # Create object with common response properties
                        class SimpleResponse:
                            def __init__(self, status, text, headers):
                                self.status_code = status
                                self.text = text
                                self.headers = headers
                        return SimpleResponse(response.status, text, dict(response.headers))
            else:
                # If client is httpx.AsyncClient
                if hasattr(client, 'request'):
                    method = 'POST' if data else 'GET'
                    response = await client.request(
                        method=method,
                        url=url,
                        params=params,
                        headers=headers,
                        data=data,
                        timeout=timeout
                    )
                    return response
                # Fallback for other client types
                else:
                    return None
        
        except asyncio.TimeoutError:
            logger.warning(f"Request timeout to {url}")
            return None
        except Exception as e:
            logger.error(f"Request error to {url}: {e}")
            import traceback
            traceback.print_exc()
            return None
