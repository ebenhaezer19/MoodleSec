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
        
        print("[PayloadInjector] Initialized")
    
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
        Inject payloads from repository to each parameter.
        
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
        Inject payloads into request headers.
        
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
        
        print(f"[PayloadInjector] Testing {len(test_headers)} headers with {len(available_payloads)} payloads")
        
        for header_name in test_headers:
            for payload_obj in available_payloads:
                payload_text = payload_obj.get('payload_text', '')
                payload_id = payload_obj.get('id', 'unknown')
                
                if not payload_text:
                    continue
                
                try:
                    test_headers_dict = headers.copy()
                    test_headers_dict[header_name] = payload_text
                    
                    response = await self._make_request(url, {}, client, headers=test_headers_dict)
                    
                    if self.debug_logger:
                        self.debug_logger.log_injection_attempt(
                            scan_id=scan_id,
                            target_url=url,
                            category=category,
                            payload_text=payload_text,
                            injection_point=f"header:{header_name}",
                            status="success" if response else "failed",
                            response_code=response.status_code if response else None
                        )
                    
                    if response:
                        finding = self._check_injection_result(
                            response=response,
                            payload_text=payload_text,
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
                            payload_text=payload_text,
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
            client: HTTP client
            headers: Request headers
            data: Request body
            timeout: Request timeout
            
        Returns:
            Response object or None on error
        """
        try:
            if not client:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        url,
                        params=params,
                        headers=headers,
                        data=data,
                        timeout=timeout,
                        ssl=False
                    ) as response:
                        return response
            else:
                # If client is provided, assume it has proper methods
                if hasattr(client, 'get'):
                    return await client.get(url, params=params)
                else:
                    return client.get(url, params=params, timeout=timeout)
        
        except asyncio.TimeoutError:
            logger.warning(f"Request timeout to {url}")
            return None
        except Exception as e:
            logger.error(f"Request error to {url}: {e}")
            return None
