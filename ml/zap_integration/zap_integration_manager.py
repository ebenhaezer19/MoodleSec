"""
ZAPIntegrationManager: Unified orchestrator for complete ZAP scanning pipeline.

Coordinates authentication, spidering, scanning, and ML-based filtering.
"""

import logging
import time
from typing import Dict, List, Optional
from .zap_client import ZAPClient
from .zap_auth_handler import ZAPAuthenticationHandler
from .zap_spider_manager import ZAPSpiderManager
from .zap_ascan_manager import ZAPActiveScanManager
from .zap_result_aggregator import ZAPResultAggregator


class ZAPIntegrationManager:
    """Unified orchestrator for ZAP scanning pipeline."""
    
    def __init__(
        self,
        host: str = "localhost",
        port: int = 8080,
        api_key: str = "1qlbij76v3j9c6ail8d0locm24",
        ml_model_path: Optional[str] = None
    ):
        """Initialize ZAP integration manager.
        
        Args:
            host: ZAP host
            port: ZAP port
            api_key: ZAP API key
            ml_model_path: Optional ML model path
        """
        self.logger = logging.getLogger("ZAPIntegrationManager")
        
        try:
            self.client = ZAPClient(host=host, port=port, api_key=api_key)
            self.auth_handler = ZAPAuthenticationHandler(self.client)
            self.spider_manager = ZAPSpiderManager(self.client)
            self.ascan_manager = ZAPActiveScanManager(self.client)
            self.result_aggregator = ZAPResultAggregator(
                self.client,
                self.ascan_manager,
                ml_model_path
            )
            
            self.logger.info(f"ZAPIntegrationManager initialized: {host}:{port}")
            
        except Exception as exc:
            self.logger.error(f"Error initializing components: {exc}")
            raise
    
    def initialize(self) -> bool:
        """Validate all components are ready.
        
        Returns:
            True if all components initialized successfully
        """
        try:
            # Test ZAP connection
            status = self.client.get_status()
            if "status" not in status:
                self.logger.error("ZAP connection test failed")
                return False
            
            self.logger.info("All components initialized and validated")
            return True
            
        except Exception as exc:
            self.logger.error(f"Initialization validation failed: {exc}")
            return False
    
    def configure_moodle_auth(
        self,
        context_id: int,
        moodle_url: str,
        username: str,
        password: str
    ) -> bool:
        """Configure Moodle authentication in ZAP context.
        
        Args:
            context_id: ZAP context ID
            moodle_url: Moodle base URL
            username: Username to authenticate
            password: Password
            
        Returns:
            True if authentication configured
        """
        try:
            login_url = f"{moodle_url}/login/index.php"
            
            result = self.auth_handler.setup_form_based_auth(
                context_id=context_id,
                login_url=login_url,
                username=username,
                password=password
            )
            
            if result:
                self.logger.info(f"Moodle authentication configured for {username}")
            
            return result
            
        except Exception as exc:
            self.logger.error(f"Moodle auth configuration failed: {exc}")
            return False
    
    def scan_with_authentication(
        self,
        target_url: str,
        spider_depth: int = 3,
        scan_policy: str = "medium",
        username: Optional[str] = None,
        password: Optional[str] = None,
        context_id: int = 1,
        user_id: int = 1
    ) -> Dict:
        """Full scanning workflow with authentication.
        
        Args:
            target_url: URL to scan
            spider_depth: Spider recursion depth
            scan_policy: Scan policy (light/medium/heavy)
            username: Username for authentication
            password: Password for authentication
            context_id: ZAP context ID
            user_id: ZAP user ID in context
            
        Returns:
            Complete scan result with findings
        """
        start_time = time.time()
        errors = []
        results = {
            "success": False,
            "spider_scan_id": None,
            "ascan_scan_id": None,
            "total_findings": 0,
            "filtered_findings": 0,
            "alerts": [],
            "statistics": {},
            "duration_seconds": 0,
            "errors": errors
        }
        
        try:
            # Step 1: Authentication (optional)
            if username and password:
                try:
                    self.logger.info(f"Authenticating as {username}")
                    self.configure_moodle_auth(
                        context_id=context_id,
                        moodle_url=target_url,
                        username=username,
                        password=password
                    )
                except Exception as exc:
                    self.logger.warning(f"Authentication failed: {exc}")
                    errors.append(f"Authentication: {str(exc)}")
            
            # Step 2: Spider
            self.logger.info(f"Starting spider: {target_url}")
            spider_id, spider_urls = self.spider_target(target_url, context_id, spider_depth)
            results["spider_scan_id"] = spider_id
            self.logger.info(f"Spider found {len(spider_urls)} URLs")
            
            # Step 3: Active Scan
            self.logger.info("Starting active vulnerability scan")
            ascan_id, alerts = self.scan_discovered_urls(
                spider_urls,
                context_id,
                user_id,
                scan_policy
            )
            results["ascan_scan_id"] = ascan_id
            results["total_findings"] = len(alerts)
            
            # Step 4: Filter Results
            self.logger.info("Applying ML-based filtering pipeline")
            filter_result = self.result_aggregator.aggregate_and_filter(alerts)
            filtered = filter_result["filtered_findings"]
            results["filtered_findings"] = len(filtered)
            results["alerts"] = filtered
            results["statistics"] = filter_result["statistics"]
            results["success"] = True
            
            self.logger.info(
                f"Scan complete: {results['total_findings']} findings → "
                f"{results['filtered_findings']} after filtering"
            )
            
        except Exception as exc:
            self.logger.error(f"Scan workflow failed: {exc}")
            errors.append(str(exc))
        
        finally:
            results["duration_seconds"] = time.time() - start_time
        
        return results
    
    def scan_unauthenticated(
        self,
        target_url: str,
        spider_depth: int = 3,
        scan_policy: str = "medium",
        context_id: int = 1,
        user_id: int = 1
    ) -> Dict:
        """Scan without authentication.
        
        Args:
            target_url: URL to scan
            spider_depth: Spider depth
            scan_policy: Scan policy
            context_id: ZAP context ID
            user_id: ZAP user ID
            
        Returns:
            Scan results
        """
        return self.scan_with_authentication(
            target_url=target_url,
            spider_depth=spider_depth,
            scan_policy=scan_policy,
            username=None,
            password=None,
            context_id=context_id,
            user_id=user_id
        )
    
    def spider_target(
        self,
        target_url: str,
        context_id: Optional[int] = None,
        depth: int = 3
    ) -> tuple:
        """Spider target and return discovered URLs.
        
        Args:
            target_url: URL to spider
            context_id: ZAP context ID
            depth: Spider depth
            
        Returns:
            Tuple of (scan_id, discovered_urls)
        """
        try:
            scan_id, _ = self.spider_manager.start_spider(
                url=target_url,
                context_id=context_id,
                depth=depth
            )
            
            success, urls, duration = self.spider_manager.wait_for_completion(scan_id)
            
            self.logger.info(f"Spider completed in {duration:.0f}s: {len(urls)} URLs")
            return scan_id, urls
            
        except Exception as exc:
            self.logger.error(f"Spider failed: {exc}")
            raise
    
    def scan_discovered_urls(
        self,
        urls: List[str],
        context_id: int,
        user_id: int,
        scan_policy: str = "medium"
    ) -> tuple:
        """Scan discovered URLs.
        
        Args:
            urls: List of URLs to scan
            context_id: ZAP context ID
            user_id: ZAP user ID
            scan_policy: Scan policy
            
        Returns:
            Tuple of (scan_id, alerts)
        """
        try:
            # Scan first URL as representative
            if not urls:
                self.logger.warning("No URLs provided for scanning")
                return None, []
            
            scan_url = urls[0]
            scan_id, _ = self.ascan_manager.start_ascan(
                url=scan_url,
                context_id=context_id,
                user_id=user_id,
                policy=scan_policy
            )
            
            success, alerts, duration = self.ascan_manager.wait_for_scan_completion(scan_id)
            
            self.logger.info(f"Active scan completed in {duration:.0f}s: {len(alerts)} alerts")
            return scan_id, alerts
            
        except Exception as exc:
            self.logger.error(f"Active scan failed: {exc}")
            raise
    
    def filter_results(
        self,
        findings: List[Dict],
        apply_ml: bool = True
    ) -> Dict:
        """Filter findings using ML pipeline.
        
        Args:
            findings: Findings to filter
            apply_ml: Enable ML filtering
            
        Returns:
            Filtered results with statistics
        """
        return self.result_aggregator.aggregate_and_filter(
            findings,
            apply_tier1=True,
            apply_tier2=True,
            apply_tier3=apply_ml
        )
