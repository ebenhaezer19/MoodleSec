"""
ZAPActiveScanManager: Orchestrates OWASP ZAP active vulnerability scanning.

Manages active security scans and aggregates findings.
"""

import logging
import time
from typing import Dict, List, Optional, Tuple
from .zap_client import ZAPClient


class ZAPScanError(Exception):
    """Raised when scan operation fails."""
    pass


class ZAPScanTimeoutError(Exception):
    """Raised when scan exceeds timeout."""
    pass


class ZAPAlertParseError(Exception):
    """Raised when alert parsing fails."""
    pass


class ZAPActiveScanManager:
    """Manages OWASP ZAP active vulnerability scanning."""
    
    def __init__(self, client: ZAPClient):
        if not isinstance(client, ZAPClient):
            raise TypeError("client must be a ZAPClient instance")
        
        self.client = client
        self.logger = logging.getLogger("ZAPActiveScanManager")
        self._scan_jobs: Dict[str, Dict] = {}
        
        self.logger.info("ZAPActiveScanManager initialized")
    
    def start_ascan(
        self,
        url: str,
        context_id: int,
        user_id: Optional[int] = None,
        policy: str = "medium",
        max_runtime: int = 3600
    ) -> Tuple[str, float]:
        """Start active vulnerability scan.
        
        Args:
            url: Target URL to scan
            context_id: ZAP context ID for authentication
            user_id: User ID in context (optional)
            policy: Scan policy (light/medium/heavy)
            max_runtime: Max scan duration in seconds
            
        Returns:
            Tuple of (scan_id: str, start_time: float)
            
        Raises:
            ZAPScanError: If scan fails to start
        """
        try:
            self.logger.info(f"Starting active scan on {url} (policy={policy})")
            
            params = {
                "url": url,
                "contextId": context_id,
                "userId": user_id or -1,
                "scanPolicyName": policy,
                "method": "GET"
            }
            
            response = self.client.request("GET", "ascan/action/scan", params=params)
            
            if "id" not in response:
                raise ZAPScanError(f"Scan start failed: {response}")
            
            scan_id = str(response["id"])
            start_time = time.time()
            
            self._scan_jobs[scan_id] = {
                "url": url,
                "start_time": start_time,
                "status": "Running",
                "policy": policy
            }
            
            self.logger.info(f"Active scan started: scan_id={scan_id}")
            return scan_id, start_time
            
        except ZAPScanError:
            raise
        except Exception as exc:
            self.logger.error(f"Error starting scan: {exc}")
            raise ZAPScanError(f"Failed to start active scan: {exc}") from exc
    
    def get_ascan_progress(self, scan_id: str) -> Dict:
        """Get active scan progress.
        
        Args:
            scan_id: Scan ID
            
        Returns:
            Dictionary with progress info
            
        Raises:
            ZAPScanError: If progress query fails
        """
        try:
            params = {"scanId": scan_id}
            response = self.client.request("GET", "ascan/view/status", params=params)
            
            if "error" in response:
                raise ZAPScanError(f"Invalid scan ID: {scan_id}")
            
            progress = int(response.get("status", 0))
            alerts = int(response.get("totalAlerts", 0))
            requests = int(response.get("requestsSent", 0))
            
            result = {
                "id": scan_id,
                "progress": progress,
                "status": "Running" if progress < 100 else "Stopped",
                "alerts_found": alerts,
                "requests_sent": requests,
                "current_step": response.get("currentPlugin", "")
            }
            
            self.logger.debug(f"Scan progress: {result}")
            return result
            
        except ZAPScanError:
            raise
        except Exception as exc:
            self.logger.error(f"Error getting scan progress: {exc}")
            raise ZAPScanError(f"Failed to get scan progress: {exc}") from exc
    
    def wait_for_scan_completion(
        self,
        scan_id: str,
        timeout_minutes: int = 60,
        poll_interval: int = 10
    ) -> Tuple[bool, List[Dict], float]:
        """Wait for active scan completion.
        
        Args:
            scan_id: Scan ID to monitor
            timeout_minutes: Timeout in minutes
            poll_interval: Polling interval in seconds
            
        Returns:
            Tuple of (success: bool, alerts: List[Dict], duration: float)
            
        Raises:
            ZAPScanTimeoutError: If timeout exceeded
        """
        try:
            timeout_seconds = timeout_minutes * 60
            start_time = time.time()
            last_progress = 0
            
            self.logger.info(f"Waiting for scan completion (timeout: {timeout_minutes}m)")
            
            while True:
                elapsed = time.time() - start_time
                if elapsed > timeout_seconds:
                    self.stop_ascan(scan_id)
                    raise ZAPScanTimeoutError(f"Scan timeout: {timeout_minutes}m exceeded")
                
                try:
                    progress = self.get_ascan_progress(scan_id)
                except ZAPScanError:
                    time.sleep(poll_interval)
                    continue
                
                current_progress = progress["progress"]
                if current_progress >= last_progress + 25:
                    self.logger.info(
                        f"Scan progress: {current_progress}% "
                        f"({progress['alerts_found']} alerts, {elapsed:.0f}s)"
                    )
                    last_progress = current_progress
                
                if current_progress >= 100:
                    duration = time.time() - start_time
                    alerts = self.get_alerts(scan_id=scan_id)
                    self.logger.info(f"Scan completed: {len(alerts)} alerts in {duration:.0f}s")
                    return True, alerts, duration
                
                time.sleep(poll_interval)
                
        except ZAPScanTimeoutError:
            raise
        except Exception as exc:
            self.logger.error(f"Error waiting for scan: {exc}")
            raise ZAPScanError(f"Failed while waiting for scan: {exc}") from exc
    
    def get_alerts(
        self,
        scan_id: Optional[str] = None,
        base_url: Optional[str] = None
    ) -> List[Dict]:
        """Get alerts from scan with normalization.
        
        Args:
            scan_id: Specific scan ID (optional)
            base_url: Filter by base URL (optional)
            
        Returns:
            List of normalized alert dictionaries
            
        Raises:
            ZAPScanError: If alerts cannot be retrieved
        """
        try:
            params = {}
            if base_url:
                params["baseurl"] = base_url
            
            response = self.client.request("GET", "core/view/alerts", params=params)
            
            if isinstance(response, dict) and "error" in response:
                raise ZAPScanError(f"Failed to get alerts: {response}")
            
            alerts_list = response if isinstance(response, list) else response.get("alerts", [])
            
            normalized = []
            for alert in alerts_list:
                try:
                    normalized.append(self._normalize_alert(alert))
                except ZAPAlertParseError as exc:
                    self.logger.warning(f"Error parsing alert: {exc}")
                    continue
            
            self.logger.info(f"Retrieved {len(normalized)} alerts")
            return normalized
            
        except ZAPScanError:
            raise
        except Exception as exc:
            self.logger.error(f"Error retrieving alerts: {exc}")
            raise ZAPScanError(f"Failed to get alerts: {exc}") from exc
    
    def _normalize_alert(self, raw_alert: Dict) -> Dict:
        """Normalize ZAP alert to standard format.
        
        Args:
            raw_alert: Raw alert from ZAP API
            
        Returns:
            Normalized alert dictionary
            
        Raises:
            ZAPAlertParseError: If alert parsing fails
        """
        try:
            normalized = {
                "id": str(raw_alert.get("id", "")),
                "type": raw_alert.get("alert", "Unknown"),
                "risk": raw_alert.get("risk", "Low"),
                "confidence": raw_alert.get("confidence", "Low"),
                "url": raw_alert.get("url", ""),
                "method": raw_alert.get("method", "GET"),
                "param": raw_alert.get("param", ""),
                "wascid": int(raw_alert.get("wascid", 0)) if raw_alert.get("wascid") else 0,
                "cwe": int(raw_alert.get("cwe", 0)) if raw_alert.get("cwe") else 0,
                "description": raw_alert.get("description", ""),
                "other_info": raw_alert.get("otherInfo", ""),
                "solution": raw_alert.get("solution", ""),
                "reference": raw_alert.get("reference", ""),
                "evidence": raw_alert.get("evidence", ""),
                "plugin_id": int(raw_alert.get("pluginId", 0)) if raw_alert.get("pluginId") else 0
            }
            return normalized
        except Exception as exc:
            raise ZAPAlertParseError(f"Failed to parse alert: {exc}") from exc
    
    def get_alerts_by_risk(self, risk_level: str) -> List[Dict]:
        """Filter alerts by risk level.
        
        Args:
            risk_level: Risk level (High/Medium/Low/Informational)
            
        Returns:
            Filtered alerts
            
        Raises:
            ValueError: If invalid risk_level
        """
        valid_levels = ["High", "Medium", "Low", "Informational"]
        if risk_level not in valid_levels:
            raise ValueError(f"Invalid risk_level. Must be one of {valid_levels}")
        
        all_alerts = self.get_alerts()
        return [a for a in all_alerts if a["risk"] == risk_level]
    
    def get_alerts_by_type(self, alert_type: str) -> List[Dict]:
        """Filter alerts by vulnerability type.
        
        Args:
            alert_type: Alert type to filter
            
        Returns:
            Filtered alerts
        """
        all_alerts = self.get_alerts()
        return [a for a in all_alerts if alert_type.lower() in a["type"].lower()]
    
    def stop_ascan(self, scan_id: str) -> bool:
        """Stop active scan.
        
        Args:
            scan_id: Scan ID to stop
            
        Returns:
            True if stopped successfully
        """
        try:
            self.logger.info(f"Stopping scan {scan_id}")
            params = {"scanId": scan_id}
            response = self.client.request("GET", "ascan/action/stop", params=params)
            
            if response.get("code") == "ok" or "error" not in response:
                if scan_id in self._scan_jobs:
                    self._scan_jobs[scan_id]["status"] = "Stopped"
                self.logger.info(f"Scan {scan_id} stopped")
                return True
            return False
        except Exception as exc:
            self.logger.error(f"Error stopping scan: {exc}")
            return False
    
    def aggregate_findings(self, alerts: List[Dict]) -> Dict:
        """Analyze and aggregate findings.
        
        Args:
            alerts: List of normalized alerts
            
        Returns:
            Aggregation statistics
        """
        by_risk = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        by_type = {}
        
        for alert in alerts:
            risk = alert.get("risk", "Low")
            if risk in by_risk:
                by_risk[risk] += 1
            
            alert_type = alert.get("type", "Unknown")
            by_type[alert_type] = by_type.get(alert_type, 0) + 1
        
        top_vulns = sorted(by_type.items(), key=lambda x: x[1], reverse=True)[:5]
        high_risk = by_risk.get("High", 0)
        exploitable_pct = (high_risk / len(alerts) * 100) if alerts else 0
        
        return {
            "total": len(alerts),
            "by_risk": by_risk,
            "by_type": by_type,
            "top_vulnerabilities": [v[0] for v in top_vulns],
            "high_risk_count": high_risk,
            "exploitable_percentage": exploitable_pct
        }
