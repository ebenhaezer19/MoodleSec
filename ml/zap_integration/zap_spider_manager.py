"""
ZAPSpiderManager: Orchestrates OWASP ZAP spider/crawler for page discovery.

This module manages:
- Spider initialization and configuration
- Progress monitoring and polling
- URL discovery and collection
- Spider lifecycle (start, pause, resume, stop)
"""

import logging
import time
from typing import Dict, List, Optional, Callable, Tuple
from .zap_client import ZAPClient


# Custom Exceptions
class ZAPSpiderError(Exception):
    """Raised when spider operation fails."""
    pass


class ZAPSpiderTimeoutError(Exception):
    """Raised when spider operation exceeds timeout."""
    pass


class ZAPSpiderManager:
    """Manages OWASP ZAP spider for page discovery.
    
    Orchestrates multiple phases:
    - Spider initialization with target URL
    - Progress monitoring and polling
    - URL discovery collection
    - Spider lifecycle management
    """
    
    def __init__(self, client: ZAPClient):
        """Initialize spider manager.
        
        Args:
            client: ZAPClient instance for API communication
            
        Raises:
            TypeError: If client is not a ZAPClient instance
        """
        if not isinstance(client, ZAPClient):
            raise TypeError("client must be a ZAPClient instance")
        
        self.client = client
        self.logger = logging.getLogger("ZAPSpiderManager")
        self._spider_jobs: Dict[str, Dict] = {}  # Track spider jobs
        
        self.logger.info("ZAPSpiderManager initialized")
    
    def start_spider(
        self,
        url: str,
        context_id: Optional[int] = None,
        depth: int = 3,
        max_children: int = 0
    ) -> Tuple[str, float]:
        """Start spider on target URL.
        
        Initiates a new spider/crawler operation on the specified URL.
        
        Args:
            url: Target URL to spider
            context_id: ZAP context ID (optional, for authenticated scanning)
            depth: Maximum recursion depth (default 3)
            max_children: Max child nodes (0 = unlimited)
            
        Returns:
            Tuple of (scan_id: str, start_time: float)
            
        Raises:
            ZAPSpiderError: If spider fails to start
        """
        try:
            self.logger.info(f"Starting spider on {url} (depth={depth})")
            
            params = {
                "url": url,
                "maxDuration": 0,
                "maxChildren": max_children,
                "contextId": context_id or -1,
                "subtreeOnly": "false"
            }
            
            response = self.client.request("GET", "spider/action/scan", params=params)
            
            if "id" not in response:
                raise ZAPSpiderError(f"Spider start failed: {response}")
            
            scan_id = str(response["id"])
            start_time = time.time()
            
            self._spider_jobs[scan_id] = {
                "url": url,
                "start_time": start_time,
                "status": "Running"
            }
            
            self.logger.info(f"Spider started: scan_id={scan_id}")
            return scan_id, start_time
            
        except ZAPSpiderError:
            raise
        except Exception as exc:
            self.logger.error(f"Error starting spider: {exc}")
            raise ZAPSpiderError(f"Failed to start spider: {exc}") from exc
    
    def get_progress(self, scan_id: str) -> Dict:
        """Get current spider progress.
        
        Queries ZAP for spider progress including percentage, page count,
        status, and current URL.
        
        Args:
            scan_id: Spider scan ID returned from start_spider()
            
        Returns:
            Dictionary with keys:
            - progress: int (0-100)
            - pages_found: int
            - status: str ("Running", "Stopped", "Paused")
            - current_url: str
            - id: str
            
        Raises:
            ZAPSpiderError: If progress query fails or scan not found
        """
        try:
            params = {"scanId": scan_id}
            response = self.client.request("GET", "spider/view/status", params=params)
            
            if "error" in response:
                raise ZAPSpiderError(f"Invalid scan ID: {scan_id}")
            
            # Parse response from ZAP
            progress = int(response.get("status", 0))
            pages = int(response.get("spider", {}).get("pages", 0)) if isinstance(response.get("spider"), dict) else 0
            
            result = {
                "progress": progress,
                "pages_found": pages,
                "status": "Running" if progress < 100 else "Stopped",
                "current_url": response.get("currentUrl", ""),
                "id": scan_id
            }
            
            self.logger.debug(f"Spider progress: {result}")
            return result
            
        except ZAPSpiderError:
            raise
        except Exception as exc:
            self.logger.error(f"Error getting spider progress: {exc}")
            raise ZAPSpiderError(f"Failed to get spider progress: {exc}") from exc
    
    def wait_for_completion(
        self,
        scan_id: str,
        timeout_minutes: int = 30,
        poll_interval: int = 5,
        progress_callback: Optional[Callable[[Dict], None]] = None
    ) -> Tuple[bool, List[str], float]:
        """Wait for spider to complete.
        
        Blocks until spider completes or timeout, polling at regular intervals.
        Optionally calls progress_callback for UI updates.
        
        Args:
            scan_id: Spider scan ID
            timeout_minutes: Maximum wait time in minutes (default 30)
            poll_interval: Seconds between status checks (default 5)
            progress_callback: Optional function called with progress dict
            
        Returns:
            Tuple of (success: bool, discovered_urls: List[str], duration_seconds: float)
            
        Raises:
            ZAPSpiderTimeoutError: If timeout exceeded
        """
        try:
            timeout_seconds = timeout_minutes * 60
            start_time = time.time()
            last_progress = 0
            
            self.logger.info(f"Waiting for spider completion (timeout: {timeout_minutes}m)")
            
            while True:
                # Check timeout
                elapsed = time.time() - start_time
                if elapsed > timeout_seconds:
                    self.stop_spider(scan_id)
                    raise ZAPSpiderTimeoutError(
                        f"Spider timeout exceeded: {timeout_minutes} minutes"
                    )
                
                # Get progress
                try:
                    progress = self.get_progress(scan_id)
                except ZAPSpiderError:
                    # Retry on transient errors
                    time.sleep(poll_interval)
                    continue
                
                # Call progress callback if provided
                if progress_callback:
                    try:
                        progress_callback(progress)
                    except Exception as cb_exc:
                        self.logger.warning(f"Progress callback error: {cb_exc}")
                
                # Log progress milestones
                current_progress = progress["progress"]
                if current_progress >= last_progress + 25:
                    self.logger.info(
                        f"Spider progress: {current_progress}% "
                        f"({progress['pages_found']} pages, {elapsed:.0f}s)"
                    )
                    last_progress = current_progress
                
                # Check completion
                if current_progress >= 100:
                    duration = time.time() - start_time
                    urls = self.get_discovered_urls(scan_id)
                    self.logger.info(
                        f"Spider completed: {len(urls)} URLs found in {duration:.0f}s"
                    )
                    return True, urls, duration
                
                # Wait before next poll
                time.sleep(poll_interval)
                
        except ZAPSpiderTimeoutError:
            raise
        except Exception as exc:
            self.logger.error(f"Error waiting for spider completion: {exc}")
            raise ZAPSpiderError(f"Failed while waiting for spider: {exc}") from exc
    
    def get_discovered_urls(self, scan_id: str) -> List[str]:
        """Get all URLs discovered by spider.
        
        Fetches complete list of discovered URLs, removes duplicates,
        and returns sorted list.
        
        Args:
            scan_id: Spider scan ID
            
        Returns:
            Sorted list of unique URLs discovered
            
        Raises:
            ZAPSpiderError: If results cannot be retrieved
        """
        try:
            self.logger.debug(f"Fetching discovered URLs for scan {scan_id}")
            
            params = {"scanId": scan_id}
            response = self.client.request("GET", "spider/view/results", params=params)
            
            if isinstance(response, dict) and "error" in response:
                raise ZAPSpiderError(f"Failed to get spider results: {response}")
            
            # Extract URLs from response
            urls = set()
            
            if isinstance(response, list):
                # Response is list of URLs
                urls = set(response)
            elif isinstance(response, dict) and "results" in response:
                # Response has results key
                results = response["results"]
                if isinstance(results, list):
                    urls = set(results)
            
            sorted_urls = sorted(list(urls))
            self.logger.info(f"Retrieved {len(sorted_urls)} unique URLs from spider")
            
            return sorted_urls
            
        except ZAPSpiderError:
            raise
        except Exception as exc:
            self.logger.error(f"Error retrieving spider results: {exc}")
            raise ZAPSpiderError(f"Failed to get discovered URLs: {exc}") from exc
    
    def get_spider_status(self, scan_id: str) -> Dict:
        """Get detailed spider status.
        
        Provides comprehensive status information including timing,
        issues, and detailed progress.
        
        Args:
            scan_id: Spider scan ID
            
        Returns:
            Dictionary with status details:
            - id: str
            - progress: int (0-100)
            - status: str
            - pages_found: int
            - start_time: str (ISO format)
            - duration_seconds: float
            - issues: List[str]
            
        Raises:
            ZAPSpiderError: If status cannot be retrieved
        """
        try:
            progress = self.get_progress(scan_id)
            
            if scan_id not in self._spider_jobs:
                raise ZAPSpiderError(f"Scan {scan_id} not found in job tracking")
            
            job_info = self._spider_jobs[scan_id]
            start_time_obj = job_info["start_time"]
            duration = time.time() - start_time_obj
            
            status = {
                "id": scan_id,
                "progress": progress["progress"],
                "status": progress["status"],
                "pages_found": progress["pages_found"],
                "url": job_info["url"],
                "start_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", 
                                           time.gmtime(start_time_obj)),
                "duration_seconds": duration,
                "issues": []
            }
            
            self.logger.debug(f"Spider status: {status}")
            return status
            
        except ZAPSpiderError:
            raise
        except Exception as exc:
            self.logger.error(f"Error getting spider status: {exc}")
            raise ZAPSpiderError(f"Failed to get spider status: {exc}") from exc
    
    def stop_spider(self, scan_id: str) -> bool:
        """Stop active spider.
        
        Terminates spider operation immediately.
        
        Args:
            scan_id: Spider scan ID to stop
            
        Returns:
            True if stopped successfully, False otherwise
        """
        try:
            self.logger.info(f"Stopping spider {scan_id}")
            
            params = {"scanId": scan_id}
            response = self.client.request("GET", "spider/action/stop", params=params)
            
            if response.get("code") == "ok" or "error" not in response:
                if scan_id in self._spider_jobs:
                    self._spider_jobs[scan_id]["status"] = "Stopped"
                self.logger.info(f"Spider {scan_id} stopped successfully")
                return True
            else:
                self.logger.warning(f"Stop spider response: {response}")
                return False
                
        except Exception as exc:
            self.logger.error(f"Error stopping spider: {exc}")
            return False
    
    def pause_spider(self, scan_id: str) -> bool:
        """Pause spider without stopping it.
        
        Pauses spider operation; can be resumed later.
        
        Args:
            scan_id: Spider scan ID to pause
            
        Returns:
            True if paused successfully, False otherwise
        """
        try:
            self.logger.info(f"Pausing spider {scan_id}")
            
            params = {"scanId": scan_id}
            response = self.client.request("GET", "spider/action/pause", params=params)
            
            if response.get("code") == "ok" or "error" not in response:
                if scan_id in self._spider_jobs:
                    self._spider_jobs[scan_id]["status"] = "Paused"
                self.logger.info(f"Spider {scan_id} paused successfully")
                return True
            else:
                self.logger.warning(f"Pause spider response: {response}")
                return False
                
        except Exception as exc:
            self.logger.error(f"Error pausing spider: {exc}")
            return False
    
    def resume_spider(self, scan_id: str) -> bool:
        """Resume paused spider.
        
        Resumes spider operation from pause.
        
        Args:
            scan_id: Spider scan ID to resume
            
        Returns:
            True if resumed successfully, False otherwise
        """
        try:
            self.logger.info(f"Resuming spider {scan_id}")
            
            params = {"scanId": scan_id}
            response = self.client.request("GET", "spider/action/resume", params=params)
            
            if response.get("code") == "ok" or "error" not in response:
                if scan_id in self._spider_jobs:
                    self._spider_jobs[scan_id]["status"] = "Running"
                self.logger.info(f"Spider {scan_id} resumed successfully")
                return True
            else:
                self.logger.warning(f"Resume spider response: {response}")
                return False
                
        except Exception as exc:
            self.logger.error(f"Error resuming spider: {exc}")
            return False
