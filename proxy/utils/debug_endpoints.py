"""
Debug Endpoints for Payload Injection Tracking

Provides API endpoints for retrieving payload injection debug logs
and displaying them in the Moodle UI.
"""

from typing import Dict, Any, List, Optional
from fastapi import HTTPException, APIRouter
from datetime import datetime

# Create router for debug endpoints
debug_router = APIRouter(prefix="/api/debug", tags=["debug"])


def setup_debug_endpoints(app, debug_logger, scanner_engine):
    """
    Setup all debug endpoints.
    
    Args:
        app: FastAPI application instance
        debug_logger: PayloadDebugLogger instance
        scanner_engine: ScannerEngine instance
    """
    
    @debug_router.post("/payload/loaded")
    async def log_payload_loaded(category: str, count: int, payloads: Optional[List[str]] = None):
        """
        Log when payloads are loaded from repository.
        
        Args:
            category: Payload category (XSS, SQL, CSRF, etc.)
            count: Number of payloads loaded
            payloads: Optional list of payload samples
            
        Returns:
            Confirmation
        """
        if debug_logger:
            debug_logger.log_payload_loaded(category, count, payloads)
            return {
                'status': 'logged',
                'category': category,
                'count': count,
                'timestamp': datetime.utcnow().isoformat()
            }
        else:
            raise HTTPException(status_code=500, detail="Debug logger not initialized")
    
    
    @debug_router.post("/payload/injected")
    async def log_injection(scan_id: str, target_url: str, category: str, 
                          payload_text: str, injection_point: str,
                          status: str = 'ATTEMPT', error: Optional[str] = None,
                          response_code: Optional[int] = None):
        """
        Log when a payload is injected into a request.
        
        Args:
            scan_id: ID of the current scan
            target_url: URL being scanned
            category: Payload category
            payload_text: The payload being injected
            injection_point: Where injected (parameter name, header, body, etc.)
            status: Injection status (ATTEMPT, SUCCESS, FAILED, etc.)
            error: Optional error message
            response_code: HTTP response code
            
        Returns:
            Confirmation
        """
        if debug_logger:
            debug_logger.log_injection_attempt(
                scan_id, target_url, category, payload_text,
                injection_point, status, error, response_code
            )
            return {
                'status': 'logged',
                'scan_id': scan_id,
                'injection_point': injection_point,
                'timestamp': datetime.utcnow().isoformat()
            }
        else:
            raise HTTPException(status_code=500, detail="Debug logger not initialized")
    
    
    @debug_router.post("/scan/start")
    async def log_scan_start(scan_id: str, scan_type: str, target_url: str):
        """
        Log when a scan starts.
        
        Args:
            scan_id: Unique scan identifier
            scan_type: Type of scan (full, auth, api, etc.)
            target_url: Target URL being scanned
            
        Returns:
            Confirmation
        """
        if debug_logger:
            debug_logger.log_scan_start(scan_id, scan_type, target_url)
            return {
                'status': 'logged',
                'scan_id': scan_id,
                'scan_type': scan_type,
                'timestamp': datetime.utcnow().isoformat()
            }
        else:
            raise HTTPException(status_code=500, detail="Debug logger not initialized")
    
    
    @debug_router.post("/scan/complete")
    async def log_scan_complete(scan_id: str, findings_count: int, status: str = 'SUCCESS'):
        """
        Log when a scan completes.
        
        Args:
            scan_id: Scan identifier
            findings_count: Number of findings discovered
            status: Completion status (SUCCESS, FAILED, CANCELLED)
            
        Returns:
            Confirmation
        """
        if debug_logger:
            debug_logger.log_scan_complete(scan_id, findings_count, status)
            return {
                'status': 'logged',
                'scan_id': scan_id,
                'findings': findings_count,
                'timestamp': datetime.utcnow().isoformat()
            }
        else:
            raise HTTPException(status_code=500, detail="Debug logger not initialized")
    
    
    @debug_router.get("/scan/{scan_id}/logs")
    async def get_scan_debug_logs(scan_id: str) -> Dict[str, Any]:
        """
        Retrieve all debug logs for a specific scan.
        
        Shows:
        - When payloads were loaded
        - Each payload injection attempt
        - When payloads were injected into headers/parameters
        - Success/failure of each attempt
        - Errors encountered
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            Complete debug log for the scan
        """
        if debug_logger:
            logs = debug_logger.get_scan_debug_log(scan_id)
            return logs
        else:
            raise HTTPException(status_code=500, detail="Debug logger not initialized")
    
    
    @debug_router.get("/logs/recent")
    async def get_recent_debug_logs(limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve recent debug logs across all scans.
        
        Args:
            limit: Maximum number of logs to return (default 100)
            
        Returns:
            List of recent debug log entries
        """
        if debug_logger:
            logs = debug_logger.get_recent_debug_logs(limit)
            return {
                'total': len(logs),
                'logs': logs,
                'timestamp': datetime.utcnow().isoformat()
            }
        else:
            raise HTTPException(status_code=500, detail="Debug logger not initialized")
    
    
    @debug_router.get("/statistics")
    async def get_debug_statistics(scan_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get statistics about payload injections and debug events.
        
        Shows:
        - Total injection attempts
        - Success rate
        - Injection points distribution
        - Category distribution
        
        Args:
            scan_id: Optional - get statistics for specific scan only
            
        Returns:
            Statistics about injection events
        """
        if debug_logger:
            stats = debug_logger.get_payload_injection_statistics(scan_id)
            return {
                'scan_id': scan_id,
                'statistics': stats,
                'timestamp': datetime.utcnow().isoformat()
            }
        else:
            raise HTTPException(status_code=500, detail="Debug logger not initialized")
    
    
    @debug_router.post("/logs/clear")
    async def clear_old_logs(days: int = 7) -> Dict[str, Any]:
        """
        Clear debug logs older than specified days.
        
        Args:
            days: Age threshold in days (default 7)
            
        Returns:
            Number of logs deleted
        """
        if debug_logger:
            deleted = debug_logger.clear_old_logs(days)
            return {
                'status': 'cleared',
                'deleted_count': deleted,
                'age_threshold_days': days,
                'timestamp': datetime.utcnow().isoformat()
            }
        else:
            raise HTTPException(status_code=500, detail="Debug logger not initialized")
    
    
    @debug_router.get("/scanner/status")
    async def get_scanner_debug_status() -> Dict[str, Any]:
        """
        Get current scanner status for debugging.
        
        Shows:
        - Payloads loaded per category
        - Scanner readiness
        - Last reload timestamp
        
        Returns:
            Scanner status and debug information
        """
        if scanner_engine:
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'scanner_status': scanner_engine.get_scanner_status() if hasattr(scanner_engine, 'get_scanner_status') else {},
                'scanners': {
                    name: {
                        'enabled': info['enabled'],
                        'has_detector': hasattr(info['detector'], '__call__')
                    }
                    for name, info in scanner_engine.scanners.items()
                }
            }
        else:
            raise HTTPException(status_code=500, detail="Scanner engine not initialized")
    
    
    @debug_router.get("/health")
    async def debug_health_check() -> Dict[str, Any]:
        """
        Health check for debug and logging systems.
        
        Returns:
            Status of all debug components
        """
        return {
            'status': 'ok',
            'components': {
                'debug_logger': 'initialized' if debug_logger else 'not_initialized',
                'scanner_engine': 'initialized' if scanner_engine else 'not_initialized'
            },
            'timestamp': datetime.utcnow().isoformat()
        }
    
    
    # Include router in app
    app.include_router(debug_router)
    print(f"[Debug Endpoints] Registered {len(debug_router.routes)} debug endpoints")
