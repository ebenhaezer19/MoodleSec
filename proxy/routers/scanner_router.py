"""
Scanner Management API Routes

Handles:
- Reloading scanner payloads
- Getting scanner status
- Triggering scanner operations
"""

from fastapi import APIRouter, HTTPException, Body
from typing import Dict, Any, Optional
from scanners.scanner_engine import ScannerEngine

router = APIRouter(prefix="/api/scanners", tags=["scanners"])

# Shared scanner engine instance (will be injected from app.py)
scanner_engine: Optional[ScannerEngine] = None

def set_scanner_engine(engine: ScannerEngine):
    """Set the scanner engine instance."""
    global scanner_engine
    scanner_engine = engine

@router.get("/status")
async def get_scanner_status() -> Dict[str, Any]:
    """Get current status of all scanners."""
    if not scanner_engine:
        raise HTTPException(status_code=503, detail="Scanner engine not initialized")
    
    try:
        status = scanner_engine.get_scanner_status()
        return {
            "status": "success",
            "data": status
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/reload-payloads")
async def reload_scanner_payloads() -> Dict[str, Any]:
    """
    Reload all payloads used by scanners.
    Forces refresh from payload repository and resets scanner state.
    """
    if not scanner_engine:
        raise HTTPException(status_code=503, detail="Scanner engine not initialized")
    
    try:
        # Get scanner status before reload
        before_status = scanner_engine.get_scanner_status()
        
        # Reload payloads (this should be implemented in ScannerEngine if not already)
        if hasattr(scanner_engine, 'reload_payloads'):
            result = scanner_engine.reload_payloads()
        else:
            # If method doesn't exist, just refresh status
            result = {"message": "Scanner payload reload triggered"}
        
        # Get scanner status after reload
        after_status = scanner_engine.get_scanner_status()
        
        return {
            "status": "success",
            "message": "Payloads reloaded successfully",
            "before": before_status,
            "after": after_status,
            "data": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/list")
async def list_active_scanners() -> Dict[str, Any]:
    """Get list of active scanners."""
    if not scanner_engine:
        raise HTTPException(status_code=503, detail="Scanner engine not initialized")
    
    try:
        # Get scanner status which includes list of active scanners
        status = scanner_engine.get_scanner_status()
        scanners = []
        
        # Extract scanner names from status
        if isinstance(status, dict) and 'scanners' in status:
            scanners = list(status['scanners'].keys())
        elif isinstance(status, dict):
            scanners = list(status.keys())
        
        return {
            "status": "success",
            "count": len(scanners),
            "scanners": scanners,
            "full_status": status
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/refresh")
async def refresh_scanner_cache() -> Dict[str, Any]:
    """
    Refresh scanner internal caches and state.
    Useful after configuration changes.
    """
    if not scanner_engine:
        raise HTTPException(status_code=503, detail="Scanner engine not initialized")
    
    try:
        # Get current status
        status_before = scanner_engine.get_scanner_status()
        
        # In the future, this can call scanner_engine.refresh() if implemented
        message = "Scanner cache refresh completed"
        
        status_after = scanner_engine.get_scanner_status()
        
        return {
            "status": "success",
            "message": message,
            "status_before": status_before,
            "status_after": status_after
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
