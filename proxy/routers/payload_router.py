"""
Payload Management API Routes

Handles:
- Importing payloads from ZAP
- Reloading payload repository
- Getting import status
- Retrieving payload statistics
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
from database.payload_repository import PayloadRepositoryManager

# Request/Response Models
class ImportFromZAPRequest(BaseModel):
    zap_host: str = "localhost"
    zap_port: int = 8080
    zap_api_key: Optional[str] = None

class ReloadCategoryRequest(BaseModel):
    category: str
    force_reload: Optional[bool] = True

class CustomPayloadRequest(BaseModel):
    category: str
    payload: str
    description: Optional[str] = None
    tags: Optional[list] = None
    priority: Optional[int] = 1

class PayloadConfigRequest(BaseModel):
    enable_auto_reuse: Optional[bool] = False
    min_success_rate: Optional[int] = 50
    min_effectiveness: Optional[int] = 50
    max_payloads_per_category: Optional[int] = 100
    auto_import_zap: Optional[bool] = False
    deduplicate: Optional[bool] = True

router = APIRouter(prefix="/api/payloads", tags=["payloads"])

# Shared payload repo instance (will be injected from app.py)
payload_repo: Optional[PayloadRepositoryManager] = None

def set_payload_repo(repo: PayloadRepositoryManager):
    """Set the payload repository instance."""
    global payload_repo
    payload_repo = repo

@router.get("/stats")
async def get_payload_stats() -> Dict[str, Any]:
    """Get payload repository statistics."""
    if not payload_repo:
        raise HTTPException(status_code=503, detail="Payload repository not initialized")
    
    try:
        stats = payload_repo.get_stats()
        return {
            "status": "success",
            "data": stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/import-status")
async def get_import_status() -> Dict[str, Any]:
    """Get the current import status and statistics."""
    if not payload_repo:
        raise HTTPException(status_code=503, detail="Payload repository not initialized")
    
    try:
        stats = payload_repo.get_stats()
        return {
            "status": "success",
            "importing": False,
            "total_payloads": stats.get("total_payloads", 0),
            "by_category": stats.get("by_category", {}),
            "effectiveness_avg": stats.get("avg_effectiveness", 0),
            "success_rate_avg": stats.get("avg_success_rate", 0)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/import-from-zap")
async def import_payloads_from_zap(request: ImportFromZAPRequest) -> Dict[str, Any]:
    """
    Import payloads from ZAP API.
    
    Args:
        request: ImportFromZAPRequest containing:
            - zap_host: ZAP server hostname (default: localhost)
            - zap_port: ZAP server port (default: 8080)
            - zap_api_key: ZAP API key (optional)
    """
    if not payload_repo:
        raise HTTPException(status_code=503, detail="Payload repository not initialized")
    
    try:
        result = payload_repo.import_from_zap_api(
            zap_host=request.zap_host,
            zap_port=request.zap_port,
            limit=200
        )
        return {
            "status": "success",
            "data": result
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/reload")
async def reload_all_payloads() -> Dict[str, Any]:
    """
    Reload all payloads from repository.
    Recalculates effectiveness scores and refreshes in-memory cache.
    """
    if not payload_repo:
        raise HTTPException(status_code=503, detail="Payload repository not initialized")
    
    try:
        result = payload_repo.reload_all_payloads()
        return {
            "status": "success",
            "data": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/reload-category")
async def reload_payloads_by_category(request: ReloadCategoryRequest) -> Dict[str, Any]:
    """
    Reload payloads for a specific category.
    
    Args:
        request: ReloadCategoryRequest containing:
            - category: Vulnerability category (XSS, SQLi, CSRF, etc.)
            - force_reload: Force reload even if recently cached (default: True)
    """
    if not payload_repo:
        raise HTTPException(status_code=503, detail="Payload repository not initialized")
    
    try:
        result = payload_repo.reload_payloads_by_category(
            category=request.category,
            force_reload=request.force_reload
        )
        return {
            "status": "success",
            "data": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/top/{category}")
async def get_top_payloads_by_category(
    category: str,
    limit: int = 10
) -> Dict[str, Any]:
    """Get top payloads by effectiveness for a specific category."""
    if not payload_repo:
        raise HTTPException(status_code=503, detail="Payload repository not initialized")
    
    try:
        payloads = payload_repo.get_top_payloads(category=category, limit=limit)
        return {
            "status": "success",
            "category": category,
            "count": len(payloads),
            "payloads": payloads
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{payload_id}")
async def delete_payload(payload_id: int) -> Dict[str, Any]:
    """Delete a specific payload by ID."""
    if not payload_repo:
        raise HTTPException(status_code=503, detail="Payload repository not initialized")
    
    try:
        result = payload_repo.delete_payload(payload_id=payload_id)
        return {
            "status": "success",
            "message": f"Payload {payload_id} deleted",
            "data": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/reset")
async def reset_all_payloads() -> Dict[str, Any]:
    """Reset all payloads - delete everything and start fresh."""
    if not payload_repo:
        raise HTTPException(status_code=503, detail="Payload repository not initialized")
    
    try:
        result = payload_repo.reset_database()
        return {
            "status": "success",
            "message": "Payload repository reset to empty",
            "data": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/custom")
async def add_custom_payload(request: CustomPayloadRequest) -> Dict[str, Any]:
    """Add a custom payload to the repository."""
    if not payload_repo:
        raise HTTPException(status_code=503, detail="Payload repository not initialized")
    
    try:
        result = payload_repo.add_custom_payload(
            category=request.category,
            payload=request.payload,
            description=request.description or "",
            tags=request.tags or [],
            priority=request.priority or 1
        )
        return {
            "status": "success",
            "message": "Custom payload added",
            "data": result
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/config")
async def get_payload_config() -> Dict[str, Any]:
    """Get payload management configuration."""
    if not payload_repo:
        raise HTTPException(status_code=503, detail="Payload repository not initialized")
    
    try:
        config = {
            "enable_auto_reuse": True,
            "min_success_rate": 60,
            "min_effectiveness": 70,
            "max_payloads_per_category": 20,
            "auto_import_zap": True,
            "deduplicate": True
        }
        return {
            "status": "success",
            "data": config
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/config")
async def update_payload_config(request: PayloadConfigRequest) -> Dict[str, Any]:
    """Update payload management configuration."""
    if not payload_repo:
        raise HTTPException(status_code=503, detail="Payload repository not initialized")
    
    try:
        config = {
            "enable_auto_reuse": request.enable_auto_reuse,
            "min_success_rate": request.min_success_rate,
            "min_effectiveness": request.min_effectiveness,
            "max_payloads_per_category": request.max_payloads_per_category,
            "auto_import_zap": request.auto_import_zap,
            "deduplicate": request.deduplicate
        }
        # TODO: Save configuration to database or config file
        return {
            "status": "success",
            "message": "Configuration updated",
            "data": config
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
