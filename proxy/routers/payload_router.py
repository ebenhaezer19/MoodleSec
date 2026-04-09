"""
Payload Management API Routes

Handles:
- Importing payloads from ZAP
- Reloading payload repository
- Getting import status
- Retrieving payload statistics
"""

from fastapi import APIRouter, HTTPException, Body
from typing import Dict, Any, Optional
from database.payload_repository import PayloadRepositoryManager

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
async def import_payloads_from_zap(
    zap_host: str = Body("localhost"),
    zap_port: int = Body(8080),
    zap_api_key: str = Body("")
) -> Dict[str, Any]:
    """
    Import payloads from ZAP API.
    
    Args:
        zap_host: ZAP server hostname
        zap_port: ZAP server port
        zap_api_key: ZAP API key (optional)
    """
    if not payload_repo:
        raise HTTPException(status_code=503, detail="Payload repository not initialized")
    
    try:
        result = payload_repo.import_from_zap_api(
            zap_host=zap_host,
            zap_port=zap_port,
            zap_api_key=zap_api_key if zap_api_key else None
        )
        return {
            "status": "success",
            "data": result
        }
    except Exception as e:
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
async def reload_payloads_by_category(
    category: str = Body(...),
    force_reload: bool = Body(True)
) -> Dict[str, Any]:
    """
    Reload payloads for a specific category.
    
    Args:
        category: Vulnerability category (XSS, SQLi, CSRF, etc.)
        force_reload: Force reload even if recently cached
    """
    if not payload_repo:
        raise HTTPException(status_code=503, detail="Payload repository not initialized")
    
    try:
        result = payload_repo.reload_payloads_by_category(
            category=category,
            force_reload=force_reload
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
async def add_custom_payload(
    category: str = Body(...),
    payload: str = Body(...),
    description: str = Body(""),
    tags: list = Body(default_factory=list),
    priority: int = Body(1)
) -> Dict[str, Any]:
    """Add a custom payload to the repository."""
    if not payload_repo:
        raise HTTPException(status_code=503, detail="Payload repository not initialized")
    
    try:
        result = payload_repo.add_custom_payload(
            category=category,
            payload=payload,
            description=description,
            tags=tags,
            priority=priority
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
async def update_payload_config(
    enable_auto_reuse: bool = Body(...),
    min_success_rate: int = Body(60),
    min_effectiveness: int = Body(70),
    max_payloads_per_category: int = Body(20),
    auto_import_zap: bool = Body(True),
    deduplicate: bool = Body(True)
) -> Dict[str, Any]:
    """Update payload management configuration."""
    if not payload_repo:
        raise HTTPException(status_code=503, detail="Payload repository not initialized")
    
    try:
        config = {
            "enable_auto_reuse": enable_auto_reuse,
            "min_success_rate": min_success_rate,
            "min_effectiveness": min_effectiveness,
            "max_payloads_per_category": max_payloads_per_category,
            "auto_import_zap": auto_import_zap,
            "deduplicate": deduplicate
        }
        # TODO: Save configuration to database or config file
        return {
            "status": "success",
            "message": "Configuration updated",
            "data": config
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
