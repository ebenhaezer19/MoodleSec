"""
FastAPI reverse proxy for Moodle with logging and DAST scanning capabilities.
"""

import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, Request, Response, HTTPException
from pydantic import BaseModel, Field

from config import MOODLE_URL, LISTEN_PORT, LOG_DIR, MAX_LOG_ENTRIES
from utils.logger import append_log, read_logs, ensure_log_directory


app = FastAPI(
    title="Moodle Proxy Service",
    description="Reverse proxy for Moodle with request/response logging and DAST scanning",
    version="1.0.0"
)

# Initialize log directory on startup
ensure_log_directory(LOG_DIR)


class ScanRequest(BaseModel):
    """Request model for DAST scan trigger."""
    path: str = Field(..., description="Path to scan (e.g., /login/index.php)")
    method: str = Field(default="GET", description="HTTP method to use")
    parameters: Optional[Dict[str, str]] = Field(default=None, description="Optional query/body parameters")


class ScanFinding(BaseModel):
    """Model for a DAST scan finding."""
    severity: str
    category: str
    description: str
    evidence: Optional[str] = None


class ScanResult(BaseModel):
    """Response model for DAST scan results."""
    scan_id: str
    target_url: str
    timestamp: str
    findings: List[ScanFinding]
    summary: Dict[str, int]


@app.get("/health")
async def health_check() -> Dict[str, str]:
    """
    Health check endpoint.
    
    Returns:
        Dictionary with status information
    """
    return {"status": "ok"}


@app.get("/logs")
async def get_logs(limit: int = MAX_LOG_ENTRIES) -> Dict[str, Any]:
    """
    Retrieve recent log entries.
    
    Args:
        limit: Maximum number of log entries to return (default from config)
        
    Returns:
        Dictionary containing log entries and metadata
    """
    try:
        logs = read_logs(LOG_DIR, min(limit, MAX_LOG_ENTRIES))
        return {
            "count": len(logs),
            "logs": logs
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read logs: {str(e)}")


@app.post("/scan-trigger", response_model=ScanResult)
async def trigger_scan(scan_request: ScanRequest) -> ScanResult:
    """
    Trigger a simulated DAST scan of a specified path.
    
    Args:
        scan_request: Scan configuration including path and parameters
        
    Returns:
        Scan results with findings
    """
    scan_id = f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    target_url = f"{MOODLE_URL}{scan_request.path}"
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    # Simulate DAST scan findings
    findings: List[ScanFinding] = []
    
    # Simulated security checks
    if "login" in scan_request.path.lower():
        findings.append(ScanFinding(
            severity="Medium",
            category="Authentication",
            description="Login page detected - verify CSRF protection is enabled",
            evidence=f"Path contains 'login': {scan_request.path}"
        ))
    
    if scan_request.method == "POST" and not scan_request.parameters:
        findings.append(ScanFinding(
            severity="Low",
            category="Input Validation",
            description="POST request without parameters - potential for injection attacks",
            evidence=f"Method: {scan_request.method}, Parameters: None"
        ))
    
    if "admin" in scan_request.path.lower():
        findings.append(ScanFinding(
            severity="High",
            category="Access Control",
            description="Administrative path detected - ensure proper authentication is required",
            evidence=f"Path contains 'admin': {scan_request.path}"
        ))
    
    if not scan_request.path.startswith("/"):
        findings.append(ScanFinding(
            severity="Low",
            category="Configuration",
            description="Path should start with forward slash",
            evidence=f"Invalid path format: {scan_request.path}"
        ))
    
    # Add a generic finding if no specific issues detected
    if not findings:
        findings.append(ScanFinding(
            severity="Info",
            category="General",
            description="No obvious security issues detected in basic scan",
            evidence=None
        ))
    
    # Calculate summary
    summary = {
        "high": sum(1 for f in findings if f.severity == "High"),
        "medium": sum(1 for f in findings if f.severity == "Medium"),
        "low": sum(1 for f in findings if f.severity == "Low"),
        "info": sum(1 for f in findings if f.severity == "Info")
    }
    
    # Log the scan
    scan_log = {
        "type": "dast_scan",
        "scan_id": scan_id,
        "target_url": target_url,
        "method": scan_request.method,
        "parameters": scan_request.parameters,
        "findings_count": len(findings),
        "summary": summary,
        "timestamp": timestamp
    }
    append_log(LOG_DIR, scan_log)
    
    return ScanResult(
        scan_id=scan_id,
        target_url=target_url,
        timestamp=timestamp,
        findings=findings,
        summary=summary
    )


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy_request(request: Request, path: str) -> Response:
    """
    Proxy all other requests to the target Moodle instance.
    
    Args:
        request: Incoming FastAPI request
        path: Request path to forward
        
    Returns:
        Response from the target Moodle instance
    """
    # Build target URL
    target_url = f"{MOODLE_URL}/{path}"
    if request.url.query:
        target_url += f"?{request.url.query}"
    
    # Prepare request data
    headers = dict(request.headers)
    # Remove host header to avoid conflicts
    headers.pop("host", None)
    
    # Read request body
    body = await request.body()
    
    # Log the incoming request
    request_log = {
        "type": "proxy_request",
        "method": request.method,
        "path": path,
        "target_url": target_url,
        "query_params": dict(request.query_params),
        "headers": {k: v for k, v in headers.items() if k.lower() not in ["authorization", "cookie"]},
        "body_size": len(body),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    
    try:
        # Forward request to Moodle
        async with httpx.AsyncClient(follow_redirects=False, timeout=30.0) as client:
            response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body
            )
        
        # Log the response
        response_log = {
            "type": "proxy_response",
            "method": request.method,
            "path": path,
            "target_url": target_url,
            "status_code": response.status_code,
            "response_size": len(response.content),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        append_log(LOG_DIR, {**request_log, **response_log, "type": "proxy_transaction"})
        
        # Return response (remove Content-Length to avoid conflicts)
        response_headers = dict(response.headers)
        response_headers.pop("content-length", None)
        response_headers.pop("transfer-encoding", None)
        
        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=response_headers,
            media_type=response.headers.get("content-type")
        )
        
    except httpx.RequestError as e:
        error_log = {
            **request_log,
            "type": "proxy_error",
            "error": str(e),
            "error_type": type(e).__name__
        }
        append_log(LOG_DIR, error_log)
        
        raise HTTPException(
            status_code=502,
            detail=f"Failed to connect to target Moodle instance: {str(e)}"
        )
    except Exception as e:
        error_log = {
            **request_log,
            "type": "proxy_error",
            "error": str(e),
            "error_type": type(e).__name__
        }
        append_log(LOG_DIR, error_log)
        
        raise HTTPException(
            status_code=500,
            detail=f"Internal proxy error: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=LISTEN_PORT)
