"""
FastAPI wrapper for CVSS v3.1 calculator.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field, validator

from cvss_calculator import calculate_cvss, severity


app = FastAPI(
    title="CVSS v3.1 Calculator API",
    description="API for calculating CVSS v3.1 base scores",
    version="1.0.0"
)


class CVSSRequest(BaseModel):
    """Request model for CVSS score calculation."""
    vector: str = Field(
        ...,
        description="CVSS v3.1 vector string",
        example="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    
    @validator('vector')
    def validate_vector(cls, v):
        """Validate vector format."""
        if not v.startswith("CVSS:3.1/"):
            raise ValueError("Vector must start with 'CVSS:3.1/'")
        return v


class CVSSResponse(BaseModel):
    """Response model for CVSS score calculation."""
    score: float = Field(..., description="CVSS base score (0.0 - 10.0)")
    severity: str = Field(..., description="Severity rating")


@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "name": "CVSS v3.1 Calculator API",
        "version": "1.0.0",
        "endpoints": {
            "POST /score": "Calculate CVSS score from vector",
            "GET /health": "Health check"
        }
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/score", response_model=CVSSResponse)
async def calculate_score(request: CVSSRequest) -> CVSSResponse:
    """
    Calculate CVSS v3.1 base score from vector string.
    
    Args:
        request: CVSS request with vector string
        
    Returns:
        CVSS score and severity rating
        
    Raises:
        HTTPException: If vector is invalid
    """
    try:
        score = calculate_cvss(request.vector)
        sev = severity(score)
        
        return CVSSResponse(
            score=score,
            severity=sev
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
