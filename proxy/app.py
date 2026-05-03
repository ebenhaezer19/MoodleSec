"""
FastAPI reverse proxy for Moodle with logging and DAST scanning capabilities.
"""

import os
import sys
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx
from fastapi import FastAPI, Request, Response, HTTPException, Body
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Ensure canonical package imports resolve independent of current working directory.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import (
    MOODLE_URL,
    LISTEN_PORT,
    LOG_DIR,
    MAX_LOG_ENTRIES,
    SLACK_WEBHOOK_URL,
    SLACK_ENABLED,
    ANOMALY_DETECTION_ENABLED,
    ANOMALY_LOOKBACK_SECONDS,
    ANOMALY_MIN_SCORE_TO_LOG,
    ANOMALY_BLOCK_ON_DETECTION,
    ANOMALY_BLOCK_THRESHOLD,
)
from utils.logger import append_log, read_logs, ensure_log_directory
from utils.slack_notifier import SlackNotifier
from scanners.scanner_engine import ScannerEngine
from scanners.phishing_detector import PhishingDetector
from crawler.web_crawler import WebCrawler
from risk.risk_scorer import RiskScorer
from database.scan_history import ScanHistoryDB
from database.scheduler_db import SchedulerDB
from database.payload_repository import PayloadRepositoryManager
from reporting.pdf_generator import PDFReportGenerator
from integrations.integration_manager import IntegrationManager
from integrations.ml_pipeline_integration import process_http_request, pipeline as ml_pipeline_instance
from proxy.ml.ml_manager import MLManager
from routers.payload_router import (
    router as payload_router,
    set_payload_repo,
    set_scanner_engine as payload_router_set_scanner_engine
)
from routers.scanner_router import (
    router as scanner_router,
    set_scanner_engine as scanner_router_set_scanner_engine
)




app = FastAPI(
    title="Moodle Proxy Service",
    description="Reverse proxy for Moodle with request/response logging and DAST scanning",
    version="2.0.0"
)

# Add CORS middleware to allow requests from Moodle UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "http://127.0.0.1:8000"],  # Moodle URL
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods (GET, POST, etc.)
    allow_headers=["*"],  # Allow all headers
)

# Initialize log directory on startup
ensure_log_directory(LOG_DIR)

# Initialize scanner engine
scanner_engine = ScannerEngine()

# Initialize risk scorer
risk_scorer = RiskScorer()

# Initialize scan history database
scan_history_db = ScanHistoryDB()

# Initialize scheduler database
scheduler_db = SchedulerDB()

# Initialize PDF generator
pdf_generator = PDFReportGenerator()

# Initialize integration manager
integration_manager = IntegrationManager()

# Initialize ML Manager
ml_manager = MLManager(enable_ml=True)

# Initialize Payload Repository
payload_repo = PayloadRepositoryManager()

# Register routers and inject dependencies
app.include_router(payload_router)
app.include_router(scanner_router)
set_payload_repo(payload_repo)
payload_router_set_scanner_engine(scanner_engine)  # payload_router needs scanner for reload
scanner_router_set_scanner_engine(scanner_engine)  # scanner_router status/reload endpoints

# Connect payload repository to scanner engine for active injection testing
# (scanner_engine was initialized before payload_repo existed, so we wire them now)
scanner_engine.payload_repo = payload_repo
scanner_engine.initialize_scanners()  # re-creates detectors + PayloadInjector with the repo
print(f"[Scanner Engine] Payload repository connected: {type(payload_repo).__name__}")



# Initialize Phishing Detector
MOODLE_BASE_DOMAIN = "localhost"  # Change to your actual domain
phishing_detector = PhishingDetector(moodle_base_domain=MOODLE_BASE_DOMAIN)
print(f"[Phishing Detector] Initialized with base domain: {MOODLE_BASE_DOMAIN}")

# Initialize Slack notifier (if enabled)
slack_notifier = None
if SLACK_ENABLED and SLACK_WEBHOOK_URL:
    slack_notifier = SlackNotifier(SLACK_WEBHOOK_URL)

# In-memory runtime buffers for anomaly observability in proxy traffic.
RECENT_TRAFFIC_MAXLEN = 5000
RECENT_ANOMALIES_MAXLEN = 200
recent_traffic_events = deque(maxlen=RECENT_TRAFFIC_MAXLEN)
recent_anomalies = deque(maxlen=RECENT_ANOMALIES_MAXLEN)

TRUSTED_SCANNER_HEADER_NAME = "x-moodlesec-scanner"
TRUSTED_SCANNER_HEADER_VALUE = "internal"
TRUSTED_SCANNER_ALLOWED_SOURCES = {"127.0.0.1", "::1", "localhost"}


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


class NativeAuthScanRequest(BaseModel):
    """Request model for native authenticated scan."""
    max_depth: int = Field(default=2, description="Maximum crawl depth")
    max_pages: int = Field(default=50, description="Maximum pages to scan")
    username: str = Field(default="admin", description="Username for authentication")
    password: str = Field(default="Admin@1234", description="Password for authentication")


def _get_client_ip(request: Request) -> str:
    """Resolve client IP with proxy-aware header fallback."""
    x_forwarded_for = request.headers.get("x-forwarded-for")
    if x_forwarded_for:
        return x_forwarded_for.split(",")[0].strip()

    x_real_ip = request.headers.get("x-real-ip")
    if x_real_ip:
        return x_real_ip.strip()

    if request.client and request.client.host:
        return request.client.host

    return "unknown"


def _sanitize_headers(headers: Dict[str, Any]) -> Dict[str, str]:
    """Drop sensitive headers before logging or ML processing."""
    sensitive_headers = {"authorization", "cookie", "set-cookie"}
    return {
        str(key): str(value)
        for key, value in headers.items()
        if str(key).lower() not in sensitive_headers
    }


def _is_trusted_scanner_request(request: Request) -> Tuple[bool, str]:
    """Validate trusted scanner marker using strict local-source header check."""
    marker = request.headers.get(TRUSTED_SCANNER_HEADER_NAME, "").strip().lower()
    if marker != TRUSTED_SCANNER_HEADER_VALUE:
        return False, "missing_or_invalid_scanner_header"

    source_ip = request.client.host if request.client and request.client.host else "unknown"
    if source_ip not in TRUSTED_SCANNER_ALLOWED_SOURCES:
        return False, f"scanner_header_from_untrusted_source:{source_ip}"

    return True, f"{TRUSTED_SCANNER_HEADER_NAME}={TRUSTED_SCANNER_HEADER_VALUE};source={source_ip}"


def _prune_recent_traffic(now_ts: float) -> None:
    """Keep only events within configured lookback window."""
    cutoff = now_ts - ANOMALY_LOOKBACK_SECONDS
    while recent_traffic_events and recent_traffic_events[0]["ts"] < cutoff:
        recent_traffic_events.popleft()


def _build_anomaly_payload(
    request: Request,
    target_url: str,
    request_headers: Dict[str, str],
    request_body: bytes,
    response_status_code: int,
    response_size: int,
    response_time_ms: int,
    response_headers: Dict[str, str],
    request_count_last_minute: int,
    unique_ips_last_minute: int,
    error_rate_last_minute: float,
) -> Dict[str, Any]:
    """Map proxy transaction into anomaly detector feature schema."""
    decoded_body = request_body[:4096].decode("utf-8", errors="ignore") if request_body else ""

    return {
        "request": {
            "url": target_url,
            "method": request.method,
            "headers": _sanitize_headers(request_headers),
            "body": decoded_body,
        },
        "response": {
            "status_code": int(response_status_code),
            "size": int(response_size),
            "time": int(response_time_ms),
            "headers": _sanitize_headers(response_headers),
        },
        "request_count_last_minute": int(request_count_last_minute),
        "unique_ips_last_minute": int(max(unique_ips_last_minute, 1)),
        "error_rate_last_minute": float(error_rate_last_minute),
    }


@app.get("/health")
async def health_check() -> Dict[str, str]:
    """
    Health check endpoint.
    
    Returns:
        Dictionary with status information
    """
    return {"status": "ok"}


@app.get("/scanners/status")
async def get_scanners_status() -> Dict[str, Any]:
    """
    Get status of all available scanners.
    
    Returns:
        Dictionary with scanner status information
    """
    return scanner_engine.get_scanner_status()


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
    Trigger a comprehensive DAST scan of a specified path.
    
    Args:
        scan_request: Scan configuration including path and parameters
        
    Returns:
        Scan results with findings
    """
    target_url = f"{MOODLE_URL}{scan_request.path}"
    
    # Fetch the target page to analyze
    response_body = ""
    response_headers = {}
    status_code = 200
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.request(
                method=scan_request.method,
                url=target_url,
                params=scan_request.parameters if scan_request.method == "GET" else None,
                data=scan_request.parameters if scan_request.method == "POST" else None
            )
            response_body = response.text
            response_headers = dict(response.headers)
            status_code = response.status_code
    except Exception as e:
        # If request fails, still run scanners on URL/params
        pass
    
    # Run comprehensive scan using scanner engine
    scan_results = await scanner_engine.scan(
        url=target_url,
        method=scan_request.method,
        params=scan_request.parameters,
        response_body=response_body,
        response_headers=response_headers,
        status_code=status_code
    )
    
    # Enrich findings with risk scores
    enriched_findings = risk_scorer.batch_enrich_findings(scan_results['findings'])
    
    # === ML FILTERING: FP Reducer + Severity Predictor (real-time inference) ===
    print(f"[DAST Scan] BEFORE ML: {len(enriched_findings)} findings")
    ml_results = ml_manager.filter_findings(enriched_findings)
    enriched_findings = ml_results['findings']
    print(f"[DAST Scan] AFTER ML: {len(enriched_findings)} findings "
          f"({ml_results['filtered_count']} FPs removed, "
          f"{ml_results['severity_adjusted_count']} severities adjusted)")
    
    # Recalculate summary after ML filtering
    ml_summary = {
        'critical': sum(1 for f in enriched_findings if f.get('severity', '').lower() == 'critical'),
        'high':     sum(1 for f in enriched_findings if f.get('severity', '').lower() == 'high'),
        'medium':   sum(1 for f in enriched_findings if f.get('severity', '').lower() == 'medium'),
        'low':      sum(1 for f in enriched_findings if f.get('severity', '').lower() == 'low'),
        'info':     sum(1 for f in enriched_findings if f.get('severity', '').lower() == 'info'),
    }
    
    # Log the scan
    scan_log = {
        "type": "dast_scan",
        "scan_id": scan_results['scan_id'],
        "target_url": target_url,
        "method": scan_request.method,
        "parameters": scan_request.parameters,
        "findings_count": len(enriched_findings),
        "ml_stats": {
            "original_findings": ml_results['original_count'],
            "false_positives_removed": ml_results['filtered_count'],
            "actual_vulnerabilities": ml_results['final_count'],
            "severity_adjusted": ml_results['severity_adjusted_count'],
        },
        "summary": ml_summary,
        "timestamp": scan_results['timestamp']
    }
    append_log(LOG_DIR, scan_log)
    
    # Save to database
    scan_data = {
        'scan_id': scan_results['scan_id'],
        'scan_type': 'dast',
        'target_url': target_url,
        'timestamp': scan_results['timestamp'],
        'total_findings': len(enriched_findings),
        'ml_stats': ml_results,
        'summary': ml_summary,
        'findings': enriched_findings
    }
    scan_history_db.save_scan(scan_data)
    print(f"[DAST Scan] Saved scan {scan_results['scan_id']} to database with {len(enriched_findings)} findings")
    
    # Convert to response model
    findings = [
        ScanFinding(
            severity=f.get('severity', 'Info'),
            category=f.get('category', 'General'),
            description=f.get('description', ''),
            evidence=f.get('evidence')
        )
        for f in enriched_findings
    ]
    
    return ScanResult(
        scan_id=scan_results['scan_id'],
        target_url=target_url,
        timestamp=scan_results['timestamp'],
        findings=findings,
        summary=ml_summary
    )


@app.post("/crawl")
async def crawl_site(max_depth: int = 3, max_pages: int = 50) -> Dict[str, Any]:
    """
    Crawl the Moodle site to discover all endpoints.
    
    Args:
        max_depth: Maximum crawl depth
        max_pages: Maximum pages to crawl
        
    Returns:
        Crawl results with discovered endpoints and forms
    """
    try:
        crawler = WebCrawler(
            base_url=MOODLE_URL,
            max_depth=max_depth,
            max_pages=max_pages
        )
        
        results = await crawler.crawl()
        
        return {
            'status': 'success',
            'crawl_results': results,
            'scan_targets': crawler.get_endpoints_for_scanning()
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Crawl failed: {str(e)}")

@app.post("/scan-complete")
async def complete_security_scan(target_url: str) -> Dict[str, Any]:
    """
    Complete security scan: DAST + Auth + API
    """
    # Existing DAST scan
    dast_results = await full_site_scan()
    
    # P3: Authentication & API scan
    from auth.session_tester import SessionTester
    from auth.rbac_tester import RBACTester
    from auth.oauth_tester import OAuthTester
    from api.rest_scanner import RESTScanner
    
    session = SessionTester(target_url)
    rbac = RBACTester(target_url)
    oauth = OAuthTester(target_url)
    api_scanner = RESTScanner(target_url)
    
    auth_results = {
        'session': await session.test_all(),
        'rbac': await rbac.test_all(),
        'oauth': await oauth.test_all(),
        'api': await api_scanner.scan_all()
    }
    
    await session.close()
    await rbac.close()
    await oauth.close()
    await api_scanner.close()
    
    return {
        'dast': dast_results,
        'authentication': auth_results,
        'total_findings': dast_results['total_findings'] + sum(
            r['total_findings'] for r in auth_results.values()
        )
    }

@app.post("/scan-full")
async def full_site_scan(max_depth: int = 2, max_pages: int = 30) -> Dict[str, Any]:
    """
    Perform full site scan: crawl + scan all discovered endpoints.
    
    Args:
        max_depth: Maximum crawl depth
        max_pages: Maximum pages to crawl
        
    Returns:
        Complete scan results with all findings
    """
    scan_id = f"full_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    timestamp = datetime.now().isoformat() + "Z"
    
    try:
        # Step 1: Crawl site
        print(f"[Full Scan] Starting crawl...")
        crawler = WebCrawler(
            base_url=MOODLE_URL,
            max_depth=max_depth,
            max_pages=max_pages
        )
        
        crawl_results = await crawler.crawl()
        targets = crawler.get_endpoints_for_scanning()
        
        print(f"[Full Scan] Discovered {len(targets)} endpoints")
        
        # Step 2: Scan all discovered endpoints
        all_findings = []
        scanned_count = 0
        
        for target in targets[:50]:  # Limit to 50 endpoints to avoid timeout
            try:
                # Fetch target page
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.request(
                        method=target['method'],
                        url=target['url'],
                        params=target.get('parameters') if target['method'] == 'GET' else None,
                        data=target.get('parameters') if target['method'] == 'POST' else None
                    )
                    response_body = response.text
                    response_headers = dict(response.headers)
                    status_code = response.status_code
                
                # Scan endpoint
                scan_results = await scanner_engine.scan(
                    url=target['url'],
                    method=target['method'],
                    params=target.get('parameters'),
                    response_body=response_body,
                    response_headers=response_headers,
                    status_code=status_code
                )
                
                # Enrich findings with risk scores
                enriched_findings = risk_scorer.batch_enrich_findings(scan_results['findings'])
                all_findings.extend(enriched_findings)
                scanned_count += 1
                
            except Exception as e:
                print(f"[Full Scan] Error scanning {target['url']}: {str(e)}")
                continue
        
        # Step 3: ML Processing
        print(f"[Full Scan] BEFORE ML: {len(all_findings)} findings")
        
        # Apply ML-enhanced processing
        ml_results = ml_manager.filter_findings(all_findings)
        filtered_findings = ml_results['findings']
        
        print(f"[Full Scan] AFTER ML: {len(filtered_findings)} findings")
        print(f"[Full Scan] ML Stats: {ml_results['filtered_count']} FPs filtered, "
              f"{ml_results['severity_adjusted_count']} severities adjusted")
        
        # Step 4: Aggregate results
        # Sort by risk score
        filtered_findings.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
        
        # Calculate summary
        summary = {
            'critical': sum(1 for f in filtered_findings if f.get('severity', '').lower() == 'critical'),
            'high': sum(1 for f in filtered_findings if f.get('severity', '').lower() == 'high'),
            'medium': sum(1 for f in filtered_findings if f.get('severity', '').lower() == 'medium'),
            'low': sum(1 for f in filtered_findings if f.get('severity', '').lower() == 'low'),
            'info': sum(1 for f in filtered_findings if f.get('severity', '').lower() == 'info')
        }
        
        # Log the full scan
        scan_log = {
            "type": "full_site_scan",
            "scan_id": scan_id,
            "base_url": MOODLE_URL,
            "endpoints_discovered": len(targets),
            "endpoints_scanned": scanned_count,
            "findings_count": len(filtered_findings),
            "ml_stats": {
                "original_findings": ml_results['original_count'],
                "fp_filtered": ml_results['filtered_count'],
                "severity_adjusted": ml_results['severity_adjusted_count']
            },
            "summary": summary,
            "timestamp": timestamp
        }
        append_log(LOG_DIR, scan_log)
        
        # Save to database for historical tracking
        scan_data_for_db = {
            'scan_id': scan_id,
            'scan_type': 'full',
            'target_url': MOODLE_URL,
            'timestamp': timestamp,
            'endpoints_discovered': len(targets),
            'endpoints_scanned': scanned_count,
            'total_findings': len(filtered_findings),
            'ml_stats': ml_results,
            'summary': summary,
            'findings': filtered_findings
        }
        scan_history_db.save_scan(scan_data_for_db)
        
        # Prepare result
        result = {
            'scan_id': scan_id,
            'timestamp': timestamp,
            'target_url': MOODLE_URL,
            'crawl_statistics': crawl_results['statistics'],
            'endpoints_discovered': len(targets),
            'endpoints_scanned': scanned_count,
            'total_findings': len(filtered_findings),
            'ml_stats': ml_results,
            'summary': summary,
            'findings': filtered_findings[:100],  # Return top 100 findings
            'top_risks': filtered_findings[:10]  # Top 10 highest risk findings
        }
        
        # Send Slack notification if enabled
        if slack_notifier:
            try:
                print(f"[Slack] Sending scan complete notification...")
                success = await slack_notifier.send_scan_complete(result)
                print(f"[Slack] Scan complete notification: {'✅ SUCCESS' if success else '❌ FAILED'}")
                
                # Send critical alerts for critical findings
                critical_findings = [f for f in all_findings if f.get('severity', '').lower() == 'critical']
                if critical_findings:
                    print(f"[Slack] Sending {len(critical_findings[:3])} critical alerts...")
                    for finding in critical_findings[:3]:  # Alert for top 3 critical
                        alert_success = await slack_notifier.send_critical_alert(finding, scan_id)
                        print(f"[Slack] Critical alert: {'✅ SUCCESS' if alert_success else '❌ FAILED'}")
            except Exception as e:
                import traceback
                print(f"[Slack] Notification failed: {str(e)}")
                print(f"[Slack] Traceback: {traceback.format_exc()}")
        
        return result
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Full scan failed: {str(e)}")


@app.get("/risk/calculate")
async def calculate_risk(
    category: str,
    severity: str,
    url: str = ""
) -> Dict[str, Any]:
    """
    Calculate risk score for a finding.
    
    Args:
        category: Vulnerability category
        severity: Severity level
        url: Target URL for context
        
    Returns:
        Risk score details
    """
    finding = {
        'category': category,
        'severity': severity,
        'url': url,
        'evidence': url
    }
    
    risk_info = risk_scorer.calculate_risk_score(finding)
    return risk_info


@app.get("/trends")
async def get_trends(days: int = 30) -> Dict[str, Any]:
    """
    Get vulnerability trend data.
    
    Args:
        days: Number of days to analyze
        
    Returns:
        Trend data
    """
    try:
        trends = scan_history_db.get_trend_data(days)
        return trends
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get trends: {str(e)}")


@app.get("/regressions")
async def detect_regressions(lookback_scans: int = 5) -> Dict[str, Any]:
    """
    Detect new vulnerabilities (regressions).
    
    Args:
        lookback_scans: Number of recent scans to compare
        
    Returns:
        List of new findings
    """
    try:
        regressions = scan_history_db.detect_regressions(lookback_scans)
        return {
            'regressions_count': len(regressions),
            'regressions': regressions
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to detect regressions: {str(e)}")


@app.get("/fix-rate")
async def get_fix_rate(days: int = 30) -> Dict[str, Any]:
    """
    Get vulnerability fix rate statistics.
    
    Args:
        days: Period to analyze
        
    Returns:
        Fix rate statistics
    """
    try:
        fix_rate = scan_history_db.get_fix_rate(days)
        return fix_rate
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get fix rate: {str(e)}")


@app.get("/reports/executive-summary")
async def generate_executive_summary(scan_id: str) -> Response:
    """
    Generate executive summary PDF report.
    
    Args:
        scan_id: Scan ID to generate report for
        
    Returns:
        PDF file
    """
    try:
        print(f"[Report] Generating executive summary for scan: {scan_id}")
        
        # Get complete scan data with findings from database
        scan_data = scan_history_db.get_scan_with_findings(scan_id)
        
        if not scan_data:
            print(f"[Report] Scan not found: {scan_id}")
            raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")
        
        print(f"[Report] Scan data retrieved: {scan_data.get('scan_type', 'unknown')} scan with {scan_data.get('total_findings', 0)} findings")
        
        # Generate PDF
        pdf_bytes = pdf_generator.generate_executive_summary(scan_data)
        
        print(f"[Report] PDF generated successfully, size: {len(pdf_bytes)} bytes")
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=executive_summary_{scan_id}.pdf"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_detail = f"Failed to generate report: {str(e)}\n{traceback.format_exc()}"
        print(f"[Report] ERROR: {error_detail}")
        raise HTTPException(status_code=500, detail=error_detail)


@app.get("/reports/compliance")
async def generate_compliance_report(scan_id: str, framework: str = "OWASP") -> Response:
    """
    Generate compliance report PDF.
    
    Args:
        scan_id: Scan ID
        framework: Compliance framework (OWASP, PCI-DSS)
        
    Returns:
        PDF file
    """
    try:
        # Get complete scan data with findings from database
        scan_data = scan_history_db.get_scan_with_findings(scan_id)
        
        if not scan_data:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        pdf_bytes = pdf_generator.generate_compliance_report(scan_data, framework)
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=compliance_{framework}_{scan_id}.pdf"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate compliance report: {str(e)}")


@app.get("/reports/auth-api-summary")
async def generate_auth_api_report(scan_id: str) -> Response:
    """
    Generate Auth & API Security Scan PDF report.
    
    Args:
        scan_id: Scan ID to generate report for
        
    Returns:
        PDF file with scan results
    """
    try:
        # Get complete scan data with findings from database
        scan_data = scan_history_db.get_scan_with_findings(scan_id)
        
        if not scan_data:
            raise HTTPException(status_code=404, detail=f"Scan not found: {scan_id}")
        
        # Check if it's an auth or API scan
        if scan_data['scan_type'] not in ['authentication', 'api']:
            raise HTTPException(status_code=400, detail="This endpoint is only for authentication and API scans")
        
        # Generate PDF using existing generator
        pdf_bytes = pdf_generator.generate_executive_summary(scan_data)
        
        scan_type = scan_data['scan_type']
        filename = f"{scan_type}_security_report_{scan_id}.pdf"
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        error_detail = f"Failed to generate report: {str(e)}\n{traceback.format_exc()}"
        print(error_detail)  # Log to console
        raise HTTPException(status_code=500, detail=error_detail)


@app.post("/integrations/webhook")
async def send_webhook_notification(
    webhook_type: str,
    message: Dict[str, Any],
    config: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Send webhook notification.
    
    Args:
        webhook_type: Type of webhook (slack, teams, discord, custom)
        message: Message data
        config: Webhook configuration
        
    Returns:
        Success status
    """
    try:
        success = await integration_manager.send_webhook(webhook_type, message, config)
        return {'success': success}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Webhook failed: {str(e)}")


@app.post("/integrations/ticket")
async def create_ticket(
    ticketing_type: str,
    ticket_data: Dict[str, Any],
    config: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Create ticket in ticketing system.
    
    Args:
        ticketing_type: Type of ticketing system (jira, servicenow, github)
        ticket_data: Ticket information
        config: Ticketing system configuration
        
    Returns:
        Ticket ID
    """
    try:
        ticket_id = await integration_manager.create_ticket(ticketing_type, ticket_data, config)
        
        if ticket_id:
            return {'success': True, 'ticket_id': ticket_id}
        else:
            return {'success': False, 'error': 'Failed to create ticket'}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ticket creation failed: {str(e)}")


class ScheduleRequest(BaseModel):
    """Request model for creating a schedule."""
    target_url: str
    cron_expression: str
    scan_type: str = "full"
    priority: str = "normal"


@app.post("/schedule/create")
async def create_schedule(schedule_req: ScheduleRequest) -> Dict[str, Any]:
    """
    Create a scheduled scan.
    
    Args:
        schedule_req: Schedule request data
        
    Returns:
        Schedule details
    """
    try:
        import uuid
        from datetime import datetime
        
        # Create schedule ID
        schedule_id = str(uuid.uuid4())
        
        # Calculate next run time
        next_run = scheduler_db.calculate_next_run(schedule_req.cron_expression)
        
        # Create schedule data
        schedule_info = {
            'schedule_id': schedule_id,
            'target_url': schedule_req.target_url,
            'cron_expression': schedule_req.cron_expression,
            'scan_type': schedule_req.scan_type,
            'priority': schedule_req.priority,
            'next_run': next_run
        }
        
        # Save to database
        result = scheduler_db.create_schedule(schedule_info)
        
        if 'error' in result:
            raise HTTPException(status_code=400, detail=result['error'])
        
        return result
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create schedule: {str(e)}")


@app.get("/schedule/list")
async def list_schedules() -> List[Dict[str, Any]]:
    """
    Get all scheduled scans.
    
    Returns:
        List of schedules
    """
    try:
        schedules = scheduler_db.get_all_schedules()
        return schedules
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to list schedules: {str(e)}")


@app.delete("/schedule/{schedule_id}")
async def delete_schedule(schedule_id: str) -> Dict[str, Any]:
    """
    Delete a scheduled scan.
    
    Args:
        schedule_id: Schedule ID to delete
        
    Returns:
        Success status
    """
    try:
        success = scheduler_db.delete_schedule(schedule_id)
        
        if success:
            return {'success': True, 'message': 'Schedule deleted'}
        else:
            raise HTTPException(status_code=404, detail='Schedule not found')
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete schedule: {str(e)}")


@app.get("/schedule/{schedule_id}/history")
async def get_schedule_history(schedule_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Get execution history for a schedule.
    
    Args:
        schedule_id: Schedule ID
        limit: Maximum number of records
        
    Returns:
        Execution history
    """
    try:
        history = scheduler_db.get_execution_history(schedule_id, limit)
        return history
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get history: {str(e)}")


@app.get("/scan-history")
async def get_scan_history_endpoint(limit: int = 10) -> Dict[str, Any]:
    """
    Get scan history from database.
    
    Args:
        limit: Maximum number of scans to return
        
    Returns:
        Dictionary containing scans array
    """
    try:
        scans = scan_history_db.get_scan_history(limit)
        return {
            'scans': scans,
            'total': len(scans)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get scan history: {str(e)}")


@app.post("/scan-auth")
async def scan_authentication() -> Dict[str, Any]:
    """
    Comprehensive authentication & authorization security scan.
    
    Tests:
    - Session management
    - RBAC (Role-Based Access Control)
    - OAuth/SSO security
    
    Returns:
        Complete authentication security assessment
    """
    from auth.session_tester import SessionTester
    from auth.rbac_tester import RBACTester
    from auth.oauth_tester import OAuthTester
    
    scan_id = f"auth_scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    print(f"[Auth Scan] Starting authentication security scan: {scan_id}")
    
    results = {
        'scan_id': scan_id,
        'scan_type': 'authentication',
        'target_url': MOODLE_URL,
        'timestamp': timestamp,
        'tests': {}
    }
    
    try:
        # Test 1: Session Management
        print("[Auth Scan] Testing session management...")
        session_tester = SessionTester(MOODLE_URL)
        results['tests']['session'] = await session_tester.test_all()
        await session_tester.close()
        
        # Test 2: RBAC
        print("[Auth Scan] Testing RBAC...")
        rbac_tester = RBACTester(MOODLE_URL)
        results['tests']['rbac'] = await rbac_tester.test_all()
        await rbac_tester.close()
        
        # Test 3: OAuth/SSO
        print("[Auth Scan] Testing OAuth/SSO...")
        oauth_tester = OAuthTester(MOODLE_URL)
        results['tests']['oauth'] = await oauth_tester.test_all()
        await oauth_tester.close()
        
        # Compile all findings
        all_findings = []
        for test_name, test_results in results['tests'].items():
            all_findings.extend(test_results.get('findings', []))
        
        # Enrich findings with risk scores
        print("=" * 80)
        print(f"[Auth Scan] BEFORE ENRICHMENT: {len(all_findings)} findings")
        if all_findings:
            print(f"[Auth Scan] Sample finding before: risk_score={all_findings[0].get('risk_score', 'NOT SET')}")
            print(f"[Auth Scan] Finding details: category={all_findings[0].get('category')}, severity={all_findings[0].get('severity')}, description={all_findings[0].get('description')}")
        
        print(f"[Auth Scan] Enriching {len(all_findings)} findings with risk scores...")
        all_findings = risk_scorer.batch_enrich_findings(all_findings)
        
        print(f"[Auth Scan] AFTER ENRICHMENT: {len(all_findings)} findings")
        if all_findings:
            print(f"[Auth Scan] Sample finding after: risk_score={all_findings[0].get('risk_score', 'NOT SET')}")
        print("=" * 80)
        
        # ML-Enhanced Processing
        print(f"[Auth Scan] ML Processing: Filtering false positives and adjusting severity...")
        print(f"[Auth Scan] Before ML: {len(all_findings)} findings")
        ml_result = ml_manager.filter_findings(all_findings, context={'environment': 'production'})
        
        # Show what was filtered
        if ml_result['filtered_count'] > 0:
            print(f"[Auth Scan] ⚠️  WARNING: {ml_result['filtered_count']} findings marked as FALSE POSITIVE by ML:")
            for i, finding in enumerate(all_findings):
                if finding not in ml_result['findings']:
                    print(f"[Auth Scan]   - Filtered #{i+1}: {finding.get('category')} | {finding.get('severity')} | {finding.get('description')[:60]}...")
        
        all_findings = ml_result['findings']
        print(f"[Auth Scan] ML Results: {ml_result['filtered_count']} FPs filtered, {ml_result['severity_adjusted_count']} severities adjusted")
        print(f"[Auth Scan] Final count: {ml_result['final_count']} findings")
        print(f"[Auth Scan] After ML: {len(all_findings)} findings remain")
        
        results['total_findings'] = len(all_findings)
        results['all_findings'] = all_findings
        results['summary'] = _generate_finding_summary(all_findings)
        
        # Debug: Check if PoC exists in findings
        for finding in all_findings:
            if 'poc' in finding:
                print(f"[Auth Scan] Finding has PoC: {finding.get('category')} - PoC keys: {list(finding['poc'].keys())}")
            else:
                print(f"[Auth Scan] Finding WITHOUT PoC: {finding.get('category')}")
        
        # Save to database
        scan_data = {
            'scan_id': scan_id,
            'scan_type': 'authentication',
            'target_url': MOODLE_URL,
            'timestamp': timestamp,
            'total_findings': len(all_findings),
            'summary': results['summary'],
            'findings': all_findings
        }
        print(f"[Auth Scan] Saving {len(all_findings)} findings to database...")
        scan_history_db.save_scan(scan_data)
        print(f"[Auth Scan] Database save complete")
        
        print(f"[Auth Scan] Complete! Found {len(all_findings)} issues")
        
        # Send Slack notification if enabled
        if slack_notifier and len(all_findings) > 0:
            try:
                await slack_notifier.send_scan_complete({
                    'scan_id': scan_id,
                    'target_url': MOODLE_URL,
                    'endpoints_scanned': 3,  # 3 test modules
                    'total_findings': len(all_findings),
                    'summary': results['summary']
                })
            except Exception as e:
                print(f"[Slack] Notification failed: {str(e)}")
        
        return results
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Auth scan failed: {str(e)}")


@app.post("/test/rbac")
async def test_rbac(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Dedicated RBAC (Role-Based Access Control) security test endpoint.
    
    Tests:
    - Unauthenticated access to admin endpoints
    - Privilege escalation vulnerabilities
    - IDOR (Insecure Direct Object References)
    - Function-level access control
    - Role enumeration
    
    Request body:
        {
            "base_url": "http://localhost/moodle"  # Optional, defaults to configured MOODLE_URL
        }
    
    Returns:
        Detailed RBAC test results with findings
    """
    from auth.rbac_tester import RBACTester
    
    # Get base URL from request or use default
    base_url = request.get('base_url', MOODLE_URL)
    
    scan_id = f"rbac_test_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    print(f"[RBAC Test] Starting RBAC security test: {scan_id}")
    print(f"[RBAC Test] Target: {base_url}")
    
    try:
        # Run RBAC tests
        rbac_tester = RBACTester(base_url)
        results = await rbac_tester.test_all()
        await rbac_tester.close()
        
        # Add metadata
        results['scan_id'] = scan_id
        results['scan_type'] = 'rbac'
        results['target_url'] = base_url
        results['timestamp'] = timestamp
        
        # Enrich findings with risk scores
        findings = results.get('findings', [])
        if findings:
            print(f"[RBAC Test] Enriching {len(findings)} findings with risk scores...")
            findings = risk_scorer.batch_enrich_findings(findings)
            results['findings'] = findings
            results['total_findings'] = len(findings)
            results['summary'] = _generate_finding_summary(findings)
        else:
            results['total_findings'] = 0
            results['summary'] = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        
        # Save to database
        scan_data = {
            'scan_id': scan_id,
            'scan_type': 'rbac',
            'target_url': base_url,
            'timestamp': timestamp,
            'total_findings': results['total_findings'],
            'summary': results['summary'],
            'findings': findings
        }
        scan_history_db.save_scan(scan_data)
        
        print(f"[RBAC Test] Complete! Found {results['total_findings']} issues")
        
        # Send Slack notification if enabled
        if slack_notifier and results['total_findings'] > 0:
            try:
                await slack_notifier.send_scan_complete({
                    'scan_id': scan_id,
                    'target_url': base_url,
                    'endpoints_scanned': len(results.get('tests', {}).get('unauth_access', {}).get('accessible_endpoints', [])),
                    'total_findings': results['total_findings'],
                    'summary': results['summary']
                })
            except Exception as e:
                print(f"[Slack] Notification failed: {str(e)}")
        
        return results
    
    except Exception as e:
        print(f"[RBAC Test] Error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"RBAC test failed: {str(e)}")


@app.post("/scan-api")
async def scan_api() -> Dict[str, Any]:
    """
    Comprehensive REST API security scan.
    
    Tests:
    - API endpoint discovery
    - Authentication bypass
    - Input validation
    - Rate limiting
    - Mass assignment
    - Data exposure
    
    Returns:
        Complete API security assessment
    """
    from api.rest_scanner import RESTScanner
    from api.api_discovery import APIDiscovery
    
    scan_id = f"api_scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    print(f"[API Scan] Starting API security scan: {scan_id}")
    
    results = {
        'scan_id': scan_id,
        'scan_type': 'api',
        'target_url': MOODLE_URL,
        'timestamp': timestamp
    }
    
    try:
        # API Discovery
        print("[API Scan] Discovering API endpoints...")
        api_discovery = APIDiscovery(MOODLE_URL)
        discovery_results = await api_discovery.discover_all()
        await api_discovery.close()
        
        # API Security Scan
        print("[API Scan] Running security tests...")
        api_scanner = RESTScanner(MOODLE_URL)
        scan_results = await api_scanner.scan_all()
        await api_scanner.close()
        
        results['discovery'] = discovery_results
        results['security_tests'] = scan_results
        
        # Enrich findings with risk scores
        print(f"[API Scan] Enriching {len(scan_results['findings'])} findings with risk scores...")
        enriched_findings = risk_scorer.batch_enrich_findings(scan_results['findings'])
        
        # === ML FILTERING: FP Reducer + Severity Predictor (real-time inference) ===
        print(f"[API Scan] BEFORE ML: {len(enriched_findings)} findings")
        ml_result = ml_manager.filter_findings(enriched_findings)
        enriched_findings = ml_result['findings']
        print(f"[API Scan] AFTER ML: {len(enriched_findings)} findings "
              f"({ml_result['filtered_count']} FPs removed, "
              f"{ml_result['severity_adjusted_count']} severities adjusted)")
        
        results['total_findings'] = len(enriched_findings)
        results['all_findings'] = enriched_findings
        results['ml_stats'] = {
            'original_count': ml_result['original_count'],
            'fp_filtered': ml_result['filtered_count'],
            'severity_adjusted': ml_result['severity_adjusted_count'],
            'final_count': ml_result['final_count'],
        }
        results['summary'] = _generate_finding_summary(enriched_findings)
        results['discovered_endpoints'] = scan_results['discovered_endpoints']
        
        # Save to database
        scan_data = {
            'scan_id': scan_id,
            'scan_type': 'api',
            'target_url': MOODLE_URL,
            'timestamp': timestamp,
            'total_findings': results['total_findings'],
            'ml_stats': ml_result,
            'summary': results['summary'],
            'findings': results['all_findings']
        }
        scan_history_db.save_scan(scan_data)
        
        print(f"[API Scan] Complete! Found {results['total_findings']} issues")
        print(f"[API Scan] Discovered {len(results['discovered_endpoints'])} endpoints")
        
        # Send Slack notification if enabled
        if slack_notifier and results['total_findings'] > 0:
            try:
                await slack_notifier.send_scan_complete({
                    'scan_id': scan_id,
                    'target_url': MOODLE_URL,
                    'endpoints_scanned': len(results['discovered_endpoints']),
                    'total_findings': results['total_findings'],
                    'summary': results['summary']
                })
            except Exception as e:
                print(f"[Slack] Notification failed: {str(e)}")
        
        return results
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"API scan failed: {str(e)}")



@app.post("/ml/post-process-zap")
async def ml_post_process_zap(findings: List[Dict[str, Any]] = Body(...)) -> Dict[str, Any]:
    """
    Real-time ML post-processing for ZAP scan findings.

    Called by moodle-plugin (zap_scan.php / zap_results.php) immediately after
    a ZAP scan completes so that FP Reducer and Severity Predictor are applied
    even though ZAP saves directly to the Moodle DB (bypassing the proxy).

    Args:
        findings: List of raw ZAP findings (JSON array in request body)

    Returns:
        ML-filtered findings + ml_stats summary
    """
    if not findings:
        return {
            'findings': [],
            'ml_stats': {
                'original_count': 0,
                'fp_filtered': 0,
                'severity_adjusted': 0,
                'final_count': 0,
            },
            'ml_enabled': ml_manager.enable_ml,
        }

    print(f"[ZAP ML Post-Process] Received {len(findings)} raw ZAP findings")

    # Run ML pipeline (FP Reducer + Severity Predictor)
    ml_result = ml_manager.filter_findings(findings)

    print(f"[ZAP ML Post-Process] Done: {ml_result['filtered_count']} FPs removed, "
          f"{ml_result['severity_adjusted_count']} severities adjusted, "
          f"{ml_result['final_count']} remain")

    return {
        'findings': ml_result['findings'],
        'ml_stats': {
            'original_count': ml_result['original_count'],
            'fp_filtered': ml_result['filtered_count'],
            'severity_adjusted': ml_result['severity_adjusted_count'],
            'final_count': ml_result['final_count'],
        },
        'ml_enabled': True,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
    }


@app.post("/api/scan-native-auth")
async def scan_native_authenticated(request: NativeAuthScanRequest) -> Dict[str, Any]:
    """
    Native authenticated full-site vulnerability scan.

    Process:
    1. Authenticate as specified user
    2. Crawl authenticated areas of the application
    3. Scan discovered endpoints with authenticated session
    4. Enrich findings with risk scores
    5. Filter false positives using ML
    6. Save results to database

    Args:
        request: NativeAuthScanRequest with credentials and options

    Returns:
        Complete authenticated scan results with findings and statistics
    """
    # Extract parameters from request
    max_depth = request.max_depth
    max_pages = request.max_pages
    username = request.username
    password = request.password
    scan_id = f"native_auth_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    timestamp = datetime.now().isoformat() + "Z"
    
    print(f"\n{'='*80}")
    print(f"[Native Auth Scan] Starting authenticated vulnerability scan: {scan_id}")
    print(f"[Native Auth Scan] Target: {MOODLE_URL}")
    print(f"[Native Auth Scan] User: {username}")
    print(f"[Native Auth Scan] Max depth: {max_depth}, Max pages: {max_pages}")
    print(f"{'='*80}\n")
    
    try:
        # Step 1: Authenticate
        print(f"[Native Auth Scan] STEP 1: Authenticating as {username}...")
        auth_client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
        
        # Get login page to extract logintoken
        login_page_url = f"{MOODLE_URL}/login/index.php"
        login_response = await auth_client.get(login_page_url)
        login_html = login_response.text
        
        # Extract logintoken
        import re
        token_match = re.search(r'name=["\']logintoken["\'].*?value=["\']([^"\']+)["\']', login_html)
        if not token_match:
            raise ValueError("Failed to extract logintoken from login page")
        
        logintoken = token_match.group(1)
        print(f"[Native Auth Scan] Extracted logintoken: {logintoken[:20]}...")
        
        # Perform login
        login_data = {
            'username': username,
            'password': password,
            'logintoken': logintoken,
            'rememberusername': 1
        }
        
        login_post_response = await auth_client.post(login_page_url, data=login_data)
        
        # Check if login successful (look for redirect or absence of login form in response)
        if 'login' in login_post_response.text.lower() and len(login_post_response.text) < 5000:
            # If response is still showing login form and is small, login might have failed
            print(f"[Native Auth Scan] ⚠️  WARNING: Login response appears to be login page")
            print(f"[Native Auth Scan] Response length: {len(login_post_response.text)}")
            print(f"[Native Auth Scan] Response preview: {login_post_response.text[:500]}")
        else:
            print(f"[Native Auth Scan] ✓ Login successful (redirected, session established)")
        
        # Step 2: Crawl authenticated site
        print(f"\n[Native Auth Scan] STEP 2: Crawling authenticated site...")
        
        # Create a custom crawler that uses the authenticated session
        targets = []
        visited_urls = set()
        discovered_endpoints = []
        
        async def crawl_authenticated_url(url: str, depth: int = 0):
            """Recursively crawl with authenticated session."""
            if depth > max_depth or len(visited_urls) >= max_pages:
                return
            
            if url in visited_urls:
                return
            
            visited_urls.add(url)
            
            try:
                print(f"[Native Auth Scan] Crawling: {url} (depth {depth})")
                
                response = await auth_client.get(url)
                
                # Extract links from response
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    
                    # Normalize URL
                    from urllib.parse import urljoin
                    next_url = urljoin(MOODLE_URL, href)
                    
                    # Only follow internal links
                    if MOODLE_URL in next_url and next_url not in visited_urls:
                        # Save as endpoint to scan
                        if next_url not in [t['url'] for t in targets]:
                            targets.append({
                                'url': next_url,
                                'method': 'GET',
                                'parameters': {}
                            })
                        
                        # Continue crawling if we haven't hit limits
                        if len(visited_urls) < max_pages and depth < max_depth:
                            await crawl_authenticated_url(next_url, depth + 1)
                
                # Also extract form inputs for POST endpoints
                for form in soup.find_all('form'):
                    form_url = form.get('action', url)
                    form_url = urljoin(MOODLE_URL, form_url)
                    form_method = form.get('method', 'GET').upper()
                    
                    # Extract form fields
                    form_params = {}
                    for input_field in form.find_all('input'):
                        field_name = input_field.get('name')
                        field_value = input_field.get('value', '')
                        if field_name:
                            form_params[field_name] = field_value
                    
                    if form_url not in [t['url'] for t in targets]:
                        targets.append({
                            'url': form_url,
                            'method': form_method,
                            'parameters': form_params
                        })
                    
            except Exception as e:
                print(f"[Native Auth Scan] Error crawling {url}: {str(e)}")
        
        # Start crawling from Moodle dashboard
        dashboard_url = f"{MOODLE_URL}/my/"
        await crawl_authenticated_url(dashboard_url)
        
        print(f"[Native Auth Scan] Crawl complete! Visited {len(visited_urls)} pages")
        print(f"[Native Auth Scan] Discovered {len(targets)} endpoints to scan")
        
        # Step 3: Scan endpoints with authenticated session
        print(f"\n[Native Auth Scan] STEP 3: Scanning {len(targets)} endpoints...")
        
        all_findings = []
        scanned_count = 0
        
        # Limit scanning to avoid timeout
        targets_to_scan = targets[:max_pages] if len(targets) > max_pages else targets
        
        for i, target in enumerate(targets_to_scan, 1):
            try:
                print(f"[Native Auth Scan] Scanning {i}/{len(targets_to_scan)}: {target['url'][:80]}...")
                
                # Make request with authenticated session
                if target['method'] == 'GET':
                    response = await auth_client.get(target['url'], params=target.get('parameters'))
                else:
                    response = await auth_client.post(target['url'], data=target.get('parameters'))
                
                # Scan endpoint
                response_body = response.text
                response_headers = dict(response.headers)
                status_code = response.status_code
                
                scan_results = await scanner_engine.scan(
                    url=target['url'],
                    method=target['method'],
                    params=target.get('parameters'),
                    response_body=response_body,
                    response_headers=response_headers,
                    status_code=status_code,
                    client=auth_client
                )
                
                # Enrich findings with risk scores
                enriched_findings = risk_scorer.batch_enrich_findings(scan_results['findings'])
                all_findings.extend(enriched_findings)
                scanned_count += 1
                
                if scan_results['findings']:
                    print(f"[Native Auth Scan]   → Found {len(scan_results['findings'])} vulnerabilities")
                
            except Exception as e:
                print(f"[Native Auth Scan] Error scanning {target['url']}: {str(e)}")
                continue
        
        # Step 4: ML-Enhanced Processing
        print(f"\n[Native Auth Scan] STEP 4: ML-Enhanced Processing...")
        print(f"[Native Auth Scan] BEFORE ML: {len(all_findings)} findings")
        
        # Apply ML filtering
        ml_results = ml_manager.filter_findings(all_findings, context={
            'environment': 'production',
            'auth_status': 'authenticated',
            'scan_type': 'native'
        })
        filtered_findings = ml_results['findings']
        
        print(f"[Native Auth Scan] AFTER ML: {len(filtered_findings)} findings")
        print(f"[Native Auth Scan] ML Stats: {ml_results['filtered_count']} FPs filtered, "
              f"{ml_results['severity_adjusted_count']} severities adjusted")
        
        # Step 5: Aggregate results
        filtered_findings.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
        
        summary = {
            'critical': sum(1 for f in filtered_findings if f.get('severity', '').lower() == 'critical'),
            'high': sum(1 for f in filtered_findings if f.get('severity', '').lower() == 'high'),
            'medium': sum(1 for f in filtered_findings if f.get('severity', '').lower() == 'medium'),
            'low': sum(1 for f in filtered_findings if f.get('severity', '').lower() == 'low'),
            'info': sum(1 for f in filtered_findings if f.get('severity', '').lower() == 'info')
        }
        
        # Step 6: Save to database
        print(f"\n[Native Auth Scan] STEP 5: Saving results to database...")
        scan_data = {
            'scan_id': scan_id,
            'scan_type': 'native_authenticated',
            'target_url': MOODLE_URL,
            'username': username,
            'timestamp': timestamp,
            'pages_visited': len(visited_urls),
            'endpoints_discovered': len(targets),
            'endpoints_scanned': scanned_count,
            'total_findings': len(filtered_findings),
            'summary': summary,
            'findings': filtered_findings,
            'ml_stats': ml_results
        }
        scan_history_db.save_scan(scan_data)
        print(f"[Native Auth Scan] ✓ Results saved to database")
        
        # Send Slack notification if enabled
        if slack_notifier and len(filtered_findings) > 0:
            try:
                await slack_notifier.send_scan_complete({
                    'scan_id': scan_id,
                    'target_url': MOODLE_URL,
                    'endpoints_scanned': scanned_count,
                    'total_findings': len(filtered_findings),
                    'summary': summary,
                    'authenticated': True,
                    'username': username
                })
            except Exception as e:
                print(f"[Slack] Notification failed: {str(e)}")
        
        # Prepare final result
        result = {
            'scan_id': scan_id,
            'timestamp': timestamp,
            'target_url': MOODLE_URL,
            'username': username,
            'authenticated': True,
            'pages_visited': len(visited_urls),
            'endpoints_discovered': len(targets),
            'endpoints_scanned': scanned_count,
            'total_findings': len(filtered_findings),
            'summary': summary,
            'findings': filtered_findings,
            'ml_stats': {
                'original_count': ml_results['original_count'],
                'filtered_count': ml_results['filtered_count'],
                'severity_adjusted_count': ml_results['severity_adjusted_count'],
                'final_count': ml_results['final_count']
            }
        }
        
        print(f"\n{'='*80}")
        print(f"[Native Auth Scan] SUCCESS! Scan complete")
        print(f"[Native Auth Scan] Pages visited: {len(visited_urls)}")
        print(f"[Native Auth Scan] Endpoints discovered: {len(targets)}")
        print(f"[Native Auth Scan] Endpoints scanned: {scanned_count}")
        print(f"[Native Auth Scan] Total findings: {len(filtered_findings)}")
        print(f"[Native Auth Scan] Summary: Critical={summary['critical']}, High={summary['high']}, "
              f"Medium={summary['medium']}, Low={summary['low']}, Info={summary['info']}")
        print(f"{'='*80}\n")
        
        await auth_client.aclose()
        return result
        
    except Exception as e:
        print(f"\n[Native Auth Scan] ERROR: {str(e)}\n")
        await auth_client.aclose()
        raise HTTPException(status_code=500, detail=f"Native authenticated scan failed: {str(e)}")


def _generate_finding_summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Generate summary of findings by severity."""
    summary = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0
    }
    
    for finding in findings:
        severity = finding.get('severity', '').lower()
        if severity in summary:
            summary[severity] += 1
    
    return summary


# ML Endpoints - MUST be before catch-all route
@app.get("/ml/status")
async def get_ml_status():
    """
    Get ML modules status.
    
    Returns:
        ML modules status and training information
    """
    return ml_manager.get_status()


@app.get("/ml-test")
async def ml_test() -> Dict[str, Any]:
    """Quick check endpoint for ML pipeline integration availability."""
    return {
        "status": "ok",
        "pipeline_loaded": bool(ml_pipeline_instance is not None),
    }


@app.get("/ml/models/info")
async def get_ml_models_info():
    """
    Get detailed information about all ML models.
    
    Returns:
        Detailed ML models information
    """
    return ml_manager.export_models_info()


@app.post("/ml/feedback")
async def provide_ml_feedback(
    finding_id: str,
    is_false_positive: bool,
    scan_id: Optional[str] = None
):
    """
    Provide feedback for ML model improvement.
    
    Args:
        finding_id: ID of the finding
        is_false_positive: Whether the finding is a false positive
        scan_id: Optional scan ID
        
    Returns:
        Feedback confirmation
    """
    # Get finding from database
    if scan_id:
        scan_data = scan_history_db.get_scan_with_findings(scan_id)
        if scan_data:
            findings = scan_data.get('findings', [])
            finding = next((f for f in findings if f.get('id') == finding_id), None)
            
            if finding:
                ml_manager.provide_feedback(finding, is_false_positive)
                return {
                    'success': True,
                    'message': 'Feedback recorded for ML training',
                    'finding_id': finding_id,
                    'is_false_positive': is_false_positive
                }


@app.post("/api/check-phishing")
async def check_phishing(request: Request):
    """
    Check content for phishing/HTML injection.
    
    For Moodle plugin integration - checks user-generated content
    (comments, forum posts, etc.) for malicious content.
    
    Request body:
        {
            "content": "text to analyze",
            "context": {
                "user_id": 123,
                "post_id": 456,
                "type": "comment"
            }
        }
    
    Returns:
        {
            "is_malicious": bool,
            "confidence": float,
            "threat_type": str,
            "details": [],
            "recommendation": str
        }
    """
    try:
        data = await request.json()
        content = data.get('content', '')
        context = data.get('context', {})
        
        if not content:
            return {
                'success': False,
                'error': 'No content provided'
            }
        
        # Use phishing detector
        result = ml_manager.phishing_detector.detect(content, context)
        
        # Add recommendation
        result['recommendation'] = ml_manager.phishing_detector.get_recommendation(result)
        result['success'] = True
        
        return result
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'is_malicious': False,
            'confidence': 0.0
        }


# Phishing Detection Endpoints (FastAPI native)
@app.post("/phishing/scan/profile")
async def scan_user_profile_phishing(request: Request) -> Dict[str, Any]:
    """
    Scan user profile bio for phishing.
    
    Request Body:
    {
        "user_id": 123,
        "bio_content": "User bio HTML/text"
    }
    """
    try:
        data = await request.json()
        user_id = data.get('user_id')
        bio_content = data.get('bio_content')
        
        if not user_id or not bio_content:
            raise HTTPException(status_code=400, detail="Missing required fields: user_id, bio_content")
        
        result = phishing_detector.scan_user_profile(user_id, bio_content)
        result['success'] = True
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.post("/phishing/scan/comment")
async def scan_comment_phishing(request: Request) -> Dict[str, Any]:
    """
    Scan comment/forum post for phishing.
    
    Request Body:
    {
        "comment_id": 456,
        "comment_content": "Comment HTML/text",
        "context": "comment" | "forum_post" | "assignment_feedback"
    }
    """
    try:
        data = await request.json()
        comment_id = data.get('comment_id')
        comment_content = data.get('comment_content')
        context = data.get('context', 'comment')
        
        if not comment_id or not comment_content:
            raise HTTPException(status_code=400, detail="Missing required fields: comment_id, comment_content")
        
        result = phishing_detector.scan_comment(comment_id, comment_content, context)
        result['success'] = True
        
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@app.post("/phishing/scan/batch")
async def scan_batch_content_phishing(request: Request) -> Dict[str, Any]:
    """
    Scan multiple content items in batch.
    
    Request Body:
    {
        "items": [
            {
                "type": "profile" | "comment",
                "id": 123,
                "content": "...",
                "context": "..."
            }
        ]
    }
    """
    try:
        data = await request.json()
        items = data.get('items', [])
        
        if not items:
            raise HTTPException(status_code=400, detail="Missing required field: items")
        
        results = []
        suspicious_count = 0
        
        for item in items:
            item_type = item.get('type')
            item_id = item.get('id')
            content = item.get('content')
            context = item.get('context', 'unknown')
            
            if not all([item_type, item_id, content]):
                results.append({'id': item_id, 'error': 'Missing required fields'})
                continue
            
            if item_type == 'profile':
                result = phishing_detector.scan_user_profile(item_id, content)
            elif item_type == 'comment':
                result = phishing_detector.scan_comment(item_id, content, context)
            else:
                results.append({'id': item_id, 'error': f'Unknown type: {item_type}'})
                continue
            
            results.append(result)
            if result['findings_count'] > 0:
                suspicious_count += 1
        
        return {
            'success': True,
            'total_items': len(items),
            'suspicious_items': suspicious_count,
            'results': results
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Batch scan failed: {str(e)}")


@app.get("/phishing/stats")
async def get_phishing_stats() -> Dict[str, Any]:
    """
    Get phishing detection statistics.
    """
    try:
        return {
            'success': True,
            'moodle_domain': phishing_detector.moodle_domain,
            'detector_ready': True,
            'detection_methods': [
                'URL Shortener Detection',
                'IP-based URL Detection',
                'Suspicious TLD Analysis',
                'Domain Spoofing (Typosquatting)',
                'Link Text vs URL Mismatch',
                'URL Obfuscation Detection',
                'Homograph Attack Detection',
                'Social Engineering Keyword Analysis'
            ],
            'suspicious_tlds': phishing_detector.SUSPICIOUS_TLDS,
            'url_shorteners': phishing_detector.URL_SHORTENERS
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get stats: {str(e)}")
    
    raise HTTPException(status_code=404, detail="Finding not found")


@app.get("/ml/ip-stats/{ip}")
async def get_ip_stats(ip: str):
    """
    Get rate limiting statistics for an IP.
    
    Args:
        ip: IP address
        
    Returns:
        IP statistics
    """
    return ml_manager.get_ip_stats(ip)


@app.post("/ml/whitelist/{ip}")
async def whitelist_ip(ip: str):
    """
    Add IP to whitelist.
    
    Args:
        ip: IP address to whitelist
        
    Returns:
        Confirmation
    """
    ml_manager.whitelist_ip(ip)
    return {
        'success': True,
        'message': f'IP {ip} added to whitelist',
        'ip': ip
    }


@app.post("/ml/blacklist/{ip}")
async def blacklist_ip(ip: str):
    """
    Add IP to blacklist.
    
    Args:
        ip: IP address to blacklist
        
    Returns:
        Confirmation
    """
    ml_manager.blacklist_ip(ip)
    return {
        'success': True,
        'message': f'IP {ip} added to blacklist',
        'ip': ip
    }


@app.get("/ml/anomalies/recent")
async def get_recent_anomalies(limit: int = 50):
    """Get recent proxy anomalies detected by ML."""
    safe_limit = max(1, min(limit, RECENT_ANOMALIES_MAXLEN))
    anomalies = list(recent_anomalies)[:safe_limit]

    return {
        'success': True,
        'count': len(anomalies),
        'limit': safe_limit,
        'anomaly_detection_enabled': ANOMALY_DETECTION_ENABLED,
        'anomaly_block_on_detection': ANOMALY_BLOCK_ON_DETECTION,
        'anomaly_block_threshold': ANOMALY_BLOCK_THRESHOLD,
        'lookback_seconds': ANOMALY_LOOKBACK_SECONDS,
        'anomalies': anomalies
    }


@app.get("/ml/anomalies/runtime")
async def get_anomaly_runtime():
    """Get runtime stats for traffic window used by anomaly detection."""
    now_ts = datetime.utcnow().timestamp()
    _prune_recent_traffic(now_ts)
    window_events = list(recent_traffic_events)

    request_count_last_minute = len(window_events)
    unique_ips_last_minute = len({event['ip'] for event in window_events}) if window_events else 0
    error_count = sum(1 for event in window_events if event['status_code'] >= 400)
    error_rate_last_minute = (error_count / request_count_last_minute) if request_count_last_minute else 0.0

    return {
        'success': True,
        'anomaly_detection_enabled': ANOMALY_DETECTION_ENABLED,
        'window_stats': {
            'request_count_last_minute': request_count_last_minute,
            'unique_ips_last_minute': unique_ips_last_minute,
            'error_rate_last_minute': round(error_rate_last_minute, 4),
        },
        'buffer_sizes': {
            'recent_traffic_events': len(recent_traffic_events),
            'recent_anomalies': len(recent_anomalies),
        }
    }


@app.get("/ml/dashboard/recent-scans")
async def get_ml_dashboard_recent_scans(limit: int = 10):
    """
    Return recent scan summaries with ML filtering stats.
    Called by moodle-plugin/lib.php to populate the dashboard activity feed.

    Returns:
        recent_scans: list of scans with severity_breakdown and ml_filtering
    """
    try:
        history = scan_history_db.get_scan_history(limit=limit)
        recent_scans = []

        for scan in history:
            # Parse metadata JSON for ml_stats if stored
            metadata = {}
            try:
                import json as _json
                metadata = _json.loads(scan.get('metadata') or '{}')
            except Exception:
                pass

            ml_stats = metadata.get('ml_stats', {})
            raw_findings    = ml_stats.get('original_count', scan.get('total_findings', 0))
            fp_removed      = ml_stats.get('filtered_count', 0)
            actual_findings = ml_stats.get('final_count', scan.get('total_findings', 0))

            recent_scans.append({
                'scan_id':    scan.get('scan_id', ''),
                'scan_type':  scan.get('scan_type', 'security_scan'),
                'timestamp':  scan.get('timestamp', ''),
                'target_url': scan.get('target_url', ''),
                'findings_count': int(scan.get('total_findings', 0)),
                'severity_breakdown': {
                    'critical': int(scan.get('critical_count', 0)),
                    'high':     int(scan.get('high_count', 0)),
                    'medium':   int(scan.get('medium_count', 0)),
                    'low':      int(scan.get('low_count', 0)),
                    'info':     int(scan.get('info_count', 0)),
                },
                'ml_filtering': {
                    'raw_findings':           int(raw_findings),
                    'false_positives_removed': int(fp_removed),
                    'actual_vulnerabilities':  int(actual_findings),
                }
            })

        return {
            'success': True,
            'count': len(recent_scans),
            'recent_scans': recent_scans,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }

    except Exception as e:
        print(f"[ML Dashboard] Error fetching recent scans: {e}")
        return {
            'success': False,
            'count': 0,
            'recent_scans': [],
            'error': str(e)
        }



# IMPORTANT: Catch-all proxy route MUST be at the end to not interfere with specific endpoints
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy_request_catchall(request: Request, path: str) -> Response:
    """
    Proxy all other requests to the target Moodle instance.
    This route catches everything that doesn't match specific endpoints above.
    """
    # Build target URL
    target_url = f"{MOODLE_URL}/{path}"
    if request.url.query:
        target_url += f"?{request.url.query}"
    
    # Prepare request data
    headers = dict(request.headers)
    headers.pop("host", None)
    client_ip = _get_client_ip(request)
    trusted_scanner_request, trusted_scanner_detail = _is_trusted_scanner_request(request)
    enforcement_bypassed = False
    bypass_reasons: List[str] = []
    
    # Read request body
    body = await request.body()
    
    # Log the incoming request
    request_log = {
        "type": "proxy_request",
        "client_ip": client_ip,
        "method": request.method,
        "path": path,
        "target_url": target_url,
        "query_params": dict(request.query_params),
        "headers": {k: v for k, v in headers.items() if k.lower() not in ["authorization", "cookie"]},
        "body_size": len(body),
        "trusted_scanner_request": trusted_scanner_request,
        "enforcement_bypassed": False,
        "bypass_reason": "",
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

    # Run ML pipeline check before forwarding request to destination.
    try:
        ml_raw_request = {
            "uri": str(request.url),
            "method": request.method,
            "headers": dict(request.headers),
            "body": body.decode("utf-8", errors="ignore") if body else "",
            "request_raw": f"{request.method} {request.url.path}"
            + (f"?{request.url.query}" if request.url.query else ""),
        }
        ml_result = process_http_request(ml_raw_request)
        print("[PROXY ML RESULT]", ml_result)
    except Exception as ml_error:
        ml_result = {
            "decision": "IGNORE",
            "severity": "LOW",
            "attack_type": "unknown",
            "confidence": 0.0,
            "anomaly_score": 0.0,
            "reason": "ML failure fallback",
        }
        print("[PROXY ML RESULT]", ml_result)

    if str(ml_result.get("decision", "")).upper() == "BLOCK":
        if trusted_scanner_request:
            enforcement_bypassed = True
            bypass_reasons.append("ml_pipeline_block_bypassed_for_trusted_scanner")
            append_log(LOG_DIR, {
                "type": "proxy_ml_block_bypassed",
                "client_ip": client_ip,
                "method": request.method,
                "path": path,
                "target_url": target_url,
                "ml_result": ml_result,
                "trusted_scanner_request": True,
                "enforcement_bypassed": True,
                "bypass_reason": bypass_reasons[-1],
                "trusted_scanner_detail": trusted_scanner_detail,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            })
        else:
            ml_blocked_event = {
                "type": "proxy_ml_blocked_request",
                "client_ip": client_ip,
                "method": request.method,
                "path": path,
                "target_url": target_url,
                "ml_result": ml_result,
                "trusted_scanner_request": False,
                "enforcement_bypassed": False,
                "bypass_reason": "",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
            append_log(LOG_DIR, ml_blocked_event)
            return JSONResponse(
                status_code=403,
                content={
                    "status": 403,
                    "message": "Blocked by ML security system",
                    "reason": ml_result.get("reason", "Pipeline decision BLOCK"),
                },
            )
    
    try:
        request_start = datetime.utcnow()

        # Forward request to Moodle
        async with httpx.AsyncClient(follow_redirects=False, timeout=30.0) as client:
            response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body
            )

        response_time_ms = int((datetime.utcnow() - request_start).total_seconds() * 1000)

        # Update rolling traffic window for anomaly context.
        now_ts = datetime.utcnow().timestamp()
        recent_traffic_events.append({
            "ts": now_ts,
            "ip": client_ip,
            "status_code": response.status_code,
        })
        _prune_recent_traffic(now_ts)

        window_events = list(recent_traffic_events)
        request_count_last_minute = len(window_events)
        unique_ips_last_minute = len({event["ip"] for event in window_events}) if window_events else 1
        error_count = sum(1 for event in window_events if event["status_code"] >= 400)
        error_rate_last_minute = (error_count / request_count_last_minute) if request_count_last_minute else 0.0

        anomaly_detected = False
        anomaly_score = 0.0
        anomaly_reason = "Anomaly detection disabled"

        if ANOMALY_DETECTION_ENABLED:
            anomaly_payload = _build_anomaly_payload(
                request=request,
                target_url=target_url,
                request_headers=headers,
                request_body=body,
                response_status_code=response.status_code,
                response_size=len(response.content),
                response_time_ms=response_time_ms,
                response_headers=dict(response.headers),
                request_count_last_minute=request_count_last_minute,
                unique_ips_last_minute=unique_ips_last_minute,
                error_rate_last_minute=error_rate_last_minute,
            )

            try:
                anomaly_detected, anomaly_score, anomaly_reason = ml_manager.detect_anomaly(anomaly_payload)
            except Exception as anomaly_error:
                anomaly_reason = f"Anomaly detector error: {str(anomaly_error)}"
                append_log(LOG_DIR, {
                    "type": "anomaly_detector_error",
                    "client_ip": client_ip,
                    "path": path,
                    "target_url": target_url,
                    "error": str(anomaly_error),
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                })

        if anomaly_detected and anomaly_score >= ANOMALY_MIN_SCORE_TO_LOG:
            anomaly_event = {
                "type": "proxy_anomaly",
                "client_ip": client_ip,
                "method": request.method,
                "path": path,
                "target_url": target_url,
                "status_code": response.status_code,
                "response_time_ms": response_time_ms,
                "anomaly_score": round(float(anomaly_score), 4),
                "anomaly_reason": anomaly_reason,
                "request_count_last_minute": request_count_last_minute,
                "unique_ips_last_minute": unique_ips_last_minute,
                "error_rate_last_minute": round(error_rate_last_minute, 4),
                "timestamp": datetime.utcnow().isoformat() + "Z",
            }
            recent_anomalies.appendleft(anomaly_event)
            append_log(LOG_DIR, anomaly_event)

        if (
            ANOMALY_DETECTION_ENABLED
            and ANOMALY_BLOCK_ON_DETECTION
            and anomaly_detected
            and anomaly_score >= ANOMALY_BLOCK_THRESHOLD
        ):
            if trusted_scanner_request:
                enforcement_bypassed = True
                bypass_reasons.append("anomaly_block_bypassed_for_trusted_scanner")
                append_log(LOG_DIR, {
                    "type": "proxy_anomaly_block_bypassed",
                    "client_ip": client_ip,
                    "method": request.method,
                    "path": path,
                    "target_url": target_url,
                    "status_code": response.status_code,
                    "anomaly_score": round(float(anomaly_score), 4),
                    "anomaly_reason": anomaly_reason,
                    "trusted_scanner_request": True,
                    "enforcement_bypassed": True,
                    "bypass_reason": bypass_reasons[-1],
                    "trusted_scanner_detail": trusted_scanner_detail,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                })
            else:
                blocked_event = {
                    "type": "proxy_blocked_response",
                    "client_ip": client_ip,
                    "method": request.method,
                    "path": path,
                    "target_url": target_url,
                    "status_code": response.status_code,
                    "anomaly_score": round(float(anomaly_score), 4),
                    "anomaly_reason": anomaly_reason,
                    "trusted_scanner_request": False,
                    "enforcement_bypassed": False,
                    "bypass_reason": "",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                }
                append_log(LOG_DIR, blocked_event)
                return Response(
                    content='{"detail":"Response blocked by anomaly detector"}',
                    status_code=403,
                    media_type="application/json",
                    headers={"X-MoodleSec-Blocked": "anomaly"},
                )
        
        # Log the response
        response_log = {
            "type": "proxy_response",
            "client_ip": client_ip,
            "method": request.method,
            "path": path,
            "target_url": target_url,
            "status_code": response.status_code,
            "response_time_ms": response_time_ms,
            "response_size": len(response.content),
            "anomaly_detected": anomaly_detected,
            "anomaly_score": round(float(anomaly_score), 4),
            "anomaly_reason": anomaly_reason if anomaly_detected else "Normal behavior",
            "ml_decision": str(ml_result.get("decision", "")).upper(),
            "ml_attack_type": ml_result.get("attack_type", "unknown"),
            "ml_confidence": float(ml_result.get("confidence", 0.0)),
            "trusted_scanner_request": trusted_scanner_request,
            "enforcement_bypassed": enforcement_bypassed,
            "bypass_reason": "; ".join(bypass_reasons),
            "trusted_scanner_detail": trusted_scanner_detail if trusted_scanner_request else "",
            "window_request_count": request_count_last_minute,
            "window_unique_ips": unique_ips_last_minute,
            "window_error_rate": round(error_rate_last_minute, 4),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        append_log(LOG_DIR, {**request_log, **response_log, "type": "proxy_transaction"})
        
        # Return response
        response_headers = dict(response.headers)
        response_headers.pop("content-length", None)
        response_headers.pop("transfer-encoding", None)

        if anomaly_detected:
            response_headers["X-MoodleSec-Anomaly"] = "1"
            response_headers["X-MoodleSec-Anomaly-Score"] = f"{float(anomaly_score):.3f}"
        if enforcement_bypassed:
            response_headers["X-MoodleSec-Enforcement-Bypass"] = "trusted-scanner"
            response_headers["X-MoodleSec-Scanner"] = "internal"
        
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
            "error_type": type(e).__name__,
            "trusted_scanner_request": trusted_scanner_request,
            "enforcement_bypassed": enforcement_bypassed,
            "bypass_reason": "; ".join(bypass_reasons),
            "trusted_scanner_detail": trusted_scanner_detail if trusted_scanner_request else "",
        }
        append_log(LOG_DIR, error_log)
        
        raise HTTPException(
            status_code=500,
            detail=f"Internal proxy error: {str(e)}"
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=LISTEN_PORT)
