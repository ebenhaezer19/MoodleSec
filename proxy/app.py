"""
FastAPI reverse proxy for Moodle with logging and DAST scanning capabilities.
"""

import os
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, Request, Response, HTTPException
from pydantic import BaseModel, Field

from config import MOODLE_URL, LISTEN_PORT, LOG_DIR, MAX_LOG_ENTRIES, SLACK_WEBHOOK_URL, SLACK_ENABLED
from utils.logger import append_log, read_logs, ensure_log_directory
from utils.slack_notifier import SlackNotifier
from scanners.scanner_engine import ScannerEngine
from crawler.web_crawler import WebCrawler
from risk.risk_scorer import RiskScorer
from database.scan_history import ScanHistoryDB
from database.scheduler_db import SchedulerDB
from reporting.pdf_generator import PDFReportGenerator
from integrations.integration_manager import IntegrationManager


app = FastAPI(
    title="Moodle Proxy Service",
    description="Reverse proxy for Moodle with request/response logging and DAST scanning",
    version="2.0.0"
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

# Initialize Slack notifier (if enabled)
slack_notifier = None
if SLACK_ENABLED and SLACK_WEBHOOK_URL:
    slack_notifier = SlackNotifier(SLACK_WEBHOOK_URL)


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
    scan_results = scanner_engine.scan(
        url=target_url,
        method=scan_request.method,
        params=scan_request.parameters,
        response_body=response_body,
        response_headers=response_headers,
        status_code=status_code
    )
    
    # Convert findings to ScanFinding objects
    findings = [
        ScanFinding(
            severity=f.get('severity', 'Info'),
            category=f.get('category', 'General'),
            description=f.get('description', ''),
            evidence=f.get('evidence')
        )
        for f in scan_results['findings']
    ]
    
    # Log the scan
    scan_log = {
        "type": "dast_scan",
        "scan_id": scan_results['scan_id'],
        "target_url": target_url,
        "method": scan_request.method,
        "parameters": scan_request.parameters,
        "findings_count": len(findings),
        "summary": scan_results['summary'],
        "timestamp": scan_results['timestamp']
    }
    append_log(LOG_DIR, scan_log)
    
    return ScanResult(
        scan_id=scan_results['scan_id'],
        target_url=target_url,
        timestamp=scan_results['timestamp'],
        findings=findings,
        summary=scan_results['summary']
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
    scan_id = f"full_scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
    timestamp = datetime.utcnow().isoformat() + "Z"
    
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
                scan_results = scanner_engine.scan(
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
        
        # Step 3: Aggregate results
        # Sort by risk score
        all_findings.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
        
        # Calculate summary
        summary = {
            'critical': sum(1 for f in all_findings if f.get('severity', '').lower() == 'critical'),
            'high': sum(1 for f in all_findings if f.get('severity', '').lower() == 'high'),
            'medium': sum(1 for f in all_findings if f.get('severity', '').lower() == 'medium'),
            'low': sum(1 for f in all_findings if f.get('severity', '').lower() == 'low'),
            'info': sum(1 for f in all_findings if f.get('severity', '').lower() == 'info')
        }
        
        # Log the full scan
        scan_log = {
            "type": "full_site_scan",
            "scan_id": scan_id,
            "base_url": MOODLE_URL,
            "endpoints_discovered": len(targets),
            "endpoints_scanned": scanned_count,
            "findings_count": len(all_findings),
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
            'total_findings': len(all_findings),
            'summary': summary,
            'findings': all_findings
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
            'total_findings': len(all_findings),
            'summary': summary,
            'findings': all_findings[:100],  # Return top 100 findings
            'top_risks': all_findings[:10]  # Top 10 highest risk findings
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
        # Get complete scan data with findings from database
        scan_data = scan_history_db.get_scan_with_findings(scan_id)
        
        if not scan_data:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Generate PDF
        pdf_bytes = pdf_generator.generate_executive_summary(scan_data)
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=executive_summary_{scan_id}.pdf"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")


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
