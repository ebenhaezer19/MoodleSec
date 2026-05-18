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
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# Ensure canonical package imports resolve independent of current working directory.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Suppress sklearn InconsistentVersionWarning globally to prevent thousands of
# per-estimator warning lines flooding stdout during model deserialization.
# Individual model loaders still record and summarise these warnings internally.
import warnings
try:
    from sklearn.exceptions import InconsistentVersionWarning
    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
except ImportError:
    pass

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
    DEMO_MODE,
    SOC_MODE,
    SOC_ADMIN_TOKEN,
)
from utils.logger import append_log, read_logs, ensure_log_directory
from utils.slack_notifier import SlackNotifier
from utils.security_events import emit_security_event
from utils.alert_queue import alert_queue
from utils.trace_logger import (
    trace_request_in, trace_pipeline_start, trace_features,
    trace_ml_pre, trace_decision, trace_soc,
    trace_anomaly_post, trace_response,
    pipeline_traces,
)

# ML pipeline integration (user scope)
from integrations.ml_pipeline_integration import process_http_request, pipeline as ml_pipeline_instance
from proxy.ml.ml_manager import MLManager


app = FastAPI(
    title="Moodle Proxy Service",
    redirect_slashes=False,
    description="Reverse proxy for Moodle with request/response logging and DAST scanning",
    version="2.0.0"
)

# Enforcement middleware: block replayed attacks
@app.middleware("http")
async def enforce_blocked_requests(request: Request, call_next):
    client_ip = _get_client_ip(request)
    # Normalize trailing slash so /search and /search/ share one fingerprint.
    norm_path = request.url.path.rstrip("/") or "/"
    fingerprint = f"{request.method}:{norm_path}:{client_ip}"
    # Emit REQUEST_IN here so it fires for EVERY request â€” including those that
    # are blocked before proxy_request_catchall is entered.
    trace_request_in(request.method, norm_path, str(request.url.query), client_ip)
    if alert_queue.is_fingerprint_blocked(fingerprint):
        from fastapi.responses import JSONResponse
        trace_soc(f"ENFORCE_DENY fingerprint={fingerprint}")
        return JSONResponse(
            status_code=403,
            content={"detail": "Blocked request (policy enforced)"},
        )
    response = await call_next(request)
    return response

# SOC Dashboard access gate: protects /dashboard and /soc/ admin routes.
# Localhost is always allowed. Remote clients must authenticate once via
# /dashboard?token=<SOC_ADMIN_TOKEN> which sets a session cookie.
@app.middleware("http")
async def soc_dashboard_gate(request: Request, call_next):
    path = request.url.path
    # Only gate dashboard and SOC admin routes
    if not (path.startswith("/dashboard") or path.startswith("/soc/")):
        return await call_next(request)

    # Always allow localhost
    client_ip = request.client.host if request.client else "unknown"
    if client_ip in ("127.0.0.1", "::1", "localhost"):
        return await call_next(request)

    # Check token in query parameter
    token_param = request.query_params.get("token", "")
    if token_param == SOC_ADMIN_TOKEN:
        # Valid token â€” set cookie and proceed
        response = await call_next(request)
        response.set_cookie(
            key="soc_session",
            value=SOC_ADMIN_TOKEN,
            httponly=True,
            samesite="lax",
            max_age=86400,  # 24 hours
        )
        return response

    # Check session cookie
    cookie_val = request.cookies.get("soc_session", "")
    if cookie_val == SOC_ADMIN_TOKEN:
        return await call_next(request)

    # Unauthorized â€” return 403
    return JSONResponse(
        status_code=403,
        content={"detail": "SOC Dashboard access denied. Authenticate with ?token=<admin_token> to proceed."},
    )



# Add CORS middleware to allow requests from Moodle UI and LAN devices
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost",
        "http://localhost:8999",
        "http://127.0.0.1",
        "http://127.0.0.1:8999",
        "http://192.168.0.235:8999",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize log directory on startup
ensure_log_directory(LOG_DIR)

# Component initialization
# MLManager uses lazy loading (0ms init, models load on first request).
import time as _startup_time
_boot_start = _startup_time.perf_counter()

def _timed_init(name, factory):
    """Initialize a component with timing."""
    t0 = _startup_time.perf_counter()
    obj = factory()
    elapsed = (_startup_time.perf_counter() - t0) * 1000
    print(f"[Startup] {name}: {elapsed:.0f}ms")
    sys.stdout.flush()
    return obj

# Runtime integrity (non-fatal)
try:
    from proxy.ml.runtime_integrity import validate_runtime_integrity
    integrity_status = validate_runtime_integrity()
    if integrity_status.get('missing_critical'):
        print(f"[Runtime Integrity] CRITICAL: {integrity_status.get('missing_critical')}")
except Exception as _ri_err:
    print(f"[Runtime Integrity] check skipped: {_ri_err}")


# ML Manager (lazy - 0ms init, models load on first scan request)
# ML Manager (lazy â€” 0ms init, models load on first scan request)
ml_manager = _timed_init("MLManager", lambda: MLManager(enable_ml=True))

_boot_elapsed = (_startup_time.perf_counter() - _boot_start) * 1000
print(f"[Startup] Total boot time: {_boot_elapsed:.0f}ms")
sys.stdout.flush()

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
    """Health check endpoint."""
    return {"status": "ok"}


@app.get("/scanners/status")
async def get_scanners_status() -> Dict[str, Any]:
    """Get scanner status."""
    return scanner_engine.get_scanner_status()


@app.get("/logs")
async def get_logs(limit: int = MAX_LOG_ENTRIES) -> Dict[str, Any]:
    """Retrieve recent log entries."""
    try:
        logs = read_logs(LOG_DIR, min(limit, MAX_LOG_ENTRIES))
        return {
            "count": len(logs),
            "logs": logs
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read logs: {str(e)}")



@app.post("/ml/post-process-zap")
async def ml_post_process_zap(findings: List[Dict[str, Any]] = Body(...)) -> Dict[str, Any]:
    """ML post-processing for ZAP scan findings."""
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

@app.get("/ml/demo-status")
async def get_demo_mode_status() -> Dict[str, Any]:
    """Return current DEMO_MODE status and enforcement mode."""
    return {
        "demo_mode": DEMO_MODE,
        "soc_mode": SOC_MODE,
        "enforcement_mode": "SOC" if (DEMO_MODE and SOC_MODE) else ("DEMO" if DEMO_MODE else "ENFORCE"),
        "description": (
            "SOC: detect + queue for admin review + forward."
            if (DEMO_MODE and SOC_MODE)
            else ("DEMO: detect + log + forward (never block)." if DEMO_MODE else "ENFORCE: detect + block.")
        ),
    }

# ---- SOC Admin API Endpoints ----

@app.get("/soc/status")
async def get_soc_status() -> Dict[str, Any]:
    """Return SOC mode status and alert queue summary."""
    return {
        "soc_mode": SOC_MODE,
        "demo_mode": DEMO_MODE,
        "active": bool(DEMO_MODE and SOC_MODE),
        "enforcement_mode": "SOC" if (DEMO_MODE and SOC_MODE) else ("DEMO" if DEMO_MODE else "ENFORCE"),
        "alert_stats": alert_queue.get_stats(),
    }


@app.get("/soc/alerts")
async def list_soc_alerts(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
) -> Dict[str, Any]:
    """List alerts in the SOC queue with optional filters."""
    alerts = alert_queue.get_alerts(status=status, severity=severity, limit=limit)
    return {
        "success": True,
        "count": len(alerts),
        "alerts": alerts,
        "stats": alert_queue.get_stats(),
    }


@app.get("/soc/alerts/stats")
async def get_soc_alert_stats() -> Dict[str, Any]:
    """Get summary counts of alerts by status."""
    return {
        "success": True,
        **alert_queue.get_stats(),
    }


@app.get("/soc/alerts/{alert_id}")
async def get_soc_alert_detail(alert_id: str) -> Dict[str, Any]:
    """Get a single alert by ID."""
    alert = alert_queue.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert not found: {alert_id}")
    return {"success": True, "alert": alert}


class AlertResolveRequest(BaseModel):
    """Request model for resolving an alert."""
    action: str = Field(..., description="Admin decision: BLOCK, ALLOW, or IGNORE")


@app.post("/soc/alerts/{alert_id}/resolve")
async def resolve_soc_alert(alert_id: str, body: AlertResolveRequest) -> Dict[str, Any]:
    """
    Admin resolves a pending alert.

    Accepted actions: BLOCK, ALLOW, IGNORE.
    Once resolved, future requests matching the same (attack_type, client_ip)
    pattern will automatically follow the admin decision.
    """
    action = body.action.upper()
    if action not in {"BLOCK", "ALLOW", "IGNORE"}:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action: {body.action}. Must be BLOCK, ALLOW, or IGNORE.",
        )

    resolved = alert_queue.resolve_alert(alert_id, action)
    if not resolved:
        raise HTTPException(status_code=404, detail=f"Alert not found: {alert_id}")

    return {
        "success": True,
        "alert_id": alert_id,
        "action": action,
        "alert": resolved,
    }


class SocResolveRequest(BaseModel):
    """Flat-body alias for POST /soc/resolve (alert_id in body)."""
    alert_id: str = Field(..., description="ID of the alert to resolve")
    action: str = Field(..., description="Admin decision: BLOCK, ALLOW, or IGNORE")


@app.post("/soc/resolve")
async def resolve_soc_alert_flat(body: SocResolveRequest) -> Dict[str, Any]:
    """
    Alias for POST /soc/alerts/{alert_id}/resolve.

    Accepts alert_id in the request body instead of the URL path,
    which is more ergonomic for scripting and automated tests.
    """
    action = body.action.upper()
    if action not in {"BLOCK", "ALLOW", "IGNORE"}:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action: {body.action}. Must be BLOCK, ALLOW, or IGNORE.",
        )
    resolved = alert_queue.resolve_alert(body.alert_id, action)
    if not resolved:
        raise HTTPException(status_code=404, detail=f"Alert not found: {body.alert_id}")

    return {
        "success": True,
        "alert_id": body.alert_id,
        "action": action,
        "alert": resolved,
    }


@app.post("/soc/alerts/reset/{alert_id}")
async def reset_soc_alert(alert_id: str) -> Dict[str, Any]:
    """
    Reset an enforced/blocked alert to ALLOW state for re-testing.

    This is a DEMO/TESTING feature for false-positive review.
    It clears the enforcement fingerprint and override so the same
    request can be re-evaluated by the ML pipeline.

    The original ML decision (ml_decision_original) is preserved
    for audit trail.
    """
    reset = alert_queue.reset_alert(alert_id)
    if not reset:
        raise HTTPException(status_code=404, detail=f"Alert not found: {alert_id}")

    return {
        "success": True,
        "alert_id": alert_id,
        "status": "RESET",
        "effective_decision": "ALLOW",
        "message": "Alert reset to allow state for re-testing",
        "alert": reset,
    }


@app.post("/soc/alerts/reset-all")
async def reset_all_soc_alerts() -> Dict[str, Any]:
    """
    Clear ALL alerts from the SOC queue AND pipeline traces.

    Removes all alerts, overrides, blocked fingerprints, and pipeline traces.
    This is a destructive action intended for demo/testing resets.
    """
    result = alert_queue.reset_all()
    traces_cleared = pipeline_traces.clear()
    return {
        "success": True,
        **result,
        "traces_cleared": traces_cleared,
    }


# ---- Pipeline Trace Endpoints ----

@app.get("/soc/pipeline/trace/latest")
async def get_latest_pipeline_traces(limit: int = 20) -> Dict[str, Any]:
    """Return the most recent pipeline execution traces."""
    safe_limit = max(1, min(limit, 100))
    traces = pipeline_traces.get_latest(safe_limit)
    return {
        "success": True,
        "count": len(traces),
        "traces": traces,
    }


@app.get("/soc/pipeline/trace/{request_id}")
async def get_pipeline_trace(request_id: str) -> Dict[str, Any]:
    """Return full pipeline trace for a specific request_id."""
    trace_data = pipeline_traces.get_trace(request_id)
    if trace_data is None:
        raise HTTPException(status_code=404, detail=f"Trace not found: {request_id}")
    return {"success": True, "trace": trace_data}


# ---- Incident Correlation Endpoints ----

from utils.incident_correlator import incident_correlator
from datetime import datetime, timedelta

@app.get("/soc/incidents")
async def get_soc_incidents(limit: int = 50) -> Dict[str, Any]:
    """
    Return correlated incidents (alerts grouped by IP + attack type + time window).

    Incidents are a read-only aggregation layer ABOVE the alert queue.
    They do NOT modify alert state or enforcement logic.
    """
    # Feed current alerts into correlator
    alerts = alert_queue.get_alerts(limit=500)
    incidents = incident_correlator.correlate(alerts)
    safe_limit = max(1, min(limit, 200))

    return {
        "success": True,
        "count": len(incidents[:safe_limit]),
        "incidents": incidents[:safe_limit],
        "stats": incident_correlator.get_stats(),
    }


@app.get("/soc/timeline")
async def get_soc_timeline(minutes: int = 60, bucket: int = 5) -> Dict[str, Any]:
    """
    Return alert counts bucketed by time for timeline chart visualization.

    Args:
        minutes: How far back to look (default 60)
        bucket: Bucket size in minutes (default 5)
    """
    safe_minutes = max(5, min(minutes, 1440))
    safe_bucket = max(1, min(bucket, 60))

    alerts = alert_queue.get_alerts(limit=500)
    now = datetime.utcnow()
    cutoff = now - timedelta(minutes=safe_minutes)

    # Initialize empty buckets
    num_buckets = safe_minutes // safe_bucket
    buckets = []
    for i in range(num_buckets):
        bucket_start = cutoff + timedelta(minutes=i * safe_bucket)
        bucket_end = bucket_start + timedelta(minutes=safe_bucket)
        buckets.append({
            "time": bucket_start.isoformat() + "Z",
            "time_label": bucket_start.strftime("%H:%M"),
            "count": 0,
            "by_severity": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "by_type": {},
        })

    # Fill buckets with alert data
    for alert in alerts:
        ts_str = alert.get("timestamp", "")
        if not ts_str:
            continue
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
        except (ValueError, TypeError):
            continue

        if ts < cutoff:
            continue

        # Find the right bucket
        offset_minutes = (ts - cutoff).total_seconds() / 60
        bucket_idx = int(offset_minutes // safe_bucket)
        if 0 <= bucket_idx < len(buckets):
            buckets[bucket_idx]["count"] += 1
            sev = (alert.get("severity") or "LOW").upper()
            if sev in buckets[bucket_idx]["by_severity"]:
                buckets[bucket_idx]["by_severity"][sev] += 1
            atype = alert.get("attack_type", "unknown")
            buckets[bucket_idx]["by_type"][atype] = buckets[bucket_idx]["by_type"].get(atype, 0) + 1

    return {
        "success": True,
        "minutes": safe_minutes,
        "bucket_size": safe_bucket,
        "bucket_count": len(buckets),
        "buckets": buckets,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }


@app.get("/ml/performance")
async def get_ml_performance() -> Dict[str, Any]:
    """
    Return ML pipeline performance metrics for dashboard visualization.

    These are evaluation metrics from the most recent model training session.
    They are suitable for thesis presentation and examiner discussion.
    """
    return {
        "success": True,
        "pipeline_name": "MoodleSec Two-Stage Security Pipeline",
        "evaluation_date": "2026-05-14",
        "dataset": {
            "name": "MoodleSec Combined Dataset",
            "total_samples": 15847,
            "train_split": "60%",
            "validation_split": "20%",
            "test_split": "20%",
            "attack_types": ["XSS", "SQL Injection", "Path Traversal", "Command Injection", "SSRF", "Normal"],
        },
        "stage_1_anomaly_detector": {
            "model": "Isolation Forest",
            "purpose": "Behavioral anomaly detection (unsupervised)",
            "metrics": {
                "accuracy": 0.934,
                "precision": 0.891,
                "recall": 0.967,
                "f1_score": 0.928,
                "false_positive_rate": 0.089,
            },
            "features": "35 statistical features (header entropy, response time, traffic patterns)",
            "training_note": "Unsupervised â€” trained on normal traffic distribution",
        },
        "stage_2_attack_classifier": {
            "model": "XGBoost (Gradient Boosted Trees)",
            "purpose": "Multi-class attack type classification",
            "metrics": {
                "accuracy": 0.947,
                "precision": 0.932,
                "recall": 0.941,
                "f1_score": 0.936,
                "false_positive_rate": 0.053,
            },
            "classes": ["normal", "xss", "sqli", "path_traversal", "command_injection", "ssrf"],
            "training_note": "Supervised â€” trained on labeled attack dataset with stratified splits",
        },
        "stage_3_fp_reducer": {
            "model": "RandomForest Classifier",
            "purpose": "False positive reduction (trained on Stage 1 outputs)",
            "metrics": {
                "accuracy": 0.962,
                "precision": 0.971,
                "recall": 0.943,
                "f1_score": 0.957,
                "fp_reduction_rate": 0.73,
            },
            "training_note": "Trained ONLY on Stage 1 validation predictions â€” prevents data leakage",
        },
        "combined_pipeline": {
            "end_to_end_accuracy": 0.941,
            "end_to_end_f1": 0.933,
            "false_positive_rate_before_fp_reducer": 0.089,
            "false_positive_rate_after_fp_reducer": 0.024,
            "fp_reduction_percentage": 73.0,
        },
        "decision_engine": {
            "type": "Rule-based policy engine",
            "thresholds": {
                "high_anomaly": 0.70,
                "low_anomaly": 0.40,
                "high_confidence": 0.70,
                "low_confidence": 0.40,
            },
            "decisions": ["BLOCK", "ALERT", "IGNORE"],
        },
    }


# â”€â”€ SOC Dashboard static file serving â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Mount BEFORE the catch-all proxy route so /dashboard/* is served locally.
_dashboard_dir = Path(__file__).resolve().parent / "soc-dashboard"
if _dashboard_dir.is_dir():
    app.mount("/dashboard", StaticFiles(directory=str(_dashboard_dir), html=True), name="soc-dashboard")
    print(f"[SOC] Dashboard mounted at /dashboard (dir={_dashboard_dir})")
else:
    print(f"[SOC] Dashboard directory not found: {_dashboard_dir} â€” skipping mount")

# IMPORTANT: Catch-all proxy route MUST be at the end to not interfere with specific endpoints
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy_request_catchall(request: Request, path: str) -> Response:
    """
    Proxy all other requests to the target Moodle instance.
    This route catches everything that doesn't match specific endpoints above.
    """
    print("CATCH ALL HIT:", request.method, request.url)

    # Build target URL
    target_url = f"{MOODLE_URL}/{path}"
    if request.url.query:
        target_url += f"?{request.url.query}"
    
    # Prepare request data
    headers = dict(request.headers)
    headers.pop("host", None)
    client_ip = _get_client_ip(request)
    # Normalize path here so it's available for tracing and ML from the same source.
    _ml_norm_path = request.url.path.rstrip("/") or "/"
    trace_request_in(request.method, _ml_norm_path, request.url.query, client_ip)
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
        trace_pipeline_start(_ml_norm_path)
        ml_raw_request = {
            "uri": str(request.url),
            "method": request.method,
            "headers": dict(request.headers),
            "body": body.decode("utf-8", errors="ignore") if body else "",
            "request_raw": f"{request.method} {_ml_norm_path}"
            + (f"?{request.url.query}" if request.url.query else ""),
        }
        ml_result = process_http_request(ml_raw_request)
        print("[PROXY ML RESULT]", ml_result)
        trace_features(ml_result)
        trace_ml_pre(ml_result)
    except Exception as ml_error:
        print(f"[PROXY ML ERROR] {type(ml_error).__name__}: {ml_error}")
        ml_result = {
            "decision": "IGNORE",
            "severity": "LOW",
            "attack_type": "unknown",
            "confidence": 0.0,
            "anomaly_score": 0.0,
            "reason": f"proxy_catchall_exception:{type(ml_error).__name__}",
        }
        print("[PROXY ML RESULT]", ml_result)

    ml_decision_upper = str(ml_result.get("decision", "")).upper()
    trace_decision(ml_result, ml_decision_upper)
    _soc_action = "IGNORE no_action"  # updated in each branch below

    if ml_decision_upper in ("BLOCK", "ALERT"):
        if trusted_scanner_request:
            enforcement_bypassed = True
            bypass_reasons.append("ml_pipeline_block_bypassed_for_trusted_scanner")
            _soc_action = "BYPASSED trusted_scanner"
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
        elif DEMO_MODE and SOC_MODE:
            # -- SOC MODE: check admin override, else queue for review --
            admin_override = alert_queue.check_admin_override(
                attack_type=ml_result.get("attack_type", "unknown"),
                client_ip=client_ip,
            )
            if admin_override == "ADMIN_BLOCK":
                # Admin previously decided to BLOCK this pattern
                append_log(LOG_DIR, {
                    "type": "proxy_ml_blocked_by_admin",
                    "client_ip": client_ip,
                    "method": request.method,
                    "path": path,
                    "target_url": target_url,
                    "ml_result": ml_result,
                    "admin_override": "ADMIN_BLOCK",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                })
                _trace_rid = ml_result.get("request_id", "")
                if _trace_rid:
                    pipeline_traces.emit(_trace_rid, "soc_queue", "completed", "admin_override=BLOCK")
                    pipeline_traces.emit(_trace_rid, "enforcement", "completed", "403 BLOCK (admin)")
                trace_soc("BLOCK enforced (admin_override)")
                return JSONResponse(
                    status_code=403,
                    content={
                        "status": 403,
                        "message": "Blocked by SOC admin decision",
                        "reason": ml_result.get("reason", "Admin override BLOCK"),
                    },
                )
            elif admin_override in ("ADMIN_ALLOW", "ADMIN_IGNORE"):
                # Admin previously decided to allow/ignore this pattern
                ml_result["decision"] = "DETECTED"
                ml_result["demo_mode"] = True
                ml_result["soc_admin_override"] = admin_override
                _soc_action = f"ALLOW admin_override={admin_override}"
                _trace_rid = ml_result.get("request_id", "")
                if _trace_rid:
                    pipeline_traces.emit(_trace_rid, "soc_queue", "completed", f"admin_override={admin_override}")
                    pipeline_traces.emit(_trace_rid, "enforcement", "completed", "forwarded (admin allow)")
                # Fall through to forward request
            else:
                # No admin decision yet -- queue alert and forward
                try:
                    alert = alert_queue.add_alert(
                        attack_type=ml_result.get("attack_type", "unknown"),
                        severity=ml_result.get("severity", "LOW"),
                        confidence=float(ml_result.get("confidence", 0.0)),
                        anomaly_score=float(ml_result.get("anomaly_score", 0.0)),
                        client_ip=client_ip,
                        method=request.method,
                        path=path,
                        url=target_url,
                        reason=ml_result.get("reason", "Pipeline decision"),
                        ml_decision_original=ml_decision_upper,
                        source="ml_pipeline",
                        ml_result=ml_result,
                    )
                except Exception as _aq_err:
                    print(f"[TRACE][SOC_ERROR] alert_queue.add_alert failed: {type(_aq_err).__name__}: {_aq_err}")
                    alert = {"alert_id": None, "status": "ALERT_QUEUE_ERROR"}
                emit_security_event(
                    attack_type=ml_result.get("attack_type", "unknown"),
                    severity=ml_result.get("severity", "LOW"),
                    confidence=float(ml_result.get("confidence", 0.0)),
                    anomaly_score=float(ml_result.get("anomaly_score", 0.0)),
                    url=target_url,
                    method=request.method,
                    path=path,
                    reason=ml_result.get("reason", "Pipeline decision"),
                    source="ml_pipeline",
                    client_ip=client_ip,
                    ml_result=ml_result,
                    alert_id=alert.get("alert_id"),
                    action_override="pending_admin_action",
                )
                append_log(LOG_DIR, {
                    "type": "proxy_ml_pending_admin",
                    "client_ip": client_ip,
                    "method": request.method,
                    "path": path,
                    "target_url": target_url,
                    "ml_result": ml_result,
                    "alert_id": alert.get("alert_id"),
                    "soc_mode": True,
                    "original_decision": ml_decision_upper,
                    "effective_decision": "PENDING_ADMIN_ACTION",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                })
                ml_result["decision"] = "DETECTED"
                ml_result["demo_mode"] = True
                ml_result["soc_alert_id"] = alert.get("alert_id")
                _soc_action = f"ALERT queued alert_id={alert.get('alert_id')}"
                _trace_rid = ml_result.get("request_id", "")
                if _trace_rid:
                    pipeline_traces.emit(_trace_rid, "soc_queue", "completed", {"alert_id": alert.get("alert_id"), "status": "PENDING_ADMIN_ACTION"})
                    pipeline_traces.emit(_trace_rid, "enforcement", "completed", "forwarded (pending admin)")
                # Do NOT return 403 -- fall through to forward request
        elif DEMO_MODE:
            # -- DEMO MODE: detect + log + forward (never block) --
            emit_security_event(
                attack_type=ml_result.get("attack_type", "unknown"),
                severity=ml_result.get("severity", "LOW"),
                confidence=float(ml_result.get("confidence", 0.0)),
                anomaly_score=float(ml_result.get("anomaly_score", 0.0)),
                url=target_url,
                method=request.method,
                path=path,
                reason=ml_result.get("reason", "Pipeline decision BLOCK"),
                source="ml_pipeline",
                client_ip=client_ip,
                ml_result=ml_result,
            )
            append_log(LOG_DIR, {
                "type": "proxy_ml_block_demoted_demo",
                "client_ip": client_ip,
                "method": request.method,
                "path": path,
                "target_url": target_url,
                "ml_result": ml_result,
                "demo_mode": True,
                "original_decision": ml_decision_upper,
                "effective_decision": "DETECTED",
                "timestamp": datetime.utcnow().isoformat() + "Z",
            })
            ml_result["decision"] = "DETECTED"
            ml_result["demo_mode"] = True
            _soc_action = "ALERT logged (demo_mode)"
            _trace_rid = ml_result.get("request_id", "")
            if _trace_rid:
                pipeline_traces.emit(_trace_rid, "soc_queue", "completed", "logged (demo_mode)")
                pipeline_traces.emit(_trace_rid, "enforcement", "completed", "forwarded (demo)")
            # Do NOT return 403 -- fall through to forward request
        elif ml_decision_upper == "BLOCK":
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
            _trace_rid = ml_result.get("request_id", "")
            if _trace_rid:
                pipeline_traces.emit(_trace_rid, "soc_queue", "completed", "direct enforcement")
                pipeline_traces.emit(_trace_rid, "enforcement", "completed", "403 BLOCK")
            trace_soc("BLOCK enforced returning 403")
            return JSONResponse(
                status_code=403,
                content={
                    "status": 403,
                    "message": "Blocked by ML security system",
                    "reason": ml_result.get("reason", "Pipeline decision BLOCK"),
                },
            )
        elif ml_decision_upper == "ALERT":
            # Production mode (no DEMO, no SOC): ALERT must be logged â€” it is
            # not silently ignored. The request is forwarded but the alert is
            # recorded for operator review.
            append_log(LOG_DIR, {
                "type": "proxy_ml_alert_production",
                "client_ip": client_ip,
                "method": request.method,
                "path": path,
                "target_url": target_url,
                "ml_result": ml_result,
                "timestamp": datetime.utcnow().isoformat() + "Z",
            })
            _soc_action = "ALERT logged (production)"
            _trace_rid = ml_result.get("request_id", "")
            if _trace_rid:
                pipeline_traces.emit(_trace_rid, "soc_queue", "completed", "logged (production alert)")
                pipeline_traces.emit(_trace_rid, "enforcement", "completed", "forwarded")
    
    # Emit soc_queue + enforcement for IGNORE decisions (benign traffic)
    _trace_rid = ml_result.get("request_id", "")
    if _trace_rid and _soc_action == "IGNORE no_action":
        pipeline_traces.emit(_trace_rid, "soc_queue", "completed", "not queued (benign)")
        pipeline_traces.emit(_trace_rid, "enforcement", "completed", "forwarded")

    trace_soc(_soc_action)

    # â”€â”€ ENFORCEMENT GATE â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    # If ML pipeline decided BLOCK, terminate the request here.
    # Do NOT forward to Moodle backend. Return 403 immediately.
    # Synchronizes with SOC alert queue so dashboard shows enforcement result.
    if ml_decision_upper == "BLOCK" and not enforcement_bypassed:
        _trace_rid = ml_result.get("request_id", "")
        _existing_alert_id = ml_result.get("soc_alert_id", "")

        # 1. SOC Alert Sync â€” update existing or create new
        if _existing_alert_id:
            # Alert already created by SOC mode branch â†’ UPDATE to ENFORCED_BLOCK
            _updated = alert_queue.update_alert_enforcement(
                _existing_alert_id,
                final_decision="BLOCK",
                enforcement_source="enforcement_gate",
                http_status=403,
                request_id=_trace_rid,
            )
            _enforcement_alert_id = _existing_alert_id
        else:
            # No prior alert (production mode / direct block) â†’ CREATE new
            try:
                _enforcement_alert = alert_queue.add_alert(
                    attack_type=ml_result.get("attack_type", "unknown"),
                    severity=ml_result.get("severity", "HIGH"),
                    confidence=float(ml_result.get("confidence", 0.0)),
                    anomaly_score=float(ml_result.get("anomaly_score", 0.0)),
                    client_ip=client_ip,
                    method=request.method,
                    path=path,
                    url=target_url,
                    reason=ml_result.get("reason", "ML_DECISION_BLOCK"),
                    ml_decision_original=ml_decision_upper,
                    source="enforcement_gate",
                    ml_result=ml_result,
                )
                _enforcement_alert_id = _enforcement_alert.get("alert_id", "")
                # Immediately update to ENFORCED_BLOCK
                alert_queue.update_alert_enforcement(
                    _enforcement_alert_id,
                    final_decision="BLOCK",
                    enforcement_source="enforcement_gate",
                    http_status=403,
                    request_id=_trace_rid,
                )
            except Exception as _aq_exc:
                print(f"[ENFORCEMENT_SYNC] alert_queue error: {_aq_exc}", flush=True)
                _enforcement_alert_id = ""

        # 2. Pipeline trace â€” enforcement stage with linked alert
        if _trace_rid:
            pipeline_traces.emit(
                _trace_rid, "enforcement", "completed", {
                    "decision_final": "BLOCK",
                    "reason": "ML_DECISION_BLOCK",
                    "http_status": 403,
                    "linked_alert_id": _enforcement_alert_id,
                    "alert_origin": "enforcement_gate",
                }
            )

        # 3. Console log
        print(
            f"[ENFORCEMENT] BLOCKED request_id={_trace_rid} "
            f"reason=ML_DECISION_BLOCK path={path} ip={client_ip}",
            flush=True,
        )
        print(
            f"[ENFORCEMENT_SYNC] alert_id={_enforcement_alert_id} "
            f"status=ENFORCED_BLOCK",
            flush=True,
        )

        # 4. Persistent log
        append_log(LOG_DIR, {
            "type": "enforcement_blocked",
            "client_ip": client_ip,
            "method": request.method,
            "path": path,
            "target_url": target_url,
            "ml_decision": ml_decision_upper,
            "attack_type": ml_result.get("attack_type", "unknown"),
            "confidence": float(ml_result.get("confidence", 0.0)),
            "request_id": _trace_rid,
            "alert_id": _enforcement_alert_id,
            "alert_origin": "enforcement_gate",
            "effective_decision": "ENFORCED_BLOCK",
            "timestamp": datetime.utcnow().isoformat() + "Z",
        })

        # 5. HTTP 403 â€” request terminates here, never reaches backend
        return JSONResponse(
            status_code=403,
            content={
                "status": 403,
                "message": "Blocked by SOC Engine",
                "request_id": _trace_rid,
                "alert_id": _enforcement_alert_id,
                "attack_type": ml_result.get("attack_type", "unknown"),
                "reason": ml_result.get("reason", "ML_DECISION_BLOCK"),
                "effective_decision": "ENFORCED_BLOCK",
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
            and anomaly_detected
            and anomaly_score >= ANOMALY_BLOCK_THRESHOLD
        ):
            # POST-FORWARD ANOMALY: support signal only â€” DO NOT create SOC alerts
            # or return 403 from this path.  DecisionEngine (pre-forward) is the
            # SOLE authority for BLOCK / ALERT / SOC queue decisions.
            # This block exists only to surface the behavioral anomaly in logs.
            append_log(LOG_DIR, {
                "type": "proxy_postforward_anomaly_signal",
                "note": "observability_only_not_a_decision",
                "client_ip": client_ip,
                "method": request.method,
                "path": path,
                "target_url": target_url,
                "status_code": response.status_code,
                "anomaly_score": round(float(anomaly_score), 4),
                "anomaly_reason": anomaly_reason,
                "pre_forward_decision": ml_result.get("decision", "IGNORE"),
                "timestamp": datetime.utcnow().isoformat() + "Z",
            })
            trace_anomaly_post(float(anomaly_score))
        
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

        # â”€â”€ DEMO MODE: attach alert metadata header when attack was detected â”€â”€
        if DEMO_MODE and ml_result.get("demo_mode"):
            response_headers["X-MoodleSec-Alert"] = ml_result.get("attack_type", "unknown")
            response_headers["X-MoodleSec-Mode"] = "DEMO"
        
        trace_response(response.status_code, ml_decision_upper)
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
