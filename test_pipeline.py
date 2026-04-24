import json
import os
import sys
from urllib.parse import urlencode, urlparse

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ML_DIR = os.path.join(CURRENT_DIR, "proxy", "ml")
if ML_DIR not in sys.path:
    sys.path.insert(0, ML_DIR)

from pipeline_orchestrator import PipelineOrchestrator


REQUIRED_FIELDS = ["method", "path", "query_params", "body", "headers", "request_raw"]


def _safe_str(value):
    if value is None:
        return ""
    return str(value)


def _headers_to_string(headers_value):
    if headers_value is None:
        return ""
    if isinstance(headers_value, dict):
        parts = []
        for key, value in headers_value.items():
            parts.append(f"{_safe_str(key)}: {_safe_str(value)}")
        return "; ".join(parts)
    return _safe_str(headers_value)


def _query_to_string(query_value):
    if query_value is None:
        return ""
    if isinstance(query_value, dict):
        return urlencode({str(k): _safe_str(v) for k, v in query_value.items()})
    if isinstance(query_value, (list, tuple)):
        try:
            return urlencode(query_value)
        except Exception:
            return "&".join(_safe_str(item) for item in query_value)
    return _safe_str(query_value)


def normalize_request(raw_input: dict) -> dict:
    """
    Ensures all required fields exist.
    Replace None with empty string.
    Extract path from URI if needed.
    Always return safe format.
    """
    source = raw_input or {}

    method = _safe_str(source.get("method", source.get("http_method", "GET"))).upper()
    if not method:
        method = "GET"

    raw_uri = _safe_str(source.get("uri", source.get("url", source.get("request_uri", "")))).strip()
    parsed_uri = urlparse(raw_uri) if raw_uri else None

    path = _safe_str(source.get("path", "")).strip()
    if not path and parsed_uri is not None:
        path = parsed_uri.path or "/"
    if not path:
        path = "/"
    if not path.startswith("/"):
        path = "/" + path

    query_params = _query_to_string(source.get("query_params", source.get("query", ""))).strip()
    if query_params.startswith("?"):
        query_params = query_params[1:]
    if not query_params and parsed_uri is not None:
        query_params = _safe_str(parsed_uri.query).strip()

    body_value = source.get("body", "")
    if isinstance(body_value, (dict, list, tuple)):
        body = json.dumps(body_value, ensure_ascii=True)
    else:
        body = _safe_str(body_value)

    headers = _headers_to_string(source.get("headers", ""))

    request_raw = _safe_str(source.get("request_raw", "")).strip()
    if not request_raw:
        query_suffix = f"?{query_params}" if query_params else ""
        body_suffix = f" BODY:{body}" if body else ""
        request_raw = f"{method} {path}{query_suffix}{body_suffix}".strip()

    normalized = {
        "method": method,
        "path": path,
        "query_params": query_params,
        "body": body,
        "headers": headers,
        "request_raw": request_raw,
    }

    for key in REQUIRED_FIELDS:
        if key not in normalized:
            normalized[key] = ""
        if normalized[key] is None:
            normalized[key] = ""

    return normalized


def safe_process(pipeline, request):
    """
    Runs pipeline.process_request safely.
    If error happens, return fallback result.
    """
    try:
        return pipeline.process_request(request)
    except Exception:
        return {
            "decision": "IGNORE",
            "severity": "LOW",
            "reason": "Pipeline error fallback",
            "attack_type": "unknown",
            "confidence": 0.0,
            "anomaly_score": 0.0,
        }


def _print_result(request, result):
    print(f"[TEST] {request.get('path', '/')}")
    print(f"Decision: {result.get('decision', 'UNKNOWN')}")
    print(f"Attack: {result.get('attack_type', 'unknown')}")
    print(f"Severity: {result.get('severity', 'LOW')}")
    print(f"Confidence: {float(result.get('confidence', 0.0)):.2f}")
    print(f"Anomaly Score: {float(result.get('anomaly_score', 0.0)):.2f}")
    print(f"Reason: {result.get('reason', '-')}")
    print("-" * 60)


def test_single_request(pipeline):
    """
    Test 1 manual request (XSS example).
    Print request and result.
    """
    sample_request = {
        "method": "GET",
        "path": "/login/index.php",
        "query_params": "q=<script>alert(1)</script>",
        "body": "",
        "headers": "User-Agent: Mozilla/5.0; Content-Type: application/x-www-form-urlencoded",
        "request_raw": "GET /login/index.php?q=<script>alert(1)</script>",
    }

    normalized = normalize_request(sample_request)
    result = safe_process(pipeline, normalized)
    _print_result(normalized, result)

    return {
        "request": normalized,
        "result": result,
    }


def generate_test_requests():
    """
    Return diverse test requests.
    """
    return [
        {
            "method": "GET",
            "path": "/course/view.php",
            "query_params": "id=21&section=overview",
            "body": "",
            "headers": "User-Agent: Mozilla/5.0",
            "request_raw": "GET /course/view.php?id=21&section=overview",
        },
        {
            "method": "GET",
            "path": "/login/index.php",
            "query_params": "q=<script>alert(1)</script>",
            "body": "",
            "headers": "User-Agent: Mozilla/5.0",
            "request_raw": "GET /login/index.php?q=<script>alert(1)</script>",
        },
        {
            "method": "POST",
            "path": "/mod/forum/post.php",
            "query_params": "id=5",
            "body": "content=' OR 1=1 --",
            "headers": "User-Agent: Chrome/120.0; Content-Type: application/x-www-form-urlencoded",
            "request_raw": "POST /mod/forum/post.php?id=5 BODY:content=' OR 1=1 --",
        },
        {
            "method": "GET",
            "path": "/search/index.php",
            "query_params": "q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
            "body": "",
            "headers": "User-Agent: Edge/120.0",
            "request_raw": "GET /search/index.php?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        },
        {
            "method": "GET",
            "path": "/course/report.php",
            "query_params": "search=select+course+materials&note=drop+by+later&comment=script+for+class",
            "body": "",
            "headers": "User-Agent: Safari/537.36",
            "request_raw": "GET /course/report.php?search=select+course+materials&note=drop+by+later&comment=script+for+class",
        },
        {
            "method": "GET",
            "path": "/pluginfile.php",
            "query_params": "file=..%2f..%2f..%2fetc%2fpasswd",
            "body": "",
            "headers": "User-Agent: Mozilla/5.0",
            "request_raw": "GET /pluginfile.php?file=..%2f..%2f..%2fetc%2fpasswd",
        },
        {
            "method": "POST",
            "path": "/admin/tools.php",
            "query_params": "cmd=diagnose",
            "body": "action=list; ls -la",
            "headers": "User-Agent: curl/8.0; Content-Type: application/x-www-form-urlencoded",
            "request_raw": "POST /admin/tools.php?cmd=diagnose BODY:action=list; ls -la",
        },
        {
            "method": "POST",
            "path": "/mod/assign/view.php",
            "query_params": "id=88&mode=submit",
            "body": "message=please+review+my+script+for+class+today",
            "headers": "User-Agent: Mozilla/5.0; Content-Type: application/x-www-form-urlencoded",
            "request_raw": "POST /mod/assign/view.php?id=88&mode=submit BODY:message=please+review+my+script+for+class+today",
        },
    ]


def run_batch_test(pipeline):
    """
    Loop through test requests, normalize, process safely, print and collect results.
    """
    collected = []
    for raw_request in generate_test_requests():
        normalized = normalize_request(raw_request)
        result = safe_process(pipeline, normalized)
        _print_result(normalized, result)
        collected.append({
            "request": normalized,
            "result": result,
        })
    return collected


def _json_safe(value):
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            return str(value)
    return value


def save_results(entries, output_path="results.json"):
    payload = _json_safe(entries)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=True)


def main():
    pipeline = PipelineOrchestrator(enable_logging=False)

    print("=" * 60)
    print("SINGLE REQUEST TEST")
    print("=" * 60)
    single_result = test_single_request(pipeline)

    print("=" * 60)
    print("BATCH REQUEST TEST")
    print("=" * 60)
    batch_results = run_batch_test(pipeline)

    all_results = [single_result] + batch_results
    save_results(all_results, output_path="results.json")

    summary = {"BLOCK": 0, "ALERT": 0, "IGNORE": 0}
    for item in all_results:
        decision = str(item.get("result", {}).get("decision", "IGNORE")).upper()
        if decision not in summary:
            summary[decision] = 0
        summary[decision] += 1

    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total tests: {len(all_results)}")
    for key, value in summary.items():
        print(f"{key}: {value}")
    print("Saved: results.json")


if __name__ == "__main__":
    main()
