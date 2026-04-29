#!/usr/bin/env python3
"""
Generate a harder evaluation dataset for the ML security proxy, replay it
against a running proxy, and compute metrics.
"""

from __future__ import annotations

import argparse
import json
import random
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, quote_plus

import requests
from requests import RequestException
from requests.exceptions import ConnectionError, Timeout


DEFAULT_BASE_URL = "http://127.0.0.1:8000"
DEFAULT_PIPELINE_PATH = Path("proxy/logs/pipeline_results.json")
DEFAULT_DATASET_PATH = Path("hard_eval_dataset.json")
DEFAULT_RESULTS_PATH = Path("hard_eval_results.json")

DEFAULT_SEED = 1337
DEFAULT_TIMEOUT = 10.0
DEFAULT_MIN_DELAY = 0.2
DEFAULT_MAX_DELAY = 0.9
DEFAULT_TOP_K = 10

USER_AGENT = "MoodleSec-HardEval/1.0"

REQUIRED_TRICKY_PHRASES = [
    "how to use union in math",
    "drop database course",
    "javascript alert tutorial",
    "select best courses",
    "script execution in python",
    "path traversal explanation",
    "union select meaning in SQL class",
]

TRICKY_PHRASES = REQUIRED_TRICKY_PHRASES + [
    "sql injection lecture notes",
    "xss prevention lecture",
    "command injection examples in shell class",
    "python eval function tutorial",
    "java script string vs javascript",
    "select clause practice exercises",
    "union of sets worksheet",
    "drop by office hours",
    "alert dialog in javascript",
    "path traversal vs directory traversal",
    "how to escape quotes in SQL",
    "use of cmd in windows tutorial",
    "web security module overview",
]

KEYWORD_TAGS = [
    ("union", "keyword:union"),
    ("select", "keyword:select"),
    ("drop", "keyword:drop"),
    ("script", "keyword:script"),
    ("alert", "keyword:alert"),
    ("javascript", "keyword:javascript"),
    ("onerror", "keyword:onerror"),
    ("onload", "keyword:onload"),
    ("../", "keyword:traversal"),
    ("..\\", "keyword:traversal"),
    ("passwd", "keyword:passwd"),
    ("whoami", "keyword:whoami"),
    ("cmd", "keyword:cmd"),
    ("sleep", "keyword:sleep"),
    ("benchmark", "keyword:benchmark"),
]


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if hasattr(value, "item"):
            value = value.item()
        return float(value)
    except Exception:
        return float(default)


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_timestamp(value: Any) -> Optional[datetime]:
    text = _safe_text(value).strip()
    if not text:
        return None
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def build_query(params: Iterable[Tuple[str, Any, bool]]) -> str:
    parts: List[str] = []
    for key, value, is_encoded in params:
        key_enc = quote_plus(_safe_text(key), safe="")
        value_text = _safe_text(value)
        if is_encoded:
            value_enc = value_text
        else:
            value_enc = quote_plus(value_text, safe="")
        parts.append(f"{key_enc}={value_enc}")
    return "&".join(parts)


def join_url(base_url: str, path: str, query: str) -> str:
    base = base_url.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path + ("?" + query if query else "")


def derive_tags(
    category: str,
    attack_type: str,
    payload_text: str,
    encoded: bool,
    vector: str,
) -> List[str]:
    tags = [
        f"category:{category}",
        f"attack_type:{attack_type or 'none'}",
        f"encoding:{'encoded' if encoded else 'raw'}",
        f"vector:{vector}",
    ]

    text = payload_text.lower()
    for needle, tag in KEYWORD_TAGS:
        if needle in text:
            tags.append(tag)

    return tags


def build_case(
    *,
    run_id: str,
    case_index: int,
    base_url: str,
    category: str,
    expected_label: str,
    attack_type: str,
    path: str,
    params: List[Tuple[str, Any, bool]],
    method: str = "GET",
    body: str = "",
    headers: Optional[Dict[str, str]] = None,
    payload_text: str = "",
    encoded: bool = False,
    vector: str = "query",
    notes: str = "",
) -> Dict[str, Any]:
    eval_id = f"{run_id}-{case_index:04d}"
    tracking_params = params + [
        ("eval_run", run_id, False),
        ("eval_id", eval_id, False),
    ]
    query_params = build_query(tracking_params)
    request_path = path if path.startswith("/") else "/" + path
    request_raw = f"{method} {request_path}" + (f"?{query_params}" if query_params else "") + " HTTP/1.1"
    if body:
        request_raw += f" BODY:{body}"

    resolved_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html",
    }
    if headers:
        resolved_headers.update(headers)

    return {
        "eval_run": run_id,
        "eval_id": eval_id,
        "category": category,
        "expected_label": expected_label,
        "attack_type": attack_type,
        "encoded": encoded,
        "payload_text": payload_text,
        "vector": vector,
        "pattern_tags": derive_tags(category, attack_type, payload_text, encoded, vector),
        "notes": notes,
        "request": {
            "method": method,
            "path": request_path,
            "query_params": query_params,
            "body": body,
            "headers": resolved_headers,
            "request_raw": request_raw,
        },
        "target_url": join_url(base_url, request_path, query_params),
        "replay": {},
        "pipeline": {},
    }


def _normal_factories() -> List[Any]:
    def home(rng: random.Random) -> Dict[str, Any]:
        return {"path": "/", "params": [], "notes": "navigation"}

    def login(rng: random.Random) -> Dict[str, Any]:
        return {"path": "/login/index.php", "params": [("redirect", "0", False)], "notes": "login"}

    def course_view(rng: random.Random) -> Dict[str, Any]:
        course_id = rng.randint(1, 120)
        section = rng.choice(["overview", "grades", "participants", "forum", "content"])
        return {
            "path": "/course/view.php",
            "params": [("id", course_id, False), ("section", section, False)],
            "notes": "course page",
        }

    def course_index(rng: random.Random) -> Dict[str, Any]:
        category_id = rng.randint(1, 20)
        return {"path": "/course/index.php", "params": [("categoryid", category_id, False)], "notes": "course index"}

    def assignment_view(rng: random.Random) -> Dict[str, Any]:
        assign_id = rng.randint(1, 80)
        return {"path": "/mod/assign/view.php", "params": [("id", assign_id, False)], "notes": "assignment"}

    def calendar_view(rng: random.Random) -> Dict[str, Any]:
        course_id = rng.randint(1, 50)
        time_value = rng.randint(1700000000, 1900000000)
        return {
            "path": "/calendar/view.php",
            "params": [("view", "month", False), ("time", time_value, False), ("course", course_id, False)],
            "notes": "calendar",
        }

    def calendar_index(rng: random.Random) -> Dict[str, Any]:
        return {"path": "/calendar/index.php", "params": [], "notes": "calendar"}

    def profile(rng: random.Random) -> Dict[str, Any]:
        user_id = rng.randint(1, 2000)
        return {"path": "/user/profile.php", "params": [("id", user_id, False)], "notes": "profile"}

    def profile_edit(rng: random.Random) -> Dict[str, Any]:
        user_id = rng.randint(1, 2000)
        return {"path": "/user/edit.php", "params": [("id", user_id, False)], "notes": "profile"}

    def dashboard(rng: random.Random) -> Dict[str, Any]:
        return {"path": "/my/", "params": [], "notes": "navigation"}

    def grade_report(rng: random.Random) -> Dict[str, Any]:
        course_id = rng.randint(1, 80)
        return {"path": "/grade/report/user/index.php", "params": [("id", course_id, False)], "notes": "course grades"}

    def message_center(rng: random.Random) -> Dict[str, Any]:
        return {"path": "/message/index.php", "params": [("view", "recent", False)], "notes": "navigation"}

    def forum_view(rng: random.Random) -> Dict[str, Any]:
        forum_id = rng.randint(1, 60)
        return {"path": "/mod/forum/view.php", "params": [("id", forum_id, False)], "notes": "course forum"}

    def forum_discuss(rng: random.Random) -> Dict[str, Any]:
        discuss_id = rng.randint(1, 200)
        return {"path": "/mod/forum/discuss.php", "params": [("d", discuss_id, False)], "notes": "course forum"}

    def quiz_view(rng: random.Random) -> Dict[str, Any]:
        quiz_id = rng.randint(1, 90)
        return {"path": "/mod/quiz/view.php", "params": [("id", quiz_id, False)], "notes": "course quiz"}

    return [
        home,
        login,
        course_view,
        course_index,
        assignment_view,
        calendar_view,
        calendar_index,
        profile,
        profile_edit,
        dashboard,
        grade_report,
        message_center,
        forum_view,
        forum_discuss,
        quiz_view,
    ]


def _tricky_factory(rng: random.Random, phrase: Optional[str] = None) -> Dict[str, Any]:
    endpoints = [
        ("/search/index.php", "q"),
        ("/course/search.php", "search"),
        ("/mod/forum/search.php", "search"),
        ("/tag/index.php", "tag"),
    ]
    path, param_name = rng.choice(endpoints)
    payload = phrase or rng.choice(TRICKY_PHRASES)
    return {
        "path": path,
        "params": [(param_name, payload, False)],
        "payload_text": payload,
        "notes": "tricky benign",
    }


def _attack_payloads() -> Dict[str, List[Dict[str, Any]]]:
    return {
        "SQLi": [
            {"payload": "' OR 1=1 --", "encoded": False},
            {"payload": "\" OR 1=1 --", "encoded": False},
            {"payload": "1 OR 1=1", "encoded": False},
            {"payload": "1 UNION SELECT username,password FROM users", "encoded": False},
            {"payload": "1' UNION SELECT NULL,NULL --", "encoded": False},
            {"payload": "%27%20OR%201%3D1%20--", "encoded": True},
            {"payload": "1%20UNION%20SELECT%20username%2Cpassword%20FROM%20users", "encoded": True},
            {"payload": "%27%20UNION%20SELECT%20NULL%2CNULL%20--", "encoded": True},
            {"payload": "1%27%3B%20DROP%20TABLE%20users%3B--", "encoded": True},
        ],
        "XSS": [
            {"payload": "<script>alert(1)</script>", "encoded": False},
            {"payload": "<img src=x onerror=alert(1)>", "encoded": False},
            {"payload": "<svg onload=alert(1)>", "encoded": False},
            {"payload": "\"><script>alert(1)</script>", "encoded": False},
            {"payload": "javascript:alert(1)", "encoded": False},
            {"payload": "%3Cscript%3Ealert(1)%3C%2Fscript%3E", "encoded": True},
            {"payload": "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", "encoded": True},
            {"payload": "%3Csvg%20onload%3Dalert(1)%3E", "encoded": True},
            {"payload": "%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E", "encoded": True},
            {"payload": "javascript%3Aalert(1)", "encoded": True},
        ],
        "Path Traversal": [
            {"payload": "../../../../etc/passwd", "encoded": False},
            {"payload": "../config.php", "encoded": False},
            {"payload": "..\\..\\..\\windows\\win.ini", "encoded": False},
            {"payload": "..%2F..%2F..%2Fetc%2Fpasswd", "encoded": True},
            {"payload": "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "encoded": True},
        ],
        "Command Injection": [
            {"payload": ";cat /etc/passwd", "encoded": False},
            {"payload": "| whoami", "encoded": False},
            {"payload": "&& id", "encoded": False},
            {"payload": "$(whoami)", "encoded": False},
            {"payload": "%3Bcat%20%2Fetc%2Fpasswd", "encoded": True},
            {"payload": "%7Cwhoami", "encoded": True},
            {"payload": "%26%26id", "encoded": True},
            {"payload": "%24%28whoami%29", "encoded": True},
        ],
    }


def _attack_endpoints() -> Dict[str, List[Dict[str, Any]]]:
    return {
        "SQLi": [
            {"path": "/login/index.php", "param": "q", "method": "GET", "vector": "query"},
            {"path": "/course/view.php", "param": "id", "method": "GET", "vector": "query"},
            {"path": "/user/profile.php", "param": "id", "method": "GET", "vector": "query"},
            {"path": "/search/index.php", "param": "q", "method": "GET", "vector": "query"},
        ],
        "XSS": [
            {"path": "/search/index.php", "param": "q", "method": "GET", "vector": "query"},
            {"path": "/course/view.php", "param": "name", "method": "GET", "vector": "query"},
            {"path": "/user/profile.php", "param": "bio", "method": "GET", "vector": "query"},
            {"path": "/mod/forum/post.php", "param": "message", "method": "POST", "vector": "body"},
        ],
        "Path Traversal": [
            {"path": "/pluginfile.php", "param": "file", "method": "GET", "vector": "query"},
            {"path": "/theme/image.php", "param": "image", "method": "GET", "vector": "query"},
        ],
        "Command Injection": [
            {"path": "/admin/tool/task/schedule_task.php", "param": "cmd", "method": "GET", "vector": "query"},
            {"path": "/admin/tool/task/schedule_task.php", "param": "cmd", "method": "POST", "vector": "body"},
        ],
    }


def _build_body(param: str, payload: str, encoded: bool) -> str:
    if encoded:
        return f"{param}={payload}"
    return f"{param}={payload}"


def generate_normal_cases(
    rng: random.Random,
    run_id: str,
    base_url: str,
    start_index: int,
    count: int,
) -> Tuple[List[Dict[str, Any]], int]:
    cases: List[Dict[str, Any]] = []
    factories = _normal_factories()

    required_factories = [
        factories[0],  # home
        factories[1],  # login
        factories[2],  # course
        factories[4],  # assignment
        factories[5],  # calendar
        factories[7],  # profile
    ]

    case_index = start_index
    for factory in required_factories:
        if len(cases) >= count:
            break
        spec = factory(rng)
        cases.append(
            build_case(
                run_id=run_id,
                case_index=case_index,
                base_url=base_url,
                category="benign_normal",
                expected_label="normal",
                attack_type="none",
                path=spec["path"],
                params=spec["params"],
                notes=spec.get("notes", ""),
            )
        )
        case_index += 1

    while len(cases) < count:
        spec = rng.choice(factories)(rng)
        cases.append(
            build_case(
                run_id=run_id,
                case_index=case_index,
                base_url=base_url,
                category="benign_normal",
                expected_label="normal",
                attack_type="none",
                path=spec["path"],
                params=spec["params"],
                notes=spec.get("notes", ""),
            )
        )
        case_index += 1

    return cases, case_index


def generate_tricky_cases(
    rng: random.Random,
    run_id: str,
    base_url: str,
    start_index: int,
    count: int,
) -> Tuple[List[Dict[str, Any]], int]:
    cases: List[Dict[str, Any]] = []
    case_index = start_index

    for phrase in REQUIRED_TRICKY_PHRASES:
        if len(cases) >= count:
            break
        spec = _tricky_factory(rng, phrase=phrase)
        cases.append(
            build_case(
                run_id=run_id,
                case_index=case_index,
                base_url=base_url,
                category="benign_tricky",
                expected_label="normal",
                attack_type="none",
                path=spec["path"],
                params=spec["params"],
                payload_text=spec.get("payload_text", ""),
                notes=spec.get("notes", ""),
            )
        )
        case_index += 1

    while len(cases) < count:
        spec = _tricky_factory(rng)
        cases.append(
            build_case(
                run_id=run_id,
                case_index=case_index,
                base_url=base_url,
                category="benign_tricky",
                expected_label="normal",
                attack_type="none",
                path=spec["path"],
                params=spec["params"],
                payload_text=spec.get("payload_text", ""),
                notes=spec.get("notes", ""),
            )
        )
        case_index += 1

    return cases, case_index


def _allocate_counts(total: int, buckets: List[str]) -> Dict[str, int]:
    base = total // len(buckets)
    remainder = total % len(buckets)
    counts = {bucket: base for bucket in buckets}
    for idx in range(remainder):
        counts[buckets[idx]] += 1
    return counts


def generate_malicious_cases(
    rng: random.Random,
    run_id: str,
    base_url: str,
    start_index: int,
    count: int,
) -> Tuple[List[Dict[str, Any]], int]:
    cases: List[Dict[str, Any]] = []
    payloads = _attack_payloads()
    endpoints = _attack_endpoints()

    case_index = start_index
    attack_types = list(payloads.keys())
    counts = _allocate_counts(count, attack_types)

    for attack_type in attack_types:
        desired = counts.get(attack_type, 0)
        if desired <= 0:
            continue

        pool = payloads[attack_type]
        raw_pool = [p for p in pool if not p["encoded"]]
        enc_pool = [p for p in pool if p["encoded"]]

        selections: List[Dict[str, Any]] = []
        if raw_pool:
            selections.append(rng.choice(raw_pool))
        if enc_pool:
            selections.append(rng.choice(enc_pool))

        while len(selections) < desired:
            selections.append(rng.choice(pool))

        for payload_entry in selections[:desired]:
            endpoint = rng.choice(endpoints[attack_type])
            payload = payload_entry["payload"]
            encoded = bool(payload_entry["encoded"])
            vector = endpoint["vector"]
            method = endpoint["method"]
            param_name = endpoint["param"]

            params: List[Tuple[str, Any, bool]] = []
            body = ""
            headers: Dict[str, str] = {}

            if vector == "query":
                params.append((param_name, payload, encoded))
            else:
                body = _build_body(param_name, payload, encoded)
                headers["Content-Type"] = "application/x-www-form-urlencoded"

            cases.append(
                build_case(
                    run_id=run_id,
                    case_index=case_index,
                    base_url=base_url,
                    category="malicious",
                    expected_label="attack",
                    attack_type=attack_type,
                    path=endpoint["path"],
                    params=params,
                    method=method,
                    body=body,
                    headers=headers,
                    payload_text=payload,
                    encoded=encoded,
                    vector=vector,
                    notes=f"{attack_type} payload",
                )
            )
            case_index += 1

    return cases, case_index


def save_json(data: Any, path: Path) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=True), encoding="utf-8")


def replay_cases(
    cases: List[Dict[str, Any]],
    timeout: float,
    min_delay: float,
    max_delay: float,
) -> None:
    if not cases:
        return

    print("=" * 72)
    print("Replaying evaluation requests")
    print(f"Total requests: {len(cases)}")
    print("=" * 72)

    with requests.Session() as session:
        for idx, case in enumerate(cases, start=1):
            request = case.get("request", {})
            method = _safe_text(request.get("method", "GET")).upper() or "GET"
            url = _safe_text(case.get("target_url", ""))
            headers = request.get("headers", {})
            body = request.get("body", "")

            status_code = None
            error = ""
            timestamp = utc_timestamp()

            print(f"[{idx}/{len(cases)}] {method} {url}")

            try:
                response = session.request(
                    method,
                    url,
                    headers=headers,
                    data=body if body else None,
                    timeout=timeout,
                    allow_redirects=True,
                )
                status_code = response.status_code
                print(f"  Result: HTTP {status_code}")
            except Timeout:
                error = "timeout"
                print("  Result: timeout")
            except ConnectionError:
                error = "connection_error"
                print("  Result: connection_error")
            except RequestException as request_error:
                error = f"request_error: {request_error}"
                print(f"  Result: request_error ({request_error})")

            case["replay"] = {
                "timestamp": timestamp,
                "status_code": status_code,
                "error": error,
            }

            if idx < len(cases):
                sleep_seconds = random.uniform(min_delay, max_delay)
                print(f"  Sleeping {sleep_seconds:.2f}s")
                time.sleep(sleep_seconds)


def load_pipeline_entries(path: Path) -> List[Dict[str, Any]]:
    if not path.exists() or not path.is_file():
        print(f"[WARN] Pipeline log not found: {path}")
        return []

    try:
        raw_text = path.read_text(encoding="utf-8", errors="replace").strip()
        if not raw_text:
            print(f"[WARN] Pipeline log is empty: {path}")
            return []
        payload = json.loads(raw_text)
    except Exception as error:
        print(f"[WARN] Failed reading pipeline log: {error}")
        return []

    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        nested = payload.get("results")
        if isinstance(nested, list):
            return [item for item in nested if isinstance(item, dict)]

    print(f"[WARN] Unexpected pipeline log format: {path}")
    return []


def extract_tracking_ids(query: str) -> Tuple[str, str]:
    params = parse_qs(_safe_text(query), keep_blank_values=True)
    run_id = _safe_text(params.get("eval_run", [""])[0])
    eval_id = _safe_text(params.get("eval_id", [""])[0])
    return run_id, eval_id


def index_pipeline_entries(
    entries: List[Dict[str, Any]],
    run_id: str,
) -> Dict[str, Dict[str, Any]]:
    index: Dict[str, Dict[str, Any]] = {}
    for entry in entries:
        query = _safe_text(entry.get("query", ""))
        entry_run, eval_id = extract_tracking_ids(query)
        if not eval_id or entry_run != run_id:
            continue

        timestamp = parse_timestamp(entry.get("timestamp"))
        if eval_id not in index:
            index[eval_id] = {"entry": entry, "timestamp": timestamp}
            continue

        existing = index[eval_id]
        if timestamp and (existing["timestamp"] is None or timestamp > existing["timestamp"]):
            index[eval_id] = {"entry": entry, "timestamp": timestamp}

    return index


def attach_pipeline_results(
    cases: List[Dict[str, Any]],
    pipeline_index: Dict[str, Dict[str, Any]],
) -> List[str]:
    missing: List[str] = []

    for case in cases:
        eval_id = case.get("eval_id", "")
        match = pipeline_index.get(eval_id)
        if not match:
            missing.append(eval_id)
            continue

        entry = match["entry"]
        case["pipeline"] = {
            "timestamp": _safe_text(entry.get("timestamp")),
            "decision": _safe_text(entry.get("decision", "IGNORE")).upper(),
            "attack_type": _safe_text(entry.get("attack_type", "unknown")),
            "confidence": _safe_float(entry.get("confidence", 0.0)),
            "anomaly_score": _safe_float(entry.get("anomaly_score", 0.0)),
            "reason": _safe_text(entry.get("reason", "")),
        }

    return missing


def decision_to_label(decision: str) -> str:
    value = _safe_text(decision).upper()
    if value in {"BLOCK", "ALERT"}:
        return "attack"
    return "normal"


def compute_metrics(cases: List[Dict[str, Any]]) -> Dict[str, Any]:
    tp = fp = tn = fn = 0
    matched = 0

    for case in cases:
        pipeline = case.get("pipeline")
        if not pipeline:
            continue
        matched += 1

        expected = case.get("expected_label", "normal")
        predicted = decision_to_label(pipeline.get("decision", "IGNORE"))

        if expected == "attack" and predicted == "attack":
            tp += 1
        elif expected == "normal" and predicted == "attack":
            fp += 1
        elif expected == "normal" and predicted == "normal":
            tn += 1
        elif expected == "attack" and predicted == "normal":
            fn += 1

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
        "matched": matched,
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
    }


def summarize_status_codes(cases: List[Dict[str, Any]]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for case in cases:
        replay = case.get("replay", {})
        status = replay.get("status_code")
        if status is None:
            status_key = "none"
        else:
            status_key = str(status)
        counts[status_key] = counts.get(status_key, 0) + 1
    return counts


def select_false_cases(cases: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    fps: List[Dict[str, Any]] = []
    fns: List[Dict[str, Any]] = []

    for case in cases:
        pipeline = case.get("pipeline")
        if not pipeline:
            continue
        expected = case.get("expected_label", "normal")
        predicted = decision_to_label(pipeline.get("decision", "IGNORE"))

        if expected == "normal" and predicted == "attack":
            fps.append(case)
        elif expected == "attack" and predicted == "normal":
            fns.append(case)

    return fps, fns


def summarize_patterns(cases: List[Dict[str, Any]], top_k: int) -> List[Tuple[str, int]]:
    counter: Counter[str] = Counter()
    for case in cases:
        for tag in case.get("pattern_tags", []):
            counter[tag] += 1
    return counter.most_common(top_k)


def _case_sort_key(case: Dict[str, Any]) -> Tuple[float, float]:
    pipeline = case.get("pipeline", {})
    return (
        _safe_float(pipeline.get("confidence", 0.0)),
        _safe_float(pipeline.get("anomaly_score", 0.0)),
    )


def top_cases(cases: List[Dict[str, Any]], top_k: int) -> List[Dict[str, Any]]:
    return sorted(cases, key=_case_sort_key, reverse=True)[:top_k]


def build_case_summary(case: Dict[str, Any]) -> Dict[str, Any]:
    request = case.get("request", {})
    pipeline = case.get("pipeline", {})
    return {
        "eval_id": case.get("eval_id", ""),
        "expected_label": case.get("expected_label", ""),
        "category": case.get("category", ""),
        "attack_type": case.get("attack_type", ""),
        "encoded": case.get("encoded", False),
        "path": request.get("path", ""),
        "query_params": request.get("query_params", ""),
        "decision": pipeline.get("decision", ""),
        "pipeline_attack_type": pipeline.get("attack_type", ""),
        "confidence": pipeline.get("confidence", 0.0),
        "anomaly_score": pipeline.get("anomaly_score", 0.0),
        "reason": pipeline.get("reason", ""),
        "payload_text": case.get("payload_text", ""),
    }


def print_summary(
    run_id: str,
    cases: List[Dict[str, Any]],
    metrics: Dict[str, Any],
    fps: List[Dict[str, Any]],
    fns: List[Dict[str, Any]],
    fp_patterns: List[Tuple[str, int]],
    fn_patterns: List[Tuple[str, int]],
    missing: List[str],
    top_k: int,
) -> None:
    print("=" * 72)
    print("Hard evaluation summary")
    print("=" * 72)
    print(f"Run id: {run_id}")
    print(f"Total cases: {len(cases)}")
    print(f"Matched pipeline entries: {metrics.get('matched', 0)}")
    print(f"Missing pipeline entries: {len(missing)}")
    print("")

    print("Confusion matrix:")
    print(f"  TP={metrics.get('TP', 0)} FP={metrics.get('FP', 0)} TN={metrics.get('TN', 0)} FN={metrics.get('FN', 0)}")
    print("Metrics:")
    print(f"  Precision: {metrics.get('precision', 0.0):.4f}")
    print(f"  Recall: {metrics.get('recall', 0.0):.4f}")
    print(f"  F1: {metrics.get('f1', 0.0):.4f}")
    print(f"  False Positive Rate: {metrics.get('false_positive_rate', 0.0):.4f}")
    print(f"  False Negative Rate: {metrics.get('false_negative_rate', 0.0):.4f}")
    print("")

    print("Top false positives:")
    for case in top_cases(fps, top_k):
        summary = build_case_summary(case)
        print(
            f"  {summary['eval_id']} {summary['path']}?{summary['query_params']} -> {summary['decision']} "
            f"{summary['pipeline_attack_type']} conf={summary['confidence']:.2f}"
        )
    if not fps:
        print("  None")
    print("")

    print("Top false negatives:")
    for case in top_cases(fns, top_k):
        summary = build_case_summary(case)
        print(
            f"  {summary['eval_id']} {summary['path']}?{summary['query_params']} -> {summary['decision']} "
            f"{summary['pipeline_attack_type']} conf={summary['confidence']:.2f}"
        )
    if not fns:
        print("  None")
    print("")

    print("Most confusing payload patterns (false positives):")
    for tag, count in fp_patterns:
        print(f"  {tag:<28} {count}")
    if not fp_patterns:
        print("  None")
    print("")

    print("Most confusing payload patterns (false negatives):")
    for tag, count in fn_patterns:
        print(f"  {tag:<28} {count}")
    if not fn_patterns:
        print("  None")
    print("=" * 72)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a harder ML proxy evaluation dataset and compute metrics.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Target proxy base URL")
    parser.add_argument("--pipeline", default=str(DEFAULT_PIPELINE_PATH), help="Path to pipeline_results.json")
    parser.add_argument("--dataset-out", default=str(DEFAULT_DATASET_PATH), help="Output dataset JSON")
    parser.add_argument("--results-out", default=str(DEFAULT_RESULTS_PATH), help="Output results JSON")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED, help="Random seed for reproducibility")
    parser.add_argument("--normal-count", type=int, default=50, help="Number of benign normal cases")
    parser.add_argument("--tricky-count", type=int, default=50, help="Number of tricky benign cases")
    parser.add_argument("--malicious-count", type=int, default=50, help="Number of malicious cases")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="HTTP request timeout in seconds")
    parser.add_argument("--min-delay", type=float, default=DEFAULT_MIN_DELAY, help="Minimum delay between requests")
    parser.add_argument("--max-delay", type=float, default=DEFAULT_MAX_DELAY, help="Maximum delay between requests")
    parser.add_argument("--top-k", type=int, default=DEFAULT_TOP_K, help="Top K false cases/patterns to print")
    parser.add_argument("--run-id", default="", help="Optional run id override")
    args = parser.parse_args()

    run_id = args.run_id.strip() or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    rng = random.Random(args.seed)

    print("=" * 72)
    print("Generating hard evaluation dataset")
    print("=" * 72)
    print(f"Run id: {run_id}")
    print(f"Seed: {args.seed}")
    print(f"Normal cases: {args.normal_count}")
    print(f"Tricky cases: {args.tricky_count}")
    print(f"Malicious cases: {args.malicious_count}")
    print("=" * 72)

    case_index = 1
    cases: List[Dict[str, Any]] = []

    normal_cases, case_index = generate_normal_cases(
        rng,
        run_id,
        args.base_url,
        case_index,
        args.normal_count,
    )
    cases.extend(normal_cases)

    tricky_cases, case_index = generate_tricky_cases(
        rng,
        run_id,
        args.base_url,
        case_index,
        args.tricky_count,
    )
    cases.extend(tricky_cases)

    malicious_cases, case_index = generate_malicious_cases(
        rng,
        run_id,
        args.base_url,
        case_index,
        args.malicious_count,
    )
    cases.extend(malicious_cases)

    rng.shuffle(cases)

    replay_cases(cases, args.timeout, args.min_delay, args.max_delay)

    time.sleep(0.5)

    pipeline_entries = load_pipeline_entries(Path(args.pipeline))
    pipeline_index = index_pipeline_entries(pipeline_entries, run_id)
    missing = attach_pipeline_results(cases, pipeline_index)

    metrics = compute_metrics(cases)
    fps, fns = select_false_cases(cases)
    fp_patterns = summarize_patterns(fps, args.top_k)
    fn_patterns = summarize_patterns(fns, args.top_k)

    dataset_payload = {
        "run_id": run_id,
        "generated_at": utc_timestamp(),
        "base_url": args.base_url,
        "seed": args.seed,
        "counts": {
            "benign_normal": args.normal_count,
            "benign_tricky": args.tricky_count,
            "malicious": args.malicious_count,
            "total": len(cases),
        },
        "cases": cases,
    }

    results_payload = {
        "run_id": run_id,
        "generated_at": utc_timestamp(),
        "base_url": args.base_url,
        "seed": args.seed,
        "counts": {
            "benign_normal": args.normal_count,
            "benign_tricky": args.tricky_count,
            "malicious": args.malicious_count,
            "total": len(cases),
        },
        "status_codes": summarize_status_codes(cases),
        "metrics": metrics,
        "confusion_matrix": {
            "TP": metrics.get("TP", 0),
            "FP": metrics.get("FP", 0),
            "TN": metrics.get("TN", 0),
            "FN": metrics.get("FN", 0),
        },
        "false_positives": [build_case_summary(case) for case in fps],
        "false_negatives": [build_case_summary(case) for case in fns],
        "most_confusing_patterns": {
            "false_positives": fp_patterns,
            "false_negatives": fn_patterns,
        },
        "missing_pipeline_entries": {
            "count": len(missing),
            "eval_ids": missing,
        },
        "dataset_file": str(Path(args.dataset_out)),
        "pipeline_log": str(Path(args.pipeline)),
    }

    save_json(dataset_payload, Path(args.dataset_out))
    save_json(results_payload, Path(args.results_out))

    print_summary(
        run_id,
        cases,
        metrics,
        fps,
        fns,
        fp_patterns,
        fn_patterns,
        missing,
        args.top_k,
    )

    print(f"Dataset saved to: {Path(args.dataset_out).resolve()}")
    print(f"Results saved to: {Path(args.results_out).resolve()}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
