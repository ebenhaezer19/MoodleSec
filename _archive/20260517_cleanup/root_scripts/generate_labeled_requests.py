#!/usr/bin/env python3
"""
Generate labeled HTTP request samples for ML pipeline evaluation.
"""

import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import requests
from requests import RequestException
from requests.exceptions import ConnectionError, Timeout


TEST_CASES: Dict[str, List[str]] = {
    "normal": [
        # NORMAL
        "http://127.0.0.1:8000/",
        "http://127.0.0.1:8000/login/index.php",
        "http://127.0.0.1:8000/course/view.php?id=1",
        "http://127.0.0.1:8000/course/view.php?id=2&section=overview",
        "http://127.0.0.1:8000/mod/assign/view.php?id=10",
        # TRICKY NORMAL
        "http://127.0.0.1:8000/search/index.php?q=select course materials",
        "http://127.0.0.1:8000/search/index.php?q=how to use script in python",
        "http://127.0.0.1:8000/course/view.php?note=drop by later",
        "http://127.0.0.1:8000/course/view.php?comment=union of sets in math",
    ],
    "attack": [
        # XSS
        "http://127.0.0.1:8000/login/index.php?q=<script>alert(1)</script>",
        "http://127.0.0.1:8000/login/index.php?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "http://127.0.0.1:8000/search/index.php?q=<img src=x onerror=alert(1)>",
        "http://127.0.0.1:8000/search/index.php?q=%3Cimg%20src=x%20onerror=alert(1)%3E",
        "http://127.0.0.1:8000/course/view.php?name=<svg onload=alert(1)>",
        # SQLi
        "http://127.0.0.1:8000/login/index.php?q=' OR 1=1 --",
        "http://127.0.0.1:8000/login/index.php?q=%27%20OR%201=1%20--",
        "http://127.0.0.1:8000/course/view.php?id=1 OR 1=1",
        "http://127.0.0.1:8000/course/view.php?id=1 UNION SELECT username,password FROM users",
        "http://127.0.0.1:8000/search/index.php?q=' UNION SELECT null,null --",
        # PATH TRAVERSAL
        "http://127.0.0.1:8000/pluginfile.php?file=../../../../etc/passwd",
        "http://127.0.0.1:8000/pluginfile.php?file=..%2F..%2F..%2Fetc%2Fpasswd",
        "http://127.0.0.1:8000/pluginfile.php?file=../../config.php",
    ],
}

MIN_REPEATS = 5
MAX_REPEATS = 10
MIN_DELAY_SECONDS = 0.3
MAX_DELAY_SECONDS = 1.5
REQUEST_TIMEOUT_SECONDS = 10
OUTPUT_PATH = Path("labeled_requests.json")
USER_AGENT = "MoodleSec-Labeled-Request-Generator/1.0"


def build_request_plan() -> List[Dict[str, str]]:
    """Build and shuffle request list with per-URL random repetition."""
    queued_requests: List[Dict[str, str]] = []

    for label, urls in TEST_CASES.items():
        for url in urls:
            repeat_count = random.randint(MIN_REPEATS, MAX_REPEATS)
            for _ in range(repeat_count):
                queued_requests.append({"url": url, "true_label": label})

    random.shuffle(queued_requests)
    return queued_requests


def utc_timestamp() -> str:
    """Return ISO8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def send_labeled_requests() -> List[Dict[str, Any]]:
    """Send queued requests and collect labeled results."""
    queued_requests = build_request_plan()
    total_requests = len(queued_requests)
    results: List[Dict[str, Any]] = []

    print("=" * 72)
    print("Starting labeled request generation")
    print(f"Total queued requests: {total_requests}")
    print(f"Output file: {OUTPUT_PATH.resolve()}")
    print("=" * 72)

    with requests.Session() as session:
        session.headers.update({"User-Agent": USER_AGENT})

        for index, item in enumerate(queued_requests, start=1):
            url = item["url"]
            true_label = item["true_label"]
            timestamp = utc_timestamp()
            status_code = None

            print(f"[{index}/{total_requests}] Sending {true_label.upper()} request")
            print(f"  URL: {url}")

            try:
                response = session.get(
                    url,
                    timeout=REQUEST_TIMEOUT_SECONDS,
                    allow_redirects=True,
                )
                status_code = response.status_code
                print(f"  Result: HTTP {status_code}")

            except Timeout:
                print("  Result: timeout")

            except ConnectionError:
                print("  Result: connection_error")

            except RequestException as request_error:
                print(f"  Result: request_error ({request_error})")

            record: Dict[str, Any] = {
                "url": url,
                "true_label": true_label,
                "status_code": status_code,
                "timestamp": timestamp,
            }

            results.append(record)

            if index < total_requests:
                sleep_seconds = random.uniform(MIN_DELAY_SECONDS, MAX_DELAY_SECONDS)
                print(f"  Sleeping {sleep_seconds:.2f}s")
                time.sleep(sleep_seconds)

    return results


def save_results(results: List[Dict[str, Any]]) -> None:
    """Write results to JSON file."""
    OUTPUT_PATH.write_text(json.dumps(results, indent=2), encoding="utf-8")


def print_summary(results: List[Dict[str, Any]]) -> None:
    """Print run summary with basic stats."""
    normal_count = sum(1 for item in results if item.get("true_label") == "normal")
    attack_count = sum(1 for item in results if item.get("true_label") == "attack")
    blocked_count = sum(1 for item in results if item.get("status_code") == 403)
    successful_count = sum(1 for item in results if isinstance(item.get("status_code"), int))
    error_count = sum(1 for item in results if item.get("status_code") is None)

    print("=" * 72)
    print("Dataset generation complete")
    print(f"Saved: {OUTPUT_PATH.resolve()}")
    print(f"Total records: {len(results)}")
    print(f"Label counts -> normal: {normal_count}, attack: {attack_count}")
    print(f"HTTP success records: {successful_count}")
    print(f"HTTP 403 records: {blocked_count}")
    print(f"Error records: {error_count}")
    print("=" * 72)


def main() -> None:
    """Entry point."""
    random.seed()
    results = send_labeled_requests()
    save_results(results)
    print_summary(results)


if __name__ == "__main__":
    main()
