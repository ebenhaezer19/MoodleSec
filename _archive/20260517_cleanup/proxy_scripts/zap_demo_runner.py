#!/usr/bin/env python3
"""
ZAP Demo Runner - Untuk keperluan sidang/demo
Menjalankan ZAP scan terhadap Moodle localhost dan mengimport payloads

Usage (dari prd env):
    python zap_demo_runner.py

Workflow:
    1. Start ZAP daemon (background)
    2. Wait for API ready
    3. Spider Moodle
    4. Active scan (SQLi, XSS, CSRF)
    5. Import findings ke payload repository
    6. Print summary
"""

import subprocess
import time
import sys
import os
import requests
import json
from pathlib import Path

ZAP_BAT = r"C:\Program Files\ZAP\Zed Attack Proxy\zap.bat"
ZAP_API  = "http://localhost:8080"
MOODLE   = "http://localhost"          # ganti jika perlu
ZAP_KEY  = ""                          # api.disablekey=true jadi kosong

sys.path.insert(0, str(Path(__file__).parent / "database"))
from payload_repository import PayloadRepositoryManager

REPO = PayloadRepositoryManager("data/payload_repository.db")


# ─── helpers ─────────────────────────────────────────────────────────────────

def zap_get(endpoint: str, params: dict = None):
    p = params or {}
    if ZAP_KEY:
        p["apikey"] = ZAP_KEY
    r = requests.get(f"{ZAP_API}{endpoint}", params=p, timeout=60)
    return r.json()


def wait_for_zap(max_wait=120):
    print("[ZAP] Waiting for ZAP API to be ready", end="", flush=True)
    for _ in range(max_wait):
        try:
            r = requests.get(f"{ZAP_API}/JSON/core/view/version/", timeout=3)
            if r.status_code == 200:
                ver = r.json().get("version", "?")
                print(f"\n[ZAP] ✓ Ready  (version {ver})")
                return True
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(1)
    print("\n[ZAP] ✗ Timeout — ZAP did not start")
    return False


def is_zap_running():
    try:
        r = requests.get(f"{ZAP_API}/JSON/core/view/version/", timeout=3)
        return r.status_code == 200
    except Exception:
        return False


# ─── main flow ───────────────────────────────────────────────────────────────

def main():
    print("=" * 65)
    print("  ZAP DEMO RUNNER  —  MoodleSec Sidang")
    print("=" * 65)

    # 1. Start ZAP if not running
    if is_zap_running():
        print("[ZAP] Already running ✓")
    else:
        print("[ZAP] Starting ZAP daemon...")
        subprocess.Popen(
            [
                ZAP_BAT,
                "-daemon",
                "-port", "8080",
                "-host", "0.0.0.0",
                "-config", "api.disablekey=true",
                "-config", "api.addrs.addr.name=.*",
                "-config", "api.addrs.addr.regex=true",
                "-config", "connection.timeoutInSecs=60",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if not wait_for_zap(max_wait=120):
            print("[!] ZAP failed to start. Trying to import from existing reports instead...")
            _import_from_reports_fallback()
            return

    # 2. Spider
    print(f"\n[ZAP] Starting Spider on {MOODLE} ...")
    resp = zap_get("/JSON/spider/action/scan/", {"url": MOODLE, "maxChildren": 10, "recurse": "true"})
    scan_id = resp.get("scan", "0")
    print(f"[ZAP] Spider scan ID: {scan_id}")

    for _ in range(60):
        prog = zap_get("/JSON/spider/view/status/", {"scanId": scan_id})
        pct = prog.get("status", "0")
        print(f"      Spider: {pct}%", end="\r", flush=True)
        if str(pct) == "100":
            break
        time.sleep(3)
    print(f"\n[ZAP] ✓ Spider complete")

    # 3. Active Scan
    print(f"\n[ZAP] Starting Active Scan on {MOODLE} ...")
    resp = zap_get("/JSON/ascan/action/scan/", {
        "url": MOODLE,
        "recurse": "true",
        "scanPolicyName": "",
        "method": "GET",
    })
    ascan_id = resp.get("scan", "0")
    print(f"[ZAP] Active scan ID: {ascan_id}")

    start = time.time()
    while time.time() - start < 300:          # max 5 min
        prog = zap_get("/JSON/ascan/view/status/", {"scanId": ascan_id})
        pct = prog.get("status", "0")
        print(f"      Active scan: {pct}%", end="\r", flush=True)
        if str(pct) == "100":
            break
        time.sleep(5)
    print(f"\n[ZAP] ✓ Active scan complete")

    # 4. Fetch alerts and import to DB
    print(f"\n[ZAP] Fetching alerts...")
    data = zap_get("/JSON/core/view/alerts/", {"baseurl": MOODLE, "count": "500"})
    alerts = data.get("alerts", [])
    print(f"[ZAP] Found {len(alerts)} alerts")

    _import_alerts(alerts)


def _import_alerts(alerts):
    RISK_MAP = {"0": "Info", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}
    CAT_MAP  = [
        (["sql"], "SQL Injection"),
        (["xss", "cross site scripting", "cross-site scripting"], "XSS"),
        (["csrf", "anti-forgery", "cross-site request forgery"], "CSRF"),
        (["path traversal", "directory"], "Path Traversal"),
        (["header", "strict-transport", "content-security", "x-frame"], "Security Header"),
        (["cookie", "httponly", "samesite"], "Insecure Cookie"),
        (["information disclosure", "disclosure"], "Information Disclosure"),
    ]

    def norm_cat(name):
        n = name.lower()
        for kws, cat in CAT_MAP:
            if any(k in n for k in kws):
                return cat
        return "Other"

    imported = 0
    by_cat = {}

    for alert in alerts:
        name      = alert.get("alert", alert.get("name", "Unknown"))
        riskcode  = str(alert.get("riskcode", "1"))
        evidence  = alert.get("evidence", "").strip()
        attack    = alert.get("attack", "").strip()
        uri       = alert.get("url", "")
        category  = norm_cat(name)
        severity  = RISK_MAP.get(riskcode, "Low")

        payload_text = attack or evidence
        if not payload_text or len(payload_text) < 2:
            continue

        try:
            REPO.add_payload(
                payload_text=payload_text[:1000],
                category=category,
                payload_type="zap_live_scan",
                severity=severity,
                source="ZAP_live",
                description=f"ZAP live: {name}",
                url=uri,
                ml_confidence=None,
                created_method="zap_demo_runner",
                source_metadata=json.dumps({"zap_alert": name, "riskcode": riskcode}),
            )
            imported += 1
            by_cat[category] = by_cat.get(category, 0) + 1
        except Exception:
            pass

    print(f"\n✅ Imported {imported} payloads from ZAP live scan\n")
    print(f"  {'Category':<35} {'Count':>6}")
    print(f"  {'-'*42}")
    for cat, cnt in sorted(by_cat.items(), key=lambda x: -x[1]):
        print(f"  {cat:<35} {cnt:>6}")

    stats = REPO.get_stats()
    print(f"\n  Total in payload DB : {stats.get('total_payloads', '?')}")
    print(f"\n▶ Restart proxy dan jalankan scan untuk menggunakan payloads ini.")


def _import_from_reports_fallback():
    """Import dari local JSON report files jika ZAP tidak bisa start."""
    print("\n[Fallback] Running import_from_zap_reports.py ...")
    script = Path(__file__).parent / "import_from_zap_reports.py"
    if script.exists():
        os.system(f'python "{script}"')
    else:
        print("[Fallback] import_from_zap_reports.py not found")


if __name__ == "__main__":
    main()
