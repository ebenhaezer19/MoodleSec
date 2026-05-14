#!/usr/bin/env python3
"""
Import payloads DIRECTLY from ZAP JSON report files (no ZAP server needed).

Reads ZAP report JSON files in proxy/data/ and extracts real attack payloads
into the payload repository database for use by the Native Auth Scanner.

Usage (from proxy/ directory):
    python import_from_zap_reports.py
"""

import json
import sys
import os
from pathlib import Path
from typing import List, Dict, Any

sys.path.insert(0, str(Path(__file__).parent / "database"))
from payload_repository import PayloadRepositoryManager

# ── Config ────────────────────────────────────────────────────────────────────
DATA_DIR = Path(__file__).parent / "data"
PAYLOAD_DB = str(DATA_DIR / "payload_repository.db")

ZAP_REPORTS = [
    DATA_DIR / "2025-12-04-ZAP-Report-.json",
    DATA_DIR / "2025-12-05-ZAP-Report-capacitacion100.milaulas.com.json",
    DATA_DIR / "20251219_JSON_http_localhost_8998_.json",
]

# ZAP riskcode → severity
RISK_MAP = {"0": "Info", "1": "Low", "2": "Medium", "3": "High", "4": "Critical"}

# Alert name keyword → normalized category
CATEGORY_MAP = [
    (["sql injection", "sql", "database error"], "SQL Injection"),
    (["cross site scripting", "xss", "reflected xss", "stored xss", "dom xss"], "XSS"),
    (["csrf", "cross-site request forgery", "anti-forgery"], "CSRF"),
    (["path traversal", "directory traversal", "lfi", "rfi"], "Path Traversal"),
    (["command injection", "os injection", "remote code"], "OS Command Injection"),
    (["header", "strict-transport", "content-security", "x-frame", "x-content"], "Security Header"),
    (["information disclosure", "disclosure", "server version", "server info"], "Information Disclosure"),
    (["cookie", "session", "httponly", "samesite", "secure flag"], "Insecure Cookie"),
    (["open redirect", "redirect"], "Open Redirect"),
]


def normalize_category(alert_name: str) -> str:
    name_lower = alert_name.lower()
    for keywords, cat in CATEGORY_MAP:
        if any(k in name_lower for k in keywords):
            return cat
    return "Other"


def parse_zap_standard(data: dict) -> List[Dict[str, Any]]:
    """Parse standard ZAP JSON format: {'site': [{'alerts': [...]}]}"""
    payloads = []
    for site in data.get("site", []):
        site_url = site.get("@name", "")
        for alert in site.get("alerts", []):
            name = alert.get("alert") or alert.get("name", "Unknown")
            riskcode = str(alert.get("riskcode", "1"))
            severity = RISK_MAP.get(riskcode, "Low")
            category = normalize_category(name)
            desc = alert.get("desc", "")[:300].replace("<p>", "").replace("</p>", "")

            for inst in alert.get("instances", []):
                attack = inst.get("attack", "").strip()
                evidence = inst.get("evidence", "").strip()
                uri = inst.get("uri", site_url)

                payload_text = attack or evidence
                if payload_text and len(payload_text) > 2:
                    payloads.append({
                        "payload_text": payload_text[:1000],
                        "category": category,
                        "severity": severity,
                        "description": f"ZAP: {name}",
                        "url": uri,
                        "source_meta": f'{{"alert": "{name}", "riskcode": "{riskcode}"}}'
                    })
    return payloads


def parse_acunetix_export(data: dict) -> List[Dict[str, Any]]:
    """Parse Acunetix export format: {'export': {'scans': [...]}}"""
    payloads = []
    sev_map = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
    for scan in data.get("export", {}).get("scans", []):
        target_url = scan.get("info", {}).get("target", {}).get("url", "")
        for vt in scan.get("vulnerability_types", []):
            name = vt.get("name", "Unknown")
            severity = sev_map.get(vt.get("severity", 0), "Low")
            category = normalize_category(name)
            # Use recommendation as payload hint for Acunetix (no raw attack strings)
            rec = vt.get("recommendation", "").strip()[:500]
            desc = vt.get("description", "").strip()[:200]
            if rec and len(rec) > 5:
                payloads.append({
                    "payload_text": rec,
                    "category": category,
                    "severity": severity,
                    "description": f"Acunetix: {name}",
                    "url": target_url,
                    "source_meta": f'{{"source": "acunetix", "name": "{name}"}}'
                })
    return payloads


def load_report(path: Path) -> List[Dict[str, Any]]:
    print(f"\n[+] Loading: {path.name} ({path.stat().st_size // 1024} KB)")
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    if "site" in data:
        payloads = parse_zap_standard(data)
        print(f"    Format : ZAP standard → {len(payloads)} payloads")
    elif "export" in data:
        payloads = parse_acunetix_export(data)
        print(f"    Format : Acunetix export → {len(payloads)} payloads")
    else:
        print(f"    Format : Unknown — skipping")
        payloads = []

    return payloads


def main():
    print("=" * 65)
    print("  IMPORT ZAP/ACUNETIX REPORT PAYLOADS → Payload Repository")
    print("=" * 65)

    repo = PayloadRepositoryManager(PAYLOAD_DB)

    all_payloads: List[Dict[str, Any]] = []
    for report_path in ZAP_REPORTS:
        if not report_path.exists():
            print(f"\n[-] Not found: {report_path.name} — skipping")
            continue
        payloads = load_report(report_path)
        all_payloads.extend(payloads)

    if not all_payloads:
        print("\n❌ No payloads extracted from any report file.")
        return

    print(f"\n[*] Total extracted: {len(all_payloads)} payloads across all reports")
    print("[*] Inserting into payload repository...")

    imported = 0
    by_cat: Dict[str, int] = {}

    for p in all_payloads:
        try:
            repo.add_payload(
                payload_text=p["payload_text"],
                category=p["category"],
                payload_type="zap_report",
                severity=p["severity"],
                source="ZAP_report_file",
                description=p["description"],
                url=p.get("url", ""),
                ml_confidence=None,
                created_method="import_from_zap_reports",
                source_metadata=p.get("source_meta", "{}"),
            )
            imported += 1
            by_cat[p["category"]] = by_cat.get(p["category"], 0) + 1
        except Exception as e:
            pass  # Duplicates are silently skipped

    print(f"\n✅ Imported: {imported} payloads\n")
    print(f"  {'Category':<35} {'Count':>6}")
    print(f"  {'-'*42}")
    for cat, cnt in sorted(by_cat.items(), key=lambda x: -x[1]):
        print(f"  {cat:<35} {cnt:>6}")

    stats = repo.get_stats()
    print(f"\n  Payload DB total     : {stats.get('total_payloads', '?')}")
    print(f"  Vulnerable payloads  : {stats.get('vulnerable_payloads', '?')}")
    print(f"\n▶ Restart proxy dan jalankan scan untuk menggunakan payloads ini.")


if __name__ == "__main__":
    main()
