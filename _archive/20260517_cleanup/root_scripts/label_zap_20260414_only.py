import json
from pathlib import Path
from collections import Counter

INPUT_PATH = Path("proxy/ml/training_data/2026-04-14-ZAP-Report-localhost.json")
OUTPUT_PATH = Path("proxy/ml/training_data/2026-04-14-ZAP-Report-localhost_labeled.json")

# Label mapping requested by user
TP_ALERTS = {
    'Server Leaks Version Information via "Server" HTTP Response Header Field',
    'Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s)',
    'X-Content-Type-Options Header Missing',
    'Cookie No HttpOnly Flag',
    'Cookie without SameSite Attribute',
    'Hidden File Found',
    'Information Disclosure - Sensitive Information in URL',
}

FP_ALERTS = {
    'Authentication Request Identified',
    'Modern Web Application',
    'User Agent Fuzzer',
    'Session Management Response Identified',
    'ZAP is Out of Date',
}

POTENTIAL_ALERTS = {
    'Content Security Policy (CSP) Header Not Set',
    'Missing Anti-clickjacking Header',
    'Big Redirect Detected (Potential Sensitive Information Leak)',
}


def label_for_alert(alert_name: str):
    if alert_name in TP_ALERTS:
        return 0, "TP"
    if alert_name in FP_ALERTS:
        return 1, "FP"
    if alert_name in POTENTIAL_ALERTS:
        return 2, "Potential"
    return 2, "Potential"


def severity_from_riskdesc(riskdesc: str):
    r = (riskdesc or "").lower()
    if "high" in r:
        return "High"
    if "medium" in r:
        return "Medium"
    if "low" in r:
        return "Low"
    return "Low"


def clean_html(text: str):
    # Keep simple and dependency-free: input mostly plain text in this report
    return (text or "").strip()


def main():
    if not INPUT_PATH.exists():
        raise FileNotFoundError(f"Input not found: {INPUT_PATH}")

    data = json.loads(INPUT_PATH.read_text(encoding="utf-8"))
    out = []

    for site in data.get("site", []):
        site_name = site.get("@name", "")
        for alert in site.get("alerts", []):
            alert_name = alert.get("alert", "Unknown")
            riskdesc = alert.get("riskdesc", "")
            severity = severity_from_riskdesc(riskdesc)
            label, label_name = label_for_alert(alert_name)

            for inst in alert.get("instances", []):
                evidence = clean_html(inst.get("evidence", ""))
                if not evidence:
                    evidence = clean_html(inst.get("otherinfo", ""))
                if not evidence:
                    evidence = clean_html(alert.get("desc", ""))

                out.append({
                    "severity": severity,
                    "category": alert_name,
                    "description": clean_html(alert.get("desc", "")),
                    "evidence": evidence,
                    "url": inst.get("uri", ""),
                    "cvss_score": 0.0,
                    "label": label,
                    "label_name": label_name,
                    "confidence": 0.95 if label_name == "TP" else 0.85 if label_name == "FP" else 0.60,
                    "reason": "Evidence-backed weakness in response" if label_name == "TP" else "Scanner metadata/context finding, not direct vulnerability evidence" if label_name == "FP" else "Needs manual confirmation from response headers/redirect behavior",
                    "strategy": "manual_mapping:2026-04-14-zap-only",
                    "scan_id": "zap_2026-04-14-ZAP-Report-localhost",
                    "source_site": site_name,
                })

    OUTPUT_PATH.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")

    counts = Counter(x["label_name"] for x in out)
    print(f"OUTPUT: {OUTPUT_PATH}")
    print(f"TOTAL: {len(out)}")
    print(f"TP: {counts.get('TP', 0)}")
    print(f"FP: {counts.get('FP', 0)}")
    print(f"Potential: {counts.get('Potential', 0)}")


if __name__ == "__main__":
    main()
