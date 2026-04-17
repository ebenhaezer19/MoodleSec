#!/usr/bin/env python3
import csv
import json
from pathlib import Path

INPUT_JSON = Path("proxy/ml/training_data/2026-04-14-ZAP-Report-localhost.json")
OUT_JSON = Path("proxy/ml/training_data/potential_229_review_template.json")
OUT_CSV = Path("proxy/ml/training_data/potential_229_review_template.csv")

POTENTIAL_ALERTS = {
    "Content Security Policy (CSP) Header Not Set": {
        "type": "Misconfiguration",
        "severity": "Low",
        "review_hint": "Check response headers. If CSP header truly absent on target page -> TP. If header exists but scanner missed -> FP.",
    },
    "Missing Anti-clickjacking Header": {
        "type": "Misconfiguration",
        "severity": "Low",
        "review_hint": "Check X-Frame-Options or frame-ancestors in CSP. If protection absent -> TP. If protection present -> FP.",
    },
    "Big Redirect Detected (Potential Sensitive Information Leak)": {
        "type": "Info Disclosure",
        "severity": "Low",
        "review_hint": "Check redirect target/content. If sensitive data is exposed in URL/query/Location -> TP. If normal redirect only -> FP.",
    },
}


def build_rows(data):
    rows = []
    for site in data.get("site", []):
        site_name = site.get("@name", "")
        for alert in site.get("alerts", []):
            alert_name = alert.get("alert", "")
            if alert_name not in POTENTIAL_ALERTS:
                continue

            meta = POTENTIAL_ALERTS[alert_name]
            riskdesc = alert.get("riskdesc", "")
            desc = alert.get("desc", "")

            for inst in alert.get("instances", []):
                row = {
                    "final_label": "",  # fill manually: TP or FP
                    "manual_reason": "",  # fill manually
                    "alert": alert_name,
                    "type": meta["type"],
                    "severity": meta["severity"],
                    "uri": inst.get("uri", ""),
                    "method": inst.get("method", ""),
                    "param": inst.get("param", ""),
                    "evidence": inst.get("evidence", ""),
                    "otherinfo": inst.get("otherinfo", ""),
                    "riskdesc": riskdesc,
                    "alert_description": desc,
                    "review_hint": meta["review_hint"],
                    "site": site_name,
                }
                rows.append(row)
    return rows


def main():
    if not INPUT_JSON.exists():
        raise FileNotFoundError(f"Input file not found: {INPUT_JSON}")

    data = json.loads(INPUT_JSON.read_text(encoding="utf-8"))
    rows = build_rows(data)

    OUT_JSON.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")

    fieldnames = [
        "final_label",
        "manual_reason",
        "alert",
        "type",
        "severity",
        "uri",
        "method",
        "param",
        "evidence",
        "otherinfo",
        "riskdesc",
        "review_hint",
        "site",
    ]

    with OUT_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow({k: r.get(k, "") for k in fieldnames})

    by_alert = {}
    for r in rows:
        by_alert[r["alert"]] = by_alert.get(r["alert"], 0) + 1

    print(f"TOTAL_POTENTIAL_ROWS {len(rows)}")
    for k, v in sorted(by_alert.items(), key=lambda x: x[1], reverse=True):
        print(f"{v} | {k}")
    print(f"JSON_OUT {OUT_JSON}")
    print(f"CSV_OUT {OUT_CSV}")


if __name__ == "__main__":
    main()
