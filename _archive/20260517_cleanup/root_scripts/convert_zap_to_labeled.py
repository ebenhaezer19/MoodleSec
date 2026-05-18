#!/usr/bin/env python3
"""
Convert ZAP JSON Report to labeled training format
"""

import json
import re
from datetime import datetime
from pathlib import Path

def extract_severity_level(riskdesc):
    """Extract severity level from ZAP riskdesc"""
    if not riskdesc:
        return "Info"
    
    if "High" in riskdesc or "Critical" in riskdesc:
        return "High"
    elif "Medium" in riskdesc:
        return "Medium"
    elif "Low" in riskdesc:
        return "Low"
    else:
        return "Info"

def determine_label(alert, riskcode):
    """
    Determine label: 1 = FP (False Positive), 0 = TP (True Positive)
    
    FP (1) = Common false positives:
      - Missing headers
      - Configuration issues
      - Not actual vulnerabilities
    
    TP (0) = Real vulnerabilities:
      - SQL Injection
      - XSS
      - Actual exploits
    """
    fp_patterns = [
        "header", "missing", "not set", "configuration",
        "deprecated", "outdated", "information disclosure",
        "server leaks", "version", "anti-clickjacking"
    ]
    
    tp_patterns = [
        "injection", "xss", "csrf", "rce", "command execution",
        "path traversal", "file inclusion", "buffer overflow"
    ]
    
    alert_lower = alert.lower()
    
    # Check TP patterns first (more specific)
    for pattern in tp_patterns:
        if pattern in alert_lower:
            return 0  # TP (True Positive)
    
    # Check FP patterns
    for pattern in fp_patterns:
        if pattern in alert_lower:
            return 1  # FP (False Positive)
    
    # Default: treat as FP (missing header/config issues are typically FP)
    return 1

def convert_confidence(zap_confidence):
    """Convert ZAP confidence (0-3) to decimal (0-1)"""
    try:
        conf = int(zap_confidence)
        # ZAP: 0=falsePositive, 1=low, 2=medium, 3=high
        confidence_map = {
            "0": 0.5,
            "1": 0.65,
            "2": 0.80,
            "3": 0.95
        }
        return confidence_map.get(str(conf), 0.75)
    except:
        return 0.75

def compute_cvss_score(severity, riskcode):
    """Compute approximate CVSS score based on risk"""
    score_map = {
        "High": 7.5,
        "Medium": 5.5,
        "Low": 3.5,
        "Info": 0.0
    }
    return score_map.get(severity, 0.0)

def get_strategy_from_alert(alert):
    """Determine strategy/pattern from alert type"""
    alert_lower = alert.lower()
    
    if "header" in alert_lower:
        return "pattern:missing_header"
    elif "injection" in alert_lower:
        return "pattern:injection"
    elif "xss" in alert_lower:
        return "pattern:xss"
    elif "csrf" in alert_lower:
        return "pattern:csrf"
    elif "path" in alert_lower or "traversal" in alert_lower:
        return "pattern:path_traversal"
    elif "cookie" in alert_lower:
        return "pattern:cookie_security"
    elif "redirect" in alert_lower:
        return "pattern:redirect"
    elif "authentication" in alert_lower:
        return "pattern:auth"
    else:
        return "pattern:general"

def clean_html(html_string):
    """Remove HTML tags from string"""
    if not html_string:
        return ""
    clean = re.compile('<.*?>')
    return re.sub(clean, '', html_string).strip()

def convert_zap_report(input_file, output_file):
    """Convert ZAP report to training format"""
    
    print(f"📖 Reading ZAP report: {input_file}")
    with open(input_file, 'r', encoding='utf-8') as f:
        zap_data = json.load(f)
    
    # Extract metadata
    scan_id = f"zap_{Path(input_file).stem}"
    generated = zap_data.get('@generated', datetime.now().isoformat())
    
    # Convert alerts
    converted_data = []
    instance_count = 0
    
    # For each site
    for site in zap_data.get('site', []):
        site_name = site.get('@name', 'unknown')
        
        # For each alert in site
        for alert in site.get('alerts', []):
            alert_name = alert.get('alert', 'Unknown')
            riskcode = alert.get('riskcode', '1')
            confidence = alert.get('confidence', '2')
            riskdesc = alert.get('riskdesc', '')
            description = alert.get('desc', '')
            solution = alert.get('solution', '')
            
            severity = extract_severity_level(riskdesc)
            label = determine_label(alert_name, riskcode)
            confidence_score = convert_confidence(confidence)
            cvss_score = compute_cvss_score(severity, riskcode)
            strategy = get_strategy_from_alert(alert_name)
            
            # For each instance of this alert
            for instance in alert.get('instances', []):
                uri = instance.get('uri', '')
                method = instance.get('method', 'GET')
                param = instance.get('param', '')
                attack = instance.get('attack', '')
                evidence = instance.get('evidence', '')
                otherinfo = instance.get('otherinfo', '')
                
                # Construct reason
                if label == 0:  # TP
                    reason = f"Potential {alert_name.lower()} vulnerability"
                else:  # FP
                    reason = f"{alert_name} (missing security best practice)"
                
                # Construct evidence
                if not evidence or evidence == "":
                    evidence = clean_html(otherinfo if otherinfo else description)
                
                # Create converted record
                converted_record = {
                    "severity": severity,
                    "category": alert_name,
                    "description": clean_html(description),
                    "evidence": clean_html(evidence),
                    "url": uri,
                    "method": method,
                    "param": param,
                    "attack": attack,
                    "cvss_score": cvss_score,
                    "label": label,  # 0 = TP, 1 = FP
                    "confidence": round(confidence_score, 2),
                    "reason": reason,
                    "strategy": strategy,
                    "scan_id": scan_id,
                    "scan_date": generated,
                    "from_site": site_name
                }
                
                converted_data.append(converted_record)
                instance_count += 1
        
    print(f"✅ Converted {instance_count} instances from {len(zap_data.get('site', []))} site(s)")
    
    # Save converted data
    print(f"💾 Saving to: {output_file}")
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(converted_data, f, indent=2, ensure_ascii=False)
    
    # Print summary
    print(f"\n📊 SUMMARY:")
    print(f"  Total findings: {len(converted_data)}")
    
    tp_count = sum(1 for x in converted_data if x['label'] == 0)
    fp_count = sum(1 for x in converted_data if x['label'] == 1)
    
    print(f"  TP findings: {tp_count} ({100*tp_count//len(converted_data)}%)")
    print(f"  FP findings: {fp_count} ({100*fp_count//len(converted_data)}%)")
    
    severity_counts = {}
    for item in converted_data:
        sev = item['severity']
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    print(f"\n  By Severity:")
    for sev in ["High", "Medium", "Low", "Info"]:
        if sev in severity_counts:
            print(f"    {sev}: {severity_counts[sev]}")
    
    return converted_data

if __name__ == "__main__":
    # Configuration
    input_zap_report = "proxy/ml/training_data/2026-04-14-ZAP-Report-localhost.json"
    output_labeled = "proxy/ml/training_data/zap_scan_labeled.json"
    
    # Check if input exists
    if not Path(input_zap_report).exists():
        print(f"❌ Error: {input_zap_report} not found!")
        print(f"   Please provide ZAP report path")
        exit(1)
    
    # Convert
    converted = convert_zap_report(input_zap_report, output_labeled)
    
    print(f"\n✨ Done! Labeled data saved to: {output_labeled}")
