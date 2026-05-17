#!/usr/bin/env python3
"""
CVE Priority Tracker

Track progress of Moodle CVE reproduction and TP sample collection.
"""

import json
from pathlib import Path
from datetime import datetime

# High-priority Moodle CVEs for TP collection
CVE_PRIORITIES = [
    {
        "cve_id": "CVE-2021-36393",
        "severity": "High",
        "type": "SQL Injection",
        "affected": "Moodle < 3.9.8, < 3.10.5, < 3.11.1",
        "component": "Badges",
        "description": "SQL injection in badges component via badge ID parameter",
        "url_pattern": "/badges/overview.php?id=",
        "payload": "1' OR '1'='1 --",
        "priority": 1,
        "ease_of_reproduction": "Easy",
        "scanner_detection": "High",
        "status": "pending"
    },
    {
        "cve_id": "CVE-2021-36394",
        "severity": "High",
        "type": "XSS",
        "affected": "Moodle < 3.9.8, < 3.10.5, < 3.11.1",
        "component": "User Profile",
        "description": "Stored XSS in user profile custom fields",
        "url_pattern": "/user/profile.php",
        "payload": "<script>alert('XSS')</script>",
        "priority": 2,
        "ease_of_reproduction": "Easy",
        "scanner_detection": "High",
        "status": "pending"
    },
    {
        "cve_id": "CVE-2020-14321",
        "severity": "Critical",
        "type": "SQL Injection",
        "affected": "Moodle < 3.9.1, < 3.8.4, < 3.7.7",
        "component": "Forum",
        "description": "SQL injection in forum search functionality",
        "url_pattern": "/mod/forum/search.php",
        "payload": "search=test' UNION SELECT",
        "priority": 3,
        "ease_of_reproduction": "Medium",
        "scanner_detection": "Medium",
        "status": "pending"
    },
    {
        "cve_id": "CVE-2023-28329",
        "severity": "High",
        "type": "XSS",
        "affected": "Moodle < 4.1.2, < 4.0.7, < 3.11.13",
        "component": "Calendar",
        "description": "Stored XSS in calendar event description",
        "url_pattern": "/calendar/event.php",
        "payload": "<img src=x onerror=alert(1)>",
        "priority": 4,
        "ease_of_reproduction": "Easy",
        "scanner_detection": "High",
        "status": "pending"
    },
    {
        "cve_id": "CVE-2020-14318",
        "severity": "High",
        "type": "CSRF",
        "affected": "Moodle < 3.9.1, < 3.8.4, < 3.7.7",
        "component": "Course Management",
        "description": "CSRF protection bypass in course management",
        "url_pattern": "/course/delete.php",
        "payload": "No CSRF token required",
        "priority": 5,
        "ease_of_reproduction": "Medium",
        "scanner_detection": "Low",
        "status": "pending"
    }
]

def save_tracker():
    """Save CVE tracker to JSON."""
    tracker_file = Path('ml/training_data/cve_tracker.json')
    tracker_file.parent.mkdir(parents=True, exist_ok=True)
    
    tracker_data = {
        "last_updated": datetime.now().isoformat(),
        "total_cves": len(CVE_PRIORITIES),
        "pending": sum(1 for cve in CVE_PRIORITIES if cve['status'] == 'pending'),
        "in_progress": sum(1 for cve in CVE_PRIORITIES if cve['status'] == 'in_progress'),
        "completed": sum(1 for cve in CVE_PRIORITIES if cve['status'] == 'completed'),
        "failed": sum(1 for cve in CVE_PRIORITIES if cve['status'] == 'failed'),
        "cves": CVE_PRIORITIES
    }
    
    with open(tracker_file, 'w', encoding='utf-8') as f:
        json.dump(tracker_data, f, indent=2, ensure_ascii=False)
    
    return tracker_file

def display_priorities():
    """Display CVE priorities."""
    print("=" * 100)
    print("MOODLE CVE PRIORITY LIST - TRUE POSITIVE COLLECTION")
    print("=" * 100)
    print("\n🎯 Target: Collect 20-30 TP samples from documented CVEs")
    print("📊 Current TP count: 8")
    print("🎯 Target TP count: 30+")
    print("\n")
    
    for i, cve in enumerate(CVE_PRIORITIES, 1):
        print(f"\n{'='*100}")
        print(f"Priority {i}: {cve['cve_id']}")
        print(f"{'='*100}")
        print(f"🔴 Severity: {cve['severity']}")
        print(f"🏷️  Type: {cve['type']}")
        print(f"📦 Component: {cve['component']}")
        print(f"🎯 Affected Versions: {cve['affected']}")
        print(f"\n📝 Description:")
        print(f"   {cve['description']}")
        print(f"\n🔗 Attack Pattern:")
        print(f"   URL: {cve['url_pattern']}")
        print(f"   Payload: {cve['payload']}")
        print(f"\n📊 Reproduction Difficulty: {cve['ease_of_reproduction']}")
        print(f"🔍 Scanner Detection Rate: {cve['scanner_detection']}")
        print(f"✅ Status: {cve['status'].upper()}")
    
    # Next steps
    print(f"\n\n{'='*100}")
    print("NEXT STEPS")
    print(f"{'='*100}")
    print("\n1️⃣  Setup Test Environment:")
    print("   - Install Moodle 3.9.0 (vulnerable version)")
    print("   - Docker: docker pull moodle/moodle:3.9.0")
    print("   - Or Bitnami: https://bitnami.com/stack/moodle/installer")
    print("\n2️⃣  Start with Priority 1 (CVE-2021-36393 - SQL Injection in Badges):")
    print("   - Easiest to reproduce")
    print("   - High scanner detection rate")
    print("   - Clear exploitation path")
    print("\n3️⃣  Reproduction Workflow:")
    print("   a. Setup vulnerable Moodle 3.9.0")
    print("   b. Create badges module")
    print("   c. Test SQL injection: /badges/overview.php?id=1' OR '1'='1")
    print("   d. Scan with OWASP ZAP")
    print("   e. Extract finding and label as TP")
    print("\n4️⃣  Timeline Estimate:")
    print("   - 5 CVEs × 2 hours = 10 hours")
    print("   - ~2 days dedicated work")
    print("   - Result: +5-10 TP samples")
    print(f"\n{'='*100}")
    
    # Save tracker
    tracker_file = save_tracker()
    print(f"\n💾 CVE tracker saved to: {tracker_file}")
    print("\n📖 Full guide available at: CVE_COLLECTION_GUIDE.md")
    print(f"\n{'='*100}\n")

if __name__ == '__main__':
    display_priorities()
