#!/usr/bin/env python3
"""Populate database with test payloads demonstrating all confidence tiers"""
from proxy.database.payload_repository import PayloadRepositoryManager

repo = PayloadRepositoryManager()

# Clear first
repo.reset_database()
print("✅ Database cleared\n")

test_data = [
    # TIER 1: Scan Extraction - ML High (95% confidence)
    {
        "payload": "<script>alert('XSS')</script>",
        "category": "XSS",
        "source": "scan_extraction",
        "ml_confidence": 0.95,
        "created_method": "scan_extraction",
        "source_metadata": '{"scan_id": "scan_001", "severity": "High", "ml_confidence": 0.95}'
    },
    # TIER 1: Scan Extraction - ML Medium (85% confidence)
    {
        "payload": "' OR '1'='1",
        "category": "SQL Injection",
        "source": "scan_extraction",
        "ml_confidence": 0.78,
        "created_method": "scan_extraction",
        "source_metadata": '{"scan_id": "scan_001", "severity": "Critical", "ml_confidence": 0.78}'
    },
    # TIER 1: Scan Extraction - Low (40% confidence - FP Candidate)
    {
        "payload": "../../../etc/passwd",
        "category": "Path Traversal",
        "source": "scan_extraction",
        "ml_confidence": 0.55,
        "created_method": "scan_extraction",
        "source_metadata": '{"scan_id": "scan_002", "severity": "Medium", "ml_confidence": 0.55}'
    },
    # TIER 2: ZAP Import - Standard (80% confidence)
    {
        "payload": "<img src=x onerror='alert(1)'>",
        "category": "XSS",
        "source": "ZAP_API_import",
        "created_method": "zap_api_import",
        "source_metadata": '{"zap_alert": "Cross Site Scripting", "severity": "High"}'
    },
    # TIER 2: ZAP Import - Custom (70% confidence)
    {
        "payload": "1 UNION SELECT NULL--",
        "category": "SQL Injection",
        "source": "ZAP_API_import",
        "created_method": "zap_api_import",
        "source_metadata": '{"zap_alert": "SQL Injection", "severity": "Critical"}'
    },
    # TIER 3: Manual Input - Unverified (50% confidence)
    {
        "payload": "<svg onload=alert(1)>",
        "category": "XSS",
        "source": "custom_manual",
        "created_method": "manual_input",
        "source_metadata": '{"priority": 1, "user": "admin"}'
    },
]

print("Adding test payloads...\n")
for i, data in enumerate(test_data, 1):
    try:
        payload_id = repo.add_payload(
            payload_text=data["payload"],
            category=data["category"],
            payload_type="test",
            severity="High",
            source=data["source"],
            description=f"Test payload {i}",
            ml_confidence=data.get("ml_confidence"),
            created_method=data["created_method"],
            source_metadata=data["source_metadata"]
        )
        print(f"✅ [{i}] Added: {payload_id} | {data['created_method']}")
    except Exception as e:
        print(f"❌ [{i}] Error: {e}")

print("\n" + "=" * 80)
stats = repo.get_stats()
print(f"\n📊 Repository Stats:")
print(f"   Total Payloads: {stats['total_payloads']}")
print(f"   Avg Effectiveness: {stats['avg_effectiveness']}")

# Show payload details with tiers
import sqlite3
conn = sqlite3.connect(repo.db_path)
cursor = conn.cursor()
cursor.execute("""
    SELECT id, category, created_method, confidence_tier, confidence_score
    FROM payloads
    ORDER BY confidence_score DESC
""")

print(f"\n📋 Payloads by Confidence Tier:\n")
print(f"{'ID':<4} {'Category':<15} {'Created Method':<20} {'Confidence Tier':<25} {'Score':<8}")
print("-" * 80)

for row in cursor.fetchall():
    print(f"{row[0]:<4} {row[1]:<15} {row[2]:<20} {row[3]:<25} {row[4]:.2f}")

conn.close()
print("\n✅ Test data loaded successfully!")
