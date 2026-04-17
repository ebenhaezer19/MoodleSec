#!/usr/bin/env python3
"""Diagnose ZAP import and payload display issues."""
import sys
sys.path.insert(0, 'proxy')

import sqlite3
from proxy.database.payload_repository import PayloadRepositoryManager

# Check database
repo = PayloadRepositoryManager()
conn = sqlite3.connect(repo.db_path)
cursor = conn.cursor()

print("=" * 80)
print("[DIAGNOSIS] Payload Repository Status")
print("=" * 80)

# Get total count
cursor.execute("SELECT COUNT(*) FROM payloads")
total = cursor.fetchone()[0]
print(f"\n[1] Total payloads in database: {total}")

# Get all payloads with details
cursor.execute("""
    SELECT id, category, payload_text, source, created_method, 
           confidence_tier, confidence_score
    FROM payloads
    ORDER BY id DESC
    LIMIT 20
""")

payloads = cursor.fetchall()
print(f"\n[2] Last 20 payloads:")
for payload_id, category, payload_text, source, created_method, tier, score in payloads:
    # Show first 40 chars of payload
    preview = (payload_text[:40] + '...') if payload_text and len(payload_text) > 40 else (payload_text or '(empty)')
    print(f"\n    ID: {payload_id}")
    print(f"      Category: {category}")
    print(f"      Source: {source}")
    print(f"      Method: {created_method}")
    print(f"      Tier: {tier} ({score})")
    print(f"      Preview: {preview}")

# Check by source (to see where ZAP imports are)
print("\n[3] Payloads by source:")
cursor.execute("""
    SELECT source, COUNT(*) as count
    FROM payloads
    GROUP BY source
    ORDER BY count DESC
""")

for source, count in cursor.fetchall():
    print(f"    {source}: {count} payloads")

# Check API response
print("\n[4] Testing get_stats() API response:")
stats = repo.get_stats()
print(f"    Total: {stats['total_payloads']}")
print(f"    Categories: {list(stats['by_category'].keys())}")

# Test get_all_payloads
print("\n[5] Testing get_all_payloads() retrieval:")
all_payloads = repo.get_all_payloads()
print(f"    Retrieved: {len(all_payloads)} payloads")

if all_payloads:
    first = all_payloads[0]
    print(f"    First payload keys: {list(first.keys())}")
    print(f"    Has 'payload' field: {'payload' in first}")
    print(f"    Has 'confidence_tier' field: {'confidence_tier' in first}")
    
    # Check if payload text is empty
    payload_text = first.get('payload', '')
    print(f"    Payload text length: {len(payload_text)}")
    print(f"    Payload preview: {(payload_text[:50] + '...') if payload_text else '(EMPTY)'}")
else:
    print("    ERROR: No payloads returned!")

conn.close()

print("\n" + "=" * 80)
print("[RECOMMENDATION]")
print("=" * 80)
print("""
If ZAP payloads are not showing:
1. Check if ZAP import actually ran (look for [ZAP Import] SUMMARY messages)
2. Verify payload text is being captured properly
3. Check if get_all_payloads() returns confidence fields correctly

If payloads are empty:
1. May need to re-run ZAP import
2. Check that evidence/payload text is not empty in ZAP alerts
3. Ensure category normalization is working
""")
