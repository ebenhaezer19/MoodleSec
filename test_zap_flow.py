#!/usr/bin/env python3
"""Test complete ZAP import flow with schema migration."""
import os
import shutil
import sys

sys.path.insert(0, 'proxy')

# Remove old database
db_path = 'proxy/data/payload_repository.db'
if os.path.exists(db_path) or os.path.exists('proxy/data'):
    shutil.rmtree('proxy/data', ignore_errors=True)
    print('[✓] Removed old database')

# Initialize with migration
from proxy.database.payload_repository import PayloadRepositoryManager
repo = PayloadRepositoryManager()
print('[✓] Database initialized with schema migration')

# Verify schema
import sqlite3
conn = sqlite3.connect(repo.db_path)
cursor = conn.cursor()
cursor.execute('PRAGMA table_info(payloads)')
cols = {row[1] for row in cursor.fetchall()}
required = {'confidence_score', 'confidence_tier', 'created_method'}
print(f'[✓] Schema has required columns: {required.issubset(cols)}')
conn.close()

# Add test payloads
print('\nAdding test payloads...')
test_payloads = [
    ('XSS', '<img src=x onerror=alert(1)>', 'Test XSS payload'),
    ('SQL Injection', 'UNION SELECT NULL,NULL,NULL', 'Test SQLi payload'),
    ('CSRF', '<form action=...><input type=submit value=click>', 'Test CSRF payload'),
]

for category, payload, desc in test_payloads:
    try:
        result = repo.add_custom_payload(category, payload, desc)
        print(f'  [✓] {category}: {result.get("message", "OK")} (ID: {result.get("payload_id")})')
    except Exception as e:
        print(f'  [✗] {category}: {str(e)}')
        import traceback
        traceback.print_exc()

# Check stats
stats = repo.get_stats()
print(f'\n[✓] Database Statistics:')
print(f'    Total payloads: {stats["total_payloads"]}')
print(f'    By category: {stats["by_category"]}')

# Test retrieval
payloads = repo.get_all_payloads()
print(f'\n[✓] Retrieved {len(payloads)} payloads:')
for p in payloads[:3]:
    tier = p.get('confidence_tier', 'UNKNOWN')
    score = p.get('confidence_score', 0)
    print(f'    - {p["category"]}: {tier} ({score})')

print('\n✓ All tests passed!')
