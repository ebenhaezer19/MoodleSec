#!/usr/bin/env python3
"""Quick test of schema migration."""
import os
import sys
import sqlite3

sys.path.insert(0, 'proxy')

# Remove old database
db_path = 'proxy/data/payload_repository.db'
if os.path.exists(db_path):
    os.remove(db_path)
    print(f'✓ Removed old database')

# Initialize
from proxy.database.payload_repository import PayloadRepositoryManager
repo = PayloadRepositoryManager()

print(f'DB Path: {repo.db_path}')
print(f'Absolute: {os.path.abspath(repo.db_path)}')
print(f'DB Exists: {os.path.exists(repo.db_path)}')
print('✓ Repository initialized with migration')

# Check schema
conn = sqlite3.connect(repo.db_path)
cursor = conn.cursor()

cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [row[0] for row in cursor.fetchall()]
print(f'\n✓ Tables in database: {tables}')

if 'payloads' in tables:
    cursor.execute('PRAGMA table_info(payloads)')
    columns = cursor.fetchall()
    print(f'\n✓ Columns in payloads table ({len(columns)} total):')
    
    required = {'confidence_score', 'confidence_tier', 'created_method', 'validated_by', 'validation_status', 'source_metadata', 'validated_at'}
    found_required = set()
    
    for col_id, col_name, col_type, not_null, default, pk in columns:
        status = '✓' if col_name in required else ' '
        print(f'  {status} {col_name} ({col_type})')
        if col_name in required:
            found_required.add(col_name)
    
    missing = required - found_required
    if missing:
        print(f'\n✗ Missing required columns: {missing}')
    else:
        print(f'\n✓ All required confidence columns present!')
else:
    print('\n✗ Payloads table not created!')

conn.close()
