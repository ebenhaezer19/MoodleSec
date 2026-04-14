#!/usr/bin/env python3
from proxy.database.payload_repository import PayloadRepositoryManager
import sqlite3

r = PayloadRepositoryManager()
conn = sqlite3.connect(r.db_path)
cursor = conn.cursor()

cursor.execute('SELECT id, category, payload_text, confidence_tier, confidence_score FROM payloads LIMIT 5')
rows = cursor.fetchall()

print('Current Payloads in Database:')
print('=' * 100)
for row in rows:
    payload_preview = row[2][:40] + '...' if len(row[2]) > 40 else row[2]
    print(f'ID: {row[0]:<3} | Category: {row[1]:<15} | Tier: {str(row[3]):<25} | Score: {row[4]}')
    print(f'       Payload: {payload_preview}')
    print('-' * 100)

# Count by tier
cursor.execute('SELECT confidence_tier, COUNT(*) FROM payloads GROUP BY confidence_tier')
tier_counts = cursor.fetchall()
print('\nPayloads by Confidence Tier:')
print('=' * 50)
for tier, count in tier_counts:
    print(f'{tier}: {count}')

conn.close()
