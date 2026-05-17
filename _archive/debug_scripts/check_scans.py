import sqlite3

conn = sqlite3.connect('data/scan_history.db')
cursor = conn.cursor()

print("Recent scans in database:")
print("-" * 80)
cursor.execute('SELECT scan_id, scan_type, total_findings, timestamp FROM scans ORDER BY id DESC LIMIT 10')

for row in cursor.fetchall():
    print(f"Scan ID: {row[0]}")
    print(f"  Type: {row[1]}")
    print(f"  Findings: {row[2]}")
    print(f"  Time: {row[3]}")
    print()

conn.close()
