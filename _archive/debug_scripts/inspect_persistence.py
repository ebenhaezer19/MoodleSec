import json
from collections import Counter

data = json.loads(open('logs/alert_queue.json', encoding='utf-8').read())
statuses = Counter(a.get('status') for a in data)
fps = set()
for a in data:
    p = str(a.get('path', ''))
    if p and not p.startswith('/'):
        p = '/' + p
    if a.get('status') == 'ADMIN_BLOCK':
        fps.add(f"{a.get('method')}:{p}:{a.get('client_ip')}")

print(f"Total alerts in alert_queue.json : {len(data)}")
print(f"Statuses                         : {dict(statuses)}")
print(f"ADMIN_BLOCK fingerprints on disk : {fps if fps else '(none)'}")
print(f"Oldest alert_id : {data[0].get('alert_id') if data else 'none'}")
print(f"Newest alert_id : {data[-1].get('alert_id') if data else 'none'}")

pl = json.loads(open('logs/pipeline_results.json', encoding='utf-8').read())
print(f"\nTotal pipeline_results.json rows : {len(pl)}")
from datetime import datetime
if pl:
    print(f"Earliest result timestamp : {pl[0].get('timestamp', '?')[:19]}")
    print(f"Latest  result timestamp  : {pl[-1].get('timestamp', '?')[:19]}")

import os
for f in ['logs/alert_queue.json', 'logs/pipeline_results.json']:
    sz = os.path.getsize(f)
    print(f"\nFile: {f}  size={sz:,} bytes ({sz//1024} KB)")
