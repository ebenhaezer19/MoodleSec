import json, sys

data = json.loads(open('logs/pipeline_results.json', encoding='utf-8').read())
alert_data = json.loads(open('logs/alert_queue.json', encoding='utf-8').read())

print(f"Total pipeline results: {len(data)}")
print(f"Total SOC alerts:       {len(alert_data)}")
print()

# ── Decision summary ──────────────────────────────────────────────────
from collections import Counter
decisions = Counter(r.get('decision', '?') for r in data)
attacks   = Counter(r.get('attack_type', '?') for r in data if r.get('decision') != 'IGNORE')
print("=== DECISION SUMMARY ===")
for k, v in decisions.most_common():
    print(f"  {k:8} {v}")
print()
print("=== ATTACK TYPES (non-IGNORE) ===")
for k, v in attacks.most_common():
    print(f"  {k:12} {v}")
print()

# ── Last 20 decisions ─────────────────────────────────────────────────
print("=== LAST 20 PIPELINE DECISIONS ===")
print(f"{'Timestamp':20} {'Method':5} {'Path':30} {'Decision':7} {'Attack':10} {'Conf':5} {'Anom':5} Reason")
print("-" * 120)
for r in data[-20:]:
    ts    = str(r.get('timestamp',''))[:19]
    meth  = str(r.get('method','?'))[:4]
    path  = str(r.get('path','?'))[:30]
    dec   = str(r.get('decision','?'))[:7]
    atk   = str(r.get('attack_type','?'))[:10]
    conf  = float(r.get('confidence', 0))
    anom  = float(r.get('anomaly_score', 0))
    reason = str(r.get('reason',''))[:55]
    print(f"{ts:20} {meth:5} {path:30} {dec:7} {atk:10} {conf:.2f}  {anom:.2f}  {reason}")

# ── IGNORE with ML fallback ───────────────────────────────────────────
print()
print("=== SUSPICIOUS IGNORES (low confidence or fallback reason) ===")
suspicious = [
    r for r in data
    if r.get('decision') == 'IGNORE'
    and (
        'fallback' in str(r.get('reason','')).lower()
        or 'pipeline_failure' in str(r.get('reason','')).lower()
        or 'no_reason' in str(r.get('reason','')).lower()
        or float(r.get('confidence', 1)) == 0.0
    )
]
if suspicious:
    for r in suspicious[-10:]:
        print(f"  {str(r.get('timestamp',''))[:19]}  {r.get('path','?')}  conf={r.get('confidence')}  reason={r.get('reason')}")
else:
    print("  None found.")

# ── SOC alert status ──────────────────────────────────────────────────
print()
print("=== SOC ALERTS ===")
soc_statuses = Counter(a.get('status','?') for a in alert_data)
for k, v in soc_statuses.most_common():
    print(f"  {k:25} {v}")
for a in alert_data[-5:]:
    print(f"  alert_id={a.get('alert_id')} status={a.get('status')} type={a.get('attack_type')} ip={a.get('client_ip')} path={a.get('path')}")
