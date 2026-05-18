#!/usr/bin/env python3
"""Compare v1 vs v2 replay results."""
import json

v1 = json.load(open("har_replay_results.json", "r", encoding="utf-8"))
v2 = json.load(open("har_replay_results_v2.json", "r", encoding="utf-8"))

print("=" * 65)
print("  COMPARISON: v1 (old replay) vs v2 (payload-preserving replay)")
print("=" * 65)
print()

print(f"  Total requests:           v1={len(v1):>3}    v2={len(v2):>3}")

v1_attack = sum(1 for r in v1 if r.get("true_label") == "attack")
v2_attack = sum(1 for r in v2 if r.get("true_label") == "attack")
v1_normal = sum(1 for r in v1 if r.get("true_label") == "normal")
v2_normal = sum(1 for r in v2 if r.get("true_label") == "normal")
print(f"  Attack requests:          v1={v1_attack:>3}    v2={v2_attack:>3}")
print(f"  Normal requests:          v1={v1_normal:>3}    v2={v2_normal:>3}")
print()

# Label fix check
v1_pt = [r for r in v1 if "Parameter-Tempering" in r.get("source_file", "")]
v2_pt = [r for r in v2 if "Parameter-Tempering" in r.get("source_file", "")]
if v1_pt and v2_pt:
    v1_lbl = v1_pt[0].get("true_label")
    v2_lbl = v2_pt[0].get("true_label")
    print(f'  Parameter-Tempering label:  v1="{v1_lbl}"   v2="{v2_lbl}"')
    if v1_lbl != v2_lbl:
        print('    >> FIXED: was "normal", now correctly "attack"')
print()

# Query preservation
v1_has_query = sum(1 for r in v1 if "?" in r.get("url", ""))
v2_has_query = sum(1 for r in v2 if r.get("original_query"))
v2_preserved = sum(
    1
    for r in v2
    if r.get("original_query") and r.get("replay_query") == r.get("original_query")
)
print(f"  Requests with query:      v1={v1_has_query:>3}    v2={v2_has_query:>3}")
print(f"  Queries preserved (v2):          {v2_preserved:>3}")
v2_lost = sum(
    1 for r in v2 if r.get("original_query") and not r.get("replay_query")
)
print(f"  Queries lost (v2):               {v2_lost:>3}")
print()

# Body preservation
v2_body = sum(1 for r in v2 if r.get("request_body_preview"))
print(f"  Requests with body (v2):         {v2_body:>3}")
print()

# Debug fields in v2 not in v1
v2_fields = set(v2[0].keys()) if v2 else set()
v1_fields = set(v1[0].keys()) if v1 else set()
new_fields = v2_fields - v1_fields
print("  New debug fields in v2:")
for f in sorted(new_fields):
    print(f"    + {f}")
print()

# Status code comparison
v1_403 = sum(1 for r in v1 if r.get("status_code") == 403)
v2_403 = sum(1 for r in v2 if r.get("status_code") == 403)
v1_200 = sum(1 for r in v1 if r.get("status_code") == 200)
v2_200 = sum(1 for r in v2 if r.get("status_code") == 200)
v1_fail = sum(1 for r in v1 if r.get("status_code") is None)
v2_fail = sum(1 for r in v2 if r.get("status_code") is None)
print(f"  HTTP 403 (blocked):       v1={v1_403:>3}    v2={v2_403:>3}")
print(f"  HTTP 200 (allowed):       v1={v1_200:>3}    v2={v2_200:>3}")
print(f"  Failed requests:          v1={v1_fail:>3}    v2={v2_fail:>3}")
print()

# Warnings
v2_warnings = sum(1 for r in v2 if r.get("replay_warnings"))
print(f"  Replay warnings (v2):            {v2_warnings:>3}")
print()
print("=" * 65)
