#!/usr/bin/env python3
import json
from pathlib import Path
from collections import Counter

# Load needs_review data
needs_review_files = sorted(Path("ml/training_data").glob("needs_review_*.json"), reverse=True)
if not needs_review_files:
    print("No needs_review files found!")
    exit(1)

needs_review_file = needs_review_files[0]
print(f"[*] Analyzing: {needs_review_file.name}\n")

with open(needs_review_file, 'r') as f:
    data = json.load(f)

print(f"Total needs review: {len(data)}\n")

# Analyze confidence distribution
confidences = [item.get('confidence', 0) for item in data]
print(f"Confidence range: {min(confidences):.2f} - {max(confidences):.2f}")
print(f"Average confidence: {sum(confidences)/len(confidences):.2f}\n")

# Confidence buckets
buckets = {
    '0.0-0.3': 0,
    '0.3-0.5': 0,
    '0.5-0.7': 0,
    '0.7-0.8': 0,
    '0.8-1.0': 0
}

for conf in confidences:
    if conf < 0.3:
        buckets['0.0-0.3'] += 1
    elif conf < 0.5:
        buckets['0.3-0.5'] += 1
    elif conf < 0.7:
        buckets['0.5-0.7'] += 1
    elif conf < 0.8:
        buckets['0.7-0.8'] += 1
    else:
        buckets['0.8-1.0'] += 1

print("Confidence distribution:")
for bucket, count in buckets.items():
    print(f"  {bucket}: {count} findings ({count/len(data)*100:.1f}%)")

# Analyze categories
categories = Counter([item.get('category', 'unknown') for item in data])
print(f"\nTop 10 categories in needs_review:")
for cat, count in categories.most_common(10):
    print(f"  {cat}: {count}")

# Analyze strategies
strategies = Counter([item.get('strategy', 'unknown') for item in data])
print(f"\nStrategies used:")
for strat, count in strategies.items():
    print(f"  {strat}: {count}")

# Show sample low-confidence findings
print(f"\n[*] Sample findings with confidence < 0.7:")
low_conf = [item for item in data if item.get('confidence', 0) < 0.7][:5]
for i, item in enumerate(low_conf, 1):
    print(f"\n{i}. {item.get('category', 'N/A')}")
    print(f"   Confidence: {item.get('confidence', 0):.2f}")
    print(f"   Label: {item.get('label', -1)} ({'TP' if item.get('label')==0 else 'FP' if item.get('label')==1 else 'Unknown'})")
    print(f"   Reason: {item.get('reason', 'N/A')[:80]}...")
    print(f"   Strategy: {item.get('strategy', 'N/A')}")
