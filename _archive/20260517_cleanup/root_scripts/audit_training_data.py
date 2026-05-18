#!/usr/bin/env python3
"""
Audit the balanced training dataset to understand class distribution
"""

import json
from collections import Counter

# Load balanced dataset
data_path = 'proxy/ml/training_data/2026-04-14-ZAP-Report-localhost_labeled_balanced_524.json'

with open(data_path, 'r', encoding='utf-8') as f:
    data = json.load(f)

# Organize by label
tp_findings = [d for d in data if d.get('label_name') == 'TP' or d.get('label') == 0]
fp_findings = [d for d in data if d.get('label_name') == 'FP' or d.get('label') == 1]

print(f"Balanced Dataset Analysis:")
print(f"Total: {len(data)}")
print(f"TP: {len(tp_findings)}")
print(f"FP: {len(fp_findings)}\n")

# Category distribution
tp_categories = Counter(d.get('category', 'Unknown') for d in tp_findings)
fp_categories = Counter(d.get('category', 'Unknown') for d in fp_findings)

print(f"{'='*80}\nTP Categories (Top 10):\n")
for cat, count in tp_categories.most_common(10):
    print(f"  {count:3d} | {cat}")

print(f"\n{'='*80}\nFP Categories (Top 10):\n")
for cat, count in fp_categories.most_common(10):
    print(f"  {count:3d} | {cat}")

# Sample inspection
print(f"\n{'='*80}\nSample TPs (first 5):\n")
for i, finding in enumerate(tp_findings[:5], 1):
    print(f"  {i}. {finding.get('category')} - {finding.get('description', '')[:50]}...")

print(f"\n{'='*80}\nSample FPs (first 5):\n")
for i, finding in enumerate(fp_findings[:5], 1):
    print(f"  {i}. {finding.get('category')} - {finding.get('description', '')[:50]}...")
