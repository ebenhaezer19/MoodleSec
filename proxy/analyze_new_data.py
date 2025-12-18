#!/usr/bin/env python3
"""Analyze newly imported training data."""

import json
from collections import Counter

# Load data
with open('ml/training_data/auto_labeled_20251219_030244.json', 'r') as f:
    auto_labeled = json.load(f)

with open('ml/training_data/needs_review_20251219_030244.json', 'r') as f:
    needs_review = json.load(f)

print('=' * 60)
print('ANALISIS DATA IMPORT BARU')
print('=' * 60)

# Basic stats
tp = [f for f in auto_labeled if f.get('label') == 0]
fp = [f for f in auto_labeled if f.get('label') == 1]

print(f'\n📊 RINGKASAN:')
print(f'  Total findings imported: 196')
print(f'  Auto-labeled: {len(auto_labeled)} ({len(auto_labeled)/196*100:.1f}%)')
print(f'    - True Positives: {len(tp)}')
print(f'    - False Positives: {len(fp)}')
print(f'  Needs review: {len(needs_review)} ({len(needs_review)/196*100:.1f}%)')

# TP breakdown by severity
print(f'\n✅ TRUE POSITIVES BY SEVERITY:')
tp_sev = Counter(f.get('severity', 'Unknown') for f in tp)
for sev, count in tp_sev.most_common():
    print(f'  {sev}: {count}')

# TP breakdown by category
print(f'\n✅ TRUE POSITIVES BY CATEGORY (Top 5):')
tp_cat = Counter(f.get('category', 'Unknown') for f in tp)
for cat, count in tp_cat.most_common(5):
    print(f'  {cat[:50]}: {count}')

# FP breakdown
print(f'\n❌ FALSE POSITIVES BY CATEGORY (Top 5):')
fp_cat = Counter(f.get('category', 'Unknown') for f in fp)
for cat, count in fp_cat.most_common(5):
    print(f'  {cat[:50]}: {count}')

# Needs review breakdown
print(f'\n⚠️  NEEDS REVIEW BY SEVERITY:')
nr_sev = Counter(f.get('severity', 'Unknown') for f in needs_review)
for sev, count in nr_sev.most_common():
    print(f'  {sev}: {count}')

print(f'\n⚠️  NEEDS REVIEW BY CATEGORY (Top 5):')
nr_cat = Counter(f.get('category', 'Unknown') for f in needs_review)
for cat, count in nr_cat.most_common(5):
    print(f'  {cat[:50]}: {count}')

# Sample findings
print(f'\n📋 SAMPLE TRUE POSITIVES:')
for i, finding in enumerate(tp[:3], 1):
    print(f'\n{i}. {finding.get("category", "Unknown")}')
    print(f'   Severity: {finding.get("severity", "Unknown")}')
    print(f'   Confidence: {finding.get("auto_label_confidence", 0)*100:.1f}%')
    print(f'   Reason: {finding.get("auto_label_reason", "Unknown")[:70]}...')

print(f'\n📋 SAMPLE NEEDS REVIEW:')
for i, finding in enumerate(needs_review[:3], 1):
    print(f'\n{i}. {finding.get("category", "Unknown")}')
    print(f'   Severity: {finding.get("severity", "Unknown")}')
    print(f'   Confidence: {finding.get("auto_label_confidence", 0)*100:.1f}%')
    if 'description' in finding:
        print(f'   Description: {finding["description"][:70]}...')

print('\n' + '=' * 60)
print('REKOMENDASI:')
print('=' * 60)
print(f'\n1. Review {len(needs_review)} findings yang perlu validasi manual')
print(f'2. Merge dengan data training lama')
print(f'3. Retrain model dengan total ~{144 + len(auto_labeled)} samples')
print(f'4. Expected improvement: Better coverage untuk configuration issues')
print('\n' + '=' * 60)
