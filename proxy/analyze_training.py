#!/usr/bin/env python3
"""Analyze training data quality."""

import json
import numpy as np
from collections import Counter

# Load training data
with open('ml/data/false_positive_training.json', 'r') as f:
    data = json.load(f)

samples = data['data']
labels = data['labels']

print(f"Total samples: {len(samples)}")
print(f"Labels: TP={labels.count(0)}, FP={labels.count(1)}")
print(f"FP ratio: {labels.count(1)/len(labels)*100:.1f}%")

# Analyze severity distribution
severity_by_label = {'TP': [], 'FP': []}
status_by_label = {'TP': [], 'FP': []}
response_time_by_label = {'TP': [], 'FP': []}

for sample, label in zip(samples, labels):
    label_name = 'FP' if label == 1 else 'TP'
    severity_by_label[label_name].append(sample['finding']['severity'])
    status_by_label[label_name].append(sample['context']['status_code'])
    response_time_by_label[label_name].append(sample['context']['response_time'])

print("\n=== Severity Distribution ===")
print("TP:", Counter(severity_by_label['TP']))
print("FP:", Counter(severity_by_label['FP']))

print("\n=== Status Code Distribution ===")
print("TP:", Counter(status_by_label['TP']))
print("FP:", Counter(status_by_label['FP']))

print("\n=== Response Time Stats ===")
print(f"TP: mean={np.mean(response_time_by_label['TP']):.1f}, std={np.std(response_time_by_label['TP']):.1f}")
print(f"FP: mean={np.mean(response_time_by_label['FP']):.1f}, std={np.std(response_time_by_label['FP']):.1f}")

# Check for perfect separation
print("\n=== Check for Perfect Separation ===")
tp_severities = set(severity_by_label['TP'])
fp_severities = set(severity_by_label['FP'])
print(f"Unique TP severities: {tp_severities}")
print(f"Unique FP severities: {fp_severities}")
print(f"Overlap: {tp_severities & fp_severities}")

print("\n=== Sample Examples ===")
print("\nTP Sample 1:")
for i, (sample, label) in enumerate(zip(samples, labels)):
    if label == 0:
        print(f"  Severity: {sample['finding']['severity']}")
        print(f"  Category: {sample['finding']['category']}")
        print(f"  Status: {sample['context']['status_code']}")
        print(f"  Response time: {sample['context']['response_time']}ms")
        break

print("\nFP Sample 1:")
for i, (sample, label) in enumerate(zip(samples, labels)):
    if label == 1:
        print(f"  Severity: {sample['finding']['severity']}")
        print(f"  Category: {sample['finding']['category']}")
        print(f"  Status: {sample['context']['status_code']}")
        print(f"  Response time: {sample['context']['response_time']}ms")
        break
