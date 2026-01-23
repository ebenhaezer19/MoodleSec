#!/usr/bin/env python3
"""Debug severity assignment."""

import sys
sys.path.insert(0, '.')

from ml.training_data_generator import TrainingDataGenerator

gen = TrainingDataGenerator()
data, labels = gen.generate_fp_training_data(30)

print("=== First 30 Samples ===")
print("Label: 0=TP, 1=FP\n")

for i in range(30):
    label_name = 'FP' if labels[i] == 1 else 'TP'
    severity = data[i]['finding']['severity']
    print(f"{i+1}. Label={label_name}, Severity={severity}")

# Check overlap
tp_severities = set()
fp_severities = set()

for sample, label in zip(data, labels):
    sev = sample['finding']['severity']
    if label == 0:  # TP
        tp_severities.add(sev)
    else:  # FP
        fp_severities.add(sev)

print(f"\n=== Overlap Check ===")
print(f"TP severities: {sorted(tp_severities)}")
print(f"FP severities: {sorted(fp_severities)}")
print(f"Overlap: {sorted(tp_severities & fp_severities)}")
