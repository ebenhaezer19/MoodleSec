#!/usr/bin/env python3
from ml.training_data_generator import TrainingDataGenerator
gen = TrainingDataGenerator()
data, labels = gen.generate_fp_training_data(200)

num_fp = sum(labels)
num_tp = len(labels) - num_fp
print(f"Total: {len(labels)}, FP: {num_fp}, TP: {num_tp}")

# Check first samples
print("\n=== First 10 FP samples ===")
fp_count = 0
for i, (sample, label) in enumerate(zip(data, labels)):
    if label == 1:  # FP
        fp_count += 1
        if fp_count <= 10:
            print(f"FP #{fp_count}: Severity={sample['finding']['severity']}")

print("\n=== First 10 TP samples ===")
tp_count = 0
for i, (sample, label) in enumerate(zip(data, labels)):
    if label == 0:  # TP
        tp_count += 1
        if tp_count <= 10:
            print(f"TP #{tp_count}: Severity={sample['finding']['severity']}")
