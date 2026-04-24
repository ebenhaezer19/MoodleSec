import pandas as pd
import numpy as np

df = pd.read_csv('ml/training_data/phase3_balanced_dataset_20260424.csv')

print("=" * 80)
print("DATASET INSPECTION - PHASE 3 BUGGY EXTRACTION")
print("=" * 80)
print(f"\nShape: {df.shape}")
print(f"\nColumns: {list(df.columns)}")

print("\n" + "=" * 80)
print("BUG 1: NaN VALUES IN method COLUMN")
print("=" * 80)
print(f"method column - NaN count: {df['method'].isna().sum()} out of {len(df)}")
print(f"method column - unique non-NaN values: {df['method'].dropna().unique()}")
print(f"method column value counts:\n{df['method'].value_counts(dropna=False)}")

print("\n" + "=" * 80)
print("BUG 2: REQUEST_TIME_MS ANALYSIS (should be 100-10000ms, not 0)")
print("=" * 80)
for label in [0, 1]:
    subset = df[df['label'] == label]['request_time_ms']
    print(f"\nLabel {label} (attack={label if label == 1 else 'normal'}):")
    print(f"  Count: {len(subset)}")
    print(f"  Mean: {subset.mean():.2f}ms")
    print(f"  Min: {subset.min():.2f}ms")
    print(f"  Max: {subset.max():.2f}ms")
    print(f"  Values == 0: {(subset == 0).sum()}")

print("\n" + "=" * 80)
print("BUG 3: HAS_SESSION_COOKIE (normal should be ~95%, not 0%)")
print("=" * 80)
for label in [0, 1]:
    subset = df[df['label'] == label]['has_session_cookie']
    print(f"\nLabel {label} (attack={label if label == 1 else 'normal'}):")
    print(f"  Count: {len(subset)}")
    print(f"  Mean: {subset.mean():.2%}")
    print(f"  Unique values: {sorted(subset.unique())}")

print("\n" + "=" * 80)
print("BUG 4: HAS_POST_DATA (suspicious - normal always 100%?)")
print("=" * 80)
for label in [0, 1]:
    subset = df[df['label'] == label]['has_post_data']
    print(f"\nLabel {label} (attack={label if label == 1 else 'normal'}):")
    print(f"  Count: {len(subset)}")
    print(f"  Mean: {subset.mean():.2%}")
    print(f"  Unique values: {sorted(subset.unique())}")

print("\n" + "=" * 80)
print("SUMMARY: THESE ARE THE 4 CRITICAL BUGS THE USER IDENTIFIED")
print("=" * 80)
print("\n1. method column has NaN values - extraction failed")
print("2. request_time_ms is all 0.0 for normal - extraction uses wrong field")
print("3. has_session_cookie is 0% for normal - extraction looks in wrong place")
print("4. has_post_data shows suspicious pattern - 100% for normal vs 39% for attack")
