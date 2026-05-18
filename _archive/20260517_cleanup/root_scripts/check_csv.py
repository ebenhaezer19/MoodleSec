import pandas as pd

df = pd.read_csv('ml/training_data/real_features_dataset_20260420.csv')

print("CSV structure:")
print(f"Shape: {df.shape}")
print(f"\nFirst 3 rows:\n{df.head(3)}")
print(f"\nColumn dtypes:\n{df.dtypes}")
print(f"\nMethod column unique values:\n{df['method'].unique()}")
print(f"\nAttack (label==1) subset:")
attacks = df[df['label'] == 1]
print(f"  Count: {len(attacks)}")
print(f"  Method values: {attacks['method'].unique()}")
print(f"  Method dtype: {attacks['method'].dtype}")
print(f"  First 3 attack methods: {list(attacks['method'].head(3))}")
