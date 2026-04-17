#!/usr/bin/env python3
"""
Verify accuracy hasil manual labeling
"""

import json

def verify_accuracy():
    """
    Manual check berapa sampe akurat
    """
    
    print("📊 MANUAL VERIFICATION ACCURACY CHECK\n")
    
    # Load samples
    with open('proxy/ml/training_data/verify_200_samples.json', 'r') as f:
        samples = json.load(f)
    
    print(f"Total samples: {len(samples)}\n")
    print("📋 SAMPLE REVIEW GUIDE:\n")
    
    for i, item in enumerate(samples, 1):
        finding = item['finding']
        category = finding.get('category', 'Unknown')
        severity = finding.get('severity', 'Unknown')
        description = finding.get('description', '')
        current_label = item.get('label', 'UNKNOWN')
        label_name = "FP (False Positive)" if current_label == 1 else "TP (True Positive)" if current_label == 0 else "UNKNOWN"
        
        print(f"Sample #{i}")
        print(f"  Category: {category}")
        print(f"  Severity: {severity}")
        print(f"  Description: {description}")
        print(f"  Current Label: {label_name}")
        print(f"  \n  ❓ Is this REALLY a vulnerability?")
        print(f"     Enter Y for TP (exploitable), N for FP (not exploitable)")
        print()

if __name__ == "__main__":
    verify_accuracy()
    
    print("\n" + "="*50)
    print("AFTER YOU'RE DONE WITH MANUAL REVIEW:")
    print("="*50)
    print("""
1. Count berapa yang CORRECT
2. Count berapa yang WRONG
3. Calculate: correct / 25 × 100% = accuracy

4. Decision:
   - > 80% → Proceed to combine + augment + train
   - 60-80% → OK but with caution
   - < 60% → Review rule patterns
   
5. Run: python step2_combine_labeled_data.py
    """)
