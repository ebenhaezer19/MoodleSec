#!/usr/bin/env python3
"""Analyze Real vs Synthetic Data Distribution"""

import json
from pathlib import Path
from collections import Counter

def main():
    # Load data
    data_file = Path('ml/training_data/merged_training_data_20260129_115000.json')
    data = json.load(open(data_file))
    
    print('='*80)
    print('ANALISIS DATA REAL vs SYNTHETIC')
    print('='*80)
    print()
    
    # Check scan_id patterns
    print('Sample Scan IDs (first 20):')
    scan_ids = []
    for i, item in enumerate(data[:20]):
        finding = item.get('finding', item)
        scan_id = finding.get('scan_id', 'N/A')
        scan_type = finding.get('scan_type', 'unknown')
        label = item.get('label', -1)
        scan_ids.append(scan_id)
        print(f'{i+1:2d}. {scan_id[:70]:70s} | Type: {scan_type:10s} | Label: {label}')
    print()
    
    # Identify synthetic patterns
    print('='*80)
    print('IDENTIFYING SYNTHETIC DATA PATTERNS')
    print('='*80)
    print()
    
    # Count by scan type
    scan_types = Counter()
    for item in data:
        finding = item.get('finding', item)
        scan_type = finding.get('scan_type', 'unknown')
        scan_types[scan_type] += 1
    
    print('Scan Types Distribution:')
    for stype, count in scan_types.most_common():
        print(f'  {stype:20s}: {count:3d}')
    print()
    
    # Separate real vs synthetic based on multiple indicators
    real_data = []
    synthetic_data = []
    
    for item in data:
        finding = item.get('finding', item)
        scan_id = finding.get('scan_id', '')
        scan_type = finding.get('scan_type', 'unknown')
        
        # Check for synthetic indicators
        is_synthetic = (
            'synthetic' in scan_id.lower() or
            'generated' in scan_id.lower() or
            scan_type == 'synthetic' or
            finding.get('is_synthetic', False)
        )
        
        if is_synthetic:
            synthetic_data.append(item)
        else:
            real_data.append(item)
    
    print('='*80)
    print('DATA DISTRIBUTION')
    print('='*80)
    print()
    print(f'Total Data: {len(data)}')
    print(f'  Real Data:      {len(real_data):3d} ({len(real_data)/len(data)*100:.1f}%)')
    print(f'  Synthetic Data: {len(synthetic_data):3d} ({len(synthetic_data)/len(data)*100:.1f}%)')
    print()
    
    # Analyze REAL data labels
    print('='*80)
    print('REAL DATA ANALYSIS (OWASP ZAP + Acunetix)')
    print('='*80)
    print()
    
    real_tp = [d for d in real_data if d.get('label') == 0]
    real_fp = [d for d in real_data if d.get('label') == 1]
    real_unlabeled = [d for d in real_data if d.get('label') == -1 or d.get('label') is None]
    
    print(f'Label Distribution:')
    print(f'  True Positives (TP):   {len(real_tp):3d} ({len(real_tp)/len(real_data)*100:.1f}%)')
    print(f'  False Positives (FP):  {len(real_fp):3d} ({len(real_fp)/len(real_data)*100:.1f}%)')
    if real_unlabeled:
        print(f'  Unlabeled:             {len(real_unlabeled):3d} ({len(real_unlabeled)/len(real_data)*100:.1f}%)')
    print()
    
    # Category analysis
    print('Top 15 Categories (Real Data):')
    categories = [d.get('finding', d).get('category', 'Unknown') for d in real_data]
    cat_counter = Counter(categories)
    for i, (cat, count) in enumerate(cat_counter.most_common(15), 1):
        print(f'  {i:2d}. {cat[:65]:65s}: {count:2d}')
    print()
    
    # Severity analysis
    print('Severity Distribution (Real Data):')
    severities = [d.get('finding', d).get('severity', 'Unknown') for d in real_data]
    sev_counter = Counter(severities)
    for sev, count in sorted(sev_counter.items(), key=lambda x: x[1], reverse=True):
        print(f'  {sev:15s}: {count:3d}')
    print()
    
    # Source analysis (OWASP vs Acunetix)
    print('Source Distribution (Real Data):')
    zap_count = sum(1 for d in real_data if 'zap' in d.get('finding', d).get('scan_type', '').lower())
    acunetix_count = sum(1 for d in real_data if 'acunetix' in d.get('finding', d).get('scan_type', '').lower())
    other_count = len(real_data) - zap_count - acunetix_count
    
    print(f'  OWASP ZAP:  {zap_count:3d} ({zap_count/len(real_data)*100:.1f}%)')
    print(f'  Acunetix:   {acunetix_count:3d} ({acunetix_count/len(real_data)*100:.1f}%)')
    if other_count > 0:
        print(f'  Other:      {other_count:3d} ({other_count/len(real_data)*100:.1f}%)')
    print()
    
    # If there's synthetic data
    if synthetic_data:
        print('='*80)
        print('SYNTHETIC DATA ANALYSIS')
        print('='*80)
        print()
        
        synthetic_tp = [d for d in synthetic_data if d.get('label') == 0]
        synthetic_fp = [d for d in synthetic_data if d.get('label') == 1]
        
        print(f'Label Distribution:')
        print(f'  True Positives (TP):   {len(synthetic_tp):3d}')
        print(f'  False Positives (FP):  {len(synthetic_fp):3d}')
        print()
    
    # Summary
    print('='*80)
    print('SUMMARY')
    print('='*80)
    print()
    print('📊 Real Data (OWASP ZAP + Acunetix):')
    print(f'   TP:  {len(real_tp):3d}')
    print(f'   FP:  {len(real_fp):3d}')
    print(f'   Total: {len(real_tp) + len(real_fp)} labeled samples')
    print()
    
    if synthetic_data:
        print('📊 Synthetic Data:')
        print(f'   TP:  {len(synthetic_tp):3d}')
        print(f'   FP:  {len(synthetic_fp):3d}')
        print(f'   Total: {len(synthetic_tp) + len(synthetic_fp)} labeled samples')
        print()
    
    print('📊 Overall Dataset:')
    print(f'   Total TP:  {len(real_tp) + (len(synthetic_tp) if synthetic_data else 0)}')
    print(f'   Total FP:  {len(real_fp) + (len(synthetic_fp) if synthetic_data else 0)}')
    print(f'   Total Labeled: {len(data)} samples')
    print()
    
    # Ratio
    tp_ratio = len(real_tp) / len(real_data) * 100 if real_data else 0
    fp_ratio = len(real_fp) / len(real_data) * 100 if real_data else 0
    
    print(f'📈 TP/FP Ratio (Real Data): {len(real_tp)}:{len(real_fp)} ({tp_ratio:.1f}% TP, {fp_ratio:.1f}% FP)')
    print()

if __name__ == '__main__':
    main()
