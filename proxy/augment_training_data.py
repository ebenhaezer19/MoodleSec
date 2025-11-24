#!/usr/bin/env python3
"""
Augment training data by creating variations of existing findings.
This helps increase dataset size for ML training.
"""

import json
import random
from pathlib import Path
from datetime import datetime

def augment_xss_findings(finding):
    """Create variations of XSS findings."""
    variations = []
    
    # Original finding
    base = finding.copy()
    
    # Variation 1: Different payload
    var1 = base.copy()
    payloads = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        'javascript:alert(1)',
        '<iframe src=javascript:alert(1)>'
    ]
    var1['evidence'] = random.choice(payloads)
    var1['description'] = f"XSS with payload: {var1['evidence']}"
    variations.append(var1)
    
    # Variation 2: Different parameter
    var2 = base.copy()
    params = ['username', 'email', 'search', 'q', 'name', 'comment']
    var2['url'] = f"{base.get('url', '').split('?')[0]}?{random.choice(params)}=test"
    variations.append(var2)
    
    # Variation 3: Different severity
    var3 = base.copy()
    if base.get('severity') == 'High':
        var3['severity'] = 'Medium'
    elif base.get('severity') == 'Medium':
        var3['severity'] = 'High'
    variations.append(var3)
    
    return variations

def augment_sql_findings(finding):
    """Create variations of SQL injection findings."""
    variations = []
    
    base = finding.copy()
    
    # Different SQL payloads
    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "' UNION SELECT NULL--",
        "1' AND SLEEP(5)--"
    ]
    
    for payload in payloads[:3]:  # Create 3 variations
        var = base.copy()
        var['evidence'] = payload
        var['description'] = f"SQL injection with payload: {payload}"
        variations.append(var)
    
    return variations

def augment_csrf_findings(finding):
    """Create variations of CSRF findings."""
    variations = []
    
    base = finding.copy()
    
    # Different endpoints
    endpoints = [
        '/admin/settings.php',
        '/user/edit.php',
        '/course/edit.php',
        '/user/editadvanced.php'
    ]
    
    for endpoint in endpoints[:2]:
        var = base.copy()
        var['url'] = f"http://localhost:8998{endpoint}"
        variations.append(var)
    
    return variations

def augment_dataset(input_file, output_file, augmentation_factor=2):
    """
    Augment dataset by creating variations.
    
    Args:
        input_file: Path to merged training data
        output_file: Path to save augmented data
        augmentation_factor: How many variations per finding
    """
    print("=" * 60)
    print("DATA AUGMENTATION")
    print("=" * 60)
    
    # Load data
    print(f"\nLoading: {input_file}")
    with open(input_file, 'r') as f:
        data = json.load(f)
    
    print(f"Original dataset: {len(data)} findings")
    
    # Augment
    augmented = data.copy()
    
    for finding in data:
        category = finding.get('category', '').lower()
        
        # Only augment certain categories
        if 'xss' in category or 'cross-site scripting' in category:
            variations = augment_xss_findings(finding)
            augmented.extend(variations[:augmentation_factor])
        
        elif 'sql' in category:
            variations = augment_sql_findings(finding)
            augmented.extend(variations[:augmentation_factor])
        
        elif 'csrf' in category:
            variations = augment_csrf_findings(finding)
            augmented.extend(variations[:augmentation_factor])
    
    print(f"Augmented dataset: {len(augmented)} findings")
    print(f"Added: {len(augmented) - len(data)} variations")
    
    # Save
    with open(output_file, 'w') as f:
        json.dump(augmented, f, indent=2)
    
    print(f"\nSaved to: {output_file}")
    
    # Summary
    tp_count = sum(1 for f in augmented if f.get('label') == 0)
    fp_count = sum(1 for f in augmented if f.get('label') == 1)
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Total findings: {len(augmented)}")
    print(f"  True Positives: {tp_count}")
    print(f"  False Positives: {fp_count}")
    print(f"\nAugmentation factor: {augmentation_factor}x")
    print(f"Original: {len(data)} → Augmented: {len(augmented)}")
    
    return augmented

def main():
    # Find latest merged data
    merged_dir = Path('ml/training_data/merged')
    merged_files = sorted(merged_dir.glob('merged_training_data_*.json'))
    
    if not merged_files:
        print("❌ No merged training data found!")
        print("   Run: python merge_training_data.py first")
        return
    
    input_file = merged_files[-1]
    
    # Output file
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = merged_dir / f'augmented_training_data_{timestamp}.json'
    
    # Augment
    augmented = augment_dataset(input_file, output_file, augmentation_factor=2)
    
    print("\n" + "=" * 60)
    print("NEXT STEPS")
    print("=" * 60)
    print("1. Review augmented data (optional)")
    print("2. Retrain models: python retrain_models.py")
    print(f"3. Use augmented file: {output_file.name}")

if __name__ == '__main__':
    main()
