"""
Training Data Generator

Generates synthetic training data for ML models based on:
- OWASP Top 10 patterns
- Moodle-specific vulnerabilities
- CVE database patterns
- Real-world attack scenarios
"""

import random
from typing import Dict, List, Any, Tuple
from datetime import datetime, timedelta
import json


class TrainingDataGenerator:
    """Generate synthetic training data for ML models."""
    
    # Moodle-specific vulnerability patterns from CVEs
    MOODLE_CVES = [
        {
            'category': 'SQL Injection',
            'severity': 'critical',
            'cvss': 9.8,
            'description': 'SQL injection in user profile field',
            'url_pattern': '/user/profile.php',
            'evidence': "Parameter 'id' vulnerable to SQL injection",
            'is_fp': False
        },
        {
            'category': 'XSS',
            'severity': 'high',
            'cvss': 7.5,
            'description': 'Stored XSS in forum post',
            'url_pattern': '/mod/forum/post.php',
            'evidence': 'Unescaped user input in forum message',
            'is_fp': False
        },
        {
            'category': 'CSRF',
            'severity': 'high',
            'cvss': 6.5,
            'description': 'CSRF in course enrollment',
            'url_pattern': '/enrol/manual/ajax.php',
            'evidence': 'Missing CSRF token validation',
            'is_fp': False
        },
        {
            'category': 'Authentication Bypass',
            'severity': 'critical',
            'cvss': 9.1,
            'description': 'Authentication bypass via session fixation',
            'url_pattern': '/login/index.php',
            'evidence': 'Session ID not regenerated after login',
            'is_fp': False
        },
        {
            'category': 'Path Traversal',
            'severity': 'high',
            'cvss': 7.5,
            'description': 'Path traversal in file download',
            'url_pattern': '/pluginfile.php',
            'evidence': 'Directory traversal via filepath parameter',
            'is_fp': False
        },
        {
            'category': 'Information Disclosure',
            'severity': 'medium',
            'cvss': 5.3,
            'description': 'Sensitive information in error messages',
            'url_pattern': '/admin/index.php',
            'evidence': 'Database credentials exposed in error',
            'is_fp': False
        },
        {
            'category': 'Security Misconfiguration',
            'severity': 'low',
            'cvss': 3.7,
            'description': 'Missing security headers',
            'url_pattern': '/index.php',
            'evidence': 'X-Frame-Options header not set',
            'is_fp': True  # Often false positive in dev
        },
        {
            'category': 'Session Management',
            'severity': 'medium',
            'cvss': 5.4,
            'description': 'Session timeout not configured',
            'url_pattern': '/admin/settings.php',
            'evidence': 'Session timeout set to unlimited',
            'is_fp': False
        }
    ]
    
    # Common false positive patterns
    FALSE_POSITIVE_PATTERNS = [
        {
            'category': 'Security Misconfiguration',
            'severity': 'info',
            'cvss': 0.0,
            'description': 'Missing X-Content-Type-Options header',
            'evidence': 'Header not found in response',
            'is_fp': True
        },
        {
            'category': 'Information Disclosure',
            'severity': 'low',
            'cvss': 2.0,
            'description': 'Server version disclosed',
            'evidence': 'Server: Apache/2.4.41',
            'is_fp': True
        },
        {
            'category': 'Security Misconfiguration',
            'severity': 'info',
            'cvss': 0.0,
            'description': 'Missing Strict-Transport-Security header',
            'evidence': 'HSTS not enabled',
            'is_fp': True
        }
    ]
    
    def __init__(self, base_url: str = "http://localhost:8998"):
        """Initialize generator."""
        self.base_url = base_url
    
    def generate_fp_training_data(self, num_samples: int = 100) -> Tuple[List[Dict], List[int]]:
        """
        Generate training data for False Positive Reducer.
        
        Args:
            num_samples: Number of samples to generate
            
        Returns:
            Tuple of (training_data, labels)
        """
        training_data = []
        labels = []
        
        # Calculate number of overlap samples (15% of each class)
        num_fp = int(num_samples * 0.4)
        num_tp = num_samples - num_fp
        
        num_fp_high_severity = int(num_fp * 0.15)  # 15% of FP are High/Critical
        num_tp_low_severity = int(num_tp * 0.15)   # 15% of TP are Info/Low
        
        all_severities = ['Info', 'Low', 'Medium', 'High', 'Critical']
        
        # Generate FALSE POSITIVES
        for i in range(num_fp):
            is_fp = True
            
            # Force overlap for first 15% 
            if i < num_fp_high_severity:
                target_severity = random.choice(['Medium', 'High', 'Critical'])
                base = random.choice(self.MOODLE_CVES).copy()
                base['description'] = base['description'] + ' (false alarm - dev environment)'
            else:
                target_severity = random.choices(
                    all_severities,
                    weights=[45, 40, 8, 5, 2]
                )[0]
                if target_severity in ['High', 'Critical']:
                    base = random.choice(self.MOODLE_CVES).copy()
                    base['description'] = base['description'] + ' (scanner noise)'
                else:
                    base = random.choice(self.FALSE_POSITIVE_PATTERNS).copy()
            
            finding = self._create_finding(base)
            finding['severity'] = target_severity
            context = self._create_context(finding, is_fp)
            
            training_data.append({'finding': finding, 'context': context})
            labels.append(1)
        
        # Generate TRUE POSITIVES
        for i in range(num_tp):
            is_fp = False
            
            # Force overlap for first 15%
            if i < num_tp_low_severity:
                target_severity = random.choice(['Info', 'Low', 'Medium'])
                base = random.choice(self.FALSE_POSITIVE_PATTERNS).copy()
                base['description'] = base['description'] + ' (exploitable - verified)'
            else:
                target_severity = random.choices(
                    all_severities,
                    weights=[2, 5, 18, 35, 40]
                )[0]
                if target_severity in ['Info', 'Low']:
                    base = random.choice(self.FALSE_POSITIVE_PATTERNS + self.MOODLE_CVES).copy()
                    base['description'] = base['description'] + ' (confirmed low-impact vuln)'
                else:
                    base = random.choice(self.MOODLE_CVES).copy()
            
            finding = self._create_finding(base)
            finding['severity'] = target_severity
            context = self._create_context(finding, is_fp)
            
            training_data.append({'finding': finding, 'context': context})
            labels.append(0)
        
        return training_data, labels
    
    def generate_severity_training_data(self, num_samples: int = 100) -> Tuple[List[Dict], List[str]]:
        """
        Generate training data for Severity Predictor.
        
        Args:
            num_samples: Number of samples to generate
            
        Returns:
            Tuple of (training_data, labels)
        """
        training_data = []
        labels = []
        
        for i in range(num_samples):
            pattern = random.choice(self.MOODLE_CVES + self.FALSE_POSITIVE_PATTERNS)
            
            finding = self._create_finding(pattern)
            context = self._create_severity_context()
            
            training_data.append({
                'finding': finding,
                'context': context
            })
            labels.append(pattern['severity'])
        
        return training_data, labels
    
    def generate_anomaly_training_data(self, num_samples: int = 200) -> List[Dict]:
        """
        Generate normal behavior data for Anomaly Detector.
        
        Args:
            num_samples: Number of normal samples to generate
            
        Returns:
            List of normal request/response data
        """
        normal_data = []
        
        normal_endpoints = [
            '/login/index.php',
            '/index.php',
            '/course/view.php',
            '/mod/forum/view.php',
            '/user/profile.php',
            '/my/index.php'
        ]
        
        for i in range(num_samples):
            endpoint = random.choice(normal_endpoints)
            
            data = {
                'request': {
                    'url': f"{self.base_url}{endpoint}?id={random.randint(1, 100)}",
                    'method': random.choice(['GET', 'POST']),
                    'headers': {
                        'User-Agent': 'Mozilla/5.0',
                        'Accept': 'text/html'
                    },
                    'body': ''
                },
                'response': {
                    'status_code': random.choice([200, 200, 200, 304]),  # Mostly 200
                    'size': random.randint(1000, 50000),
                    'time': random.randint(50, 500),  # Normal response time
                    'headers': {}
                },
                'request_count_last_minute': random.randint(1, 20),
                'unique_ips_last_minute': random.randint(1, 10),
                'error_rate_last_minute': random.uniform(0, 0.05)  # Low error rate
            }
            
            normal_data.append(data)
        
        return normal_data
    
    def generate_rate_limiter_training_data(self, num_samples: int = 100) -> Tuple[List[Dict], List[float]]:
        """
        Generate training data for Rate Limiter.
        
        Args:
            num_samples: Number of samples to generate
            
        Returns:
            Tuple of (training_data, risk_scores)
        """
        training_data = []
        risk_scores = []
        
        for i in range(num_samples):
            # Generate different risk scenarios
            scenario = random.choice(['low', 'medium', 'high', 'critical'])
            
            if scenario == 'low':
                request_count = random.randint(1, 10)
                suspicious_patterns = 0
                risk_score = random.uniform(0, 30)
            elif scenario == 'medium':
                request_count = random.randint(10, 30)
                suspicious_patterns = random.randint(0, 1)
                risk_score = random.uniform(30, 60)
            elif scenario == 'high':
                request_count = random.randint(30, 60)
                suspicious_patterns = random.randint(1, 2)
                risk_score = random.uniform(60, 85)
            else:  # critical
                request_count = random.randint(60, 150)
                suspicious_patterns = random.randint(2, 5)
                risk_score = random.uniform(85, 100)
            
            url = self._generate_url(suspicious_patterns > 0)
            
            data = {
                'request': {
                    'url': url,
                    'method': random.choice(['GET', 'POST', 'PUT', 'DELETE']),
                    'headers': {'User-Agent': 'Mozilla/5.0'} if random.random() > 0.2 else {},
                    'body': ''
                },
                'ip': f"192.168.1.{random.randint(1, 254)}"
            }
            
            training_data.append(data)
            risk_scores.append(risk_score)
        
        return training_data, risk_scores
    
    def _create_finding(self, pattern: Dict) -> Dict[str, Any]:
        """Create a finding from pattern."""
        return {
            'severity': pattern['severity'].capitalize(),
            'category': pattern['category'],
            'description': pattern['description'],
            'evidence': pattern['evidence'],
            'cvss_score': pattern['cvss'],
            'risk_score': self._calculate_risk_score(pattern['cvss']),
            'url': f"{self.base_url}{pattern.get('url_pattern', '/index.php')}",
            'recommendation': f"Fix {pattern['category']} vulnerability",
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
    
    def _create_context(self, finding: Dict, is_fp: bool) -> Dict[str, Any]:
        """Create context for a finding with realistic variability."""
        # More realistic: FP and TP can have overlapping characteristics
        # FP tends to have: normal status codes, faster response, more occurrences
        # TP tends to have: error codes sometimes, slower response, fewer occurrences
        # But there's significant overlap - no perfect correlation
        
        if is_fp:
            # False positives: tend to be normal responses but not always
            status_code = random.choices(
                [200, 304, 403, 500],
                weights=[60, 20, 15, 5]  # Mostly 200, but can be errors
            )[0]
            response_time = random.randint(50, 500)  # Generally faster
            occurrence_count = random.randint(1, 15)  # Can appear multiple times
        else:
            # True positives: more likely to have errors but can be 200
            status_code = random.choices(
                [200, 403, 500, 400],
                weights=[40, 25, 25, 10]  # More errors, but still can be 200
            )[0]
            response_time = random.randint(100, 5000)  # Generally slower, but overlap
            occurrence_count = random.randint(1, 8)  # Usually fewer, but overlap
        
        return {
            'status_code': status_code,
            'response_time': response_time,
            'occurrence_count': occurrence_count,
            'days_since_first_seen': random.randint(0, 30)
        }
    
    def _create_severity_context(self) -> Dict[str, Any]:
        """Create context for severity prediction."""
        return {
            'environment': random.choice(['production', 'staging', 'development']),
            'public_facing': random.choice([True, False]),
            'requires_auth': random.choice([True, False]),
            'data_sensitivity': random.choice(['critical', 'high', 'medium', 'low']),
            'exploitability': random.choice(['trivial', 'easy', 'medium', 'hard']),
            'impact_scope': random.choice(['system', 'application', 'user', 'limited'])
        }
    
    def _calculate_risk_score(self, cvss: float) -> float:
        """Calculate risk score from CVSS."""
        # Simple formula: risk_score = cvss * 0.8 + random variation
        base_risk = cvss * 0.8
        variation = random.uniform(-0.5, 0.5)
        return max(0, min(10, base_risk + variation))
    
    def _generate_url(self, suspicious: bool) -> str:
        """Generate URL (suspicious or normal)."""
        if suspicious:
            patterns = [
                f"{self.base_url}/admin/../../etc/passwd",
                f"{self.base_url}/user/profile.php?id=1' OR '1'='1",
                f"{self.base_url}/course/view.php?id=<script>alert(1)</script>",
                f"{self.base_url}/mod/forum/post.php?id=1 UNION SELECT NULL--"
            ]
            return random.choice(patterns)
        else:
            endpoints = ['/login/index.php', '/course/view.php', '/user/profile.php']
            return f"{self.base_url}{random.choice(endpoints)}?id={random.randint(1, 100)}"
    
    def export_training_data(self, output_dir: str = "ml/data"):
        """
        Export all training data to JSON files.
        
        Args:
            output_dir: Directory to save training data
        """
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate all training datasets
        fp_data, fp_labels = self.generate_fp_training_data(200)
        severity_data, severity_labels = self.generate_severity_training_data(200)
        anomaly_data = self.generate_anomaly_training_data(300)
        rate_data, rate_scores = self.generate_rate_limiter_training_data(200)
        
        # Export to JSON
        datasets = {
            'false_positive': {
                'data': fp_data,
                'labels': fp_labels,
                'description': 'False positive reduction training data (0=TP, 1=FP)'
            },
            'severity': {
                'data': severity_data,
                'labels': severity_labels,
                'description': 'Severity prediction training data'
            },
            'anomaly': {
                'data': anomaly_data,
                'description': 'Normal behavior data for anomaly detection'
            },
            'rate_limiter': {
                'data': rate_data,
                'labels': rate_scores,
                'description': 'Rate limiter risk scoring training data (0-100)'
            }
        }
        
        for name, dataset in datasets.items():
            filepath = os.path.join(output_dir, f"{name}_training.json")
            with open(filepath, 'w') as f:
                json.dump(dataset, f, indent=2)
            print(f"[Training Data] Exported {name} to {filepath}")
        
        # Export metadata
        metadata = {
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'base_url': self.base_url,
            'datasets': {
                name: {
                    'samples': len(dataset['data']),
                    'description': dataset['description']
                }
                for name, dataset in datasets.items()
            },
            'sources': [
                'Moodle CVE database patterns',
                'OWASP Top 10 vulnerabilities',
                'Synthetic attack scenarios',
                'Common false positive patterns'
            ]
        }
        
        metadata_path = os.path.join(output_dir, 'metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        print(f"[Training Data] Exported metadata to {metadata_path}")
        
        return datasets


if __name__ == "__main__":
    """Generate and export training data."""
    print("="*80)
    print("TRAINING DATA GENERATOR")
    print("="*80)
    
    generator = TrainingDataGenerator()
    datasets = generator.export_training_data()
    
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    for name, dataset in datasets.items():
        print(f"\n{name.upper()}:")
        print(f"  Samples: {len(dataset['data'])}")
        print(f"  Description: {dataset['description']}")
    
    print("\n✅ Training data generated successfully!")
    print("📁 Location: ml/data/")
