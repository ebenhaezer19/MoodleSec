#!/usr/bin/env python3
"""
Phishing and HTML injection detector for Moodle comments.
"""

import re
from typing import Dict, List, Tuple, Any
from urllib.parse import urlparse
import pickle
from pathlib import Path
from .path_utils import normalize_model_path


class PhishingDetector:
    """Detect phishing and HTML injection in Moodle comments."""
    
    def __init__(self, model_path: str = "ml/models/phishing_detector.pkl"):
        self.model_path = normalize_model_path(model_path, "phishing_detector.pkl")
        self.is_trained = False
        
        # HTML injection patterns
        self.html_injection_patterns = [
            r'<script[^>]*>.*?</script>',
            r'<iframe[^>]*>.*?</iframe>',
            r'<embed[^>]*>',
            r'<object[^>]*>',
            r'<form[^>]*>.*?</form>',
            r'<input[^>]*>',
            r'javascript:',
            r'on\w+\s*=',  # Event handlers: onclick, onload, etc.
            r'<img[^>]*src\s*=\s*["\']?javascript:',
            r'<a[^>]*href\s*=\s*["\']?javascript:',
        ]
        
        # Phishing URL patterns
        self.suspicious_url_patterns = [
            r'bit\.ly',
            r'tinyurl\.com',
            r'goo\.gl',
            r't\.co',
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP addresses
        ]
        
        # Phishing keywords (social engineering)
        self.phishing_keywords = [
            'verify account', 'suspended', 'urgent', 'click here',
            'confirm password', 'update payment', 'unusual activity',
            'verify identity', 'account locked', 'security alert',
            'immediate action', 'expire', 'limited time',
            'reset password', 'confirm identity', 'billing problem',
            'prize', 'winner', 'congratulations', 'claim now',
            'free money', 'act now', 'don\'t miss',
        ]
        
        # Legitimate Moodle domains (whitelist)
        self.trusted_domains = [
            'moodle.org',
            'moodle.com',
            'localhost',
            '127.0.0.1',
        ]
        
        self._load_model()
    
    def _load_model(self):
        """Load trained model if exists."""
        model_file = Path(self.model_path)
        if model_file.exists():
            try:
                with open(model_file, 'rb') as f:
                    data = pickle.load(f)
                    self.is_trained = True
                    print(f"[Phishing Detector] Loaded model from {self.model_path}")
            except Exception as e:
                print(f"[Phishing Detector] Could not load model: {e}")
                self.is_trained = False
    
    def detect(self, content: str, context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Detect phishing/HTML injection in content."""
        if not content:
            return {
                'is_malicious': False,
                'confidence': 0.0,
                'threat_type': 'none',
                'details': []
            }
        
        results = {
            'is_malicious': False,
            'confidence': 0.0,
            'threat_type': 'none',
            'details': [],
            'findings': []
        }
        
        # Check for HTML injection
        html_score, html_findings = self._check_html_injection(content)
        
        # Check for phishing URLs
        url_score, url_findings = self._check_phishing_urls(content)
        
        # Check for social engineering
        social_score, social_findings = self._check_social_engineering(content)
        
        # Aggregate scores
        total_score = html_score + url_score + social_score
        
        # Combine findings
        all_findings = html_findings + url_findings + social_findings
        
        # Determine threat type
        threat_types = []
        if html_score > 0.3:
            threat_types.append('html_injection')
        if url_score > 0.3:
            threat_types.append('phishing_url')
        if social_score > 0.3:
            threat_types.append('social_engineering')
        
        # Final classification (lowered threshold for better detection)
        is_malicious = total_score > 0.3
        
        results.update({
            'is_malicious': is_malicious,
            'confidence': min(total_score, 1.0),
            'threat_type': ', '.join(threat_types) if threat_types else 'none',
            'details': all_findings,
            'scores': {
                'html_injection': html_score,
                'phishing_url': url_score,
                'social_engineering': social_score,
                'total': total_score
            }
        })
        
        return results
    
    def _check_html_injection(self, content: str) -> Tuple[float, List[str]]:
        """Check for HTML injection patterns."""
        score = 0.0
        findings = []
        
        for pattern in self.html_injection_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            if matches:
                score += 0.4
                findings.append(f"HTML injection pattern detected: {pattern[:50]}")
        
        # Check for encoded HTML
        if any(encoded in content.lower() for encoded in ['%3c', '&lt;', '&#60;']):
            score += 0.2
            findings.append("Encoded HTML detected (possible evasion)")
        
        return min(score, 1.0), findings
    
    def _check_phishing_urls(self, content: str) -> Tuple[float, List[str]]:
        """Check for phishing URLs."""
        score = 0.0
        findings = []
        
        # Extract URLs
        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', content)
        
        for url in urls:
            # Parse URL
            try:
                parsed = urlparse(url if url.startswith('http') else f'http://{url}')
                domain = parsed.netloc.lower()
                
                # Check if trusted domain
                is_trusted = any(trusted in domain for trusted in self.trusted_domains)
                if is_trusted:
                    continue
                
                # Check suspicious patterns
                for pattern in self.suspicious_url_patterns:
                    if re.search(pattern, domain):
                        score += 0.3
                        findings.append(f"Suspicious URL detected: {url[:50]}")
                        break
                
                # Check for IP address
                if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
                    score += 0.4
                    findings.append(f"URL with IP address (suspicious): {url[:50]}")
                
                # Check for misleading domains
                if any(keyword in domain for keyword in ['login', 'verify', 'account', 'secure']):
                    if not is_trusted:
                        score += 0.2
                        findings.append(f"Potentially misleading domain: {domain}")
                
            except Exception:
                continue
        
        return min(score, 1.0), findings
    
    def _check_social_engineering(self, content: str) -> Tuple[float, List[str]]:
        """Check for social engineering patterns."""
        score = 0.0
        findings = []
        content_lower = content.lower()
        
        # Check for phishing keywords
        keyword_count = 0
        found_keywords = []
        for keyword in self.phishing_keywords:
            if keyword in content_lower:
                keyword_count += 1
                found_keywords.append(keyword)
        
        if keyword_count > 0:
            score += min(keyword_count * 0.15, 0.6)
            findings.append(f"Social engineering keywords detected: {', '.join(found_keywords[:3])}")
        
        # Check for urgency indicators
        urgency_patterns = [
            r'urgent', r'immediate', r'asap', r'now', r'today',
            r'expire', r'limited time', r'act fast'
        ]
        
        urgency_count = sum(1 for pattern in urgency_patterns if re.search(pattern, content_lower))
        if urgency_count >= 2:
            score += 0.3
            findings.append("Multiple urgency indicators detected")
        
        # Check for credential requests
        credential_patterns = [
            r'password', r'username', r'login', r'credential',
            r'pin', r'security code', r'verification code'
        ]
        
        credential_count = sum(1 for pattern in credential_patterns if re.search(pattern, content_lower))
        if credential_count >= 2:
            score += 0.4
            findings.append("Potential credential harvesting attempt")
        
        return min(score, 1.0), findings
    
    def get_recommendation(self, detection_result: Dict[str, Any]) -> str:
        """Get security recommendation based on detection result."""
        if not detection_result['is_malicious']:
            return "Content appears safe"
        
        threat_type = detection_result['threat_type']
        
        recommendations = {
            'html_injection': "Remove HTML tags and sanitize input. Enable HTML filtering in Moodle.",
            'phishing_url': "Block suspicious URLs. Warn users not to click untrusted links.",
            'social_engineering': "Review content for social engineering. Educate users about phishing.",
        }
        
        if ',' in threat_type:
            return "Multiple threats detected. Remove content and investigate user account."
        
        return recommendations.get(threat_type, "Review and remove malicious content")
