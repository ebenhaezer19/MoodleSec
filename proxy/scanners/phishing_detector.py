"""
MoodleSec - Phishing Link Detector
Detects phishing attempts in user-generated content (bio, comments, posts)
Analyzes URLs, suspicious patterns, and known phishing indicators
"""

import re
import urllib.parse
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import tldextract
from difflib import SequenceMatcher

@dataclass
class PhishingFinding:
    """Phishing detection result"""
    is_suspicious: bool
    risk_score: float  # 0-10
    indicators: List[str]
    suspicious_url: str
    context: str
    recommendation: str
    
class PhishingDetector:
    """
    Detects phishing attempts in Moodle user content
    
    Detection Methods:
    1. URL Analysis (domain spoofing, suspicious TLDs)
    2. Link Text vs Actual URL mismatch
    3. Homograph attacks (lookalike domains)
    4. URL shorteners (bit.ly, tinyurl, etc.)
    5. IP-based URLs
    6. Known phishing patterns
    7. Urgency keywords (common in phishing)
    """
    
    # Suspicious TLDs often used in phishing
    SUSPICIOUS_TLDS = [
        'tk', 'ml', 'ga', 'cf', 'gq',  # Free domains
        'zip', 'review', 'country', 'stream',  # New TLDs
        'top', 'work', 'click', 'link'
    ]
    
    # URL shortener services
    URL_SHORTENERS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co',
        'ow.ly', 'is.gd', 'buff.ly', 'adf.ly',
        'short.link', 'cutt.ly', 'rebrandly.com'
    ]
    
    # Legitimate domains that might be spoofed (education context)
    LEGITIMATE_DOMAINS = [
        'moodle.org', 'moodle.com',
        'google.com', 'microsoft.com', 'office.com',
        'gmail.com', 'outlook.com', 'yahoo.com',
        'github.com', 'gitlab.com',
        'zoom.us', 'teams.microsoft.com'
    ]
    
    # Phishing urgency keywords (Bahasa Indonesia + English)
    URGENCY_KEYWORDS = [
        # Indonesian
        'segera', 'urgent', 'penting', 'verifikasi', 'konfirmasi',
        'akun anda', 'password', 'kadaluarsa', 'expired', 'blokir',
        'suspend', 'klik disini', 'login sekarang', 'update data',
        'hadiah', 'menang', 'gratis', 'bonus',
        
        # English
        'urgent', 'immediate', 'verify', 'confirm', 'suspended',
        'blocked', 'click here', 'login now', 'update account',
        'prize', 'winner', 'free', 'congratulations'
    ]
    
    def __init__(self, moodle_base_domain: str):
        """
        Initialize phishing detector
        
        Args:
            moodle_base_domain: Base domain of Moodle instance (e.g., 'university.ac.id')
        """
        self.moodle_domain = moodle_base_domain
        self.suspicious_patterns = self._compile_patterns()
        
    def _compile_patterns(self) -> Dict[str, re.Pattern]:
        """Compile regex patterns for phishing detection"""
        return {
            'html_link': re.compile(r'<a\s+(?:[^>]*?\s+)?href=(["\'])(.*?)\1', re.IGNORECASE),
            'markdown_link': re.compile(r'\[([^\]]+)\]\(([^\)]+)\)'),
            'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
            'ip_address': re.compile(r'https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?'),
            'email_harvest': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            'obfuscated_url': re.compile(r'https?://[^\s]*(?:%[0-9A-Fa-f]{2}){3,}'),
        }
    
    def scan_content(self, content: str, context: str = "user_content") -> List[PhishingFinding]:
        """
        Scan user content for phishing indicators
        
        Args:
            content: User-generated content (HTML, text)
            context: Context of content (bio, comment, forum_post, etc.)
            
        Returns:
            List of phishing findings
        """
        findings = []
        
        # Extract all URLs from content
        urls = self._extract_urls(content)
        
        for url_info in urls:
            url = url_info['url']
            link_text = url_info.get('text', '')
            
            indicators = []
            risk_score = 0.0
            
            # Check 1: URL Shorteners
            if self._is_url_shortener(url):
                indicators.append("URL Shortener detected (hides destination)")
                risk_score += 3.0
            
            # Check 2: IP-based URL
            if self._is_ip_based_url(url):
                indicators.append("IP-based URL (suspicious)")
                risk_score += 4.0
            
            # Check 3: Suspicious TLD
            tld_risk = self._check_suspicious_tld(url)
            if tld_risk > 0:
                indicators.append(f"Suspicious TLD detected")
                risk_score += tld_risk
            
            # Check 4: Domain spoofing (typosquatting)
            spoofing_check = self._check_domain_spoofing(url)
            if spoofing_check:
                indicators.append(f"Possible domain spoofing: {spoofing_check}")
                risk_score += 5.0
            
            # Check 5: Link text vs URL mismatch (suspicious generic text)
            if link_text and self._check_link_text_mismatch(link_text, url):
                indicators.append("Suspicious link text (generic/misleading)")
                risk_score += 5.0  # Increased from 4.0
            
            # Check 6: External domain (not Moodle instance)
            is_external = not self._is_internal_domain(url)
            if is_external:
                indicators.append("External link (outside Moodle)")
                risk_score += 1.0
                
                # Check 6b: Unknown external domain (not in legitimate list)
                if not self._is_known_legitimate_domain(url):
                    indicators.append("Unknown/uncommon external domain")
                    risk_score += 2.0  # Additional risk for unknown domains
            
            # Check 7: Obfuscated URL (excessive encoding)
            if self._is_obfuscated_url(url):
                indicators.append("URL obfuscation detected")
                risk_score += 3.0
            
            # Check 8: Multiple redirects/parameters
            if self._has_suspicious_parameters(url):
                indicators.append("Suspicious URL parameters")
                risk_score += 2.0
            
            # Check 9: Homograph attack (lookalike characters)
            if self._check_homograph_attack(url):
                indicators.append("Possible homograph attack (lookalike characters)")
                risk_score += 6.0
            
            # Normalize risk score (0-10)
            risk_score = min(risk_score, 10.0)
            
            # Create finding if suspicious
            if risk_score >= 3.0:  # Threshold for reporting
                finding = PhishingFinding(
                    is_suspicious=True,
                    risk_score=risk_score,
                    indicators=indicators,
                    suspicious_url=url,
                    context=context,
                    recommendation=self._generate_recommendation(risk_score, indicators)
                )
                findings.append(finding)
        
        # Check for urgency keywords (social engineering)
        urgency_check = self._check_urgency_keywords(content)
        if urgency_check and urls:  # Only flag if URLs present
            finding = PhishingFinding(
                is_suspicious=True,
                risk_score=4.0,
                indicators=[f"Social engineering keywords: {', '.join(urgency_check[:3])}"],
                suspicious_url="N/A (text-based)",
                context=context,
                recommendation="Content contains urgency keywords typical of phishing attempts"
            )
            findings.append(finding)
        
        return findings
    
    def _extract_urls(self, content: str) -> List[Dict[str, str]]:
        """Extract URLs from content with context"""
        urls = []
        
        # Extract HTML links <a href="...">text</a>
        for match in self.suspicious_patterns['html_link'].finditer(content):
            url = match.group(2)
            # Try to extract link text
            link_start = match.end()
            link_end = content.find('</a>', link_start)
            text = content[link_start:link_end].strip() if link_end != -1 else ''
            text = re.sub(r'<[^>]+>', '', text)  # Remove inner tags
            
            urls.append({'url': url, 'text': text, 'type': 'html'})
        
        # Extract markdown links [text](url)
        for match in self.suspicious_patterns['markdown_link'].finditer(content):
            urls.append({'url': match.group(2), 'text': match.group(1), 'type': 'markdown'})
        
        # Extract plain URLs
        for match in self.suspicious_patterns['url'].finditer(content):
            url = match.group(0)
            # Skip if already captured
            if not any(u['url'] == url for u in urls):
                urls.append({'url': url, 'text': '', 'type': 'plain'})
        
        return urls
    
    def _is_url_shortener(self, url: str) -> bool:
        """Check if URL is from known shortener service"""
        try:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            return domain in self.URL_SHORTENERS
        except:
            return False
    
    def _is_ip_based_url(self, url: str) -> bool:
        """Check if URL uses IP address instead of domain"""
        return bool(self.suspicious_patterns['ip_address'].match(url))
    
    def _check_suspicious_tld(self, url: str) -> float:
        """Check for suspicious top-level domains"""
        try:
            extracted = tldextract.extract(url)
            if extracted.suffix in self.SUSPICIOUS_TLDS:
                return 3.0
            return 0.0
        except:
            return 0.0
    
    def _check_domain_spoofing(self, url: str) -> Optional[str]:
        """
        Check for domain spoofing (typosquatting)
        Returns spoofed domain if detected
        """
        try:
            extracted = tldextract.extract(url)
            target_domain = f"{extracted.domain}.{extracted.suffix}"
            
            for legit_domain in self.LEGITIMATE_DOMAINS:
                similarity = SequenceMatcher(None, target_domain.lower(), legit_domain.lower()).ratio()
                
                # High similarity but not exact match = typosquatting
                if 0.7 < similarity < 1.0:
                    return f"Similar to {legit_domain}"
                
                # Check for subdomain spoofing (e.g., microsoft.com.phishing.com)
                if legit_domain in target_domain and target_domain != legit_domain:
                    return f"Subdomain spoofing of {legit_domain}"
            
            return None
        except:
            return None
    
    def _check_link_text_mismatch(self, link_text: str, url: str) -> bool:
        """Check if link text misleads about destination"""
        # Common generic/suspicious link texts used in phishing
        suspicious_link_texts = [
            'klik disini', 'klik di sini', 'click here', 'klik',
            'click', 'here', 'di sini', 'disini',
            'claim', 'verify', 'confirm', 'update',
            'login', 'sign in', 'masuk',
            'download', 'unduh', 'get', 'lihat'
        ]
        
        link_text_lower = link_text.lower().strip()
        
        # Check if link text is generic/suspicious (phishing red flag)
        if any(susp in link_text_lower for susp in suspicious_link_texts):
            return True
        
        # Extract domain from link text if it looks like URL
        text_domain = None
        url_pattern = re.search(r'(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', link_text)
        if url_pattern:
            text_domain = url_pattern.group(1).lower()
        
        # Extract actual domain
        try:
            extracted = tldextract.extract(url)
            actual_domain = f"{extracted.domain}.{extracted.suffix}".lower()
            
            # If link text contains domain reference, check if it matches
            if text_domain and text_domain != actual_domain:
                return True
            
            return False
        except:
            return False
    
    def _is_internal_domain(self, url: str) -> bool:
        """Check if URL is internal to Moodle instance"""
        try:
            extracted = tldextract.extract(url)
            url_domain = f"{extracted.domain}.{extracted.suffix}"
            return url_domain == self.moodle_domain or url.startswith('/')
        except:
            return False
    
    def _is_known_legitimate_domain(self, url: str) -> bool:
        """Check if URL is from a known legitimate domain"""
        try:
            extracted = tldextract.extract(url)
            url_domain = f"{extracted.domain}.{extracted.suffix}".lower()
            
            # Check against legitimate domains list
            for legit_domain in self.LEGITIMATE_DOMAINS:
                if url_domain == legit_domain.lower():
                    return True
            
            return False
        except:
            return False
    
    def _is_obfuscated_url(self, url: str) -> bool:
        """Check for excessive URL encoding (obfuscation)"""
        return bool(self.suspicious_patterns['obfuscated_url'].match(url))
    
    def _has_suspicious_parameters(self, url: str) -> bool:
        """Check for suspicious URL parameters"""
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            
            # Suspicious parameter names
            suspicious_params = ['redirect', 'return', 'goto', 'continue', 'next', 'url', 'link']
            
            for param in suspicious_params:
                if param in params:
                    return True
            
            # Too many parameters (potential tracking/malicious)
            if len(params) > 10:
                return True
            
            return False
        except:
            return False
    
    def _check_homograph_attack(self, url: str) -> bool:
        """
        Check for homograph attacks (Unicode lookalike characters)
        e.g., google.com vs gооgle.com (Cyrillic 'о')
        """
        try:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            
            # Check if domain contains non-ASCII characters
            if not domain.isascii():
                return True
            
            # Check for common homograph substitutions
            homograph_pairs = [
                ('o', 'о'),  # Latin o vs Cyrillic o
                ('a', 'а'),  # Latin a vs Cyrillic a
                ('e', 'е'),  # Latin e vs Cyrillic e
                ('p', 'р'),  # Latin p vs Cyrillic r
                ('c', 'с'),  # Latin c vs Cyrillic s
                ('0', 'O'),  # Zero vs letter O
                ('1', 'l'),  # One vs lowercase L
            ]
            
            # This is basic detection - production should use punycode analysis
            return False  # More sophisticated check needed
        except:
            return False
    
    def _check_urgency_keywords(self, content: str) -> List[str]:
        """Check for social engineering urgency keywords"""
        content_lower = content.lower()
        found_keywords = []
        
        for keyword in self.URGENCY_KEYWORDS:
            if keyword.lower() in content_lower:
                found_keywords.append(keyword)
        
        return found_keywords[:5]  # Return max 5 keywords
    
    def _generate_recommendation(self, risk_score: float, indicators: List[str]) -> str:
        """Generate remediation recommendation"""
        if risk_score >= 8.0:
            return "CRITICAL: Block this content immediately. High probability phishing attempt."
        elif risk_score >= 6.0:
            return "HIGH RISK: Review and likely remove. Strong phishing indicators present."
        elif risk_score >= 4.0:
            return "MEDIUM RISK: Investigate and warn user. Suspicious patterns detected."
        else:
            return "LOW RISK: Monitor. Some suspicious elements but may be legitimate."
    
    def scan_user_profile(self, user_id: int, bio_content: str) -> Dict[str, any]:
        """
        Scan user profile bio for phishing
        
        Args:
            user_id: Moodle user ID
            bio_content: User bio/description content
            
        Returns:
            Scan result with findings
        """
        findings = self.scan_content(bio_content, context=f"user_profile:{user_id}")
        
        return {
            'user_id': user_id,
            'scan_type': 'profile_bio',
            'findings_count': len(findings),
            'max_risk_score': max([f.risk_score for f in findings]) if findings else 0.0,
            'findings': [self._finding_to_dict(f) for f in findings]
        }
    
    def scan_comment(self, comment_id: int, comment_content: str, context: str = "comment") -> Dict[str, any]:
        """
        Scan comment/forum post for phishing
        
        Args:
            comment_id: Comment/post ID
            comment_content: Comment text
            context: Context (comment, forum_post, etc.)
            
        Returns:
            Scan result with findings
        """
        findings = self.scan_content(comment_content, context=f"{context}:{comment_id}")
        
        return {
            'comment_id': comment_id,
            'scan_type': context,
            'findings_count': len(findings),
            'max_risk_score': max([f.risk_score for f in findings]) if findings else 0.0,
            'findings': [self._finding_to_dict(f) for f in findings]
        }
    
    def _finding_to_dict(self, finding: PhishingFinding) -> Dict[str, any]:
        """Convert finding to dictionary"""
        return {
            'is_suspicious': finding.is_suspicious,
            'risk_score': finding.risk_score,
            'severity': self._risk_to_severity(finding.risk_score),
            'indicators': finding.indicators,
            'suspicious_url': finding.suspicious_url,
            'context': finding.context,
            'recommendation': finding.recommendation
        }
    
    def _risk_to_severity(self, risk_score: float) -> str:
        """Convert risk score to severity level"""
        if risk_score >= 8.0:
            return "CRITICAL"
        elif risk_score >= 6.0:
            return "HIGH"
        elif risk_score >= 4.0:
            return "MEDIUM"
        else:
            return "LOW"


# Example usage
if __name__ == "__main__":
    # Initialize detector
    detector = PhishingDetector(moodle_base_domain="university.ac.id")
    
    # Test case 1: Suspicious bio with URL shortener
    test_bio = """
    Halo! Saya mahasiswa baru. 
    Klik link ini untuk info beasiswa GRATIS: http://bit.ly/xyz123
    """
    
    result = detector.scan_user_profile(user_id=123, bio_content=test_bio)
    print("Test 1 - URL Shortener:")
    print(f"Findings: {result['findings_count']}, Max Risk: {result['max_risk_score']}")
    print()
    
    # Test case 2: Link text mismatch (common phishing technique)
    test_comment = """
    <a href="http://phishing-site.com/steal">Click here for Moodle login</a>
    """
    
    result = detector.scan_comment(comment_id=456, comment_content=test_comment)
    print("Test 2 - Link Mismatch:")
    print(f"Findings: {result['findings_count']}, Max Risk: {result['max_risk_score']}")
    print()
    
    # Test case 3: Urgency keywords + external link
    test_comment2 = """
    URGENT! Akun anda akan diblokir dalam 24 jam!
    Segera verifikasi di: <a href="http://fake-moodle.tk">http://moodle-verify.com</a>
    """
    
    result = detector.scan_comment(comment_id=789, comment_content=test_comment2, context="forum_post")
    print("Test 3 - Social Engineering:")
    print(f"Findings: {result['findings_count']}, Max Risk: {result['max_risk_score']}")
    for finding in result['findings']:
        print(f"  - {finding['severity']}: {', '.join(finding['indicators'][:2])}")
