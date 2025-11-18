"""
Risk Scorer with CVSS Calculation and Context-Aware Scoring

Calculates risk scores based on CVSS v3.1, business context, and environmental factors.
"""

from typing import Dict, Any, Optional
from enum import Enum


class CVSSMetric(Enum):
    """CVSS v3.1 metric values."""
    # Attack Vector (AV)
    NETWORK = "N"
    ADJACENT = "A"
    LOCAL = "L"
    PHYSICAL = "P"
    
    # Attack Complexity (AC)
    LOW = "L"
    HIGH = "H"
    
    # Privileges Required (PR)
    NONE = "N"
    LOW_PRIV = "L"
    HIGH_PRIV = "H"
    
    # User Interaction (UI)
    NONE_UI = "N"
    REQUIRED = "R"
    
    # Scope (S)
    UNCHANGED = "U"
    CHANGED = "C"
    
    # Impact (C/I/A)
    NONE_IMPACT = "N"
    LOW_IMPACT = "L"
    MEDIUM_IMPACT = "M"
    HIGH_IMPACT = "H"


class CVSSCalculator:
    """Calculate CVSS v3.1 base scores."""
    
    # CVSS v3.1 scoring weights
    WEIGHTS = {
        'AV': {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.2},
        'AC': {'L': 0.77, 'H': 0.44},
        'PR': {
            'U': {'N': 0.85, 'L': 0.62, 'H': 0.27},
            'C': {'N': 0.85, 'L': 0.68, 'H': 0.50}
        },
        'UI': {'N': 0.85, 'R': 0.62},
        'C': {'N': 0, 'L': 0.22, 'H': 0.56},
        'I': {'N': 0, 'L': 0.22, 'H': 0.56},
        'A': {'N': 0, 'L': 0.22, 'H': 0.56}
    }
    
    def calculate_base_score(self, vector: Dict[str, str]) -> float:
        """
        Calculate CVSS v3.1 base score.
        
        Args:
            vector: CVSS vector dictionary with keys: AV, AC, PR, UI, S, C, I, A
            
        Returns:
            CVSS base score (0.0 - 10.0)
        """
        # Extract metrics
        av = vector.get('AV', 'N')
        ac = vector.get('AC', 'L')
        pr = vector.get('PR', 'N')
        ui = vector.get('UI', 'N')
        s = vector.get('S', 'U')
        c = vector.get('C', 'N')
        i = vector.get('I', 'N')
        a = vector.get('A', 'N')
        
        # Calculate exploitability
        exploitability = 8.22 * self.WEIGHTS['AV'][av] * self.WEIGHTS['AC'][ac] * \
                        self.WEIGHTS['PR'][s][pr] * self.WEIGHTS['UI'][ui]
        
        # Calculate impact
        impact_base = 1 - ((1 - self.WEIGHTS['C'][c]) * 
                          (1 - self.WEIGHTS['I'][i]) * 
                          (1 - self.WEIGHTS['A'][a]))
        
        if s == 'U':
            impact = 6.42 * impact_base
        else:
            impact = 7.52 * (impact_base - 0.029) - 3.25 * pow(impact_base - 0.02, 15)
        
        # Calculate base score
        if impact <= 0:
            return 0.0
        
        if s == 'U':
            base_score = min(impact + exploitability, 10.0)
        else:
            base_score = min(1.08 * (impact + exploitability), 10.0)
        
        # Round up to one decimal
        return round(base_score, 1)
    
    def get_severity_rating(self, score: float) -> str:
        """
        Get severity rating from CVSS score.
        
        Args:
            score: CVSS score
            
        Returns:
            Severity rating (None, Low, Medium, High, Critical)
        """
        if score == 0.0:
            return "None"
        elif score < 4.0:
            return "Low"
        elif score < 7.0:
            return "Medium"
        elif score < 9.0:
            return "High"
        else:
            return "Critical"


class RiskScorer:
    """Calculate comprehensive risk scores with context awareness."""
    
    def __init__(self):
        """Initialize risk scorer."""
        self.cvss_calculator = CVSSCalculator()
        
        # Asset criticality levels
        self.asset_criticality = {
            'admin': 3.0,
            'api': 2.5,
            'auth': 2.5,
            'login': 2.5,
            'user': 2.0,
            'payment': 3.0,
            'data': 2.5,
            'public': 1.0,
            'static': 0.5
        }
        
        # Vulnerability type base scores
        self.vulnerability_base_scores = {
            'SQL Injection': {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'C', 'C': 'H', 'I': 'H', 'A': 'H'},
            'Cross-Site Scripting (XSS)': {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'R', 'S': 'C', 'C': 'L', 'I': 'L', 'A': 'N'},
            'Cross-Site Request Forgery (CSRF)': {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'R', 'S': 'U', 'C': 'L', 'I': 'L', 'A': 'L'},
            'Path Traversal': {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'N', 'A': 'N'},
            'Authentication': {'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'N'},
            'Access Control': {'AV': 'N', 'AC': 'L', 'PR': 'L', 'UI': 'N', 'S': 'U', 'C': 'H', 'I': 'H', 'A': 'N'},
        }
    
    def calculate_risk_score(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate comprehensive risk score for a finding.
        
        Args:
            finding: Finding dictionary with category, severity, evidence, etc.
            
        Returns:
            Risk score details including CVSS, context score, and final risk
        """
        # Get CVSS base score
        category = finding.get('category', 'General')
        cvss_vector = self.vulnerability_base_scores.get(category, {
            'AV': 'N', 'AC': 'L', 'PR': 'N', 'UI': 'N', 'S': 'U', 'C': 'L', 'I': 'L', 'A': 'N'
        })
        
        cvss_score = self.cvss_calculator.calculate_base_score(cvss_vector)
        
        # Calculate context multiplier
        context_multiplier = self._calculate_context_multiplier(finding)
        
        # Calculate exploitability factor
        exploitability = self._calculate_exploitability(finding)
        
        # Calculate business impact
        business_impact = self._calculate_business_impact(finding)
        
        # Calculate final risk score
        risk_score = cvss_score * context_multiplier * exploitability * business_impact
        risk_score = min(risk_score, 10.0)  # Cap at 10.0
        
        return {
            'cvss_score': cvss_score,
            'cvss_severity': self.cvss_calculator.get_severity_rating(cvss_score),
            'cvss_vector': self._vector_to_string(cvss_vector),
            'context_multiplier': context_multiplier,
            'exploitability': exploitability,
            'business_impact': business_impact,
            'risk_score': round(risk_score, 1),
            'risk_severity': self.cvss_calculator.get_severity_rating(risk_score),
            'priority': self._calculate_priority(risk_score, finding)
        }
    
    def _calculate_context_multiplier(self, finding: Dict[str, Any]) -> float:
        """Calculate context-based multiplier."""
        url = finding.get('evidence', '') or finding.get('url', '')
        multiplier = 1.0
        
        # Check URL for critical paths
        url_lower = url.lower()
        for keyword, criticality in self.asset_criticality.items():
            if keyword in url_lower:
                multiplier = max(multiplier, criticality / 2.0)
        
        return multiplier
    
    def _calculate_exploitability(self, finding: Dict[str, Any]) -> float:
        """Calculate exploitability factor."""
        category = finding.get('category', '')
        severity = finding.get('severity', 'Info').lower()
        
        # Base exploitability by severity
        exploitability_map = {
            'critical': 1.0,
            'high': 0.9,
            'medium': 0.7,
            'low': 0.5,
            'info': 0.3
        }
        
        base_exploitability = exploitability_map.get(severity, 0.5)
        
        # Adjust based on category
        if 'SQL Injection' in category:
            base_exploitability *= 1.2
        elif 'XSS' in category:
            base_exploitability *= 1.1
        elif 'Path Traversal' in category:
            base_exploitability *= 1.15
        
        return min(base_exploitability, 1.0)
    
    def _calculate_business_impact(self, finding: Dict[str, Any]) -> float:
        """Calculate business impact factor."""
        url = finding.get('evidence', '') or finding.get('url', '')
        url_lower = url.lower()
        
        # High impact areas
        if any(keyword in url_lower for keyword in ['admin', 'payment', 'api']):
            return 1.5
        
        # Medium impact areas
        elif any(keyword in url_lower for keyword in ['user', 'auth', 'login', 'data']):
            return 1.2
        
        # Low impact areas
        elif any(keyword in url_lower for keyword in ['public', 'static']):
            return 0.8
        
        # Default
        return 1.0
    
    def _calculate_priority(self, risk_score: float, finding: Dict[str, Any]) -> int:
        """
        Calculate remediation priority (1-5, 1 being highest).
        
        Args:
            risk_score: Calculated risk score
            finding: Finding details
            
        Returns:
            Priority level (1-5)
        """
        if risk_score >= 9.0:
            return 1  # Critical - Immediate action
        elif risk_score >= 7.0:
            return 2  # High - Fix within 24 hours
        elif risk_score >= 4.0:
            return 3  # Medium - Fix within 1 week
        elif risk_score >= 1.0:
            return 4  # Low - Fix within 1 month
        else:
            return 5  # Info - Monitor
    
    def _vector_to_string(self, vector: Dict[str, str]) -> str:
        """Convert CVSS vector dict to string."""
        return f"CVSS:3.1/AV:{vector['AV']}/AC:{vector['AC']}/PR:{vector['PR']}/UI:{vector['UI']}/S:{vector['S']}/C:{vector['C']}/I:{vector['I']}/A:{vector['A']}"
    
    def enrich_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich finding with risk scoring.
        
        Args:
            finding: Original finding
            
        Returns:
            Enriched finding with risk scores
        """
        risk_info = self.calculate_risk_score(finding)
        
        # Add risk information to finding
        enriched = finding.copy()
        enriched.update({
            'cvss_score': risk_info['cvss_score'],
            'cvss_severity': risk_info['cvss_severity'],
            'cvss_vector': risk_info['cvss_vector'],
            'risk_score': risk_info['risk_score'],
            'risk_severity': risk_info['risk_severity'],
            'priority': risk_info['priority'],
            'context_multiplier': risk_info['context_multiplier'],
            'exploitability': risk_info['exploitability'],
            'business_impact': risk_info['business_impact']
        })
        
        return enriched
    
    def batch_enrich_findings(self, findings: list) -> list:
        """Enrich multiple findings."""
        return [self.enrich_finding(f) for f in findings]


# Example usage
if __name__ == "__main__":
    scorer = RiskScorer()
    
    # Example finding
    finding = {
        'severity': 'High',
        'category': 'SQL Injection',
        'description': 'SQL error message detected',
        'evidence': 'SQL error in /admin/users.php',
        'url': 'http://localhost:8998/admin/users.php'
    }
    
    enriched = scorer.enrich_finding(finding)
    
    print("Original Finding:")
    print(f"  Severity: {finding['severity']}")
    print(f"  Category: {finding['category']}")
    
    print("\nRisk Scoring:")
    print(f"  CVSS Score: {enriched['cvss_score']} ({enriched['cvss_severity']})")
    print(f"  CVSS Vector: {enriched['cvss_vector']}")
    print(f"  Risk Score: {enriched['risk_score']} ({enriched['risk_severity']})")
    print(f"  Priority: {enriched['priority']}")
    print(f"  Context Multiplier: {enriched['context_multiplier']}")
    print(f"  Exploitability: {enriched['exploitability']}")
    print(f"  Business Impact: {enriched['business_impact']}")
