"""
Smart Response Validator for accurate vulnerability detection.

Implements multi-layer detection strategy:
- Error-based detection: Look for SQL/command error patterns
- Time-based detection: Compare response times
- Union-based detection: Detect union-based SQL injection patterns
- Blind-based detection: Detect observable behavioral changes
- Baseline comparison: Compare against normal responses
"""

import re
import logging
import hashlib
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class DetectionType(Enum):
    """Types of vulnerability detection methods."""
    ERROR_BASED = "error_based"
    TIME_BASED = "time_based"
    UNION_BASED = "union_based"
    BLIND_BASED = "blind_based"
    BASELINE_DEVIATION = "baseline_deviation"


@dataclass
class DetectionResult:
    """Result of a vulnerability detection test."""
    is_vulnerable: bool
    detection_types: List[DetectionType]
    confidence: float  # 0.0-1.0
    evidence: List[str]
    details: Dict


class SmartResponseValidator:
    """
    Multi-layer response validator for accurate vulnerability detection.
    
    Uses multiple detection mechanisms to reduce false positives:
    1. Error-based: Direct error messages (requires 1+ indicator)
    2. Time-based: Response time delays (requires 2+ indicators and >2s difference)
    3. Union-based: UNION-based SQL detections (requires 1+ indicator)
    4. Blind-based: Boolean-based blind SQLi (requires 2+ indicators)
    5. Baseline: Deviation from normal response (requires >20% diff)
    """
    
    # Common SQL error patterns (database-agnostic)
    SQL_ERROR_PATTERNS = {
        # MySQL
        r"(?i)(?:mysql_fetch|mysql_error|mysql_num_rows|SQL syntax|unexpected end of file)",
        # PostgreSQL
        r"(?i)(?:PostgreSQL|pgerror|syntax error at|column.*not exist)",
        # Oracle
        r"(?i)(?:Oracle|ORA-\d+|invalid column name)",
        # MSSQL
        r"(?i)(?:Conversion failed|syntax error|unclosed quotation|server side SQL error)",
        # Generic SQL
        r"(?i)(?:SQL Error|database error|query syntax|You have an error in your SQL)",
        # Command injection patterns
        r"(?i)(?:command not found|No such file|cannot execute|permission denied)",
    }
    
    # Union-based SQL detection patterns
    UNION_PATTERNS = {
        r"(?i)UNION.*SELECT",
        r"(?i)ORDER BY\s+\d+",
        r"column \d+ cannot be cast",
        r"different number of rows",
    }
    
    # Blind SQL injection indicators
    BLIND_INDICATORS = {
        r"(?i)true.*false",
        r"(?i)if\s*\(",
        r"(?i)case\s+when",
        r"(?i)substring\s*\(",
        r"(?i)condition.*true",
    }
    
    def __init__(self):
        """Initialize response validator."""
        self.baseline_responses: Dict[str, Dict] = {}
        self.detection_history: List[Dict] = []
    
    def set_baseline(
        self,
        endpoint: str,
        response_text: str,
        response_code: int,
        response_length: int
    ):
        """
        Record baseline (normal) response for comparison.
        
        Args:
            endpoint: Target endpoint
            response_text: Response body
            response_code: HTTP status code
            response_length: Response body length
        """
        baseline = {
            'status_code': response_code,
            'length': response_length,
            'content_hash': hashlib.md5(response_text.encode()).hexdigest(),
            'content_sample': response_text[:500],
            'has_error': self._contains_error_pattern(response_text),
        }
        self.baseline_responses[endpoint] = baseline
        logger.debug(f"Baseline recorded for {endpoint}: {response_code}, len={response_length}")
    
    def validate_response(
        self,
        endpoint: str,
        response_text: str,
        response_code: int,
        response_time: float,
        baseline_response_time: float = 0.5,
        payload_type: str = "sql_injection"
    ) -> DetectionResult:
        """
        Validate response for vulnerability indicators.
        
        Args:
            endpoint: Target endpoint
            response_text: Response body
            response_code: HTTP status code
            response_time: Time taken to receive response (seconds)
            baseline_response_time: Normal response time (seconds)
            payload_type: Type of payload tested (sql_injection, xss, etc)
            
        Returns:
            DetectionResult with findings
        """
        detected_types: List[DetectionType] = []
        evidence: List[str] = []
        confidence = 0.0
        
        # Check 1: Error-based detection
        if self._has_error_pattern(response_text):
            detected_types.append(DetectionType.ERROR_BASED)
            evidence.append("SQL/Command error patterns found in response")
            confidence += 0.35
            logger.debug(f"  ✓ Error-based indicator found")
        
        # Check 2: Time-based detection (requires significant delay)
        if response_time > (baseline_response_time + 2.0):
            time_diff = response_time - baseline_response_time
            detected_types.append(DetectionType.TIME_BASED)
            evidence.append(f"Response delayed by {time_diff:.2f}s beyond baseline")
            confidence += 0.30
            logger.debug(f"  ✓ Time-based indicator: {time_diff:.2f}s delay")
        
        # Check 3: Union-based detection patterns
        if self._has_union_pattern(response_text):
            detected_types.append(DetectionType.UNION_BASED)
            evidence.append("UNION-based SQL injection pattern found")
            confidence += 0.25
            logger.debug(f"  ✓ Union-based indicator found")
        
        # Check 4: Blind-based detection (requires careful analysis)
        if self._has_blind_indicator(response_text):
            detected_types.append(DetectionType.BLIND_BASED)
            evidence.append("Blind SQL injection behavior detected")
            confidence += 0.20
            logger.debug(f"  ✓ Blind-based indicator found")
        
        # Check 5: Baseline deviation (requires >20% diff)
        if endpoint in self.baseline_responses:
            baseline = self.baseline_responses[endpoint]
            length_diff = abs(len(response_text) - baseline['length'])
            length_percent = length_diff / max(baseline['length'], 1) * 100
            
            if length_percent > 20:
                detected_types.append(DetectionType.BASELINE_DEVIATION)
                evidence.append(f"Response length deviates {length_percent:.1f}% from baseline")
                confidence += 0.15
                logger.debug(f"  ✓ Baseline deviation: {length_percent:.1f}%")
        
        # Determine vulnerability based on MULTIPLE indicators
        # Require at least 2 independent detections for confirmation
        is_vulnerable = (
            len(detected_types) >= 2 or  # Multiple indicators
            (len(detected_types) == 1 and detected_types[0] in [
                DetectionType.ERROR_BASED,  # Single error pattern is usually reliable
                DetectionType.UNION_BASED,  # Union patterns are specific
            ])
        )
        
        # Cap confidence at 1.0
        confidence = min(confidence, 1.0)
        
        result = DetectionResult(
            is_vulnerable=is_vulnerable,
            detection_types=detected_types,
            confidence=confidence,
            evidence=evidence,
            details={
                'response_code': response_code,
                'response_time': response_time,
                'response_length': len(response_text),
                'baseline_available': endpoint in self.baseline_responses,
                'detection_count': len(detected_types),
            }
        )
        
        logger.info(
            f"Validation result for {endpoint}: "
            f"vulnerable={is_vulnerable}, confidence={confidence:.2f}, "
            f"detected={len(detected_types)} indicators"
        )
        
        # Record in history
        self.detection_history.append({
            'endpoint': endpoint,
            'result': result,
            'response_code': response_code,
        })
        
        return result
    
    def _contains_error_pattern(self, text: str) -> bool:
        """Check if text contains any error pattern."""
        return any(re.search(pattern, text) for pattern in self.SQL_ERROR_PATTERNS)
    
    def _has_error_pattern(self, text: str) -> bool:
        """
        Check for SQL/command error patterns in response.
        
        Args:
            text: Response text to check
            
        Returns:
            True if error patterns found
        """
        if not text:
            return False
        
        # Exclude false positives: 401/403 auth errors (not SQL errors)
        if any(phrase in text.lower() for phrase in [
            'unauthorized', 'forbidden', 'not authenticated', '401', '403'
        ]):
            return False
        
        return self._contains_error_pattern(text)
    
    def _has_union_pattern(self, text: str) -> bool:
        """Check for UNION-based SQL injection patterns."""
        if not text:
            return False
        
        return any(re.search(pattern, text) for pattern in self.UNION_PATTERNS)
    
    def _has_blind_indicator(self, text: str) -> bool:
        """Check for blind SQL injection behavioral indicators."""
        if not text:
            return False
        
        # Look for conditional logic or boolean-like responses
        indicator_count = sum(
            1 for pattern in self.BLIND_INDICATORS 
            if re.search(pattern, text)
        )
        
        # Require at least 2 indicators for blind detection
        return indicator_count >= 2
    
    def get_summary(self) -> Dict:
        """
        Get summary of detection history.
        
        Returns:
            Dictionary with detection statistics
        """
        if not self.detection_history:
            return {
                'total_tests': 0,
                'vulnerable_found': 0,
                'false_positive_rate': 0,
            }
        
        vulnerable_count = sum(
            1 for h in self.detection_history 
            if h['result'].is_vulnerable
        )
        
        false_positive_count = sum(
            1 for h in self.detection_history
            if h['result'].is_vulnerable and h['response_code'] in [401, 403]
        )
        
        return {
            'total_tests': len(self.detection_history),
            'vulnerable_found': vulnerable_count,
            'false_positive_count': false_positive_count,
            'confidence_avg': sum(
                h['result'].confidence for h in self.detection_history
            ) / len(self.detection_history),
            'by_detection_type': self._count_by_type(),
        }
    
    def _count_by_type(self) -> Dict[str, int]:
        """Count detections by type."""
        counts = {}
        for h in self.detection_history:
            for dt in h['result'].detection_types:
                counts[dt.value] = counts.get(dt.value, 0) + 1
        return counts
    
    def clear_history(self):
        """Clear detection history (for new test session)."""
        self.detection_history.clear()
        logger.debug("Detection history cleared")
