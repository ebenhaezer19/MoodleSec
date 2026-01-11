"""
ML Manager

Centralized manager for all ML-enhanced detection modules.
Coordinates false positive reduction, anomaly detection,
severity prediction, and rate limiting.
"""

from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import json
import numpy as np

from .false_positive_reducer import FalsePositiveReducer
from .anomaly_detector import AnomalyDetector
from .severity_predictor import SeverityPredictor
from .rate_limiter import MLRateLimiter
from .phishing_detector import PhishingDetector


class MLManager:
    """
    Centralized ML manager for security scanning enhancements.
    
    Provides:
    - False positive filtering
    - Anomaly detection
    - Severity prediction
    - Intelligent rate limiting
    """
    
    def __init__(self, enable_ml: bool = True):
        """
        Initialize ML Manager.
        
        Args:
            enable_ml: Whether to enable ML features (default: True)
        """
        self.enable_ml = enable_ml
        
        # Critical categories that should NEVER be filtered as false positives
        self.critical_categories = [
            'CSRF',
            'Cross-Site Request Forgery',
            'Session Management',
            'Session Security',
            'Authentication',
            'Authorization',
            'Access Control',
            'SQL Injection',
            'Command Injection',
            'Path Traversal',
            'Remote Code Execution'
        ]
        
        # Initialize ML modules
        self.fp_reducer = FalsePositiveReducer() if enable_ml else None
        self.anomaly_detector = AnomalyDetector() if enable_ml else None
        self.severity_predictor = SeverityPredictor() if enable_ml else None
        self.rate_limiter = MLRateLimiter() if enable_ml else None
        self.phishing_detector = PhishingDetector() if enable_ml else None
        
        print(f"[ML Manager] Initialized (ML {'enabled' if enable_ml else 'disabled'})")
        if enable_ml:
            self._print_model_status()
    
    def _print_model_status(self):
        """Print status of all ML models."""
        print(f"[ML Manager] False Positive Reducer: {'trained' if self.fp_reducer.is_trained else 'not trained'}")
        print(f"[ML Manager] Anomaly Detector: {'trained' if self.anomaly_detector.is_trained else 'not trained'}")
        print(f"[ML Manager] Severity Predictor: {'trained' if self.severity_predictor.is_trained else 'not trained'}")
        print(f"[ML Manager] Rate Limiter: {'trained' if self.rate_limiter.is_trained else 'not trained'}")
    
    def process_finding(self, finding: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Process a security finding through all ML modules.
        
        Args:
            finding: Security finding dictionary
            context: Additional context
            
        Returns:
            Enhanced finding with ML predictions
        """
        if not self.enable_ml:
            return finding
        
        enhanced_finding = finding.copy()
        ml_metadata = {}
        
        # 1. False Positive Detection
        is_fp, fp_confidence = self.fp_reducer.predict(finding, context)
        ml_metadata['false_positive'] = {
            'is_false_positive': is_fp,
            'confidence': fp_confidence
        }
        
        # Check if this is a critical category that should NEVER be filtered
        category = finding.get('category', '')
        is_critical = any(crit_cat.lower() in category.lower() for crit_cat in self.critical_categories)
        
        if is_critical:
            # NEVER filter critical security issues as false positives
            enhanced_finding['filtered'] = False
            enhanced_finding['critical_category'] = True
            ml_metadata['filter_bypassed'] = f'Critical category: {category}'
            print(f"[ML Manager] ⚠️  Preserving CRITICAL finding: {category} | {finding.get('severity')} | {finding.get('description', '')[:60]}...")
        # Filter out false positives with confidence > 70%
        # Also filter XSS findings with "dangerous tag" pattern (common FP)
        elif is_fp and fp_confidence > 0.7:
            enhanced_finding['filtered'] = True
            enhanced_finding['filter_reason'] = f'ML detected false positive ({fp_confidence:.2%})'
        elif finding.get('category') == 'Cross-Site Scripting (XSS)':
            description = finding.get('description', '').lower()
            # Check for multiple FP patterns
            fp_patterns = [
                'dangerous html tag',
                'potentially dangerous html tag',
                'dangerous tag detected',
                '<script>',
                '<iframe>',
                '<object>',
                '<embed>'
            ]
            if any(pattern in description for pattern in fp_patterns):
                # Aggressive filtering for known FP pattern
                enhanced_finding['filtered'] = True
                enhanced_finding['filter_reason'] = 'Known false positive pattern: Moodle legitimate HTML tags'
        
        # 2. Severity Prediction
        predicted_severity, severity_confidence, severity_dist = self.severity_predictor.predict(finding, context)
        ml_metadata['severity_prediction'] = {
            'predicted': predicted_severity,
            'confidence': severity_confidence,
            'distribution': severity_dist,
            'original': finding.get('severity', 'unknown')
        }
        
        # Update severity if ML prediction is more confident
        if severity_confidence > 0.7 and predicted_severity != finding.get('severity', '').lower():
            enhanced_finding['severity_adjusted'] = True
            enhanced_finding['original_severity'] = finding.get('severity')
            enhanced_finding['severity'] = predicted_severity.capitalize()
            enhanced_finding['severity_reason'] = f'ML prediction ({severity_confidence:.2%} confidence)'
        
        # Add ML metadata to finding
        enhanced_finding['ml_metadata'] = ml_metadata
        enhanced_finding['ml_processed'] = True
        enhanced_finding['ml_timestamp'] = datetime.utcnow().isoformat() + 'Z'
        
        return enhanced_finding
    
    def detect_anomaly(self, data: Dict[str, Any]) -> Tuple[bool, float, str]:
        """
        Detect anomalous behavior.
        
        Args:
            data: Request/response/finding data
            
        Returns:
            Tuple of (is_anomaly, score, reason)
        """
        if not self.enable_ml or not self.anomaly_detector:
            return False, 0.0, "ML disabled"
        
        return self.anomaly_detector.detect(data)
    
    def check_rate_limit(self, request_data: Dict[str, Any], ip: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Check rate limiting with ML-enhanced scoring.
        
        Args:
            request_data: Request information
            ip: Client IP address
            
        Returns:
            Tuple of (should_limit, reason, details)
        """
        if not self.enable_ml or not self.rate_limiter:
            return False, "ML disabled", {}
        
        return self.rate_limiter.check_rate_limit(request_data, ip)
    
    def filter_findings(self, findings: List[Dict[str, Any]], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Process and filter a list of findings.
        
        Args:
            findings: List of security findings
            context: Additional context
            
        Returns:
            Dictionary with filtered findings and statistics
        """
        if not self.enable_ml:
            return {
                'findings': findings,
                'filtered_count': 0,
                'severity_adjusted_count': 0,
                'ml_enabled': False
            }
        
        processed_findings = []
        filtered_count = 0
        severity_adjusted_count = 0
        
        # Debug: Track FP predictions
        fp_predictions = []
        pattern_filtered = 0
        
        # Debug: Sample first XSS finding to see description format
        xss_findings = [f for f in findings if f.get('category') == 'Cross-Site Scripting (XSS)']
        if xss_findings:
            sample = xss_findings[0]
            print(f"[Debug] Sample XSS finding:")
            print(f"  Category: {sample.get('category')}")
            print(f"  Description: {sample.get('description', 'N/A')[:100]}...")
        
        for finding in findings:
            enhanced = self.process_finding(finding, context)
            
            # Debug: Log FP prediction
            if enhanced.get('ml_metadata', {}).get('false_positive'):
                fp_info = enhanced['ml_metadata']['false_positive']
                fp_predictions.append({
                    'category': finding.get('category', 'unknown'),
                    'is_fp': fp_info['is_false_positive'],
                    'confidence': fp_info['confidence']
                })
            
            # Track statistics
            if enhanced.get('filtered'):
                filtered_count += 1
                if 'pattern' in enhanced.get('filter_reason', '').lower():
                    pattern_filtered += 1
            if enhanced.get('severity_adjusted'):
                severity_adjusted_count += 1
            
            # Include non-filtered findings OR low/info severity for informational purposes
            severity = finding.get('severity', '').lower()
            if not enhanced.get('filtered') or severity in ['low', 'info', 'informational']:
                # Mark low/info FPs as informational
                if enhanced.get('filtered') and severity in ['low', 'info', 'informational']:
                    enhanced['informational_only'] = True
                    enhanced['filtered'] = False  # Unmark as filtered so it shows
                processed_findings.append(enhanced)
        
        # Debug: Print FP prediction summary
        if fp_predictions:
            fp_count = sum(1 for p in fp_predictions if p['is_fp'])
            high_conf_fp = sum(1 for p in fp_predictions if p['is_fp'] and p['confidence'] > 0.7)
            print(f"[FP Reducer] ML Predictions: {fp_count}/{len(fp_predictions)} marked as FP")
            print(f"[FP Reducer] High confidence (>70%): {high_conf_fp} findings")
            if high_conf_fp == 0 and fp_count > 0:
                avg_conf = np.mean([p['confidence'] for p in fp_predictions if p['is_fp']])
                print(f"[FP Reducer] Average FP confidence: {avg_conf:.2%} (below 70% threshold)")
        
        print(f"[FP Reducer] Pattern-based filtering: {pattern_filtered} findings")
        print(f"[FP Reducer] Total filtered: {filtered_count} findings")
        
        return {
            'findings': processed_findings,
            'original_count': len(findings),
            'filtered_count': filtered_count,
            'severity_adjusted_count': severity_adjusted_count,
            'final_count': len(processed_findings),
            'ml_enabled': True,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
    
    def train_false_positive_reducer(self, training_data: List[Dict[str, Any]], labels: List[int]) -> Dict[str, Any]:
        """
        Train the false positive reduction model.
        
        Args:
            training_data: List of findings with context
            labels: List of labels (0 = TP, 1 = FP)
            
        Returns:
            Training results
        """
        if not self.enable_ml or not self.fp_reducer:
            return {'error': 'ML disabled'}
        
        return self.fp_reducer.train(training_data, labels)
    
    def train_anomaly_detector(self, training_data: List[Dict[str, Any]], contamination: float = 0.1) -> Dict[str, Any]:
        """
        Train the anomaly detection model.
        
        Args:
            training_data: List of normal behavior samples
            contamination: Expected anomaly proportion
            
        Returns:
            Training results
        """
        if not self.enable_ml or not self.anomaly_detector:
            return {'error': 'ML disabled'}
        
        return self.anomaly_detector.train(training_data, contamination)
    
    def train_severity_predictor(self, training_data: List[Dict[str, Any]], labels: List[str]) -> Dict[str, Any]:
        """
        Train the severity prediction model.
        
        Args:
            training_data: List of findings with context
            labels: List of actual severity labels
            
        Returns:
            Training results
        """
        if not self.enable_ml or not self.severity_predictor:
            return {'error': 'ML disabled'}
        
        return self.severity_predictor.train(training_data, labels)
    
    def train_rate_limiter(self, training_data: List[Dict[str, Any]], risk_scores: List[float]) -> Dict[str, Any]:
        """
        Train the rate limiter model.
        
        Args:
            training_data: List of request data with IP
            risk_scores: Actual risk scores (0-100)
            
        Returns:
            Training results
        """
        if not self.enable_ml or not self.rate_limiter:
            return {'error': 'ML disabled'}
        
        return self.rate_limiter.train(training_data, risk_scores)
    
    def provide_feedback(self, finding: Dict[str, Any], is_false_positive: bool, context: Optional[Dict[str, Any]] = None):
        """
        Provide user feedback for incremental learning.
        
        Args:
            finding: Security finding
            is_false_positive: User feedback
            context: Additional context
        """
        if not self.enable_ml or not self.fp_reducer:
            return
        
        self.fp_reducer.update_with_feedback(finding, is_false_positive, context)
    
    def get_ip_stats(self, ip: str) -> Dict[str, Any]:
        """
        Get rate limiting statistics for an IP.
        
        Args:
            ip: IP address
            
        Returns:
            IP statistics
        """
        if not self.enable_ml or not self.rate_limiter:
            return {'error': 'ML disabled'}
        
        return self.rate_limiter.get_ip_stats(ip)
    
    def whitelist_ip(self, ip: str):
        """Add IP to whitelist."""
        if self.enable_ml and self.rate_limiter:
            self.rate_limiter.add_to_whitelist(ip)
    
    def blacklist_ip(self, ip: str):
        """Add IP to blacklist."""
        if self.enable_ml and self.rate_limiter:
            self.rate_limiter.add_to_blacklist(ip)
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get status of all ML modules.
        
        Returns:
            Status dictionary
        """
        if not self.enable_ml:
            return {
                'ml_enabled': False,
                'message': 'ML features are disabled'
            }
        
        return {
            'ml_enabled': True,
            'modules': {
                'false_positive_reducer': self.fp_reducer.get_model_info(),
                'anomaly_detector': self.anomaly_detector.get_model_info(),
                'severity_predictor': self.severity_predictor.get_model_info(),
                'rate_limiter': self.rate_limiter.get_model_info()
            },
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
    
    def export_models_info(self) -> Dict[str, Any]:
        """
        Export detailed information about all models.
        
        Returns:
            Detailed model information
        """
        return {
            'ml_enabled': self.enable_ml,
            'models': {
                'false_positive_reducer': {
                    'trained': self.fp_reducer.is_trained if self.fp_reducer else False,
                    'info': self.fp_reducer.get_model_info() if self.fp_reducer else {}
                },
                'anomaly_detector': {
                    'trained': self.anomaly_detector.is_trained if self.anomaly_detector else False,
                    'info': self.anomaly_detector.get_model_info() if self.anomaly_detector else {}
                },
                'severity_predictor': {
                    'trained': self.severity_predictor.is_trained if self.severity_predictor else False,
                    'info': self.severity_predictor.get_model_info() if self.severity_predictor else {}
                },
                'rate_limiter': {
                    'trained': self.rate_limiter.is_trained if self.rate_limiter else False,
                    'info': self.rate_limiter.get_model_info() if self.rate_limiter else {}
                }
            },
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
