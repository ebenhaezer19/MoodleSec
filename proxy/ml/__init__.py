"""
ML-Enhanced Detection Module

Provides machine learning capabilities for:
- False positive reduction
- Anomaly detection
- Severity prediction
- Intelligent rate limiting
"""

from .false_positive_reducer import FalsePositiveReducer
from .anomaly_detector import AnomalyDetector
from .severity_predictor import SeverityPredictor
from .rate_limiter import MLRateLimiter

__all__ = [
    'FalsePositiveReducer',
    'AnomalyDetector',
    'SeverityPredictor',
    'MLRateLimiter'
]
