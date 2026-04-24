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
from .two_stage_pipeline import (
    create_strict_split,
    generate_fp_training_data,
    train_fp_reducer,
    evaluate_full_pipeline,
    cross_validate_two_stage_pipeline,
)

__all__ = [
    'FalsePositiveReducer',
    'AnomalyDetector',
    'SeverityPredictor',
    'MLRateLimiter',
    'create_strict_split',
    'generate_fp_training_data',
    'train_fp_reducer',
    'evaluate_full_pipeline',
    'cross_validate_two_stage_pipeline',
]
