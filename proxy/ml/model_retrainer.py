"""
ML Model Retrainer

Handles retraining of ML models with newly collected data.
Algorithm-specific retraining for each model.
"""

import json
import os
import sys
from typing import Dict, List, Any, Optional
from datetime import datetime
import threading

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.false_positive_reducer import FalsePositiveReducer
from ml.severity_predictor import SeverityPredictor
from ml.anomaly_detector import AnomalyDetector
from ml.rate_limiter import MLRateLimiter
from ml.training_data_aggregator import TrainingDataAggregator


class ModelRetrainer:
    """Handles retraining of ML models with new data."""
    
    def __init__(self):
        """Initialize Model Retrainer."""
        self.retrain_status = {
            'status': 'idle',  # idle, running, completed, failed
            'progress': 0,
            'current_model': '',
            'message': '',
            'start_time': None,
            'end_time': None,
            'models_results': {},
            'total_progress': {
                'completed': 0,
                'total': 4
            }
        }
        self.lock = threading.Lock()
        self.aggregator = TrainingDataAggregator()
    
    def start_retrain_async(self) -> Dict[str, Any]:
        """
        Start retraining process asynchronously.
        
        Returns:
            Status information
        """
        if self.retrain_status['status'] == 'running':
            return {
                'success': False,
                'message': 'Retraining already in progress',
                'status': self.retrain_status
            }
        
        # Start retraining in background thread
        thread = threading.Thread(target=self._retrain_worker, daemon=True)
        thread.start()
        
        return {
            'success': True,
            'message': 'Retraining started',
            'status': self.retrain_status
        }
    
    def _retrain_worker(self):
        """Worker thread for retraining."""
        with self.lock:
            self._update_status('running', 'Initializing data aggregation...', 0)
        
        try:
            # Step 1: Collect recent scan data
            print("\n" + "="*80)
            print("STEP 1: COLLECTING RECENT SCAN DATA")
            print("="*80)
            
            with self.lock:
                self._update_status('running', 'Collecting recent scan data...', 5)
            
            collection_result = self.aggregator.collect_recent_scans(limit=100)
            
            if not collection_result['success']:
                raise Exception(collection_result['message'])
            
            print(f"Collected data: {collection_result['datasets']}")
            print(f"Scans by type: {collection_result.get('scans_by_type', {})}")
            print(f"Findings by type: {collection_result.get('findings_by_type', {})}")
            
            # Save aggregated data
            self.aggregator.save_aggregated_data()
            
            with self.lock:
                self._update_status('running', 'Data collection complete', 15)
            
            # Get aggregated training data
            training_data = self.aggregator.get_aggregated_data()
            
            # Step 2: Retrain each model with algorithm-specific logic
            models_to_retrain = [
                ('false_positive_reducer', training_data['false_positive']),
                ('severity_predictor', training_data['severity']),
                ('anomaly_detector', training_data['anomaly']),
                ('rate_limiter', training_data['rate_limiter'])
            ]
            
            results = {}
            progress_increment = 80 / len(models_to_retrain)
            
            for model_name, model_data in models_to_retrain:
                # Check if we have enough data
                if model_name != 'rate_limiter' and len(model_data['data']) < 10:
                    print(f"\n[Retrainer] Insufficient data for {model_name}: {len(model_data['data'])} samples")
                    with self.lock:
                        results[model_name] = {
                            'success': False,
                            'message': f'Insufficient training data: {len(model_data["data"])} samples'
                        }
                        self.retrain_status['models_results'] = results
                    continue
                
                print(f"\n" + "="*80)
                print(f"RETRAINING: {model_name.upper()}")
                print("="*80)
                
                with self.lock:
                    current_model = model_name.replace('_', ' ').title()
                    self._update_status(
                        'running',
                        f'Retraining {current_model}...',
                        15 + (self.retrain_status['total_progress']['completed'] * progress_increment)
                    )
                    self.retrain_status['current_model'] = model_name
                
                try:
                    if model_name == 'false_positive_reducer':
                        result = self._retrain_fp_reducer(model_data)
                    elif model_name == 'severity_predictor':
                        result = self._retrain_severity_predictor(model_data)
                    elif model_name == 'anomaly_detector':
                        result = self._retrain_anomaly_detector(model_data)
                    elif model_name == 'rate_limiter':
                        result = self._retrain_rate_limiter(model_data)
                    else:
                        result = {'success': False, 'message': 'Unknown model'}
                    
                    results[model_name] = result
                    
                    with self.lock:
                        self.retrain_status['models_results'][model_name] = result
                        self.retrain_status['total_progress']['completed'] += 1
                
                except Exception as e:
                    error_msg = f'Error retraining {model_name}: {str(e)}'
                    print(f"[Retrainer] {error_msg}")
                    results[model_name] = {'success': False, 'message': error_msg}
                    
                    with self.lock:
                        self.retrain_status['models_results'][model_name] = {
                            'success': False,
                            'message': error_msg
                        }
                        self.retrain_status['total_progress']['completed'] += 1
            
            # Final status
            completed = self.retrain_status['total_progress']['completed']
            total = self.retrain_status['total_progress']['total']
            all_success = all(r.get('success', False) for r in results.values())
            
            with self.lock:
                if all_success:
                    self._update_status('completed', 'Retraining completed successfully!', 100)
                else:
                    self._update_status('completed', f'Retraining completed with some warnings ({completed}/{total})', 100)
            
            print("\n" + "="*80)
            print("RETRAINING COMPLETE")
            print("="*80)
            print(f"Results: {json.dumps(results, indent=2)}")
        
        except Exception as e:
            error_msg = f'Retraining failed: {str(e)}'
            print(f"[Retrainer] ERROR: {error_msg}")
            
            with self.lock:
                self._update_status('failed', error_msg, 0)
    
    def _retrain_fp_reducer(self, data: Dict[str, List]) -> Dict[str, Any]:
        """
        Retrain False Positive Reducer with Random Forest algorithm.
        
        Uses: sklearn.ensemble.RandomForestClassifier calibrated with CalibratedClassifierCV
        """
        print(f"[FP Reducer] Training with {len(data['data'])} samples")
        print(f"[FP Reducer] Data shape per sample: {len(data['data'][0]) if data['data'] else 0} features")
        
        try:
            fp_reducer = FalsePositiveReducer()
            
            if not data['data'] or len(data['data']) < 10:
                return {
                    'success': False,
                    'message': f'Insufficient training data: {len(data["data"])} samples (need >= 10)'
                }
            
            # Train model
            fp_reducer.train(data['data'], data['labels'])
            
            # Get model info
            model_info = fp_reducer.get_model_info()
            
            return {
                'success': True,
                'message': 'False Positive Reducer retrained successfully',
                'samples_used': len(data['data']),
                'model_info': model_info,
                'algorithm': 'Calibrated Random Forest Ensemble',
                'features': len(data['data'][0]) if data['data'] else 0
            }
        
        except Exception as e:
            return {
                'success': False,
                'message': f'FP Reducer retraining error: {str(e)}'
            }
    
    def _retrain_severity_predictor(self, data: Dict[str, List]) -> Dict[str, Any]:
        """
        Retrain Severity Predictor with Gradient Boosting algorithm.
        
        Uses: sklearn.ensemble.GradientBoostingClassifier
        """
        print(f"[Severity Predictor] Training with {len(data['data'])} samples")
        print(f"[Severity Predictor] Data shape per sample: {len(data['data'][0]) if data['data'] else 0} features")
        
        try:
            severity_predictor = SeverityPredictor()
            
            if not data['data'] or len(data['data']) < 10:
                return {
                    'success': False,
                    'message': f'Insufficient training data: {len(data["data"])} samples (need >= 10)'
                }
            
            # Train model
            severity_predictor.train(data['data'], data['labels'])
            
            # Get model info
            model_info = severity_predictor.get_model_info()
            
            return {
                'success': True,
                'message': 'Severity Predictor retrained successfully',
                'samples_used': len(data['data']),
                'model_info': model_info,
                'algorithm': 'Gradient Boosting Classifier',
                'features': len(data['data'][0]) if data['data'] else 0
            }
        
        except Exception as e:
            return {
                'success': False,
                'message': f'Severity Predictor retraining error: {str(e)}'
            }
    
    def _retrain_anomaly_detector(self, data: Dict[str, List]) -> Dict[str, Any]:
        """
        Retrain Anomaly Detector with Isolation Forest algorithm.
        
        Uses: sklearn.ensemble.IsolationForest
        """
        print(f"[Anomaly Detector] Training with {len(data['data'])} samples")
        print(f"[Anomaly Detector] Data shape per sample: {len(data['data'][0]) if data['data'] else 0} features")
        
        try:
            anomaly_detector = AnomalyDetector()
            
            if not data['data'] or len(data['data']) < 10:
                return {
                    'success': False,
                    'message': f'Insufficient training data: {len(data["data"])} samples (need >= 10)'
                }
            
            # Train model
            anomaly_detector.train(data['data'])
            
            # Get model info
            model_info = anomaly_detector.get_model_info()
            
            return {
                'success': True,
                'message': 'Anomaly Detector retrained successfully',
                'samples_used': len(data['data']),
                'model_info': model_info,
                'algorithm': 'Isolation Forest',
                'features': len(data['data'][0]) if data['data'] else 0
            }
        
        except Exception as e:
            return {
                'success': False,
                'message': f'Anomaly Detector retraining error: {str(e)}'
            }
    
    def _retrain_rate_limiter(self, data: Dict[str, List]) -> Dict[str, Any]:
        """
        Update Rate Limiter with new risk scoring data.
        
        Rate Limiter uses adaptive limiting based on CVSS scores.
        """
        print(f"[Rate Limiter] Updating with {len(data['data'])} samples")
        
        try:
            rate_limiter = MLRateLimiter()
            
            # Rate Limiter doesn't need traditional training
            # It updates its baseline statistics and limits based on new data
            if data['data']:
                # Update baseline stats if method available
                if hasattr(rate_limiter, 'update_with_findings'):
                    rate_limiter.update_with_findings(data['data'], data['labels'])
            
            # Get model info
            model_info = rate_limiter.get_model_info()
            
            return {
                'success': True,
                'message': 'Rate Limiter updated successfully',
                'samples_used': len(data['data']),
                'model_info': model_info,
                'algorithm': 'Adaptive Rate Limiting',
                'features': len(data['data'][0]) if data['data'] else 0
            }
        
        except Exception as e:
            return {
                'success': False,
                'message': f'Rate Limiter update error: {str(e)}'
            }
    
    def get_status(self) -> Dict[str, Any]:
        """Get current retraining status."""
        with self.lock:
            return dict(self.retrain_status)
    
    def _update_status(self, status: str, message: str, progress: int):
        """Update retraining status."""
        self.retrain_status['status'] = status
        self.retrain_status['message'] = message
        self.retrain_status['progress'] = progress
        if status == 'running' and not self.retrain_status['start_time']:
            self.retrain_status['start_time'] = datetime.utcnow().isoformat() + 'Z'
        if status == 'completed' or status == 'failed':
            self.retrain_status['end_time'] = datetime.utcnow().isoformat() + 'Z'
        
        print(f"[Status] {status.upper()}: {message} ({progress}%)")
