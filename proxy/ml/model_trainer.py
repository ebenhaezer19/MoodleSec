"""
Model Trainer

Trains all ML models using generated or collected training data.
"""

import json
import os
import sys
from typing import Dict, List, Any, Optional
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.ml_manager import MLManager
from ml.training_data_generator import TrainingDataGenerator


class ModelTrainer:
    """Train all ML models with training data."""
    
    def __init__(self, data_dir: str = "ml/data"):
        """
        Initialize Model Trainer.
        
        Args:
            data_dir: Directory containing training data
        """
        self.data_dir = data_dir
        self.ml_manager = MLManager(enable_ml=True)
        self.training_results = {}
    
    def train_all_models(self, use_existing_data: bool = True) -> Dict[str, Any]:
        """
        Train all ML models.
        
        Args:
            use_existing_data: Use existing JSON data if available
            
        Returns:
            Training results for all models
        """
        print("="*80)
        print("ML MODEL TRAINING")
        print("="*80)
        print(f"Timestamp: {datetime.utcnow().isoformat()}Z\n")
        
        # Load or generate training data
        if use_existing_data and os.path.exists(self.data_dir):
            print("[Trainer] Loading existing training data...")
            datasets = self._load_training_data()
        else:
            print("[Trainer] Generating new training data...")
            generator = TrainingDataGenerator()
            datasets = generator.export_training_data(self.data_dir)
        
        # Train each model
        results = {}
        
        # 1. Train False Positive Reducer
        print("\n" + "="*80)
        print("TRAINING: FALSE POSITIVE REDUCER")
        print("="*80)
        results['false_positive_reducer'] = self._train_fp_reducer(datasets['false_positive'])
        
        # 2. Train Anomaly Detector
        print("\n" + "="*80)
        print("TRAINING: ANOMALY DETECTOR")
        print("="*80)
        results['anomaly_detector'] = self._train_anomaly_detector(datasets['anomaly'])
        
        # 3. Train Severity Predictor
        print("\n" + "="*80)
        print("TRAINING: SEVERITY PREDICTOR")
        print("="*80)
        results['severity_predictor'] = self._train_severity_predictor(datasets['severity'])
        
        # 4. Train Rate Limiter
        print("\n" + "="*80)
        print("TRAINING: RATE LIMITER")
        print("="*80)
        results['rate_limiter'] = self._train_rate_limiter(datasets['rate_limiter'])
        
        self.training_results = results
        
        # Save training report
        self._save_training_report(results)
        
        return results
    
    def _train_fp_reducer(self, dataset: Dict) -> Dict[str, Any]:
        """Train False Positive Reducer."""
        training_data = dataset['data']
        labels = dataset['labels']
        
        print(f"[FP Reducer] Training with {len(training_data)} samples...")
        print(f"[FP Reducer] True Positives: {labels.count(0)}")
        print(f"[FP Reducer] False Positives: {labels.count(1)}")
        
        result = self.ml_manager.train_false_positive_reducer(training_data, labels)
        
        if result.get('success'):
            print(f"✅ Training successful!")
            print(f"   Train Accuracy: {result['train_accuracy']:.2%}")
            print(f"   Test Accuracy: {result['test_accuracy']:.2%}")
            print(f"\n   Top Features:")
            for feature, importance in sorted(
                result['feature_importance'].items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:5]:
                print(f"     {feature}: {importance:.4f}")
        else:
            print(f"❌ Training failed: {result.get('error')}")
        
        return result
    
    def _train_anomaly_detector(self, dataset: Dict) -> Dict[str, Any]:
        """Train Anomaly Detector."""
        training_data = dataset['data']
        
        print(f"[Anomaly Detector] Training with {len(training_data)} normal samples...")
        
        result = self.ml_manager.train_anomaly_detector(training_data, contamination=0.1)
        
        if result.get('success'):
            print(f"✅ Training successful!")
            print(f"   Normal Samples: {result['normal_samples']}")
            print(f"   Anomalies Detected: {result['anomalies_detected']}")
            print(f"   Contamination: {result['contamination']:.1%}")
            print(f"\n   Baseline Stats:")
            baseline = result.get('baseline_stats', {})
            print(f"     Avg Response Time: {baseline.get('avg_response_time', 0):.0f}ms")
            print(f"     Common Status Codes: {baseline.get('common_status_codes', [])}")
        else:
            print(f"❌ Training failed: {result.get('error')}")
        
        return result
    
    def _train_severity_predictor(self, dataset: Dict) -> Dict[str, Any]:
        """Train Severity Predictor."""
        training_data = dataset['data']
        labels = dataset['labels']
        
        print(f"[Severity Predictor] Training with {len(training_data)} samples...")
        
        # Count severity distribution
        from collections import Counter
        severity_dist = Counter(labels)
        print(f"[Severity Predictor] Distribution:")
        for severity, count in severity_dist.most_common():
            print(f"   {severity.capitalize()}: {count}")
        
        result = self.ml_manager.train_severity_predictor(training_data, labels)
        
        if result.get('success'):
            print(f"✅ Training successful!")
            print(f"   Train Accuracy: {result['train_accuracy']:.2%}")
            print(f"   Test Accuracy: {result['test_accuracy']:.2%}")
            print(f"\n   Top Features:")
            for feature, importance in sorted(
                result['feature_importance'].items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:5]:
                print(f"     {feature}: {importance:.4f}")
        else:
            print(f"❌ Training failed: {result.get('error')}")
        
        return result
    
    def _train_rate_limiter(self, dataset: Dict) -> Dict[str, Any]:
        """Train Rate Limiter."""
        training_data = dataset['data']
        risk_scores = dataset['labels']
        
        print(f"[Rate Limiter] Training with {len(training_data)} samples...")
        print(f"[Rate Limiter] Risk Score Range: {min(risk_scores):.1f} - {max(risk_scores):.1f}")
        
        result = self.ml_manager.train_rate_limiter(training_data, risk_scores)
        
        if result.get('success'):
            print(f"✅ Training successful!")
            print(f"   R² Score: {result['r2_score']:.4f}")
            print(f"   Mean Absolute Error: {result['mean_absolute_error']:.2f}")
            print(f"\n   Top Features:")
            for feature, importance in sorted(
                result['feature_importance'].items(), 
                key=lambda x: x[1], 
                reverse=True
            )[:5]:
                print(f"     {feature}: {importance:.4f}")
        else:
            print(f"❌ Training failed: {result.get('error')}")
        
        return result
    
    def _load_training_data(self) -> Dict[str, Dict]:
        """Load training data from JSON files."""
        datasets = {}
        
        for name in ['false_positive', 'severity', 'anomaly', 'rate_limiter']:
            filepath = os.path.join(self.data_dir, f"{name}_training.json")
            if os.path.exists(filepath):
                with open(filepath, 'r') as f:
                    datasets[name] = json.load(f)
                print(f"[Trainer] Loaded {name} data: {len(datasets[name]['data'])} samples")
            else:
                print(f"[Trainer] Warning: {filepath} not found")
        
        return datasets
    
    def _save_training_report(self, results: Dict[str, Any]):
        """Save training report to file."""
        report_path = os.path.join(self.data_dir, 'training_report.json')
        
        report = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'results': results,
            'summary': {
                'models_trained': len([r for r in results.values() if r.get('success')]),
                'total_models': len(results),
                'status': 'success' if all(r.get('success') for r in results.values()) else 'partial'
            }
        }
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[Trainer] Training report saved to {report_path}")
    
    def validate_models(self) -> Dict[str, Any]:
        """Validate trained models with test data."""
        print("\n" + "="*80)
        print("MODEL VALIDATION")
        print("="*80)
        
        validation_results = {}
        
        # Test False Positive Reducer
        print("\n[Validation] Testing False Positive Reducer...")
        test_finding = {
            'severity': 'Info',
            'category': 'Security Misconfiguration',
            'description': 'Missing X-Frame-Options header',
            'evidence': 'Header not found',
            'cvss_score': 0.0,
            'risk_score': 0.0,
            'url': 'http://localhost:8998/index.php'
        }
        is_fp, confidence = self.ml_manager.fp_reducer.predict(test_finding)
        validation_results['fp_reducer'] = {
            'is_false_positive': is_fp,
            'confidence': confidence,
            'expected': True
        }
        print(f"   Result: {'FP' if is_fp else 'TP'} (confidence: {confidence:.2%})")
        print(f"   Expected: FP - {'✅ PASS' if is_fp else '❌ FAIL'}")
        
        # Test Severity Predictor
        print("\n[Validation] Testing Severity Predictor...")
        test_finding = {
            'severity': 'Medium',
            'category': 'SQL Injection',
            'description': 'SQL injection vulnerability',
            'evidence': 'Parameter vulnerable',
            'cvss_score': 9.0,
            'risk_score': 8.5,
            'url': 'http://localhost:8998/user/profile.php'
        }
        severity, confidence, _ = self.ml_manager.severity_predictor.predict(test_finding)
        validation_results['severity_predictor'] = {
            'predicted': severity,
            'confidence': confidence,
            'expected': 'critical'
        }
        print(f"   Result: {severity.capitalize()} (confidence: {confidence:.2%})")
        print(f"   Expected: Critical - {'✅ PASS' if severity in ['critical', 'high'] else '❌ FAIL'}")
        
        # Test Anomaly Detector
        print("\n[Validation] Testing Anomaly Detector...")
        suspicious_data = {
            'request': {
                'url': 'http://localhost:8998/admin/../../etc/passwd',
                'method': 'GET',
                'headers': {},
                'body': ''
            },
            'response': {
                'status_code': 500,
                'size': 100,
                'time': 5000,
                'headers': {}
            },
            'request_count_last_minute': 150,
            'unique_ips_last_minute': 1,
            'error_rate_last_minute': 0.8
        }
        is_anomaly, score, reason = self.ml_manager.detect_anomaly(suspicious_data)
        validation_results['anomaly_detector'] = {
            'is_anomaly': is_anomaly,
            'score': score,
            'reason': reason,
            'expected': True
        }
        print(f"   Result: {'Anomaly' if is_anomaly else 'Normal'} (score: {score:.2f})")
        print(f"   Expected: Anomaly - {'✅ PASS' if is_anomaly else '❌ FAIL'}")
        
        return validation_results
    
    def print_summary(self):
        """Print training summary."""
        print("\n" + "="*80)
        print("TRAINING SUMMARY")
        print("="*80)
        
        if not self.training_results:
            print("No training results available.")
            return
        
        for model_name, result in self.training_results.items():
            status = "✅ SUCCESS" if result.get('success') else "❌ FAILED"
            print(f"\n{model_name.upper().replace('_', ' ')}:")
            print(f"  Status: {status}")
            
            if result.get('success'):
                if 'train_accuracy' in result:
                    print(f"  Train Accuracy: {result['train_accuracy']:.2%}")
                    print(f"  Test Accuracy: {result['test_accuracy']:.2%}")
                elif 'r2_score' in result:
                    print(f"  R² Score: {result['r2_score']:.4f}")
                    print(f"  MAE: {result['mean_absolute_error']:.2f}")
                elif 'normal_samples' in result:
                    print(f"  Normal Samples: {result['normal_samples']}")
                    print(f"  Anomalies: {result['anomalies_detected']}")
        
        # Overall status
        total = len(self.training_results)
        successful = sum(1 for r in self.training_results.values() if r.get('success'))
        
        print(f"\n{'='*80}")
        print(f"OVERALL: {successful}/{total} models trained successfully")
        
        if successful == total:
            print("🎉 All models trained successfully!")
        else:
            print("⚠️  Some models failed to train. Check errors above.")


def main():
    """Main training pipeline."""
    trainer = ModelTrainer()
    
    # Train all models
    results = trainer.train_all_models(use_existing_data=False)
    
    # Validate models
    validation = trainer.validate_models()
    
    # Print summary
    trainer.print_summary()
    
    print("\n" + "="*80)
    print("✅ Training pipeline complete!")
    print("📁 Models saved to: ml/models/")
    print("📊 Training data: ml/data/")
    print("📝 Report: ml/data/training_report.json")
    print("="*80)


if __name__ == "__main__":
    main()
