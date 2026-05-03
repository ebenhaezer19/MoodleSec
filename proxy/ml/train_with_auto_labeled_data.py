"""
Train Models with Auto-Labeled Data

Loads auto-labeled training data and trains/tests ML models.
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Tuple
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.ml_manager import MLManager
from ml.severity_predictor import SeverityPredictor
from ml.rate_limiter import MLRateLimiter
from ml.anomaly_false_positive_reducer import FalsePositiveReducer
from ml.anomaly_detector import AnomalyDetector


class AutoLabeledTrainer:
    """Train models using auto-labeled data from scanner results."""
    
    def __init__(self):
        """Initialize trainer with ML manager."""
        self.ml_manager = MLManager(enable_ml=True)
        self.training_data = []
        self.results = {}
    
    def load_auto_labeled_data(self, json_path: str) -> Dict[str, Any]:
        """
        Load auto-labeled data from JSON file.
        
        Args:
            json_path: Path to auto-labeled JSON file
            
        Returns:
            Loaded data
        """
        print(f"[AutoLabeledTrainer] Loading data from: {json_path}")
        
        if not os.path.exists(json_path):
            print(f"❌ File not found: {json_path}")
            return None
        
        with open(json_path, 'r') as f:
            data = json.load(f)
        
        print(f"✅ Loaded {len(data)} records from auto-labeled data")
        
        # Show stats
        labels = [record.get('label', -1) for record in data]
        confidences = [record.get('confidence', 0) for record in data]
        
        print(f"\n   TP (label=0): {labels.count(0)}")
        print(f"   FP (label=1): {labels.count(1)}")
        print(f"   Average confidence: {sum(confidences)/len(confidences):.2%}")
        
        return data
    
    def prepare_training_data(self, data: List[Dict]) -> Dict[str, Any]:
        """
        Prepare auto-labeled data for model training.
        
        Args:
            data: Auto-labeled records
            
        Returns:
            Organized training data by model type
        """
        print("\n[AutoLabeledTrainer] Preparing training data...")
        
        # Separate by category for appropriate models
        severity_data = []
        rate_limit_data = []
        fp_data = []
        
        for record in data:
            # Prepare for False Positive Reducer (label: 0=TP, 1=FP)
            fp_finding = {
                'finding': {
                    'severity': record.get('severity', 'medium').lower(),
                    'category': record.get('category', 'Unknown'),
                    'description': record.get('description', ''),
                    'evidence': record.get('evidence', ''),
                    'cvss_score': float(record.get('cvss_score', 0)),
                    'risk_score': float(record.get('cvss_score', 0)),
                    'url': record.get('url', 'unknown')
                },
                'context': {
                    'environment': 'production',
                    'public_facing': True,
                    'requires_auth': False,
                    'data_sensitivity': 'high',
                    'exploitability': 'medium',
                    'impact_scope': 'application'
                }
            }
            fp_label = 'FP' if record.get('label') == 1 else 'TP'
            fp_data.append({
                'data': fp_finding,
                'label': fp_label,
                'confidence': record.get('confidence', 0.5)
            })
            
            # Prepare for Severity Predictor (predict severity level)
            severity_finding = {
                'finding': {
                    'severity': record.get('severity', 'medium').lower(),
                    'category': record.get('category', 'Unknown'),
                    'description': record.get('description', ''),
                    'evidence': record.get('evidence', ''),
                    'cvss_score': float(record.get('cvss_score', 0)),
                    'risk_score': float(record.get('cvss_score', 0)),
                    'url': record.get('url', 'unknown')
                },
                'context': {
                    'environment': 'production',
                    'public_facing': True,
                    'requires_auth': False,
                    'data_sensitivity': 'high',
                    'exploitability': 'medium',
                    'impact_scope': 'application'
                }
            }
            # Map severity string to standard level
            severity_str = record.get('severity', 'medium').lower()
            if 'critical' in severity_str or 'crit' in severity_str:
                severity_label = 'critical'
            elif 'high' in severity_str:
                severity_label = 'high'
            elif 'medium' in severity_str or 'med' in severity_str:
                severity_label = 'medium'
            elif 'low' in severity_str:
                severity_label = 'low'
            else:
                severity_label = 'info'
            
            severity_data.append({
                'data': severity_finding,
                'label': severity_label
            })
            
            # Prepare for Rate Limiter (predict risk score 0-100)
            rate_limiter_data = {
                'request': {
                    'url': record.get('url', 'unknown'),
                    'method': 'GET',
                    'body': '',
                    'headers': {}
                },
                'ip': '127.0.0.1'
            }
            # Convert severity to risk score
            cvss = float(record.get('cvss_score', 0))
            risk_score = min(cvss * 10, 100)  # Scale CVSS to 0-100
            
            rate_limit_data.append({
                'data': rate_limiter_data,
                'risk': risk_score
            })
        
        print(f"   FP Reducer data: {len(fp_data)} samples")
        print(f"   Severity Predictor data: {len(severity_data)} samples")
        print(f"   Rate Limiter data: {len(rate_limit_data)} samples")
        
        return {
            'false_positive': fp_data,
            'severity': severity_data,
            'rate_limiter': rate_limit_data
        }
    
    def train_all_models(self, data_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Train all ML models with prepared data.
        
        Args:
            data_dict: Prepared training data
            
        Returns:
            Training results
        """
        print("\n" + "="*80)
        print("TRAINING MODELS WITH AUTO-LABELED DATA")
        print("="*80 + "\n")
        
        results = {}
        
        # 1. Train False Positive Reducer
        print("\n" + "-"*80)
        print("1. FALSE POSITIVE REDUCER")
        print("-"*80)
        fp_results = self._train_fp_reducer(data_dict['false_positive'])
        results['false_positive_reducer'] = fp_results
        
        # 2. Train Severity Predictor
        print("\n" + "-"*80)
        print("2. SEVERITY PREDICTOR")
        print("-"*80)
        severity_results = self._train_severity_predictor(data_dict['severity'])
        results['severity_predictor'] = severity_results
        
        # 3. Train Rate Limiter
        print("\n" + "-"*80)
        print("3. RATE LIMITER")
        print("-"*80)
        rate_limiter_results = self._train_rate_limiter(data_dict['rate_limiter'])
        results['rate_limiter'] = rate_limiter_results
        
        return results
    
    def _train_fp_reducer(self, data: List[Dict]) -> Dict[str, Any]:
        """Train False Positive Reducer."""
        print(f"Training with {len(data)} samples...")
        
        training_data = [d['data'] for d in data]
        labels = [d['label'] for d in data]
        
        tp_count = labels.count('TP')
        fp_count = labels.count('FP')
        
        print(f"  True Positives: {tp_count}")
        print(f"  False Positives: {fp_count}")
        
        # Train model
        result = self.ml_manager.fp_reducer.train(training_data, labels)
        
        if result.get('success'):
            print(f"✅ Training successful!")
            print(f"   Test Accuracy: {result.get('test_accuracy', 0):.1%}")
            print(f"   Training Time: {result.get('training_time', 0):.2f}s")
            print(f"   GPU Used: {result.get('gpu_used', 'N/A')}")
        else:
            print(f"❌ Training failed: {result.get('error', 'Unknown error')}")
        
        return result
    
    def _train_severity_predictor(self, data: List[Dict]) -> Dict[str, Any]:
        """Train Severity Predictor."""
        print(f"Training with {len(data)} samples...")
        
        training_data = [d['data'] for d in data]
        labels = [d['label'] for d in data]
        
        # Count by severity
        severity_counts = {}
        for label in labels:
            severity_counts[label] = severity_counts.get(label, 0) + 1
        
        for severity, count in sorted(severity_counts.items()):
            print(f"  {severity.capitalize()}: {count}")
        
        # Ensure all severity levels are represented (add dummy samples if needed)
        required_levels = ['info', 'low', 'medium', 'high', 'critical']
        for level in required_levels:
            if level not in labels:
                print(f"  Adding dummy sample for missing level: {level}")
                dummy_data = {
                    'finding': {
                        'severity': level,
                        'category': 'Unknown',
                        'description': f'Dummy sample for {level}',
                        'evidence': 'N/A',
                        'cvss_score': 0,
                        'risk_score': 0,
                        'url': 'http://localhost/'
                    },
                    'context': {
                        'environment': 'production',
                        'public_facing': True,
                        'requires_auth': False,
                        'data_sensitivity': 'high',
                        'exploitability': 'medium',
                        'impact_scope': 'application'
                    }
                }
                training_data.append(dummy_data)
                labels.append(level)
        
        # Train model
        result = self.ml_manager.severity_predictor.train(training_data, labels)
        
        if result.get('success'):
            print(f"✅ Training successful!")
            print(f"   Train Accuracy: {result.get('train_accuracy', 0):.1%}")
            print(f"   Val Accuracy: {result.get('val_accuracy', 0):.1%}")
            print(f"   Test Accuracy: {result.get('test_accuracy', 0):.1%}")
            print(f"   Test F1: {result.get('test_f1', 0):.3f}")
            print(f"   Best Iteration: {result.get('best_iteration', 'N/A')}")
            print(f"   GPU Used: {result.get('gpu_used', 'N/A')}")
            
            # Feature importance
            if result.get('feature_importance'):
                print(f"\n   Top Features:")
                features = result['feature_importance']
                # Sort by value
                sorted_features = sorted(features.items(), key=lambda x: x[1], reverse=True)[:5]
                for name, importance in sorted_features:
                    print(f"     {name}: {importance:.2%}")
        else:
            print(f"❌ Training failed: {result.get('error', 'Unknown error')}")
        
        return result
    
    def _train_rate_limiter(self, data: List[Dict]) -> Dict[str, Any]:
        """Train Rate Limiter."""
        print(f"Training with {len(data)} samples...")
        
        training_data = [d['data'] for d in data]
        risk_scores = [d['risk'] for d in data]
        
        avg_risk = sum(risk_scores) / len(risk_scores) if risk_scores else 0
        print(f"  Average Risk Score: {avg_risk:.1f}/100")
        print(f"  Risk Range: {min(risk_scores):.1f} - {max(risk_scores):.1f}")
        
        # Train model
        result = self.ml_manager.rate_limiter.train(training_data, risk_scores)
        
        if result.get('success'):
            print(f"✅ Training successful!")
            print(f"   Train R²: {result.get('train_r2', 0):.4f}")
            print(f"   Val R²: {result.get('val_r2', 0):.4f}")
            print(f"   Test R²: {result.get('test_r2', 0):.4f}")
            print(f"   Test MAE: {result.get('test_mae', 0):.2f}")
            print(f"   Best Iteration: {result.get('best_iteration', 'N/A')}")
            print(f"   GPU Used: {result.get('gpu_used', 'N/A')}")
            
            # Feature importance
            if result.get('feature_importance'):
                print(f"\n   Top Features:")
                features = result['feature_importance']
                sorted_features = sorted(features.items(), key=lambda x: x[1], reverse=True)[:5]
                for name, importance in sorted_features:
                    print(f"     {name}: {importance:.2%}")
        else:
            print(f"❌ Training failed: {result.get('error', 'Unknown error')}")
        
        return result
    
    def test_models(self) -> Dict[str, Any]:
        """Test trained models with sample data."""
        print("\n" + "="*80)
        print("TESTING TRAINED MODELS")
        print("="*80 + "\n")
        
        test_results = {}
        
        # Test 1: False Positive Reducer
        print("\n" + "-"*80)
        print("1. FALSE POSITIVE REDUCER TEST")
        print("-"*80)
        
        test_cases = [
            {
                'name': 'SQL Injection (Real)',
                'finding': {
                    'severity': 'critical',
                    'category': 'SQL Injection',
                    'description': 'SQL injection in login form',
                    'evidence': "Union-based SQL injection detected",
                    'cvss_score': 9.8,
                    'risk_score': 9.5,
                    'url': 'http://localhost/login.php'
                },
                'expected': 'TP'
            },
            {
                'name': 'HSTS Missing (Often FP)',
                'finding': {
                    'severity': 'info',
                    'category': 'Security Misconfiguration',
                    'description': 'HSTS header not set',
                    'evidence': 'Missing Strict-Transport-Security header',
                    'cvss_score': 0.0,
                    'risk_score': 0.0,
                    'url': 'http://localhost/index.php'
                },
                'expected': 'FP'
            },
            {
                'name': 'XSS (Real)',
                'finding': {
                    'severity': 'high',
                    'category': 'XSS',
                    'description': 'Stored XSS in comments',
                    'evidence': 'User input reflected without encoding',
                    'cvss_score': 7.5,
                    'risk_score': 7.0,
                    'url': 'http://localhost/comments.php'
                },
                'expected': 'TP'
            }
        ]
        
        fp_test_results = []
        for test_case in test_cases:
            is_fp, confidence = self.ml_manager.fp_reducer.predict(test_case['finding'])
            predicted = 'FP' if is_fp else 'TP'
            passed = predicted == test_case['expected']
            
            print(f"\n   {test_case['name']}")
            print(f"   Expected: {test_case['expected']}, Got: {predicted} (confidence: {confidence:.1%})")
            print(f"   {'✅ PASS' if passed else '❌ FAIL'}")
            
            fp_test_results.append({
                'test': test_case['name'],
                'expected': test_case['expected'],
                'predicted': predicted,
                'confidence': confidence,
                'passed': passed
            })
        
        test_results['false_positive'] = {
            'results': fp_test_results,
            'passed': sum(1 for r in fp_test_results if r['passed']),
            'total': len(fp_test_results)
        }
        
        # Test 2: Severity Predictor
        print("\n" + "-"*80)
        print("2. SEVERITY PREDICTOR TEST")
        print("-"*80)
        
        severity_test_cases = [
            {
                'name': 'Critical RCE',
                'finding': {
                    'severity': 'critical',
                    'category': 'Remote Code Execution',
                    'description': 'RCE vulnerability',
                    'evidence': 'Code execution possible',
                    'cvss_score': 10.0,
                    'risk_score': 9.5,
                    'url': 'http://localhost/admin/exec.php'
                },
                'expected': 'critical'
            },
            {
                'name': 'High Auth Bypass',
                'finding': {
                    'severity': 'high',
                    'category': 'Authentication Bypass',
                    'description': 'Authentication bypass',
                    'evidence': 'Can access without login',
                    'cvss_score': 8.5,
                    'risk_score': 8.0,
                    'url': 'http://localhost/admin/dashboard.php'
                },
                'expected': 'high'
            },
            {
                'name': 'Medium XSS',
                'finding': {
                    'severity': 'medium',
                    'category': 'Cross-site Scripting',
                    'description': 'Reflected XSS',
                    'evidence': 'Script tag not filtered',
                    'cvss_score': 5.3,
                    'risk_score': 4.5,
                    'url': 'http://localhost/search.php'
                },
                'expected': 'medium'
            }
        ]
        
        severity_test_results = []
        for test_case in severity_test_cases:
            predicted_severity, confidence, _ = self.ml_manager.severity_predictor.predict(test_case['finding'])
            passed = predicted_severity == test_case['expected']
            
            print(f"\n   {test_case['name']}")
            print(f"   Expected: {test_case['expected']}, Got: {predicted_severity} (confidence: {confidence:.1%})")
            print(f"   {'✅ PASS' if passed else '⚠️  DIFFERENT'}")
            
            severity_test_results.append({
                'test': test_case['name'],
                'expected': test_case['expected'],
                'predicted': predicted_severity,
                'confidence': confidence,
                'passed': passed
            })
        
        test_results['severity'] = {
            'results': severity_test_results,
            'passed': sum(1 for r in severity_test_results if r['passed']),
            'total': len(severity_test_results)
        }
        
        # Test 3: Rate Limiter
        print("\n" + "-"*80)
        print("3. RATE LIMITER TEST")
        print("-"*80)
        
        rate_limit_test_cases = [
            {
                'name': 'SQL Injection Attack',
                'request': {
                    'url': 'http://localhost/user.php?id=1 OR 1=1',
                    'method': 'GET',
                    'body': '',
                    'headers': {}
                },
                'expected_range': (70, 100)
            },
            {
                'name': 'Normal Request',
                'request': {
                    'url': 'http://localhost/index.php',
                    'method': 'GET',
                    'body': '',
                    'headers': {}
                },
                'expected_range': (10, 40)
            }
        ]
        
        rate_limit_test_results = []
        for test_case in rate_limit_test_cases:
            risk_score = self.ml_manager.rate_limiter._calculate_risk_score(
                test_case['request'], 
                '127.0.0.1'
            )
            passed = test_case['expected_range'][0] <= risk_score <= test_case['expected_range'][1]
            
            print(f"\n   {test_case['name']}")
            print(f"   Risk Score: {risk_score:.1f}/100")
            print(f"   Expected Range: {test_case['expected_range'][0]}-{test_case['expected_range'][1]}")
            print(f"   {'✅ PASS' if passed else '⚠️  OUT OF RANGE'}")
            
            rate_limit_test_results.append({
                'test': test_case['name'],
                'risk_score': risk_score,
                'expected_range': test_case['expected_range'],
                'passed': passed
            })
        
        test_results['rate_limiter'] = {
            'results': rate_limit_test_results,
            'passed': sum(1 for r in rate_limit_test_results if r['passed']),
            'total': len(rate_limit_test_results)
        }
        
        return test_results
    
    def save_results(self, training_results: Dict, test_results: Dict, output_file: str = "auto_labeled_training_results.json"):
        """Save training and test results to file."""
        combined_results = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'training': training_results,
            'testing': test_results,
            'summary': {
                'total_tests': sum(r.get('total', 0) for r in test_results.values()),
                'tests_passed': sum(r.get('passed', 0) for r in test_results.values()),
                'models_trained': len([r for r in training_results.values() if r.get('success')]),
                'status': 'SUCCESS' if all(r.get('success') for r in training_results.values()) else 'PARTIAL'
            }
        }
        
        output_path = os.path.join('ml', 'training_data', output_file)
        with open(output_path, 'w') as f:
            json.dump(combined_results, f, indent=2)
        
        print(f"\n✅ Results saved to: {output_path}")
        return combined_results


def main():
    """Main execution function."""
    print("\n" + "="*80)
    print("AUTO-LABELED DATA TRAINING & TESTING")
    print("="*80)
    
    # Find latest auto-labeled data file
    training_data_dir = 'ml/training_data'
    auto_labeled_files = sorted([
        f for f in os.listdir(training_data_dir) 
        if f.startswith('auto_labeled_') and f.endswith('.json')
    ])
    
    if not auto_labeled_files:
        print("❌ No auto-labeled data files found!")
        return
    
    latest_file = auto_labeled_files[-1]
    data_path = os.path.join(training_data_dir, latest_file)
    
    print(f"\nUsing latest auto-labeled data: {latest_file}\n")
    
    # Initialize trainer
    trainer = AutoLabeledTrainer()
    
    # Load data
    auto_labeled_data = trainer.load_auto_labeled_data(data_path)
    if not auto_labeled_data:
        return
    
    # Prepare data
    prepared_data = trainer.prepare_training_data(auto_labeled_data)
    
    # Train models
    training_results = trainer.train_all_models(prepared_data)
    
    # Test models
    test_results = trainer.test_models()
    
    # Save results
    trainer.save_results(training_results, test_results)
    
    # Print final summary
    print("\n" + "="*80)
    print("TRAINING & TESTING SUMMARY")
    print("="*80)
    
    total_tests = sum(r.get('total', 0) for r in test_results.values())
    tests_passed = sum(r.get('passed', 0) for r in test_results.values())
    
    print(f"\nTests Passed: {tests_passed}/{total_tests}")
    for model, results in test_results.items():
        print(f"  {model}: {results['passed']}/{results['total']} ✅")
    
    models_trained = len([r for r in training_results.values() if r.get('success')])
    print(f"\nModels Trained: {models_trained}/3 ✅")
    print("\n✅ All done!")


if __name__ == '__main__':
    main()
