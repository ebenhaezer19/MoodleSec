"""
False Positive Reduction using Random Forest

Reduces false positives by learning from historical scan data
and user feedback to classify findings as true/false positives.
"""

import numpy as np
import pickle
import os
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import hashlib


class FalsePositiveReducer:
    """
    Reduces false positives using Random Forest classifier.
    
    Features used:
    - Finding severity (encoded)
    - Finding category (encoded)
    - Evidence length
    - URL pattern features
    - Historical occurrence count
    - Response status code
    - Response time
    """
    
    def __init__(self, model_path: str = "ml/models/fp_reducer.pkl"):
        """
        Initialize False Positive Reducer.
        
        Args:
            model_path: Path to save/load the trained model
        """
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # Feature encodings
        self.severity_encoding = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1
        }
        
        self.category_encoding = {
            'SQL Injection': 10,
            'XSS': 9,
            'CSRF': 8,
            'Authentication': 7,
            'Authorization': 6,
            'Session Management': 5,
            'API Security': 4,
            'Input Validation': 3,
            'Security Misconfiguration': 2,
            'Information Disclosure': 1
        }
        
        # Load existing model if available
        self._load_model()
    
    def extract_features(self, finding: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> np.ndarray:
        """
        Extract features from a finding for classification.
        
        Args:
            finding: Security finding dictionary
            context: Additional context (response time, status code, etc.)
            
        Returns:
            Feature vector as numpy array
        """
        features = []
        
        # Feature 1: Severity (encoded)
        severity = finding.get('severity', 'info').lower()
        features.append(self.severity_encoding.get(severity, 1))
        
        # Feature 2: Category (encoded)
        category = finding.get('category', 'Unknown')
        features.append(self.category_encoding.get(category, 0))
        
        # Feature 3: Evidence length
        evidence = finding.get('evidence', '')
        features.append(len(str(evidence)))
        
        # Feature 4: Description length
        description = finding.get('description', '')
        features.append(len(str(description)))
        
        # Feature 5: URL complexity (number of path segments)
        url = finding.get('url', '')
        features.append(url.count('/'))
        
        # Feature 6: Has query parameters
        features.append(1 if '?' in url else 0)
        
        # Feature 7: CVSS score (if available)
        features.append(finding.get('cvss_score', 0))
        
        # Feature 8: Risk score (if available)
        features.append(finding.get('risk_score', 0))
        
        # Context features (if provided)
        if context:
            # Feature 9: Response status code
            features.append(context.get('status_code', 200))
            
            # Feature 10: Response time (ms)
            features.append(context.get('response_time', 0))
            
            # Feature 11: Historical occurrence count
            features.append(context.get('occurrence_count', 1))
            
            # Feature 12: Days since first seen
            features.append(context.get('days_since_first_seen', 0))
        else:
            # Default values if no context
            features.extend([200, 0, 1, 0])
        
        return np.array(features).reshape(1, -1)
    
    def predict(self, finding: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Tuple[bool, float]:
        """
        Predict if a finding is a false positive.
        
        Args:
            finding: Security finding dictionary
            context: Additional context
            
        Returns:
            Tuple of (is_false_positive, confidence)
        """
        if not self.is_trained:
            # If model not trained, use rule-based heuristics
            return self._heuristic_classification(finding)
        
        # Extract features
        features = self.extract_features(finding, context)
        
        # Scale features
        features_scaled = self.scaler.transform(features)
        
        # Predict
        prediction = self.model.predict(features_scaled)[0]
        probability = self.model.predict_proba(features_scaled)[0]
        
        # prediction: 0 = True Positive, 1 = False Positive
        is_false_positive = bool(prediction)
        confidence = probability[1] if is_false_positive else probability[0]
        
        return is_false_positive, float(confidence)
    
    def _heuristic_classification(self, finding: Dict[str, Any]) -> Tuple[bool, float]:
        """
        Rule-based heuristic classification when model is not trained.
        
        Args:
            finding: Security finding dictionary
            
        Returns:
            Tuple of (is_false_positive, confidence)
        """
        # Low confidence heuristics
        confidence = 0.5
        
        # Check for common false positive patterns
        evidence = str(finding.get('evidence', '')).lower()
        description = str(finding.get('description', '')).lower()
        
        # Pattern 1: Info severity with generic evidence
        if finding.get('severity', '').lower() == 'info':
            if len(evidence) < 20:
                return True, 0.6
        
        # Pattern 2: Missing security headers (often false positives in dev)
        if 'missing' in description and 'header' in description:
            return True, 0.55
        
        # Pattern 3: Very short evidence (likely incomplete scan)
        if len(evidence) < 10:
            return True, 0.6
        
        # Default: assume true positive
        return False, 0.5
    
    def train(self, training_data: List[Dict[str, Any]], labels: List[int]) -> Dict[str, Any]:
        """
        Train the Random Forest model.
        
        Args:
            training_data: List of findings with context
            labels: List of labels (0 = True Positive, 1 = False Positive)
            
        Returns:
            Training metrics
        """
        if len(training_data) < 10:
            return {
                'error': 'Insufficient training data (minimum 10 samples required)',
                'samples': len(training_data)
            }
        
        # Extract features for all training samples
        X = []
        for sample in training_data:
            finding = sample.get('finding', {})
            context = sample.get('context', {})
            features = self.extract_features(finding, context)
            X.append(features.flatten())
        
        X = np.array(X)
        y = np.array(labels)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y if len(np.unique(y)) > 1 else None
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train Random Forest
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            class_weight='balanced'  # Handle imbalanced data
        )
        
        self.model.fit(X_train_scaled, y_train)
        self.is_trained = True
        
        # Evaluate
        train_score = self.model.score(X_train_scaled, y_train)
        test_score = self.model.score(X_test_scaled, y_test)
        
        # Feature importance
        feature_names = [
            'severity', 'category', 'evidence_length', 'description_length',
            'url_complexity', 'has_params', 'cvss_score', 'risk_score',
            'status_code', 'response_time', 'occurrence_count', 'days_since_first_seen'
        ]
        
        feature_importance = dict(zip(
            feature_names,
            self.model.feature_importances_.tolist()
        ))
        
        # Save model
        self._save_model()
        
        return {
            'success': True,
            'train_accuracy': float(train_score),
            'test_accuracy': float(test_score),
            'samples_trained': len(X_train),
            'samples_tested': len(X_test),
            'feature_importance': feature_importance,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
    
    def update_with_feedback(self, finding: Dict[str, Any], is_false_positive: bool, 
                            context: Optional[Dict[str, Any]] = None):
        """
        Update model with user feedback (for incremental learning).
        
        Args:
            finding: Security finding
            is_false_positive: User feedback (True = FP, False = TP)
            context: Additional context
        """
        # Store feedback for next training cycle
        feedback_file = "ml/data/fp_feedback.pkl"
        
        feedback_entry = {
            'finding': finding,
            'context': context or {},
            'label': 1 if is_false_positive else 0,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        # Load existing feedback
        feedback_data = []
        if os.path.exists(feedback_file):
            try:
                with open(feedback_file, 'rb') as f:
                    feedback_data = pickle.load(f)
            except:
                pass
        
        # Append new feedback
        feedback_data.append(feedback_entry)
        
        # Save updated feedback
        os.makedirs(os.path.dirname(feedback_file), exist_ok=True)
        with open(feedback_file, 'wb') as f:
            pickle.dump(feedback_data, f)
        
        # Retrain if we have enough new feedback (e.g., every 50 samples)
        if len(feedback_data) % 50 == 0 and len(feedback_data) >= 50:
            self._retrain_from_feedback(feedback_data)
    
    def _retrain_from_feedback(self, feedback_data: List[Dict[str, Any]]):
        """Retrain model with accumulated feedback."""
        training_data = [
            {'finding': f['finding'], 'context': f['context']}
            for f in feedback_data
        ]
        labels = [f['label'] for f in feedback_data]
        
        self.train(training_data, labels)
    
    def _save_model(self):
        """Save trained model and scaler to disk."""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'is_trained': self.is_trained,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        with open(self.model_path, 'wb') as f:
            pickle.dump(model_data, f)
    
    def _load_model(self):
        """Load trained model from disk if available."""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    model_data = pickle.load(f)
                
                self.model = model_data['model']
                self.scaler = model_data['scaler']
                self.is_trained = model_data['is_trained']
                
                print(f"[FP Reducer] Loaded trained model from {self.model_path}")
            except Exception as e:
                print(f"[FP Reducer] Failed to load model: {e}")
                self.is_trained = False
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model."""
        if not self.is_trained:
            return {
                'trained': False,
                'message': 'Model not trained yet. Using heuristic classification.'
            }
        
        return {
            'trained': True,
            'n_estimators': self.model.n_estimators,
            'max_depth': self.model.max_depth,
            'n_features': self.model.n_features_in_,
            'model_path': self.model_path
        }
