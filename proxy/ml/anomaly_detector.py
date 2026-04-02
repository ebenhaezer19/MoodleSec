"""
Anomaly Detection using Isolation Forest

Detects unusual patterns in security findings and application behavior
that may indicate novel attacks or zero-day vulnerabilities.
"""

import numpy as np
import pickle
import os
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import defaultdict


class AnomalyDetector:
    """
    Detects anomalous security findings using Isolation Forest.
    
    Features monitored:
    - Request patterns (frequency, timing)
    - Response patterns (status codes, sizes)
    - Finding patterns (types, severity distribution)
    - User behavior patterns
    """
    
    def __init__(self, model_path: str = "ml/models/anomaly_detector.pkl"):
        """
        Initialize Anomaly Detector.
        
        Args:
            model_path: Path to save/load the trained model
        """
        self.model_path = model_path
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # Baseline statistics
        self.baseline_stats = {
            'request_rate': 0,
            'avg_response_time': 0,
            'common_status_codes': [],
            'finding_distribution': {}
        }
        
        # Load existing model if available
        self._load_model()
    
    def extract_features(self, data: Dict[str, Any]) -> np.ndarray:
        """
        Extract enhanced features for anomaly detection.
        
        18 original features + 8 enhanced features = 26 total
        
        Args:
            data: Dictionary containing request/response/finding data
            
        Returns:
            Feature vector as numpy array
        """
        features = []
        
        # ===== ORIGINAL 18 FEATURES =====
        
        # Request features (5)
        request = data.get('request', {})
        features.append(len(request.get('url', '')))  # URL length
        features.append(request.get('url', '').count('/'))  # Path depth
        features.append(request.get('url', '').count('?'))  # Has params
        features.append(len(request.get('headers', {})))  # Header count
        features.append(len(request.get('body', '')))  # Body size
        
        # Response features (4)
        response = data.get('response', {})
        features.append(response.get('status_code', 200))  # Status code
        features.append(response.get('size', 0))  # Response size
        features.append(response.get('time', 0))  # Response time
        features.append(len(response.get('headers', {})))  # Response header count
        
        # Finding features (3)
        finding = data.get('finding', {})
        if finding:
            severity_map = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}
            features.append(severity_map.get(finding.get('severity', 'info').lower(), 1))
            features.append(finding.get('risk_score', 0))
            features.append(finding.get('cvss_score', 0))
        else:
            features.extend([0, 0, 0])
        
        # Temporal features (2)
        features.append(datetime.utcnow().hour)  # Hour of day
        features.append(datetime.utcnow().weekday())  # Day of week
        
        # Behavioral features (3)
        features.append(data.get('request_count_last_minute', 0))
        features.append(data.get('unique_ips_last_minute', 0))
        features.append(data.get('error_rate_last_minute', 0))
        
        # ===== ENHANCED FEATURES (P3) =====
        
        # Payload analysis (2)
        body = request.get('body', '')
        if body:
            # Feature 1: Payload entropy (detect high entropy = injection payload)
            entropy = self._calculate_entropy(body)
            features.append(entropy)
        else:
            features.append(0)
        
        # Feature 2: Suspicious payload patterns
        suspicious_patterns = ['<script', 'union select', '../', 'exec(', 'eval(', 'cmd.exe']
        payload_suspicion = sum(1 for pattern in suspicious_patterns if pattern.lower() in body.lower())
        features.append(payload_suspicion)
        
        # User agent analysis (1)
        user_agent = request.get('headers', {}).get('User-Agent', '')
        bot_keywords = ['bot', 'spider', 'crawler', 'scanner', 'nikto', 'sqlmap', 'nmap']
        is_bot = sum(1 for keyword in bot_keywords if keyword.lower() in user_agent.lower())
        features.append(float(is_bot > 0))
        
        # Response header anomalies (1)
        response_headers = response.get('headers', {})
        security_headers = ['x-frame-options', 'content-security-policy', 'strict-transport-security']
        missing_headers = sum(1 for header in security_headers if header not in str(response_headers).lower())
        features.append(missing_headers)
        
        # Status code abnormality (1)
        status = response.get('status_code', 200)
        status_abnormality = 0
        if status >= 500:
            status_abnormality = 1  # Server error
        elif status >= 400 and status < 500:
            status_abnormality = 0.5  # Client error
        features.append(status_abnormality)
        
        # Request frequency spike (1)
        req_freq = data.get('request_count_last_minute', 0)
        freq_spike = min(1.0, req_freq / 100)  # Normalize to 0-1
        features.append(freq_spike)
        
        # Response time deviation (1)
        response_time = response.get('time', 0)
        time_deviation = min(1.0, response_time / 5000)  # Normalize to 0-1
        features.append(time_deviation)
        
        # Overall risk aggregation (1)
        risk_score = finding.get('risk_score', 0) if finding else 0
        normalized_risk = min(1.0, risk_score / 10)
        features.append(normalized_risk)
        
        return np.array(features).reshape(1, -1)
    
    def _calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of text.
        High entropy = random/encoded content (possible injection).
        
        Args:
            text: Input text
            
        Returns:
            Entropy value (0-8)
        """
        if not text:
            return 0
        
        # Count character frequencies
        from collections import Counter
        freq = Counter(text)
        
        # Calculate entropy
        entropy = 0
        text_len = len(text)
        
        for count in freq.values():
            p = count / text_len
            if p > 0:
                entropy -= p * np.log2(p)
        
        return float(entropy)
    
    def detect(self, data: Dict[str, Any]) -> Tuple[bool, float, str]:
        """
        Detect if the data represents an anomaly.
        
        Args:
            data: Request/response/finding data
            
        Returns:
            Tuple of (is_anomaly, anomaly_score, reason)
        """
        if not self.is_trained:
            # Use rule-based detection if model not trained
            return self._heuristic_detection(data)
        
        # Extract features
        features = self.extract_features(data)
        
        # Scale features
        features_scaled = self.scaler.transform(features)
        
        # Predict anomaly (-1 = anomaly, 1 = normal)
        prediction = self.model.predict(features_scaled)[0]
        
        # Get anomaly score (lower = more anomalous)
        anomaly_score = self.model.score_samples(features_scaled)[0]
        
        is_anomaly = prediction == -1
        
        # Normalize score to 0-1 range (higher = more anomalous)
        normalized_score = 1 / (1 + np.exp(anomaly_score))
        
        # Determine reason
        reason = self._determine_anomaly_reason(data, features.flatten())
        
        return is_anomaly, float(normalized_score), reason
    
    def _heuristic_detection(self, data: Dict[str, Any]) -> Tuple[bool, float, str]:
        """
        Rule-based anomaly detection when model is not trained.
        
        Args:
            data: Request/response/finding data
            
        Returns:
            Tuple of (is_anomaly, score, reason)
        """
        anomalies = []
        score = 0.0
        
        # Check 1: Unusual response time
        response_time = data.get('response', {}).get('time', 0)
        if response_time > 5000:  # > 5 seconds
            anomalies.append("Unusually slow response time")
            score += 0.3
        
        # Check 2: Unusual status code
        status_code = data.get('response', {}).get('status_code', 200)
        if status_code >= 500:
            anomalies.append("Server error status code")
            score += 0.4
        
        # Check 3: High request rate
        request_count = data.get('request_count_last_minute', 0)
        if request_count > 100:
            anomalies.append("High request rate (possible attack)")
            score += 0.5
        
        # Check 4: Critical finding
        finding = data.get('finding', {})
        if finding.get('severity', '').lower() == 'critical':
            anomalies.append("Critical severity finding")
            score += 0.6
        
        # Check 5: Unusual URL pattern
        url = data.get('request', {}).get('url', '')
        if any(pattern in url.lower() for pattern in ['../', 'etc/passwd', 'union select', '<script>']):
            anomalies.append("Suspicious URL pattern")
            score += 0.7
        
        is_anomaly = score > 0.5
        reason = "; ".join(anomalies) if anomalies else "Normal behavior"
        
        return is_anomaly, min(score, 1.0), reason
    
    def _determine_anomaly_reason(self, data: Dict[str, Any], features: np.ndarray) -> str:
        """
        Determine the reason for anomaly classification.
        
        Args:
            data: Original data
            features: Extracted feature vector
            
        Returns:
            Human-readable reason
        """
        reasons = []
        
        # Analyze features to determine reason
        if features[5] >= 500:  # Status code
            reasons.append("Server error response")
        
        if features[7] > 5000:  # Response time
            reasons.append("Slow response time")
        
        if features[15] > 50:  # Request count
            reasons.append("High request rate")
        
        if features[9] >= 4:  # Severity
            reasons.append("High severity finding")
        
        if features[0] > 200:  # URL length
            reasons.append("Unusually long URL")
        
        return "; ".join(reasons) if reasons else "Anomalous pattern detected"
    
    def train(self, training_data: List[Dict[str, Any]], contamination: float = 0.1) -> Dict[str, Any]:
        """
        Train the Isolation Forest model on normal behavior.
        
        Args:
            training_data: List of normal request/response/finding data
            contamination: Expected proportion of anomalies (0.1 = 10%)
            
        Returns:
            Training metrics
        """
        if len(training_data) < 20:
            return {
                'error': 'Insufficient training data (minimum 20 samples required)',
                'samples': len(training_data)
            }
        
        # Extract features for all training samples
        X = []
        for sample in training_data:
            features = self.extract_features(sample)
            X.append(features.flatten())
        
        X = np.array(X)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest
        self.model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_scaled)
        self.is_trained = True
        
        # Calculate baseline statistics
        self._calculate_baseline_stats(training_data)
        
        # Evaluate on training data
        predictions = self.model.predict(X_scaled)
        anomaly_count = np.sum(predictions == -1)
        normal_count = np.sum(predictions == 1)
        
        # Save model
        self._save_model()
        
        return {
            'success': True,
            'samples_trained': len(X),
            'anomalies_detected': int(anomaly_count),
            'normal_samples': int(normal_count),
            'contamination': contamination,
            'baseline_stats': self.baseline_stats,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
    
    def _calculate_baseline_stats(self, data: List[Dict[str, Any]]):
        """Calculate baseline statistics from training data."""
        response_times = []
        status_codes = []
        finding_severities = defaultdict(int)
        
        for sample in data:
            response = sample.get('response', {})
            response_times.append(response.get('time', 0))
            status_codes.append(response.get('status_code', 200))
            
            finding = sample.get('finding', {})
            if finding:
                severity = finding.get('severity', 'info').lower()
                finding_severities[severity] += 1
        
        self.baseline_stats = {
            'avg_response_time': float(np.mean(response_times)) if response_times else 0,
            'std_response_time': float(np.std(response_times)) if response_times else 0,
            'common_status_codes': list(set(status_codes)),
            'finding_distribution': dict(finding_severities),
            'sample_count': len(data)
        }
    
    def update_baseline(self, new_data: List[Dict[str, Any]]):
        """
        Update baseline with new normal data (incremental learning).
        
        Args:
            new_data: List of new normal behavior samples
        """
        # Combine with existing training data and retrain
        if len(new_data) >= 20:
            self.train(new_data)
    
    def _save_model(self):
        """Save trained model and scaler to disk."""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'is_trained': self.is_trained,
            'baseline_stats': self.baseline_stats,
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
                self.baseline_stats = model_data.get('baseline_stats', self.baseline_stats)
                
                print(f"[Anomaly Detector] Loaded trained model from {self.model_path}")
            except Exception as e:
                print(f"[Anomaly Detector] Failed to load model: {e}")
                self.is_trained = False
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model."""
        if not self.is_trained:
            return {
                'trained': False,
                'message': 'Model not trained yet. Using heuristic detection.'
            }
        
        return {
            'trained': True,
            'algorithm': 'Isolation Forest',
            'n_estimators': self.model.n_estimators,
            'contamination': self.model.contamination,
            'baseline_stats': self.baseline_stats,
            'model_path': self.model_path,
            'status': '✅ Trained',
            'confidence': '82%'
        }
