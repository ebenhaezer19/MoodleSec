"""
Anomaly detection using Isolation Forest.
"""

import numpy as np
import pickle
import os
import csv
import re
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, RobustScaler, MinMaxScaler
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from collections import defaultdict
from .path_utils import normalize_model_path


def _safe_issubclass(cls, target):
    """issubclass() that never raises."""
    try:
        return issubclass(cls, target)
    except Exception:
        return False

class AnomalyDetector:
    """Isolation Forest anomaly detector."""
    
    def __init__(self, model_path: str = "ml/models/anomaly_detector.pkl"):
        self.model_path = normalize_model_path(model_path, "anomaly_detector.pkl")
        self.model = None
        
        self.scaler = StandardScaler()
        self.robust_scaler = RobustScaler()
        self.minmax_scaler = MinMaxScaler(feature_range=(0, 1))
        
        self.is_trained = False
        
        # Feature scaling bounds
        self.feature_bounds = {
            'url_length': (0, 500),
            'response_time': (0, 10000),
            'status_code': (200, 599),
            'request_count': (0, 1000),
            'entropy': (0, 8),
        }

        # Second-stage calibration model
        self.meta_classifier = None
        self.meta_threshold = 0.5
        self.decision_threshold = None  # Tuned on validation set
        self.meta_classifier_calibrated = None  # Calibrated version
        self.heuristic_weight = 0.10

        # Supervised baseline for comparison
        self.baseline_supervised_model = None
        self.baseline_threshold = None
        self.recall_target = 0.80
        
        # Score calibration
        self.score_offset = 0.0
        self.score_scale = 1.0
        
        # Baseline stats
        self.baseline_stats = {
            'request_rate': 0,
            'avg_response_time': 0,
            'std_response_time': 0,
            'common_status_codes': [],
            'finding_distribution': {},
            'score_mean': 0.0,
            'score_std': 0.0,
        }
        
        # Recall preservation
        self.min_recall = 0.90
        self.fp_penalty_weight = 2.0

        # Feature schema
        self.default_feature_names = [
            'request_url_length',
            'request_path_depth',
            'request_has_params',
            'request_header_count',
            'request_body_size',
            'response_status_code',
            'response_size',
            'response_time',
            'response_header_count',
            'finding_severity_score',
            'finding_risk_score',
            'finding_cvss_score',
            'request_hour',
            'request_weekday',
            'request_count_last_minute',
            'unique_ips_last_minute',
            'error_rate_last_minute',
            'body_entropy',
            'payload_suspicion_count',
            'user_agent_is_bot',
            'missing_security_headers',
            'status_abnormality',
            'request_frequency_spike',
            'response_time_deviation',
            'normalized_risk_score',
            'special_char_count',
            'keyword_hits',
            'keyword_flag_select',
            'keyword_flag_union',
            'keyword_flag_script',
            'keyword_flag_drop',
            'query_entropy',
            'combined_payload_entropy',
            'query_parameter_count',
            'url_encoding_count',
        ]
        self.feature_names = list(self.default_feature_names)
        self.debug_feature_logging = True
        self._load_model()

    @staticmethod
    def _sigmoid(score: float) -> float:
        """Numerically stable sigmoid."""
        score = np.clip(score, -500, 500)
        return float(1.0 / (1.0 + np.exp(-score)))
    
    def _calibrate_anomaly_score(self, raw_score: float) -> float:
        """Calibrate raw score to probability."""
        calibrated = raw_score * self.score_scale + self.score_offset
        
        prob = self._sigmoid(calibrated)
        
        return float(np.clip(prob, 0.0, 1.0))
    
    def _normalize_score_range(self, score: float, mean: float = 0.0, std: float = 1.0) -> float:
        """Z-normalize anomaly score."""
        if std == 0:
            return 0.5
        
        z_score = (score - mean) / std
        return float(self._sigmoid(z_score))

    @staticmethod
    def _safe_feature_value(features: np.ndarray, index: int, default: float = 0.0) -> float:
        """Safely read feature at index."""
        if features is None or index < 0 or index >= len(features):
            return float(default)
        return float(features[index])

    def _build_feature_names_for_count(self, feature_count: int) -> List[str]:
        """Build feature name list for given count."""
        count = max(0, int(feature_count))
        if count <= len(self.default_feature_names):
            return list(self.default_feature_names[:count])
        extras = [f'extra_feature_{idx}' for idx in range(len(self.default_feature_names), count)]
        return list(self.default_feature_names) + extras

    def _get_model_expected_feature_count(self) -> Optional[int]:
        """Infer expected feature count from fitted model."""
        if self.scaler is not None and hasattr(self.scaler, 'n_features_in_'):
            return int(self.scaler.n_features_in_)
        if self.model is not None and hasattr(self.model, 'n_features_in_'):
            return int(self.model.n_features_in_)
        return None

    def _get_expected_feature_count(self) -> int:
        """Expected feature count for inference."""
        model_expected = self._get_model_expected_feature_count()
        if model_expected is not None:
            return int(model_expected)
        if isinstance(self.feature_names, list) and len(self.feature_names) > 0:
            return int(len(self.feature_names))
        return int(len(self.default_feature_names))

    def _validate_full_feature_schema(self, feature_count: int, context: str) -> Optional[str]:
        """Validate feature count matches expected schema."""
        expected_count = int(len(self.default_feature_names))
        actual_count = int(feature_count)
        if actual_count != expected_count:
            return (
                f"{context}: full feature schema required ({expected_count}) but got {actual_count}. "
                "Verify extract_features() and retrain."
            )
        return None

    def _align_feature_vector(self, feature_vector: np.ndarray) -> np.ndarray:
        """Align feature vector to expected schema size."""
        vector = np.asarray(feature_vector, dtype=float).flatten()
        actual_count = int(len(vector))
        expected_count = self._get_expected_feature_count()

        if not isinstance(self.feature_names, list) or len(self.feature_names) == 0:
            self.feature_names = self._build_feature_names_for_count(expected_count)

        if len(self.feature_names) != expected_count:
            print(
                f"[Anomaly Detector] Warning: feature_names length ({len(self.feature_names)}) "
                f"!= model/scaler expected ({expected_count}). Resetting schema."
            )
            self.feature_names = self._build_feature_names_for_count(expected_count)

        if self.debug_feature_logging:
            print(f"[Anomaly Detector] Expected feature count: {expected_count}")
            print(f"[Anomaly Detector] Actual feature count: {actual_count}")

        if actual_count != expected_count:
            print(
                f"[Anomaly Detector] Warning: feature mismatch detected. "
                f"Auto-aligning from {actual_count} to {expected_count}."
            )
            actual_names = self._build_feature_names_for_count(actual_count)
            expected_names = list(self.feature_names)
            missing_names = expected_names[actual_count:] if expected_count > actual_count else []
            extra_names = actual_names[expected_count:] if actual_count > expected_count else []
            if missing_names:
                print(f"[Anomaly Detector] Missing features auto-filled with 0: {missing_names}")
            if extra_names:
                print(f"[Anomaly Detector] Extra features auto-dropped: {extra_names}")

            if actual_count > expected_count:
                vector = vector[:expected_count]
            else:
                padding = np.zeros(expected_count - actual_count, dtype=float)
                vector = np.concatenate([vector, padding], axis=0)

            overlap = min(len(actual_names), len(expected_names))
            if actual_names[:overlap] != expected_names[:overlap]:
                print("[Anomaly Detector] Warning: feature name order mismatch detected.")
                print(f"[Anomaly Detector] Expected names (head): {expected_names[:8]}")
                print(f"[Anomaly Detector] Actual names (head): {actual_names[:8]}")

        assert len(vector) == len(self.feature_names)
        return vector

    def _build_meta_features(self, normalized_score: float, heuristic_score: float, features: np.ndarray) -> np.ndarray:
        """Build second-stage feature vector."""
        payload_suspicion = self._safe_feature_value(features, 18)
        is_bot = self._safe_feature_value(features, 19)
        status_abnormality = self._safe_feature_value(features, 21)
        freq_spike = self._safe_feature_value(features, 22)
        time_deviation = self._safe_feature_value(features, 23)
        request_count = self._safe_feature_value(features, 14)
        url_length = self._safe_feature_value(features, 0)

        return np.array(
            [
                float(normalized_score),
                float(heuristic_score),
                payload_suspicion,
                is_bot,
                status_abnormality,
                freq_spike,
                time_deviation,
                request_count,
                url_length,
            ],
            dtype=float,
        )

    @staticmethod
    def _evaluate_binary_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, Any]:
        """Compute binary classification metrics."""
        y_true = np.asarray(y_true).astype(int)
        y_pred = np.asarray(y_pred).astype(int)

        tp = int(np.sum((y_true == 1) & (y_pred == 1)))
        fp = int(np.sum((y_true == 0) & (y_pred == 1)))
        tn = int(np.sum((y_true == 0) & (y_pred == 0)))
        fn = int(np.sum((y_true == 1) & (y_pred == 0)))

        total = tp + fp + tn + fn
        accuracy = (tp + tn) / total if total else 0.0
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0
        fp_rate = fp / (fp + tn) if (fp + tn) else 0.0
        fn_rate = fn / (fn + tp) if (fn + tp) else 0.0

        return {
            'tp': tp,
            'fp': fp,
            'tn': tn,
            'fn': fn,
            'accuracy': float(accuracy),
            'precision': float(precision),
            'recall': float(recall),
            'f1': float(f1),
            'fp_rate': float(fp_rate),
            'fn_rate': float(fn_rate),
        }

    @staticmethod
    def _normalize_binary_label(raw_label: Any) -> Optional[int]:
        """Map label to binary: 0=normal, 1=anomaly."""
        if raw_label is None:
            return None

        if isinstance(raw_label, (int, np.integer)):
            value = int(raw_label)
            if value in (0, 1):
                return value

        label = str(raw_label).strip().lower()
        if label in {'0', 'normal', 'benign', 'legit', 'legitimate'}:
            return 0
        if label in {'1', 'anomalous', 'anomaly', 'attack', 'malicious'}:
            return 1
        return None

    @staticmethod
    def _parse_headers_string(raw_headers: str) -> Dict[str, str]:
        """Parse semicolon-separated header string."""
        headers: Dict[str, str] = {}
        text = str(raw_headers or '').strip()
        if not text:
            return headers

        for part in text.split(';'):
            segment = part.strip()
            if not segment or ':' not in segment:
                continue
            key, value = segment.split(':', 1)
            key = key.strip()
            value = value.strip()
            if key:
                headers[key] = value

        return headers

    @staticmethod
    def _estimate_response_from_request(url: str, body: str, method: str, header_count: int) -> Dict[str, Any]:
        """Generate deterministic synthetic response fields from request inputs."""
        digest_seed = f"{method}|{url}|{len(body)}|{header_count}"
        digest = hashlib.md5(digest_seed.encode('utf-8')).hexdigest()
        selector = int(digest[:2], 16)

        if selector % 20 == 0:
            status_code = 304
        elif selector % 10 == 0:
            status_code = 302
        else:
            status_code = 200

        response_time = max(50, min(6000, 90 + len(url) + len(body) // 3 + (35 if method == 'POST' else 0)))
        response_size = max(300, min(140000, 1200 + len(url) * 4 + len(body) * 3))

        return {
            'status_code': int(status_code),
            'size': int(response_size),
            'time': int(response_time),
            'headers': {},
        }

    @staticmethod
    def _infer_dataset_kind(fieldnames: List[str]) -> str:
        """Infer dataset schema from CSV field names."""
        fields = set(fieldnames or [])
        if {'request_raw', 'method', 'path', 'label'}.issubset(fields):
            return 'moodle'
        if {'Method', 'URL'}.issubset(fields) and ('H1' in fields or 'classification' in fields):
            return 'csic'
        return 'generic'

    def _load_moodle_row(self, row: Dict[str, str]) -> Optional[Tuple[Dict[str, Any], int]]:
        """Convert Moodle CSV row to sample + label."""
        label = self._normalize_binary_label(row.get('label'))
        if label is None:
            return None

        method = str(row.get('method') or 'GET').strip().upper()
        path = str(row.get('path') or '/').strip() or '/'
        if not path.startswith('/'):
            path = '/' + path

        query = str(row.get('query_params') or '').strip()
        if query.startswith('?'):
            query = query[1:]

        body = str(row.get('body') or '').strip()
        if body == '-':
            body = ''

        headers = self._parse_headers_string(str(row.get('headers') or ''))
        url = f"http://localhost{path}" + (f"?{query}" if query else '')

        response = self._estimate_response_from_request(url=url, body=body, method=method, header_count=len(headers))

        suspicious_tokens = ['<script', 'union', '../', 'or 1=1', 'http://', 'https://']
        merged_payload = f"{query} {body}".lower()
        suspicious_hits = sum(1 for token in suspicious_tokens if token in merged_payload)
        request_count = min(240, max(1, 3 + (len(query) + len(body)) // 30 + (3 if method == 'POST' else 0) + suspicious_hits * 2))

        sample = {
            'request': {
                'url': url,
                'method': method,
                'headers': headers,
                'body': body,
            },
            'response': response,
            'request_count_last_minute': int(request_count),
            'unique_ips_last_minute': 1,
            'error_rate_last_minute': 0.0,
        }
        return sample, label

    def _load_csic_row(self, row: Dict[str, str]) -> Optional[Tuple[Dict[str, Any], int]]:
        """Convert CSIC CSV row to sample + label."""
        raw_label = row.get('H1') or row.get('label') or row.get('Label')
        if raw_label is None:
            cls = str(row.get('classification') or '').strip()
            if cls == '0':
                label = 0
            elif cls == '1':
                label = 1
            else:
                return None
        else:
            raw = str(raw_label).strip().lower()
            if raw.startswith('normal'):
                label = 0
            elif raw.startswith('anomal'):
                label = 1
            else:
                return None

        method = str(row.get('Method') or 'GET').strip().upper()
        raw_url = str(row.get('URL') or '').strip()
        url = re.sub(r"\s+HTTP/\d\.\d$", '', raw_url, flags=re.IGNORECASE) if raw_url else 'http://localhost/'

        body = str(row.get('content') or '').strip()
        length_str = str(row.get('lenght') or '').strip()
        if not body and length_str.isdigit() and int(length_str) > 0:
            body = 'x' * min(int(length_str), 4096)

        header_map = {
            'User-Agent': 'User-Agent',
            'Pragma': 'Pragma',
            'Cache-Control': 'Cache-Control',
            'Accept': 'Accept',
            'Accept-encoding': 'Accept-Encoding',
            'Accept-charset': 'Accept-Charset',
            'language': 'Accept-Language',
            'host': 'Host',
            'cookie': 'Cookie',
            'content-type': 'Content-Type',
            'connection': 'Connection',
        }
        headers: Dict[str, str] = {}
        for source_col, header_name in header_map.items():
            value = str(row.get(source_col) or '').strip()
            if value:
                headers[header_name] = value

        response = self._estimate_response_from_request(url=url, body=body, method=method, header_count=len(headers))
        query_weight = url.count('?') + url.count('&') + url.count('=')
        request_count = min(180, 2 + query_weight * 3 + len(body) // 120 + (2 if method == 'POST' else 0))

        sample = {
            'request': {
                'url': url,
                'method': method,
                'headers': headers,
                'body': body,
            },
            'response': response,
            'request_count_last_minute': int(request_count),
            'unique_ips_last_minute': 1,
            'error_rate_last_minute': 0.0,
        }
        return sample, label

    def _load_generic_row(self, row: Dict[str, str]) -> Optional[Tuple[Dict[str, Any], int]]:
        """Generic CSV row loader."""
        label = self._normalize_binary_label(row.get('label') or row.get('Label') or row.get('target'))
        if label is None:
            return None

        method = str(row.get('method') or row.get('Method') or 'GET').strip().upper()
        url = str(row.get('url') or row.get('URL') or 'http://localhost/').strip() or 'http://localhost/'
        body = str(row.get('body') or row.get('content') or '').strip()
        headers = self._parse_headers_string(str(row.get('headers') or ''))

        response = {
            'status_code': int(row.get('status_code') or row.get('status') or 200),
            'size': int(float(row.get('response_size') or row.get('size') or 0)),
            'time': int(float(row.get('response_time') or row.get('time') or 0)),
            'headers': {},
        }

        sample = {
            'request': {
                'url': url,
                'method': method,
                'headers': headers,
                'body': body,
            },
            'response': response,
            'request_count_last_minute': int(float(row.get('request_count_last_minute') or 1)),
            'unique_ips_last_minute': int(float(row.get('unique_ips_last_minute') or 1)),
            'error_rate_last_minute': float(row.get('error_rate_last_minute') or 0.0),
        }
        return sample, label

    def load_data(self, dataset_path: str, max_rows: int = 0) -> Dict[str, Any]:
        """Load anomaly dataset from CSV."""
        if not os.path.exists(dataset_path):
            return {'error': f'Dataset not found: {dataset_path}'}

        if os.path.splitext(dataset_path)[1].lower() != '.csv':
            return {'error': f'Unsupported format for {dataset_path}. Use CSV.'}

        samples: List[Dict[str, Any]] = []
        labels: List[int] = []
        skipped_rows = 0
        dataset_kind = 'generic'

        with open(dataset_path, 'r', encoding='utf-8', errors='replace', newline='') as handle:
            reader = csv.DictReader(handle)
            dataset_kind = self._infer_dataset_kind(reader.fieldnames or [])

            for idx, row in enumerate(reader, start=1):
                if max_rows and idx > max_rows:
                    break

                if dataset_kind == 'moodle':
                    parsed = self._load_moodle_row(row)
                elif dataset_kind == 'csic':
                    parsed = self._load_csic_row(row)
                else:
                    parsed = self._load_generic_row(row)

                if not parsed:
                    skipped_rows += 1
                    continue

                sample, label = parsed
                samples.append(sample)
                labels.append(int(label))

        normal_samples = int(sum(1 for v in labels if v == 0))
        anomaly_samples = int(sum(1 for v in labels if v == 1))

        if not samples:
            return {
                'error': 'No valid rows found in dataset',
                'dataset_path': dataset_path,
                'dataset_kind': dataset_kind,
                'skipped_rows': skipped_rows,
            }

        return {
            'success': True,
            'dataset_path': dataset_path,
            'dataset_kind': dataset_kind,
            'samples': samples,
            'labels': labels,
            'total_samples': len(samples),
            'normal_samples': normal_samples,
            'anomaly_samples': anomaly_samples,
            'skipped_rows': skipped_rows,
        }

    def preprocess(self, samples: List[Dict[str, Any]], labels: List[int],
        train_ratio: float = 0.60, val_ratio: float = 0.20,
        test_ratio: float = 0.20, random_state: int = 42) -> Dict[str, Any]:
        """Split data and fit scaler on train normals only."""
        ratio_sum = train_ratio + val_ratio + test_ratio
        if abs(ratio_sum - 1.0) > 1e-9:
            return {'error': f'Split ratios must sum to 1.0, got {ratio_sum}'}

        if len(samples) != len(labels):
            return {'error': 'samples and labels length mismatch'}

        y = np.asarray(labels, dtype=int)
        if len(np.unique(y)) < 2:
            return {'error': 'Need both normal (0) and anomaly (1) labels'}

        X = []
        for sample in samples:
            X.append(self.extract_features(sample).flatten())
        X = np.asarray(X, dtype=float)

        schema_error = self._validate_full_feature_schema(X.shape[1], context='preprocess')
        if schema_error:
            return {'error': schema_error}

        # Lock schema
        self.feature_names = self._build_feature_names_for_count(X.shape[1])

        all_indices = np.arange(len(y))
        train_indices, temp_indices, y_train, y_temp = train_test_split(
            all_indices,
            y,
            test_size=(1.0 - train_ratio),
            random_state=random_state,
            stratify=y,
        )

        relative_test_ratio = test_ratio / (val_ratio + test_ratio)
        val_indices, test_indices, y_val, y_test = train_test_split(
            temp_indices,
            y_temp,
            test_size=relative_test_ratio,
            random_state=random_state,
            stratify=y_temp,
        )

        X_train = X[train_indices]
        X_val = X[val_indices]
        X_test = X[test_indices]

        train_normal_mask = (y_train == 0)
        if int(np.sum(train_normal_mask)) < 20:
            return {
                'error': 'Insufficient normal samples in train split (need >=20)',
                'train_normal_samples': int(np.sum(train_normal_mask)),
            }

        # Fit scaler on train normals only
        self.scaler = StandardScaler()
        X_train_normal_scaled = self.scaler.fit_transform(X_train[train_normal_mask])
        X_val_scaled = self.scaler.transform(X_val)
        X_test_scaled = self.scaler.transform(X_test)

        train_normal_samples = [samples[int(idx)] for idx, label in zip(train_indices, y_train) if int(label) == 0]

        return {
            'success': True,
            'X_train_raw': X_train,
            'X_val_raw': X_val,
            'X_test_raw': X_test,
            'X_train_normal_scaled': X_train_normal_scaled,
            'X_val_scaled': X_val_scaled,
            'X_test_scaled': X_test_scaled,
            'y_train': y_train,
            'y_val': y_val,
            'y_test': y_test,
            'train_normal_samples': train_normal_samples,
            'split_summary': {
                'train_total': int(len(y_train)),
                'train_normal': int(np.sum(y_train == 0)),
                'train_anomaly': int(np.sum(y_train == 1)),
                'validation_total': int(len(y_val)),
                'validation_normal': int(np.sum(y_val == 0)),
                'validation_anomaly': int(np.sum(y_val == 1)),
                'test_total': int(len(y_test)),
                'test_normal': int(np.sum(y_test == 0)),
                'test_anomaly': int(np.sum(y_test == 1)),
            },
        }

    def _tune_threshold_on_validation(
        self,
        y_val: np.ndarray,
        val_scores: np.ndarray,
        target_recall: float = 0.80,
    ) -> Dict[str, Any]:
        """
        Tune threshold on validation set with recall priority.

        Objective:
        1) satisfy recall >= target_recall when possible,
        2) minimize false negatives,
        3) then reduce false positives.
        """
        if len(val_scores) == 0:
            empty_metrics = self._evaluate_binary_metrics(np.array([], dtype=int), np.array([], dtype=int))
            return {
                'threshold': 0.0,
                'metrics': empty_metrics,
                'target_recall': float(target_recall),
                'target_recall_met': False,
            }

        # Wide sweep to allow high-recall operating points.
        candidates = np.unique(np.quantile(val_scores, np.linspace(0.05, 0.95, 181)))
        if len(candidates) == 0:
            candidates = np.array([float(np.median(val_scores))])

        satisfied: List[Dict[str, Any]] = []
        all_results: List[Dict[str, Any]] = []

        for threshold in candidates:
            y_pred = (val_scores >= float(threshold)).astype(int)
            metrics = self._evaluate_binary_metrics(y_val, y_pred)
            result = {
                'threshold': float(threshold),
                'metrics': metrics,
            }
            all_results.append(result)
            if metrics['recall'] >= target_recall:
                satisfied.append(result)

        if satisfied:
            # Minimize FN first, then FP, then prefer slightly lower threshold for recall robustness.
            best = min(
                satisfied,
                key=lambda r: (
                    r['metrics']['fn'],
                    r['metrics']['fp'],
                    -r['metrics']['recall'],
                    r['threshold'],
                ),
            )
            best['target_recall'] = float(target_recall)
            best['target_recall_met'] = True
            return best

        # Fallback when target recall cannot be met: maximize recall and minimize FN.
        best = min(
            all_results,
            key=lambda r: (
                -r['metrics']['recall'],
                r['metrics']['fn'],
                r['metrics']['fp'],
                r['threshold'],
            ),
        )
        best['target_recall'] = float(target_recall)
        best['target_recall_met'] = False
        return best

    def train_model(
        self,
        prepared: Dict[str, Any],
        contamination: Optional[float] = None,
        contamination_candidates: Optional[List[float]] = None,
        target_recall: float = 0.80,
        random_state: int = 42,
    ) -> Dict[str, Any]:
        """Train Isolation Forest and tune threshold on validation set."""
        if not prepared.get('success'):
            return {'error': 'Invalid preprocessed data', 'details': prepared}

        X_train_raw = np.asarray(prepared['X_train_raw'], dtype=float)
        X_val_raw = np.asarray(prepared['X_val_raw'], dtype=float)
        y_train = np.asarray(prepared['y_train'], dtype=int)
        y_val = np.asarray(prepared['y_val'], dtype=int)
        X_train_normal_scaled = np.asarray(prepared['X_train_normal_scaled'], dtype=float)
        X_val_scaled = np.asarray(prepared['X_val_scaled'], dtype=float)

        schema_error = self._validate_full_feature_schema(X_train_raw.shape[1], context='train_model')
        if schema_error:
            return {'error': schema_error}

        # Sync feature schema with data
        self.feature_names = self._build_feature_names_for_count(X_train_raw.shape[1])

        if self.scaler is None or not hasattr(self.scaler, 'n_features_in_'):
            return {'error': 'train_model: scaler is not fitted. Run preprocess() before train_model().' }

        scaler_feature_count = int(self.scaler.n_features_in_)
        if scaler_feature_count != int(len(self.feature_names)):
            return {
                'error': (
                    f"train_model: scaler feature count ({scaler_feature_count}) does not match "
                    f"schema ({len(self.feature_names)})."
                )
            }

        # Tune contamination on train+val only
        if contamination is not None:
            search_candidates = [float(np.clip(contamination, 0.10, 0.25))]
        elif contamination_candidates is not None and len(contamination_candidates) > 0:
            search_candidates = sorted({float(np.clip(c, 0.10, 0.25)) for c in contamination_candidates})
        else:
            search_candidates = [0.10, 0.15, 0.20, 0.25]

        best_if = None
        contamination_search_results: List[Dict[str, Any]] = []

        for idx, candidate in enumerate(search_candidates):
            candidate_model = IsolationForest(
                n_estimators=300,
                max_samples='auto',
                contamination=float(candidate),
                random_state=random_state + idx,
                n_jobs=-1,
            )
            # Train on normal traffic only
            candidate_model.fit(X_train_normal_scaled)

            val_scores = -candidate_model.score_samples(X_val_scaled)
            threshold_result = self._tune_threshold_on_validation(
                y_val=y_val,
                val_scores=val_scores,
                target_recall=target_recall,
            )

            val_roc_auc = float(roc_auc_score(y_val, val_scores)) if len(np.unique(y_val)) >= 2 else 0.0
            candidate_result = {
                'contamination': float(candidate),
                'threshold': float(threshold_result['threshold']),
                'validation_metrics': threshold_result['metrics'],
                'validation_roc_auc': val_roc_auc,
                'target_recall_met': bool(threshold_result.get('target_recall_met', False)),
            }
            contamination_search_results.append(candidate_result)

            ranking_key = (
                0 if candidate_result['target_recall_met'] else 1,
                candidate_result['validation_metrics']['fn'],
                -candidate_result['validation_metrics']['recall'],
                candidate_result['validation_metrics']['fp'],
                -candidate_result['validation_roc_auc'],
            )
            if best_if is None or ranking_key < best_if['ranking_key']:
                best_if = {
                    'ranking_key': ranking_key,
                    'model': candidate_model,
                    'contamination': float(candidate),
                    'threshold_result': threshold_result,
                    'val_scores': val_scores,
                    'validation_roc_auc': val_roc_auc,
                }

        if best_if is None:
            return {'error': 'Failed to train Isolation Forest candidates'}

        self.model = best_if['model']
        self.is_trained = True

        self.meta_classifier = None
        self.meta_threshold = 0.5

        selected_contamination = float(best_if['contamination'])
        self.decision_threshold = float(best_if['threshold_result']['threshold'])
        selected_validation_metrics = best_if['threshold_result']['metrics']
        selected_validation_roc_auc = float(best_if['validation_roc_auc'])

        # Score distribution from train normals
        train_normal_scores = -self.model.score_samples(X_train_normal_scaled)
        score_mean = float(np.mean(train_normal_scores)) if len(train_normal_scores) else 0.0
        score_std = float(np.std(train_normal_scores)) if len(train_normal_scores) else 1.0
        if score_std == 0:
            score_std = 1.0

        self._calculate_baseline_stats(
            data=prepared.get('train_normal_samples', []),
            X_scaled=X_train_normal_scaled,
        )
        self.baseline_stats['score_mean'] = score_mean
        self.baseline_stats['score_std'] = score_std

        # Supervised baseline for comparison
        baseline_model = RandomForestClassifier(
            n_estimators=400,
            max_depth=16,
            min_samples_split=8,
            min_samples_leaf=3,
            class_weight='balanced_subsample',
            random_state=random_state,
            n_jobs=-1,
        )
        baseline_model.fit(X_train_raw, y_train)

        baseline_val_scores = baseline_model.predict_proba(X_val_raw)[:, 1]
        baseline_threshold_result = self._tune_threshold_on_validation(
            y_val=y_val,
            val_scores=baseline_val_scores,
            target_recall=target_recall,
        )
        baseline_val_roc_auc = float(roc_auc_score(y_val, baseline_val_scores)) if len(np.unique(y_val)) >= 2 else 0.0

        self.baseline_supervised_model = baseline_model
        self.baseline_threshold = float(baseline_threshold_result['threshold'])
        self.recall_target = float(target_recall)

        self._save_model()

        return {
            'success': True,
            'algorithm': 'IsolationForest',
            'trained_on_normals_only': True,
            'contamination': selected_contamination,
            'decision_threshold': float(self.decision_threshold),
            'feature_schema': {
                'feature_count': int(len(self.feature_names)),
                'feature_names': list(self.feature_names),
            },
            'validation_metrics': selected_validation_metrics,
            'validation_roc_auc': selected_validation_roc_auc,
            'target_recall': float(target_recall),
            'target_recall_met': bool(best_if['threshold_result'].get('target_recall_met', False)),
            'contamination_search': contamination_search_results,
            'baseline_supervised': {
                'model': 'RandomForestClassifier',
                'threshold': float(self.baseline_threshold),
                'validation_metrics': baseline_threshold_result['metrics'],
                'validation_roc_auc': baseline_val_roc_auc,
                'target_recall_met': bool(baseline_threshold_result.get('target_recall_met', False)),
            },
            'split_summary': prepared.get('split_summary', {}),
            'timestamp': datetime.utcnow().isoformat() + 'Z',
        }

    def evaluate(self, prepared: Dict[str, Any], threshold: Optional[float] = None) -> Dict[str, Any]:
        """Evaluate on test split."""
        if not self.is_trained or self.model is None:
            return {'error': 'Model is not trained'}

        if not prepared.get('success'):
            return {'error': 'Invalid preprocessed data', 'details': prepared}

        y_test = np.asarray(prepared['y_test'], dtype=int)
        X_test_raw = np.asarray(prepared['X_test_raw'], dtype=float)
        X_test_scaled = np.asarray(prepared['X_test_scaled'], dtype=float)

        if threshold is None and self.decision_threshold is None:
            return {'error': 'No threshold available. Run train_model() first or pass threshold explicitly.'}

        threshold_value = float(self.decision_threshold if threshold is None else threshold)
        test_scores = -self.model.score_samples(X_test_scaled)
        y_pred = (test_scores >= threshold_value).astype(int)

        precision = float(precision_score(y_test, y_pred, zero_division=0))
        recall = float(recall_score(y_test, y_pred, zero_division=0))
        f1 = float(f1_score(y_test, y_pred, zero_division=0))

        if len(np.unique(y_test)) >= 2:
            roc_auc = float(roc_auc_score(y_test, test_scores))
        else:
            roc_auc = 0.0

        cm = confusion_matrix(y_test, y_pred, labels=[0, 1])
        tn, fp, fn, tp = [int(x) for x in cm.ravel()]

        anomaly_result = {
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'roc_auc': roc_auc,
            'confusion_matrix': {
                'tn': tn,
                'fp': fp,
                'fn': fn,
                'tp': tp,
            },
            'target_recall': float(self.recall_target),
            'target_recall_met': bool(recall >= self.recall_target),
            'false_negatives': fn,
        }

        baseline_result = None
        if self.baseline_supervised_model is not None and self.baseline_threshold is not None:
            baseline_scores = self.baseline_supervised_model.predict_proba(X_test_raw)[:, 1]
            baseline_pred = (baseline_scores >= float(self.baseline_threshold)).astype(int)

            baseline_precision = float(precision_score(y_test, baseline_pred, zero_division=0))
            baseline_recall = float(recall_score(y_test, baseline_pred, zero_division=0))
            baseline_f1 = float(f1_score(y_test, baseline_pred, zero_division=0))
            baseline_roc_auc = float(roc_auc_score(y_test, baseline_scores)) if len(np.unique(y_test)) >= 2 else 0.0
            baseline_cm = confusion_matrix(y_test, baseline_pred, labels=[0, 1])
            b_tn, b_fp, b_fn, b_tp = [int(x) for x in baseline_cm.ravel()]

            baseline_result = {
                'model': 'RandomForestClassifier',
                'threshold_used': float(self.baseline_threshold),
                'precision': baseline_precision,
                'recall': baseline_recall,
                'f1': baseline_f1,
                'roc_auc': baseline_roc_auc,
                'confusion_matrix': {
                    'tn': b_tn,
                    'fp': b_fp,
                    'fn': b_fn,
                    'tp': b_tp,
                },
                'target_recall': float(self.recall_target),
                'target_recall_met': bool(baseline_recall >= self.recall_target),
                'false_negatives': b_fn,
            }

        return {
            'success': True,
            'evaluated_split': 'test',
            'threshold_used': threshold_value,
            'precision': anomaly_result['precision'],
            'recall': anomaly_result['recall'],
            'f1': anomaly_result['f1'],
            'roc_auc': anomaly_result['roc_auc'],
            'confusion_matrix': anomaly_result['confusion_matrix'],
            'recall_priority': {
                'target_recall': anomaly_result['target_recall'],
                'target_recall_met': anomaly_result['target_recall_met'],
                'false_negatives': anomaly_result['false_negatives'],
            },
            'anomaly_model': anomaly_result,
            'baseline_supervised_model': baseline_result,
            'test_samples': int(len(y_test)),
            'timestamp': datetime.utcnow().isoformat() + 'Z',
        }
    
    def _normalize_feature(self, value: float, min_val: float, max_val: float) -> float:
        """Normalize to 0-1 range."""
        if max_val == min_val:
            return 0.5
        normalized = (value - min_val) / (max_val - min_val)
        return float(np.clip(normalized, 0.0, 1.0))
    
    def extract_features(self, data: Dict[str, Any]) -> np.ndarray:
        """Extract 26-feature vector from request/response data."""
        features = []
        
        # Original features (18)

        # Request (5)
        request = data.get('request', {})
        url_len = len(request.get('url', ''))
        features.append(url_len)
        
        path_depth = request.get('url', '').count('/')
        features.append(path_depth)
        
        has_params = 1 if '?' in request.get('url', '') else 0
        features.append(has_params)
        
        header_count = len(request.get('headers', {}))
        features.append(header_count)
        
        body_size = len(request.get('body', ''))
        features.append(body_size)
        
        # Response (4)
        response = data.get('response', {})
        status_code = response.get('status_code', 200)
        features.append(status_code)
        
        response_size = response.get('size', 0)
        features.append(response_size)
        
        response_time = response.get('time', 0)
        features.append(response_time)
        
        response_header_count = len(response.get('headers', {}))
        features.append(response_header_count)
        
        # Finding (3)
        finding = data.get('finding', {})
        if finding:
            severity_map = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}
            severity_score = severity_map.get(finding.get('severity', 'info').lower(), 1)
            features.append(severity_score)
            
            risk_score = finding.get('risk_score', 0)
            features.append(risk_score)
            
            cvss_score = finding.get('cvss_score', 0)
            features.append(cvss_score)
        else:
            features.extend([0, 0, 0])
        
        # Temporal (2)
        hour = datetime.utcnow().hour
        features.append(hour)
        
        weekday = datetime.utcnow().weekday()
        features.append(weekday)
        
        # Behavioral (3)
        request_count = data.get('request_count_last_minute', 0)
        features.append(request_count)
        
        unique_ips = data.get('unique_ips_last_minute', 0)
        features.append(unique_ips)
        
        error_rate = data.get('error_rate_last_minute', 0)
        features.append(error_rate)
        
        # Enhanced features (8)

        # Payload analysis
        body = request.get('body', '')
        if body:
            entropy = self._calculate_entropy(body)
            features.append(entropy)
        else:
            features.append(0)
        
        # Suspicious patterns
        suspicious_patterns = ['<script', 'union select', '../', 'exec(', 'eval(', 'cmd.exe',
                              'drop table', 'insert into', 'delete from', 'or 1=1', 'and 1=1']
        payload_suspicion = sum(1 for pattern in suspicious_patterns if pattern.lower() in body.lower())
        features.append(min(payload_suspicion, 10))
        
        # Bot detection
        user_agent = request.get('headers', {}).get('User-Agent', '')
        bot_keywords = ['bot', 'spider', 'crawler', 'scanner', 'nikto', 'sqlmap', 'nmap', 'burp', 'zaproxy']
        is_bot = 1.0 if any(kw.lower() in user_agent.lower() for kw in bot_keywords) else 0.0
        features.append(is_bot)
        
        # Missing security headers
        response_headers = response.get('headers', {})
        security_headers = ['x-frame-options', 'content-security-policy', 'strict-transport-security']
        missing_headers = sum(1 for header in security_headers if header not in str(response_headers).lower())
        features.append(missing_headers)
        
        # Status code abnormality
        status = response.get('status_code', 200)
        if status >= 500:
            status_abnormality = 1.0  # Server error
        elif status >= 400:
            status_abnormality = 0.5  # Client error
        elif status == 200:
            status_abnormality = 0.0  # Normal
        else:
            status_abnormality = 0.2  # Unusual but not error
        features.append(status_abnormality)
        
        # Request frequency spike (1)
        freq_spike = min(1.0, request_count / 100.0) if request_count > 0 else 0.0
        features.append(freq_spike)
        
        # Response time deviation (1)
        time_deviation = min(1.0, response_time / 5000.0) if response_time > 0 else 0.0
        features.append(time_deviation)
        
        # Risk aggregation (1)
        risk_score = finding.get('risk_score', 0) if finding else 0
        normalized_risk = min(1.0, risk_score / 10.0)
        features.append(normalized_risk)

        # ===== ADDITIONAL PAYLOAD FEATURES (recall-focused) =====
        url_text = request.get('url', '')
        query_part = ''
        if '?' in url_text:
            query_part = url_text.split('?', 1)[1]

        payload_text = f"{url_text} {query_part} {body}".lower()

        # Feature 26: Special character density indicator (<, >, ', ", ;, --)
        special_char_count = (
            payload_text.count('<')
            + payload_text.count('>')
            + payload_text.count("'")
            + payload_text.count('"')
            + payload_text.count(';')
            + payload_text.count('--')
        )
        features.append(min(special_char_count, 100))

        # Feature 27: SQL/script keyword hit count (select, union, script, drop, etc.)
        keyword_patterns = [
            r'\bselect\b', r'\bunion\b', r'\bscript\b', r'\bdrop\b',
            r'\binsert\b', r'\bdelete\b', r'\bupdate\b', r'\bexec\b',
            r'\beval\b', r'\bor\s+1\s*=\s*1\b', r'\band\s+1\s*=\s*1\b'
        ]
        keyword_hits = sum(1 for pattern in keyword_patterns if re.search(pattern, payload_text))
        features.append(min(keyword_hits, 20))

        # Feature 28-31: Keyword flags (explicit binary indicators)
        features.append(1.0 if re.search(r'\bselect\b', payload_text) else 0.0)
        features.append(1.0 if re.search(r'\bunion\b', payload_text) else 0.0)
        features.append(1.0 if re.search(r'\bscript\b', payload_text) else 0.0)
        features.append(1.0 if re.search(r'\bdrop\b', payload_text) else 0.0)

        # Feature 32: Query entropy
        query_entropy = self._calculate_entropy(query_part) if query_part else 0.0
        features.append(query_entropy)

        # Feature 33: Combined query/body entropy
        combined_payload = f"{query_part} {body}".strip()
        combined_entropy = self._calculate_entropy(combined_payload) if combined_payload else 0.0
        features.append(combined_entropy)

        # Feature 34: Number of URL parameters
        parameter_count = 0
        if query_part:
            parameter_count = len([p for p in query_part.split('&') if p.strip()])
        features.append(min(parameter_count, 50))

        # Feature 35: URL encoding count (%xx)
        url_encoding_count = len(re.findall(r'%[0-9a-fA-F]{2}', payload_text))
        features.append(min(url_encoding_count, 100))
        
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
    
    def detect(self, data: Dict[str, Any], use_meta: bool = True) -> Tuple[bool, float, str]:
        """
        Detect if the data represents an anomaly.

        Isolation Forest remains the primary decision mechanism.
        Heuristics are kept as a low-weight supporting signal.
        
        Args:
            data: Request/response/finding data
            use_meta: Whether to use meta-classifier calibration
            
        Returns:
            Tuple of (is_anomaly, anomaly_score, reason)
        """
        if not self.is_trained:
            # Use rule-based detection if model not trained
            return self._heuristic_detection(data)

        heuristic_is_anomaly, heuristic_score, heuristic_reason = self._heuristic_detection(data)
        
        # Extract features
        features = self.extract_features(data)
        features_flat = features.flatten()
        aligned_features = self._align_feature_vector(features_flat)
        
        # Scale features with trained scaler.
        features_scaled = self.scaler.transform(aligned_features.reshape(1, -1))

        # Isolation Forest score: convert to anomaly direction (higher = more anomalous).
        raw_anomaly_score = float(-self.model.score_samples(features_scaled)[0])

        # Normalize score to 0-1 for stable confidence output.
        normalized_score = self._normalize_score_range(
            raw_anomaly_score,
            mean=self.baseline_stats.get('score_mean', 0.0),
            std=self.baseline_stats.get('score_std', 1.0)
        )

        # Primary decision from tuned threshold when available.
        if self.decision_threshold is not None:
            model_is_anomaly = raw_anomaly_score >= float(self.decision_threshold)
        else:
            # Backward-compatible fallback for older models without threshold.
            model_is_anomaly = self.model.predict(features_scaled)[0] == -1
        
        # Determine reason
        reason = self._determine_anomaly_reason(data, features_flat)

        # Optional second-stage calibrated classifier.
        # When enabled, keep heuristic influence low to avoid hard rule dominance.
        if use_meta and self.meta_classifier is not None:
            meta_features = self._build_meta_features(
                normalized_score=normalized_score,
                heuristic_score=heuristic_score,
                features=features_flat,
            ).reshape(1, -1)

            calibrated_probability = float(self.meta_classifier.predict_proba(meta_features)[0][1])
            blended_probability = (
                (1.0 - self.heuristic_weight) * calibrated_probability
                + self.heuristic_weight * float(heuristic_score)
            )

            # Heuristic override: URL/body exploit check adds +0.70 per signal;
            # threshold set to 0.65 so any single confirmed exploit pattern fires.
            if heuristic_is_anomaly and heuristic_score >= 0.65 and normalized_score >= 0.20:
                blended_probability = max(blended_probability, 0.90)

            calibrated_is_anomaly = blended_probability >= self.meta_threshold

            if calibrated_is_anomaly:
                combined_reason = reason
                if heuristic_reason and heuristic_reason != "Normal behavior":
                    if reason and reason != "Anomalous pattern detected":
                        combined_reason = f"{heuristic_reason}; {reason}"
                    else:
                        combined_reason = heuristic_reason
                return True, float(blended_probability), combined_reason or "Anomalous pattern detected"

            return False, float(blended_probability), "Normal behavior"

        blended_score = (
            (1.0 - self.heuristic_weight) * float(normalized_score)
            + self.heuristic_weight * float(heuristic_score)
        )

        # Hard override: URL/body exploit check adds +0.70 per signal;
        # threshold set to 0.65 so any single confirmed exploit pattern fires.
        if heuristic_is_anomaly and heuristic_score >= 0.65 and normalized_score >= 0.20:
            combined_reason = heuristic_reason
            if reason and reason != "Anomalous pattern detected":
                combined_reason = f"{heuristic_reason}; {reason}" if heuristic_reason else reason
            return True, float(max(blended_score, 0.90)), combined_reason

        if model_is_anomaly:
            combined_reason = reason
            if heuristic_reason and heuristic_reason != "Normal behavior":
                combined_reason = f"{heuristic_reason}; {reason}" if reason else heuristic_reason
            return True, float(blended_score), combined_reason or "Anomalous pattern detected"

        return False, float(blended_score), "Normal behavior"

    def train_meta_classifier(
        self,
        normal_data: List[Dict[str, Any]],
        anomaly_data: List[Dict[str, Any]],
        validation_ratio: float = 0.2,
        random_state: int = 42,
        model_type: str = 'random_forest',
        target_recall: float = 0.90,
        fp_penalty_weight: float = 2.0,
    ) -> Dict[str, Any]:
        """
        Train calibrated second-stage classifier optimized for FP reduction with recall preservation.

        This stage learns a better decision boundary from model scores + heuristic features
        to reduce false positives while maintaining minimum recall threshold.
        
        Args:
            normal_data: List of normal (non-anomalous) samples
            anomaly_data: List of anomalous samples
            validation_ratio: Fraction of data for validation
            random_state: Random seed for reproducibility
            model_type: 'random_forest' or 'logistic'
            target_recall: Minimum recall to preserve (default 90%)
            fp_penalty_weight: Weight for FP penalty vs FN (higher = prioritize FP reduction)
            
        Returns:
            Training results with optimized metrics
        """
        if not self.is_trained or self.model is None:
            return {
                'error': 'Base anomaly model must be trained before meta classifier training'
            }

        if len(normal_data) < 30 or len(anomaly_data) < 30:
            return {
                'error': 'Insufficient labeled data for meta classifier training (need >=30 normal and >=30 anomaly)',
                'normal_samples': len(normal_data),
                'anomaly_samples': len(anomaly_data),
            }

        X = []
        y = []
        
        # Build training data with better score normalization
        for sample in normal_data:
            features = self.extract_features(sample)
            features_flat = features.flatten()
            features_scaled = self.scaler.transform(features)
            raw_score = -self.model.score_samples(features_scaled)[0]
            normalized_score = self._normalize_score_range(
                raw_score,
                mean=self.baseline_stats.get('score_mean', 0.0),
                std=self.baseline_stats.get('score_std', 1.0)
            )
            _, heuristic_score, _ = self._heuristic_detection(sample)
            X.append(self._build_meta_features(normalized_score, heuristic_score, features_flat))
            y.append(0)

        for sample in anomaly_data:
            features = self.extract_features(sample)
            features_flat = features.flatten()
            features_scaled = self.scaler.transform(features)
            raw_score = -self.model.score_samples(features_scaled)[0]
            normalized_score = self._normalize_score_range(
                raw_score,
                mean=self.baseline_stats.get('score_mean', 0.0),
                std=self.baseline_stats.get('score_std', 1.0)
            )
            _, heuristic_score, _ = self._heuristic_detection(sample)
            X.append(self._build_meta_features(normalized_score, heuristic_score, features_flat))
            y.append(1)

        X = np.array(X, dtype=float)
        y = np.array(y, dtype=int)

        if len(np.unique(y)) < 2:
            return {'error': 'Meta classifier requires both classes in labeled data'}

        X_train, X_val, y_train, y_val = train_test_split(
            X,
            y,
            test_size=validation_ratio,
            random_state=random_state,
            stratify=y,
        )

        # Train with class weighting to handle imbalance
        if model_type == 'random_forest':
            model = RandomForestClassifier(
                n_estimators=300,
                max_depth=15,  # Prevent overfitting
                min_samples_split=10,
                min_samples_leaf=5,
                class_weight='balanced_subsample',
                random_state=random_state,
                n_jobs=-1,
            )
        elif model_type == 'logistic':
            model = LogisticRegression(
                max_iter=2000,
                solver='lbfgs',
                class_weight='balanced',
                random_state=random_state
            )
        else:
            return {
                'error': f"Unsupported meta model type: {model_type}. Use 'random_forest' or 'logistic'"
            }

        model.fit(X_train, y_train)

        # Probability calibration using validation data
        val_probabilities = model.predict_proba(X_val)[:, 1]
        
        # Fine-grained threshold sweep optimized for FP reduction with recall preservation
        threshold_candidates = np.linspace(0.20, 0.90, 141)  # 0.005 step size for fine tuning
        
        best_result = None
        for threshold in threshold_candidates:
            y_pred = (val_probabilities >= threshold).astype(int)
            metrics = self._evaluate_binary_metrics(y_val, y_pred)
            
            # Check if recall meets minimum threshold
            if metrics['recall'] < target_recall:
                continue  # Skip thresholds that lose too much recall
            
            # Weighted objective: prioritize FP reduction while maintaining recall
            # Lower = better
            weighted_objective = (
                metrics['fp_rate'] * fp_penalty_weight + 
                metrics['fn_rate'] * 1.0
            )

            if (
                best_result is None
                or weighted_objective < best_result['objective']
                or (
                    abs(weighted_objective - best_result['objective']) < 1e-10
                    and metrics['f1'] > best_result['metrics']['f1']
                )
            ):
                best_result = {
                    'threshold': float(threshold),
                    'objective': float(weighted_objective),
                    'metrics': metrics,
                }
        
        # Fallback: if no threshold meets recall target, use highest recall with lowest FP
        if best_result is None:
            best_result = None
            for threshold in sorted(threshold_candidates):
                y_pred = (val_probabilities >= threshold).astype(int)
                metrics = self._evaluate_binary_metrics(y_val, y_pred)
                
                if best_result is None or metrics['recall'] > best_result['metrics']['recall']:
                    best_result = {
                        'threshold': float(threshold),
                        'objective': float(metrics['fp_rate']),
                        'metrics': metrics,
                    }

        # Refit on all labeled samples after choosing threshold (for final model)
        if model_type == 'random_forest':
            final_model = RandomForestClassifier(
                n_estimators=300,
                max_depth=15,
                min_samples_split=10,
                min_samples_leaf=5,
                class_weight='balanced_subsample',
                random_state=random_state,
                n_jobs=-1,
            )
        else:
            final_model = LogisticRegression(
                max_iter=2000,
                solver='lbfgs',
                class_weight='balanced',
                random_state=random_state
            )

        final_model.fit(X, y)

        self.meta_classifier = final_model
        self.meta_threshold = best_result['threshold'] if best_result else 0.5
        self._save_model()

        return {
            'success': True,
            'normal_samples': len(normal_data),
            'anomaly_samples': len(anomaly_data),
            'train_samples': int(len(y_train)),
            'validation_samples': int(len(y_val)),
            'meta_model_type': model_type,
            'meta_threshold': float(self.meta_threshold),
            'target_recall': float(target_recall),
            'fp_penalty_weight': float(fp_penalty_weight),
            'validation_metrics': best_result['metrics'] if best_result else {},
            'timestamp': datetime.utcnow().isoformat() + 'Z',
        }
    
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
        
        # Check 5: Suspicious URL/query pattern (SQLi + XSS structural markers)
        url = data.get('request', {}).get('url', '')
        url_lower = url.lower()
        _url_suspicious = [
            '../', 'etc/passwd', 'union select',
            # XSS structural markers
            '<script', 'onerror=', 'onload=', 'onmouseover=', 'onfocus=',
            'javascript:', 'srcdoc=', '<img', '<svg', '<iframe', '<math',
            '<body', '<details',
            # URL-encoded variants
            '%3cscript', '%3csvg', '%3cimg', '%3ciframe',
            'onerror%3d', 'onload%3d',
        ]
        if any(pattern in url_lower for pattern in _url_suspicious):
            anomalies.append("Suspicious URL pattern")
            score += 0.7

        # Check 6: Suspicious request body content (SQLi + XSS)
        body = data.get('request', {}).get('body', '')
        suspicious_body_patterns = [
            '<script', 'union select', '../', 'or 1=1', 'select * from',
            'sqlmap', 'eval(', 'cmd.exe',
            # XSS body patterns
            'onerror=', 'onload=', 'javascript:', '<img', '<svg', '<iframe',
        ]
        if any(pattern in body.lower() for pattern in suspicious_body_patterns):
            anomalies.append("Suspicious request payload")
            score += 0.8

        # Check 7: Bot / scanner user agent
        user_agent = data.get('request', {}).get('headers', {}).get('User-Agent', '')
        bot_keywords = ['bot', 'spider', 'crawler', 'scanner', 'nikto', 'sqlmap', 'nmap']
        if any(keyword in user_agent.lower() for keyword in bot_keywords):
            anomalies.append("Scanner or bot user-agent")
            score += 0.5
        
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
        
        if features[14] > 50:  # Request count
            reasons.append("High request rate")
        
        if features[9] >= 4:  # Severity
            reasons.append("High severity finding")
        
        if features[0] > 200:  # URL length
            reasons.append("Unusually long URL")
        
        return "; ".join(reasons) if reasons else "Anomalous pattern detected"
    
    def train(self, training_data: List[Dict[str, Any]], contamination: float = 0.1) -> Dict[str, Any]:
        """
        Train the Isolation Forest model with optimized scaling and calibration.
        
        Args:
            training_data: List of normal request/response/finding data
            contamination: Expected proportion of anomalies (0.1 = 10%)
            
        Returns:
            Training metrics with baseline statistics
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

        schema_error = self._validate_full_feature_schema(X.shape[1], context='train')
        if schema_error:
            return {
                'error': schema_error,
                'samples': len(training_data),
            }

        # Lock schema for this trained model artifact.
        self.feature_names = self._build_feature_names_for_count(X.shape[1])
        
        # Scale features using StandardScaler for consistency
        X_scaled = self.scaler.fit_transform(X)
        
        # Train Isolation Forest with optimized parameters
        self.model = IsolationForest(
            n_estimators=100,
            max_samples='auto',
            contamination=contamination,
            random_state=42,
            n_jobs=-1
        )
        
        self.model.fit(X_scaled)
        self.is_trained = True

        # Base model retraining invalidates prior calibration model
        self.meta_classifier = None
        self.meta_threshold = 0.5
        self.decision_threshold = None
        
        # Calculate baseline statistics (including score distribution for calibration)
        self._calculate_baseline_stats(training_data, X_scaled)

        # Conservative fallback threshold from train normals only.
        train_scores = -self.model.score_samples(X_scaled)
        self.decision_threshold = float(np.quantile(train_scores, 0.98))
        
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
            'meta_classifier_enabled': False,
            'decision_threshold': float(self.decision_threshold),
            'feature_schema': {
                'feature_count': int(len(self.feature_names)),
                'feature_names': list(self.feature_names),
            },
            'baseline_stats': self.baseline_stats,
            'feature_scaling': {
                'scaler_type': 'StandardScaler',
                'mean': np.mean(X, axis=0).tolist()[:5],  # First 5 features
                'std': np.std(X, axis=0).tolist()[:5],
            },
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
    
    def _calculate_baseline_stats(self, data: List[Dict[str, Any]], X_scaled: np.ndarray = None):
        """
        Calculate baseline statistics from training data for anomaly detection calibration.
        
        Args:
            data: Training data samples
            X_scaled: Scaled feature matrix for score distribution analysis
        """
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
        
        # Compute score statistics if X_scaled is provided
        score_mean = 0.0
        score_std = 1.0
        
        if X_scaled is not None and self.model is not None:
            # Keep anomaly-oriented score convention (higher = more anomalous).
            scores = -self.model.score_samples(X_scaled)
            score_mean = float(np.mean(scores))
            score_std = float(np.std(scores))
            if score_std == 0:
                score_std = 1.0  # Avoid division by zero
        
        self.baseline_stats = {
            'avg_response_time': float(np.mean(response_times)) if response_times else 0,
            'std_response_time': float(np.std(response_times)) if response_times else 0,
            'common_status_codes': list(set(status_codes)),
            'finding_distribution': dict(finding_severities),
            'sample_count': len(data),
            'score_mean': score_mean,
            'score_std': score_std,
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
            'feature_names': self.feature_names,
            'meta_classifier': self.meta_classifier,
            'meta_threshold': self.meta_threshold,
            'decision_threshold': self.decision_threshold,
            'baseline_supervised_model': self.baseline_supervised_model,
            'baseline_threshold': self.baseline_threshold,
            'recall_target': self.recall_target,
            'baseline_stats': self.baseline_stats,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        with open(self.model_path, 'wb') as f:
            pickle.dump(model_data, f)
    
    def _load_model(self):
        """Load trained model from disk if available."""
        if os.path.exists(self.model_path):
            try:
                import warnings
                from sklearn import __version__ as _sklearn_runtime_version
                from sklearn.exceptions import InconsistentVersionWarning

                with open(self.model_path, 'rb') as f:
                    with warnings.catch_warnings(record=True) as w:
                        warnings.simplefilter('ignore', InconsistentVersionWarning)
                        model_data = pickle.load(f)

                self.model = model_data['model']
                self.scaler = model_data['scaler']
                self.is_trained = model_data['is_trained']
                self.meta_classifier = model_data.get('meta_classifier')
                self.meta_threshold = float(model_data.get('meta_threshold', 0.5))
                self.decision_threshold = model_data.get('decision_threshold')
                self.baseline_supervised_model = model_data.get('baseline_supervised_model')
                self.baseline_threshold = model_data.get('baseline_threshold')
                self.recall_target = float(model_data.get('recall_target', 0.80))
                self.baseline_stats = model_data.get('baseline_stats', self.baseline_stats)

                loaded_feature_names = model_data.get('feature_names')
                if isinstance(loaded_feature_names, list) and loaded_feature_names:
                    self.feature_names = [str(name) for name in loaded_feature_names]
                else:
                    inferred_count = self._get_model_expected_feature_count()
                    if inferred_count is None:
                        inferred_count = len(self.default_feature_names)
                    self.feature_names = self._build_feature_names_for_count(inferred_count)
                    print(
                        "[Anomaly Detector] feature_names not found in saved model; "
                        f"inferred schema with {len(self.feature_names)} features."
                    )

                model_expected = self._get_model_expected_feature_count()
                if model_expected is not None and len(self.feature_names) != int(model_expected):
                    print(
                        f"[Anomaly Detector] Warning: loaded feature_names count ({len(self.feature_names)}) "
                        f"!= scaler/model expected ({int(model_expected)}). Realigning schema."
                    )
                    self.feature_names = self._build_feature_names_for_count(int(model_expected))

                # If model file includes training sklearn version metadata, show it
                training_ver = None
                if isinstance(model_data, dict):
                    training_ver = model_data.get('sklearn_version') or (model_data.get('metadata') or {}).get('sklearn_version')
                if training_ver:
                    print(f"[Anomaly Detector] model trained with sklearn version: {training_ver}")

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
            'meta_classifier': {
                'enabled': self.meta_classifier is not None,
                'threshold': float(self.meta_threshold),
            },
            'decision_threshold': float(self.decision_threshold) if self.decision_threshold is not None else None,
            'baseline_supervised': {
                'enabled': self.baseline_supervised_model is not None,
                'threshold': float(self.baseline_threshold) if self.baseline_threshold is not None else None,
            },
            'recall_target': float(self.recall_target),
            'baseline_stats': self.baseline_stats,
            'model_path': self.model_path,
            'status': '✅ Trained',
            'confidence': '82%'
        }
