"""
Two-stage anomaly detection + false-positive reduction pipeline.

This module enforces strict training discipline:
- Stage 1 (Anomaly Detector): already trained on train split only.
- Stage 2 (FP Reducer): trained only from stage-1 anomaly predictions on validation.
- Test split is used only for final evaluation.
"""

from typing import Any, Dict, List, Tuple, Optional

import os
import random
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

import numpy as np
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
from sklearn.model_selection import train_test_split

try:
    from .anomaly_detector import AnomalyDetector
    from .anomaly_false_positive_reducer import FalsePositiveReducer
except ImportError:
    # Support direct module usage when importing from "ml" directory itself.
    from anomaly_detector import AnomalyDetector
    from anomaly_false_positive_reducer import FalsePositiveReducer


def create_strict_split(
    samples: List[Dict[str, Any]],
    labels: List[int],
    train_ratio: float = 0.60,
    validation_ratio: float = 0.20,
    test_ratio: float = 0.20,
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Create a strict 60/20/20 split with stratification.

    Returns a dictionary containing train/validation/test samples and labels.
    """
    ratio_sum = train_ratio + validation_ratio + test_ratio
    if abs(ratio_sum - 1.0) > 1e-9:
        return {'error': f'Split ratios must sum to 1.0, got {ratio_sum}'}

    if len(samples) != len(labels):
        return {'error': 'samples and labels length mismatch'}

    y = np.asarray(labels, dtype=int)
    if len(np.unique(y)) < 2:
        return {'error': 'Need both normal (0) and attack/anomaly (1) labels'}

    all_indices = np.arange(len(y))
    train_indices, temp_indices, y_train, y_temp = train_test_split(
        all_indices,
        y,
        test_size=(1.0 - train_ratio),
        random_state=random_state,
        stratify=y,
    )

    relative_test_ratio = test_ratio / (validation_ratio + test_ratio)
    val_indices, test_indices, y_val, y_test = train_test_split(
        temp_indices,
        y_temp,
        test_size=relative_test_ratio,
        random_state=random_state,
        stratify=y_temp,
    )

    train_samples = [samples[int(i)] for i in train_indices]
    val_samples = [samples[int(i)] for i in val_indices]
    test_samples = [samples[int(i)] for i in test_indices]

    return {
        'success': True,
        'train_samples': train_samples,
        'validation_samples': val_samples,
        'test_samples': test_samples,
        'train_labels': y_train.astype(int).tolist(),
        'validation_labels': y_val.astype(int).tolist(),
        'test_labels': y_test.astype(int).tolist(),
        'split_summary': {
            'train_total': int(len(y_train)),
            'train_normal': int(np.sum(y_train == 0)),
            'train_attack': int(np.sum(y_train == 1)),
            'validation_total': int(len(y_val)),
            'validation_normal': int(np.sum(y_val == 0)),
            'validation_attack': int(np.sum(y_val == 1)),
            'test_total': int(len(y_test)),
            'test_normal': int(np.sum(y_test == 0)),
            'test_attack': int(np.sum(y_test == 1)),
        },
    }


def _compute_binary_metrics(y_true: List[int], y_pred: List[int]) -> Dict[str, Any]:
    """Compute precision, recall, F1, FP rate and confusion matrix."""
    y_true_np = np.asarray(y_true, dtype=int)
    y_pred_np = np.asarray(y_pred, dtype=int)

    precision = float(precision_score(y_true_np, y_pred_np, zero_division=0))
    recall = float(recall_score(y_true_np, y_pred_np, zero_division=0))
    f1 = float(f1_score(y_true_np, y_pred_np, zero_division=0))

    cm = confusion_matrix(y_true_np, y_pred_np, labels=[0, 1])
    tn, fp, fn, tp = [int(v) for v in cm.ravel()]
    fp_rate = float(fp / (fp + tn)) if (fp + tn) else 0.0

    return {
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'fp_rate': fp_rate,
        'confusion_matrix': {
            'tn': tn,
            'fp': fp,
            'fn': fn,
            'tp': tp,
        },
    }


def _safe_int(value: Any, default: int = 0) -> int:
    """Convert to int safely with fallback."""
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return int(default)


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Convert to float safely with fallback."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _clone_sample(sample: Dict[str, Any]) -> Dict[str, Any]:
    """Create a shallow-but-safe clone for request/response mutation."""
    cloned = dict(sample)

    request = dict(sample.get('request', {}))
    headers = request.get('headers', {})
    if isinstance(headers, dict):
        request['headers'] = dict(headers)
    cloned['request'] = request

    response = dict(sample.get('response', {}))
    response_headers = response.get('headers', {})
    if isinstance(response_headers, dict):
        response['headers'] = dict(response_headers)
    cloned['response'] = response

    return cloned


def _derive_category(url: str, payload: str) -> str:
    """
    Map to a coarse category using structure-only cues.

    This intentionally avoids direct attack keywords like script/union.
    """
    split = urlsplit(url if url else 'http://localhost/')
    query = split.query or ''
    path = split.path or '/'

    encoded_ratio = payload.count('%') / max(1, len(payload))
    param_count = len([part for part in query.split('&') if part]) if query else 0
    path_depth = path.count('/')
    punct_count = sum(1 for ch in payload if not ch.isalnum() and not ch.isspace())
    punct_density = punct_count / max(1, len(payload))

    if encoded_ratio >= 0.10:
        return 'Security Misconfiguration'
    if param_count >= 10:
        return 'Information Disclosure'
    if path_depth >= 8:
        return 'Directory Listing'
    if punct_density >= 0.25:
        return 'Header'
    return 'Security Misconfiguration'


def _derive_severity(anomaly_score: float) -> str:
    """Derive a severity level proxy from anomaly score."""
    score = float(np.clip(anomaly_score, 0.0, 1.0))
    if score >= 0.90:
        return 'critical'
    if score >= 0.75:
        return 'high'
    if score >= 0.55:
        return 'medium'
    if score >= 0.35:
        return 'low'
    return 'info'


def _sample_to_fp_entry(sample: Dict[str, Any], anomaly_score: float, anomaly_reason: str) -> Dict[str, Any]:
    """Convert an anomaly sample to FP reducer expected format (finding + context)."""
    request = sample.get('request', {})
    response = sample.get('response', {})

    url = str(request.get('url', ''))
    body = str(request.get('body', ''))
    payload = f"{url} {body}".strip()

    finding = {
        'severity': _derive_severity(anomaly_score),
        'category': _derive_category(url, payload),
        'evidence': payload[:600],
        # Keep description generic to avoid leaking direct payload keywords to stage-2.
        'description': 'Stage-1 behavioral anomaly signal from request/response statistics.',
        'url': url,
        'cvss_score': round(float(np.clip(anomaly_score * 10.0, 0.0, 10.0)), 2),
        'risk_score': round(float(np.clip(anomaly_score * 10.0, 0.0, 10.0)), 2),
    }

    context = {
        'status_code': _safe_int(response.get('status_code', 200), 200),
        'response_time': _safe_float(response.get('time', 0.0), 0.0),
        'occurrence_count': _safe_int(sample.get('request_count_last_minute', 1), 1),
        'days_since_first_seen': _safe_int(sample.get('days_since_first_seen', 0), 0),
    }

    return {
        'finding': finding,
        'context': context,
    }


def _pick_with_replacement(items: List[Dict[str, Any]], count: int, rng: random.Random) -> List[Dict[str, Any]]:
    """Sample templates with replacement."""
    if count <= 0 or not items:
        return []
    return [items[rng.randrange(len(items))] for _ in range(count)]


def _build_hard_negative_sample(sample: Dict[str, Any], rng: random.Random) -> Dict[str, Any]:
    """
    Build a normal sample that looks suspicious.

    Traits:
    - long URL path
    - many query params
    - encoded values
    - unusual but valid traffic shape
    """
    cloned = _clone_sample(sample)
    request = cloned.setdefault('request', {})
    response = cloned.setdefault('response', {})

    raw_url = str(request.get('url', 'http://localhost/course/view.php'))
    split = urlsplit(raw_url if raw_url else 'http://localhost/course/view.php')

    segment_pool = [
        'catalog', 'release', 'documentation', 'backup',
        'archive', 'reporting', 'overview', 'module'
    ]
    extra_segments = [rng.choice(segment_pool) for _ in range(rng.randint(4, 8))]
    base_path = split.path or '/course/view.php'
    new_path = (base_path.rstrip('/') + '/' + '/'.join(extra_segments)).replace('//', '/')

    query_parts: List[str] = []
    for key, value in parse_qsl(split.query, keep_blank_values=True)[:3]:
        query_parts.append(f"{key}={quote(str(value), safe='')}")

    for idx in range(rng.randint(10, 16)):
        key = f"opt{idx}_{rng.choice(['view', 'tab', 'sort', 'layout', 'lang'])}"
        if idx % 2 == 0:
            value = quote(f"{rng.choice(segment_pool)} {rng.randint(1, 40)}/v{rng.randint(1, 9)}", safe='')
        else:
            value = quote(f"{rng.choice(['alpha', 'beta', 'rc'])}_{rng.randint(100, 999)}", safe='')
        query_parts.append(f"{key}={value}")

    new_url = urlunsplit((
        split.scheme or 'http',
        split.netloc or 'localhost',
        new_path,
        '&'.join(query_parts),
        split.fragment,
    ))
    request['url'] = new_url
    request['method'] = str(request.get('method', 'GET')).upper()

    if request['method'] == 'POST':
        request['body'] = (
            f"action=preview&section={quote('course overview', safe='')}&"
            f"note={quote('release candidate build', safe='')}"
        )

    base_rate = _safe_int(sample.get('request_count_last_minute', 1), 1)
    cloned['request_count_last_minute'] = int(max(5, base_rate) + rng.randint(6, 20))
    cloned['unique_ips_last_minute'] = _safe_int(sample.get('unique_ips_last_minute', 1), 1)
    cloned['error_rate_last_minute'] = float(np.clip(_safe_float(sample.get('error_rate_last_minute', 0.0), 0.0), 0.0, 1.0))

    status_code = _safe_int(response.get('status_code', 200), 200)
    response['status_code'] = 200 if status_code >= 400 else status_code
    response['time'] = float(max(120.0, _safe_float(response.get('time', 120.0), 120.0) + rng.randint(20, 320)))

    return cloned


def _build_subtle_attack_sample(sample: Dict[str, Any], rng: random.Random, profile: str = 'train') -> Dict[str, Any]:
    """
    Build less-obvious attack variants.

    These avoid obvious literal patterns like <script> and instead use
    partial/encoded/obfuscated forms.
    """
    cloned = _clone_sample(sample)
    request = cloned.setdefault('request', {})
    response = cloned.setdefault('response', {})

    raw_url = str(request.get('url', 'http://localhost/search.php'))
    split = urlsplit(raw_url if raw_url else 'http://localhost/search.php')
    scheme = split.scheme or 'http'
    netloc = split.netloc or 'localhost'
    base_path = split.path or '/search.php'

    train_payloads = [
        ('id', '1%20aNd%201%3D1'),
        ('filter', 'name%27%20aNd%20substr%28user%28%29%2C1%2C1%29%3D%27a'),
        ('redirect', 'jaVa%73cr%69pt%3Aconfirm%281%29'),
        ('template', '${7*7}'),
        ('file', '..%252f..%252fconfig%252ephp'),
    ]
    test_payloads = [
        ('sort', 'price/**/desc'),
        ('search', 'admin%2527%2520oR%25201%253D1'),
        ('next', 'j%61v%61script%3Aalert%281%29'),
        ('view', '%2e%2e%252f%2e%2e%252fetc%252fpasswd'),
        ('expr', '${{7*7}}'),
    ]
    payload_templates = test_payloads if profile == 'test' else train_payloads
    key, payload = rng.choice(payload_templates)

    query_parts: List[str] = []
    for existing_key, existing_value in parse_qsl(split.query, keep_blank_values=True)[:4]:
        query_parts.append(f"{existing_key}={quote(str(existing_value), safe='')}")
    query_parts.append(f"{key}={payload}")
    if rng.random() < 0.60:
        query_parts.append(f"page={rng.randint(1, 5)}")

    path = base_path
    if profile == 'test' and not path.startswith('/api/v2/'):
        path = '/api/v2' + path

    request['url'] = urlunsplit((scheme, netloc, path, '&'.join(query_parts), split.fragment))
    request['method'] = str(request.get('method', 'GET')).upper()

    if request['method'] == 'POST' or rng.random() < 0.40:
        request['method'] = 'POST'
        request['body'] = rng.choice([
            f"username=admin&check=1%2527%20aNd%201%3D1&trace={quote('module preview', safe='')}",
            f"search={quote('catalog import', safe='')}&filter={payload}",
            f"data={quote('id=' + payload, safe='')}&mode=preview",
        ])

    base_rate = _safe_int(sample.get('request_count_last_minute', 1), 1)
    cloned['request_count_last_minute'] = int(max(3, base_rate) + rng.randint(3, 15))
    cloned['unique_ips_last_minute'] = int(max(1, _safe_int(sample.get('unique_ips_last_minute', 1), 1) + rng.randint(0, 2)))

    response['status_code'] = int(rng.choice([200, 200, 302, 400, 500]))
    response['time'] = float(max(180.0, _safe_float(response.get('time', 120.0), 120.0) + rng.randint(80, 900)))

    return cloned


def build_challenge_set(
    samples: List[Dict[str, Any]],
    labels: List[int],
    hard_negative_ratio: float = 0.20,
    subtle_attack_ratio: float = 0.12,
    random_state: int = 42,
    profile: str = 'train',
) -> Dict[str, Any]:
    """
    Build synthetic challenge samples for robust stage-2 training/evaluation.

    Hard negatives: normal-but-suspicious requests.
    Subtle attacks: obfuscated/encoded/partial attack patterns.
    """
    if len(samples) != len(labels):
        return {'error': 'samples and labels length mismatch for challenge set'}

    rng = random.Random(int(random_state))

    normal_samples = [sample for sample, label in zip(samples, labels) if int(label) == 0]
    attack_samples = [sample for sample, label in zip(samples, labels) if int(label) == 1]

    hard_target = int(round(len(samples) * max(0.0, hard_negative_ratio)))
    subtle_target = int(round(len(samples) * max(0.0, subtle_attack_ratio)))

    if hard_target == 0 and hard_negative_ratio > 0 and normal_samples:
        hard_target = 1
    if subtle_target == 0 and subtle_attack_ratio > 0 and (attack_samples or normal_samples):
        subtle_target = 1

    challenge_samples: List[Dict[str, Any]] = []
    challenge_labels: List[int] = []

    for template in _pick_with_replacement(normal_samples, hard_target, rng):
        challenge_samples.append(_build_hard_negative_sample(template, rng))
        challenge_labels.append(0)

    attack_templates = attack_samples if attack_samples else normal_samples
    for template in _pick_with_replacement(attack_templates, subtle_target, rng):
        challenge_samples.append(_build_subtle_attack_sample(template, rng, profile=profile))
        challenge_labels.append(1)

    return {
        'success': True,
        'samples': challenge_samples,
        'labels': challenge_labels,
        'summary': {
            'profile': profile,
            'hard_negative_samples': int(sum(1 for label in challenge_labels if int(label) == 0)),
            'subtle_attack_samples': int(sum(1 for label in challenge_labels if int(label) == 1)),
            'total_challenge_samples': int(len(challenge_samples)),
        },
    }


def _apply_distribution_shift(
    samples: List[Dict[str, Any]],
    labels: List[int],
    random_state: int,
) -> Dict[str, Any]:
    """Apply mild distribution shift to evaluation samples while preserving labels."""
    if len(samples) != len(labels):
        return {'error': 'samples and labels length mismatch for distribution shift'}

    rng = random.Random(int(random_state))
    shifted_samples: List[Dict[str, Any]] = []
    shifted_count = 0

    for sample in samples:
        cloned = _clone_sample(sample)
        request = cloned.setdefault('request', {})
        response = cloned.setdefault('response', {})

        if rng.random() < 0.45:
            raw_url = str(request.get('url', 'http://localhost/'))
            split = urlsplit(raw_url if raw_url else 'http://localhost/')

            pairs = parse_qsl(split.query, keep_blank_values=True)
            rng.shuffle(pairs)
            if rng.random() < 0.50:
                pairs.append((f"ctx{rng.randint(1, 9)}", str(rng.randint(10, 999))))

            shifted_host = rng.choice(['localhost', '127.0.0.1:8080', 'moodle.local'])
            shifted_path = split.path or '/'
            if rng.random() < 0.35 and not shifted_path.startswith('/v2/'):
                shifted_path = '/v2' + shifted_path

            request['url'] = urlunsplit((
                split.scheme or 'http',
                shifted_host,
                shifted_path,
                urlencode(pairs, doseq=True),
                split.fragment,
            ))
            shifted_count += 1

        base_time = max(0.0, _safe_float(response.get('time', 0.0), 0.0))
        response['time'] = float(max(20.0, base_time * rng.uniform(0.70, 1.60) + rng.randint(0, 120)))

        shifted_samples.append(cloned)

    return {
        'success': True,
        'samples': shifted_samples,
        'labels': [int(label) for label in labels],
        'summary': {
            'distribution_shifted_samples': int(shifted_count),
            'distribution_total_samples': int(len(shifted_samples)),
        },
    }


def generate_fp_training_data(
    anomaly_detector: AnomalyDetector,
    validation_samples: List[Dict[str, Any]],
    validation_labels: List[int],
    include_challenge_samples: bool = True,
    hard_negative_ratio: float = 0.20,
    subtle_attack_ratio: float = 0.12,
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Build FP reducer dataset from stage-1 validation predictions only.

    Rule:
    - keep only samples where stage-1 predicts anomaly
    - label for stage-2:
      * true normal (0)  -> FP class 1
      * true attack (1)  -> TP class 0
    """
    if not anomaly_detector or not anomaly_detector.is_trained:
        return {'error': 'Anomaly detector must be trained before generating FP reducer data'}

    if len(validation_samples) != len(validation_labels):
        return {'error': 'validation_samples and validation_labels length mismatch'}

    fp_training_data: List[Dict[str, Any]] = []
    fp_labels: List[int] = []

    evaluation_samples = list(validation_samples)
    evaluation_labels = [int(label) for label in validation_labels]

    challenge_summary = {
        'profile': 'disabled',
        'hard_negative_samples': 0,
        'subtle_attack_samples': 0,
        'total_challenge_samples': 0,
    }

    if include_challenge_samples:
        challenge_data = build_challenge_set(
            samples=validation_samples,
            labels=validation_labels,
            hard_negative_ratio=hard_negative_ratio,
            subtle_attack_ratio=subtle_attack_ratio,
            random_state=random_state,
            profile='train',
        )
        if challenge_data.get('success'):
            evaluation_samples.extend(challenge_data.get('samples', []))
            evaluation_labels.extend([int(label) for label in challenge_data.get('labels', [])])
            challenge_summary = challenge_data.get('summary', challenge_summary)

    stage1_predicted_anomalies = 0
    fp_class_count = 0
    tp_class_count = 0

    for sample, true_label in zip(evaluation_samples, evaluation_labels):
        predicted_anomaly, anomaly_score, anomaly_reason = anomaly_detector.detect(sample, use_meta=False)
        if not predicted_anomaly:
            continue

        stage1_predicted_anomalies += 1
        entry = _sample_to_fp_entry(sample, anomaly_score, anomaly_reason)

        if int(true_label) == 0:
            # Stage-1 false positive.
            label = 1
            fp_class_count += 1
        else:
            # Stage-1 true positive.
            label = 0
            tp_class_count += 1

        fp_training_data.append(entry)
        fp_labels.append(label)

    return {
        'success': True,
        'training_data': fp_training_data,
        'labels': fp_labels,
        'summary': {
            'validation_samples': len(validation_samples),
            'augmented_validation_samples': len(evaluation_samples),
            'stage1_predicted_anomalies': stage1_predicted_anomalies,
            'fp_class_count': fp_class_count,
            'tp_class_count': tp_class_count,
            'dataset_size': len(fp_training_data),
            'challenge_set': challenge_summary,
        },
    }


def train_fp_reducer(
    fp_reducer: FalsePositiveReducer,
    fp_dataset: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Train FP reducer only on data generated from stage-1 validation predictions.

    The FP reducer's existing internal model already uses class_weight='balanced'
    in its RandomForest component.
    """
    if not fp_dataset.get('success'):
        return {'error': 'Invalid FP dataset', 'details': fp_dataset}

    training_data = fp_dataset.get('training_data', [])
    labels = fp_dataset.get('labels', [])

    if len(training_data) < 10:
        return {
            'error': 'Insufficient FP reducer training samples (need >=10 predicted anomalies)',
            'samples': len(training_data),
            'summary': fp_dataset.get('summary', {}),
        }

    unique_labels = sorted(set(int(v) for v in labels))
    if len(unique_labels) < 2:
        return {
            'error': 'FP reducer training requires both classes from stage-1 outputs (FP=1 and TP=0)',
            'samples': len(training_data),
            'unique_labels': unique_labels,
            'summary': fp_dataset.get('summary', {}),
        }

    result = fp_reducer.train(training_data, labels)
    result['stage2_training_summary'] = fp_dataset.get('summary', {})
    result['class_balance'] = {
        'tp_class_0': int(sum(1 for v in labels if int(v) == 0)),
        'fp_class_1': int(sum(1 for v in labels if int(v) == 1)),
    }
    return result


def evaluate_full_pipeline(
    anomaly_detector: AnomalyDetector,
    fp_reducer: FalsePositiveReducer,
    test_samples: List[Dict[str, Any]],
    test_labels: List[int],
    include_challenge_samples: bool = True,
    hard_negative_ratio: float = 0.20,
    subtle_attack_ratio: float = 0.12,
    apply_distribution_shift: bool = True,
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Evaluate stage-1 only vs stage-1+stage-2 on test split.

    No tuning is performed here. Test split is used only for final metrics.
    """
    if not anomaly_detector or not anomaly_detector.is_trained:
        return {'error': 'Anomaly detector must be trained before evaluation'}

    if not fp_reducer or not fp_reducer.is_trained:
        return {'error': 'FP reducer must be trained before full pipeline evaluation'}

    if len(test_samples) != len(test_labels):
        return {'error': 'test_samples and test_labels length mismatch'}

    evaluation_samples = list(test_samples)
    evaluation_labels = [int(label) for label in test_labels]

    challenge_summary = {
        'profile': 'disabled',
        'hard_negative_samples': 0,
        'subtle_attack_samples': 0,
        'total_challenge_samples': 0,
    }
    if include_challenge_samples:
        challenge_data = build_challenge_set(
            samples=test_samples,
            labels=test_labels,
            hard_negative_ratio=hard_negative_ratio,
            subtle_attack_ratio=subtle_attack_ratio,
            random_state=random_state + 911,
            profile='test',
        )
        if challenge_data.get('success'):
            evaluation_samples.extend(challenge_data.get('samples', []))
            evaluation_labels.extend([int(label) for label in challenge_data.get('labels', [])])
            challenge_summary = challenge_data.get('summary', challenge_summary)

    shift_summary = {
        'distribution_shifted_samples': 0,
        'distribution_total_samples': len(evaluation_samples),
    }
    if apply_distribution_shift:
        shifted = _apply_distribution_shift(
            samples=evaluation_samples,
            labels=evaluation_labels,
            random_state=random_state + 1777,
        )
        if shifted.get('success'):
            evaluation_samples = shifted.get('samples', evaluation_samples)
            evaluation_labels = shifted.get('labels', evaluation_labels)
            shift_summary = shifted.get('summary', shift_summary)

    y_true: List[int] = []
    y_pred_stage1: List[int] = []
    y_pred_full: List[int] = []

    stage1_predicted_anomalies = 0
    stage2_filtered_as_fp = 0

    for sample, label in zip(evaluation_samples, evaluation_labels):
        true_label = int(label)
        y_true.append(true_label)

        stage1_anomaly, anomaly_score, anomaly_reason = anomaly_detector.detect(sample, use_meta=False)
        stage1_label = 1 if stage1_anomaly else 0
        y_pred_stage1.append(stage1_label)

        if stage1_label == 1:
            stage1_predicted_anomalies += 1
            fp_entry = _sample_to_fp_entry(sample, anomaly_score, anomaly_reason)
            is_false_positive, _ = fp_reducer.predict(
                fp_entry['finding'],
                fp_entry['context'],
            )
            if is_false_positive:
                # Remove anomaly alert.
                y_pred_full.append(0)
                stage2_filtered_as_fp += 1
            else:
                y_pred_full.append(1)
        else:
            y_pred_full.append(0)

    stage1_metrics = _compute_binary_metrics(y_true, y_pred_stage1)
    full_metrics = _compute_binary_metrics(y_true, y_pred_full)

    fp_rate_reduction_abs = stage1_metrics['fp_rate'] - full_metrics['fp_rate']
    fp_rate_reduction_pct = 0.0
    if stage1_metrics['fp_rate'] > 0:
        fp_rate_reduction_pct = fp_rate_reduction_abs / stage1_metrics['fp_rate']

    recall_drop = stage1_metrics['recall'] - full_metrics['recall']

    return {
        'success': True,
        'base_test_samples': len(test_samples),
        'test_samples': len(evaluation_samples),
        'stage1_predicted_anomalies': stage1_predicted_anomalies,
        'stage2_filtered_as_fp': stage2_filtered_as_fp,
        'anomaly_detector_only': stage1_metrics,
        'full_pipeline': full_metrics,
        'evaluation_profile': {
            'challenge_set': challenge_summary,
            'distribution_shift': shift_summary,
        },
        'comparison': {
            'fp_rate_reduction_abs': float(fp_rate_reduction_abs),
            'fp_rate_reduction_pct': float(fp_rate_reduction_pct),
            'recall_drop': float(recall_drop),
        },
    }


def _aggregate_metric(values: List[float]) -> Dict[str, float]:
    """Aggregate metric values into mean/std/min/max."""
    if not values:
        return {
            'mean': 0.0,
            'std': 0.0,
            'min': 0.0,
            'max': 0.0,
        }

    arr = np.asarray(values, dtype=float)
    return {
        'mean': float(np.mean(arr)),
        'std': float(np.std(arr)),
        'min': float(np.min(arr)),
        'max': float(np.max(arr)),
    }


def _aggregate_cv_results(fold_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build aggregate summary for all completed CV folds."""
    sections = ['anomaly_detector_only', 'full_pipeline']
    metric_names = ['precision', 'recall', 'f1', 'fp_rate']

    aggregate: Dict[str, Any] = {
        'anomaly_detector_only': {},
        'full_pipeline': {},
        'comparison': {},
    }

    for section in sections:
        for metric_name in metric_names:
            values = [float(run[section][metric_name]) for run in fold_results]
            aggregate[section][metric_name] = _aggregate_metric(values)

    for metric_name in ['fp_rate_reduction_abs', 'fp_rate_reduction_pct', 'recall_drop']:
        values = [float(run['comparison'][metric_name]) for run in fold_results]
        aggregate['comparison'][metric_name] = _aggregate_metric(values)

    aggregate['stage1_predicted_anomalies'] = _aggregate_metric([
        float(run['stage1_predicted_anomalies']) for run in fold_results
    ])
    aggregate['stage2_filtered_as_fp'] = _aggregate_metric([
        float(run['stage2_filtered_as_fp']) for run in fold_results
    ])

    return aggregate


def cross_validate_two_stage_pipeline(
    anomaly_detector: AnomalyDetector,
    samples: List[Dict[str, Any]],
    labels: List[int],
    n_splits: int = 5,
    start_random_state: int = 42,
    include_challenge_samples: bool = True,
    hard_negative_ratio: float = 0.20,
    subtle_attack_ratio: float = 0.12,
    apply_distribution_shift: bool = True,
    model_path_prefix: str = 'ml/models/fp_reducer_cv',
    cleanup_models: bool = True,
) -> Dict[str, Any]:
    """
    Evaluate two-stage pipeline across multiple random splits.

    This reports average metrics and fold variability instead of a single split.
    """
    if not anomaly_detector or not anomaly_detector.is_trained:
        return {'error': 'Anomaly detector must be trained before cross-validation'}

    if len(samples) != len(labels):
        return {'error': 'samples and labels length mismatch'}

    if n_splits < 2:
        return {'error': 'n_splits must be >= 2'}

    fold_results: List[Dict[str, Any]] = []
    skipped_folds: List[Dict[str, Any]] = []

    random_states = [int(start_random_state + 37 * idx) for idx in range(n_splits)]

    for fold_idx, split_seed in enumerate(random_states, start=1):
        split = create_strict_split(
            samples=samples,
            labels=labels,
            train_ratio=0.60,
            validation_ratio=0.20,
            test_ratio=0.20,
            random_state=split_seed,
        )
        if not split.get('success'):
            skipped_folds.append({
                'fold': fold_idx,
                'random_state': split_seed,
                'reason': split.get('error', 'split_failed'),
            })
            continue

        fp_dataset = generate_fp_training_data(
            anomaly_detector=anomaly_detector,
            validation_samples=split['validation_samples'],
            validation_labels=split['validation_labels'],
            include_challenge_samples=include_challenge_samples,
            hard_negative_ratio=hard_negative_ratio,
            subtle_attack_ratio=subtle_attack_ratio,
            random_state=split_seed,
        )
        if not fp_dataset.get('success'):
            skipped_folds.append({
                'fold': fold_idx,
                'random_state': split_seed,
                'reason': fp_dataset.get('error', 'fp_dataset_failed'),
            })
            continue

        model_path = f"{model_path_prefix}_{split_seed}.pkl"
        try:
            if os.path.exists(model_path):
                os.remove(model_path)
        except OSError:
            pass

        fp_reducer = FalsePositiveReducer(model_path=model_path)
        train_result = train_fp_reducer(fp_reducer, fp_dataset)
        if not train_result.get('success'):
            skipped_folds.append({
                'fold': fold_idx,
                'random_state': split_seed,
                'reason': train_result.get('error', 'fp_training_failed'),
            })
            if cleanup_models:
                try:
                    if os.path.exists(model_path):
                        os.remove(model_path)
                except OSError:
                    pass
            continue

        eval_result = evaluate_full_pipeline(
            anomaly_detector=anomaly_detector,
            fp_reducer=fp_reducer,
            test_samples=split['test_samples'],
            test_labels=split['test_labels'],
            include_challenge_samples=include_challenge_samples,
            hard_negative_ratio=hard_negative_ratio,
            subtle_attack_ratio=subtle_attack_ratio,
            apply_distribution_shift=apply_distribution_shift,
            random_state=split_seed,
        )

        if not eval_result.get('success'):
            skipped_folds.append({
                'fold': fold_idx,
                'random_state': split_seed,
                'reason': eval_result.get('error', 'evaluation_failed'),
            })
            if cleanup_models:
                try:
                    if os.path.exists(model_path):
                        os.remove(model_path)
                except OSError:
                    pass
            continue

        fold_results.append({
            'fold': fold_idx,
            'random_state': split_seed,
            'split_summary': split.get('split_summary', {}),
            'stage2_training_summary': fp_dataset.get('summary', {}),
            'stage1_predicted_anomalies': eval_result['stage1_predicted_anomalies'],
            'stage2_filtered_as_fp': eval_result['stage2_filtered_as_fp'],
            'anomaly_detector_only': eval_result['anomaly_detector_only'],
            'full_pipeline': eval_result['full_pipeline'],
            'comparison': eval_result['comparison'],
            'evaluation_profile': eval_result.get('evaluation_profile', {}),
            'evaluated_test_samples': eval_result['test_samples'],
        })

        if cleanup_models:
            try:
                if os.path.exists(model_path):
                    os.remove(model_path)
            except OSError:
                pass

    if not fold_results:
        return {
            'error': 'No CV folds completed successfully',
            'folds_requested': n_splits,
            'skipped_folds': skipped_folds,
        }

    return {
        'success': True,
        'folds_requested': n_splits,
        'folds_completed': len(fold_results),
        'fold_results': fold_results,
        'aggregate_metrics': _aggregate_cv_results(fold_results),
        'skipped_folds': skipped_folds,
    }
