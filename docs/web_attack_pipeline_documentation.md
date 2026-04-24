# Web Attack Detection Pipeline Documentation

## 1. System Overview
This system is designed to detect web attacks from HTTP request traffic and reduce false positives through a multi-stage machine learning pipeline.

The main goal is not only to detect suspicious activity, but also to provide more actionable and realistic security decisions for a SOC-like workflow.

Why a multi-stage pipeline is used:
- A single model is often not enough for security traffic because attack patterns are complex and noisy.
- The anomaly detector focuses on high recall, so potential attacks are rarely missed.
- The attack classifier adds interpretation by predicting attack type.
- The decision engine converts model outputs into operational actions such as BLOCK, ALERT, or IGNORE.
- This staged design helps reduce alert fatigue while keeping detection sensitivity high.

## 2. Architecture Diagram (Text-Based)
```
[ Request ]
     ↓
[ Anomaly Detector ]
     ↓
[ Attack Classifier ]
     ↓
[ Decision Engine ]
     ↓
[ Output / Alert ]
```

Flow explanation:
- Request: Raw HTTP request enters the pipeline.
- Anomaly Detector: Checks whether behavior is anomalous.
- Attack Classifier: If anomalous, predicts probable attack type.
- Decision Engine: Combines anomaly score, attack type, and confidence to produce action.
- Output/Alert: Final result is sent as an operational decision.

## 3. Module Explanation

### 3.1 Anomaly Detector
Purpose:
- Detect anomalous requests with high recall so suspicious traffic is not missed.

Model used:
- Isolation Forest.

Training strategy:
- Mostly trained on normal behavior profiles.
- Uses unsupervised anomaly learning.

Feature examples:
- Request length and structure-based indicators.
- Entropy-based features.
- Encoding and payload complexity patterns.
- Behavioral/request-context signals.

Output:
- anomaly_score (numeric score, typically 0 to 1 after normalization).
- anomaly flag (anomalous or not anomalous).

Example performance (target behavior):
- Precision: ~0.69
- Recall: ~1.0
- F1-score: ~0.82
- High false positives are expected at this stage because recall is prioritized.

### 3.2 Attack Classifier
Purpose:
- Classify the type of attack from anomalous requests.

Model used:
- Random Forest as main model.
- Logistic Regression for comparison.

Training strategy:
- Supervised learning.
- Trained on synthetic and augmented web attack data.

Feature examples:
- Structural request features (length, parameter count, path depth).
- Entropy and encoding features.
- Character-level signals.
- Limited keyword signals (not keyword-only dependence).

Typical realistic performance after dataset improvements:
- Accuracy: ~0.75 to ~0.80

### 3.3 Decision Engine
Purpose:
- Convert model signals into actionable security decisions.

Inputs:
- anomaly_score
- attack_type
- confidence

Outputs:
- decision (BLOCK / ALERT / IGNORE)
- severity (HIGH / MEDIUM / LOW)
- reason (human-readable explanation)

Logic characteristics:
- Threshold-based decision tiers.
- Uncertainty handling for borderline cases.
- Slight controlled randomness to simulate real SOC uncertainty and avoid perfectly rigid behavior.

### 3.4 Pipeline Orchestrator
Purpose:
- Integrate all modules into one end-to-end request processing pipeline.

Flow:
- Receive request.
- Run anomaly detector.
- If anomalous, run attack classifier.
- Pass outputs to decision engine.
- Return unified final decision payload.

Responsibilities:
- Request normalization from proxy/scanner input format.
- Logging of key fields (path, decision, attack type, severity).
- Error fallback handling so pipeline remains operational.

## 4. Dataset
Source:
- Synthetic Moodle attack dataset.
- Augmented attack samples for realism and harder classification.

Data schema:
- request_raw
- method
- path
- query_params
- body
- headers
- label
- attack_type

Current limitations:
- Synthetic bias still exists.
- Traffic does not fully represent real production behavior.

Planned improvement:
- Integrate real scanner/proxy traffic and validated labels to improve generalization.

## 5. Training Strategy
General strategy:
- Use strict train/test separation.
- Prevent data leakage.
- Apply stratified sampling for class balance in split.

Typical split setup:
- Attack classifier: 80/20 train-test stratified split.
- Anomaly detector pipeline: can use 60/20/20 train-validation-test for threshold tuning.

Training separation:
- Anomaly detector is trained separately from attack classifier.
- Classifier training is supervised by attack_type labels.

Optional extension:
- Add a false-positive reducer stage after anomaly detection for further alert quality improvement.

## 6. Evaluation Results

### Anomaly Detector
- Precision: ~0.69
- Recall: ~1.0
- F1: ~0.82

### Attack Classifier
- Accuracy: ~0.79
- F1: ~0.77

Interpretation:
- Recall is prioritized in anomaly detection to minimize missed attacks.
- Higher false positives in early stage are acceptable by design.
- The classifier and decision engine improve interpretation and action quality, reducing operational noise.

## 7. System Advantages
- High recall for suspicious traffic detection.
- Modular architecture that is easy to extend and maintain.
- Better false-positive management using classifier and decision layers.
- Suitable for SOC-like alert triage and decision support.

## 8. Limitations
- Dataset still contains synthetic patterns.
- Not fully validated on large-scale real traffic.
- Classifier performance depends strongly on data quality and diversity.

## 9. Future Work
- Integrate real proxy/scanner traffic with verified labels.
- Continue improving dataset realism and hard-negative sampling.
- Add a dedicated false-positive reduction stage.
- Deploy as a near real-time service for practical security monitoring.
