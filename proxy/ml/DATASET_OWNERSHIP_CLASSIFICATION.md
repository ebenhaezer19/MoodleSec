# MoodleSec Dataset Ownership Classification

Date: 2026-05-03
Scope: Architecture stabilization phase dataset ownership map (no file moves/deletes).

## 1) Runtime Datasets

Purpose: data consumed by live runtime services (proxy request processing / scanner runtime).

- `proxy/data/*.db` (operational state, not ML training corpus):
  - `proxy/data/scan_history.db`
  - `proxy/data/payload_repository.db`
  - `proxy/data/scheduler.db`
- Runtime ML modules (`proxy/ml/*`) are model-driven and do not require large
  training corpora at request-time.

## 2) Training Datasets

Purpose: model training and retraining inputs.

- Canonical active training corpus location:
  - `proxy/ml/training_data/` (large historical and generated datasets)
- Legacy/secondary training corpus location:
  - `ml/training_data/` (still referenced by many scripts)

Reference volume (grep on Python code):

- `ml/training_data` references: high (legacy-dominant)
- `proxy/ml/training_data` references: lower but present

## 3) Evaluation Datasets

Purpose: offline quality checks and benchmarking.

- Root-level evaluation artifacts, e.g.:
  - `hard_eval_dataset*.json`
  - `evaluation_results*.json`
  - `request_level_*.json`
- Evaluation scripts:
  - `run_full_pipeline_evaluation.py`
  - `run_hard_eval_comparison.py`
  - `generate_hard_eval_dataset.py`

## 4) Legacy Datasets

Purpose: historical experiments and backward compatibility.

- `ml/training_data/` (legacy path family still hardcoded in many scripts)
- `ml/data/` references exist in scripts, while top-level `ml/data` directory is absent.
- Script defaults that still assume legacy pathing should be migrated in a separate
  non-runtime cleanup phase.

## 5) Script Usage Map (Representative)

### 5.1 Runtime / Integration

- `proxy/app.py`: runtime proxy + ML inference orchestration.
- `proxy/integrations/ml_pipeline_integration.py`: runtime pipeline integration.
- `ml/zap_integration/zap_result_aggregator.py`: scanner result aggregation.

### 5.2 Training / Retraining

- `proxy/retrain_models.py`
- `proxy/retrain_fp_reducer.py`
- `proxy/retrain_anomaly_detector*.py`
- `proxy/ml/model_trainer.py`
- `proxy/ml/model_retrainer.py`
- `proxy/ml/train_with_auto_labeled_data.py`

### 5.3 Evaluation / Analysis

- `proxy/test_overfitting.py`
- `proxy/benchmark_performance.py`
- `proxy/data_provenance_audit.py`
- root-level evaluation scripts listed above

## 6) Stabilization Notes

- No datasets were moved/deleted in this phase.
- Runtime stabilization focused on deterministic model path resolution.
- Dataset path migration should be handled next as a dedicated training/eval refactor.
