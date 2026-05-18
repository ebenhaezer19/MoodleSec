# MoodleSec ML Stabilization Implementation Report

Date: 2026-05-03  
Phase: Stabilization Implementation (continuation from completed forensic audit)

Constraints honored:

- No ML detection logic rewrite
- No model retraining
- No threshold changes
- No algorithm rewrites

---

## 1) Files Modified

- `proxy/app.py`
- `proxy/integrations/ml_pipeline_integration.py`
- `proxy/integrations/zap_payload_enhancer.py`
- `proxy/ml/path_utils.py`
- `proxy/ml/pipeline_orchestrator.py`

## 2) Files Created

- `proxy/ml/DATASET_OWNERSHIP_CLASSIFICATION.md`
- `proxy/ml/ARCH_STABILIZATION_IMPLEMENTATION_REPORT.md` (this report)
- `ml/models/LEGACY_RUNTIME_NOTICE.md`

---

## 3) Runtime Path Fixes Applied

### 3.1 Canonical deterministic model-path utility

Added `proxy/ml/path_utils.py` with:

- canonical model dir resolver
- canonical model path builder
- path normalization from legacy aliases to canonical path
- absolute-legacy-path remap safeguard (`root/ml/models/*` -> `proxy/ml/models/*`)

### 3.2 Runtime modules now normalize model paths

The following runtime ML modules now normalize default/legacy paths to canonical:

- `proxy/ml/anomaly_detector.py`
- `proxy/ml/attack_classifier.py`
- `proxy/ml/anomaly_false_positive_reducer.py`
- `proxy/ml/severity_predictor.py`
- `proxy/ml/rate_limiter.py`
- `proxy/ml/phishing_detector.py`

### 3.3 Pipeline model resolution hardened

`proxy/ml/pipeline_orchestrator.py` now:

- resolves default model files under `proxy/ml/models/`
- no longer searches `root/ml/models` as runtime candidate
- emits explicit warnings for legacy dir detection and missing canonical model files

### 3.4 Duplicate and legacy warnings

Warnings now emitted during runtime initialization when applicable:

- legacy model directory presence (`root/ml/models`)
- duplicate filename across canonical + legacy model dirs

---

## 4) Import Normalization Summary

### 4.1 Runtime canonicalized

- `proxy/app.py` now imports `MLManager` via canonical runtime namespace:
  - `from proxy.ml.ml_manager import MLManager`
- `proxy/integrations/ml_pipeline_integration.py` now imports:
  - `from proxy.ml.pipeline_orchestrator import PipelineOrchestrator`
- `proxy/ml/pipeline_orchestrator.py` now uses only internal relative imports
  (removed dual fallback import block).

### 4.2 Runtime ambiguity reduced

- Removed `sys.path` mutation from `proxy/integrations/zap_payload_enhancer.py`
- Replaced with canonical import:
  - `from proxy.database.payload_repository import PayloadRepositoryManager`

---

## 5) Remaining Risky Files (Merge-Conflict Hotspots)

- `proxy/app.py` (large multi-responsibility runtime entrypoint)
- `proxy/ml/pipeline_orchestrator.py` (core decision orchestration)
- `proxy/integrations/ml_pipeline_integration.py` (boundary between HTTP layer and ML)
- `proxy/ml/ml_manager.py` (central multipurpose ML coordinator)

---

## 6) Remaining Legacy Dependencies

### 6.1 Legacy model directory

- `root/ml/models/` still exists and is now explicitly marked legacy via:
  - `ml/models/LEGACY_RUNTIME_NOTICE.md`
- Runtime now warns and prefers canonical `proxy/ml/models/`.

### 6.2 Legacy `ml.*` imports in non-runtime scripts

- Many training/evaluation scripts still use `ml.*` imports and/or `sys.path` hacks.
- Compatibility shims currently keep these scripts functional.
- This is intentional for non-breaking transition.

---

## 7) Deterministic Model-Loading Verification

Validation executed:

- `py_compile` on modified runtime files: passed.
- Runtime import smoke tests: passed.
- Live object verification:
  - `MLManager().fp_reducer.model_path` resolves to absolute `proxy/ml/models/fp_reducer.pkl`
  - `MLManager().anomaly_detector.model_path` resolves to absolute `proxy/ml/models/anomaly_detector.pkl`
  - `PipelineOrchestrator` resolves anomaly/attack/fp models to `proxy/ml/models/*`
- Expected warnings observed:
  - legacy model directory warning
  - duplicate filename warning (for `attack_classifier.pkl`, `fp_reducer.pkl`)

---

## 8) Root `ml/` Dependency Status

- Root `ml/` remains as **compatibility layer**.
- Runtime-critical modules now canonicalized to `proxy.ml.*`.
- `root/ml/models` is treated as legacy; runtime should not rely on it.

---

## 9) Dataset Ownership Map (Summary)

Detailed classification: `proxy/ml/DATASET_OWNERSHIP_CLASSIFICATION.md`

Summary:

- Runtime operational data:
  - `proxy/data/*.db`
- Canonical training corpus:
  - `proxy/ml/training_data/`
- Legacy training path family:
  - `ml/training_data/` (still heavily referenced by scripts)
- Evaluation artifacts:
  - root-level `hard_eval_*`, `evaluation_*`, `request_level_*` JSON files

---

## 10) Unresolved Risks

1. Many non-runtime scripts still hardcode legacy dataset paths (`ml/training_data`, `ml/data`).
2. Widespread `sys.path` mutation persists in training/testing scripts.
3. Compatibility shim layer (`root/ml/*`) remains necessary until script migration is complete.
4. Environment-level sklearn version mismatch warnings persist when loading pickles
   (not changed in this phase).

---

## 11) Recommended Next Stabilization Step

1. Migrate training/eval script imports from `ml.*` to `proxy.ml.*` (or package-relative under `proxy/ml/training`).
2. Migrate training/eval dataset path constants to canonical directories:
   - training data: `proxy/ml/training_data/`
   - runtime/static data: `proxy/ml/data/`
3. Introduce a small ML runtime boundary module (e.g., `proxy/ml/runtime_entrypoints.py`)
   to reduce churn in `proxy/app.py`.
4. After migration completeness is proven, deprecate and eventually remove root `ml/*` shims.
