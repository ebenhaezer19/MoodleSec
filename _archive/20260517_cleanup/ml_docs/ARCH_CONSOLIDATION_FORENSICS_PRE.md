# MoodleSec ML Architecture Forensics (Pre-Change)

Date: 2026-05-03
Scope: Full repository audit focused on ML runtime ownership and path/import ambiguity.

## 1) Executive Summary

- Primary intended runtime ML code exists in `proxy/ml/`.
- Repository still contains mixed import style (`ml.*` vs `proxy.ml.*`) and multiple legacy path assumptions.
- Scanner integration and proxy runtime now partially separated for reducer ownership, but import/runtime ambiguity remains.

## 2) Import Forensics

### 2.1 Mixed namespace imports

- `from ml.*` / `import ml.*` occurrences in Python files: **59**
- `from proxy.ml.*` occurrences exist but are not yet universal.

Key runtime-relevant examples:

- `proxy/app.py`: `from ml.ml_manager import MLManager`
- `proxy/integrations/ml_pipeline_integration.py`: tries `proxy.ml.*` then falls back to `ml.*`
- `ml/zap_integration/zap_result_aggregator.py`: uses `proxy.ml.scanner_false_positive_reducer` (already scanner-decoupled)

### 2.2 Reducer-specific references

- `false_positive_reducer` references still present in docs/comments and model-status keys.
- Runtime reducer separation status (pre-change):
  - Anomaly side: `proxy/ml/anomaly_false_positive_reducer.py`
  - Scanner side: `proxy/ml/scanner_false_positive_reducer.py` (placeholder)
  - Compatibility shim: `proxy/ml/false_positive_reducer.py`

### 2.3 Dynamic import and path hacks

- `sys.path` manipulations in Python files: **67**
- Common pattern: scripts force local package resolution from `proxy/` or `proxy/ml/`.
- Dynamic import indicators (`__import__`, etc.) mostly test/dev context, not core runtime pipeline.

## 3) Model Path Forensics

### 3.1 Model path references in code

- `ml/models` references in Python files: **43**
- Core runtime classes use default model paths under `"ml/models/*.pkl"` (relative string).

### 3.2 On-disk model directories

- `ml/models`: exists, files = **2**
- `proxy/ml/models`: exists, files = **16**

Current split indicates stale dual-location model storage.

## 4) Dataset Path Forensics

- `ml/training_data` references in Python files: **126**
- `proxy/ml/training_data` references in Python files: **17**
- `proxy/ml/data` references in Python files: **2**

Directory state:

- `ml/training_data`: exists, files = **6**
- `proxy/ml/training_data`: exists, files = **500066**
- `ml/data`: missing
- `proxy/ml/data`: exists, files = **11**

This confirms heavy legacy path usage and mixed dataset ownership assumptions.

## 5) Runtime Ambiguity Hotspots

- `proxy/app.py` (proxy runtime entrypoint + ML wiring + enforcement logic)
- `proxy/integrations/ml_pipeline_integration.py` (dual namespace fallback behavior)
- `proxy/ml/pipeline_orchestrator.py` (model directory resolution candidates include legacy locations)
- `proxy/ml/*` trainer/retrainer scripts that still import via `ml.*` and use `sys.path` hacks

## 6) Consolidation Risks Identified (Pre-Change)

- Inconsistent execution context expectations (run from repo root vs run from `proxy/`).
- Relative `ml/models` default strings can load from different folders depending on CWD.
- Large volume of training/evaluation scripts still coupled to legacy `ml/training_data` paths.

## 7) Planned Stabilization Direction (Post-Forensics)

- Canonical runtime ownership: `proxy/ml/`
- Canonical runtime model directory: `proxy/ml/models/`
- Keep backward compatibility through lightweight shims where needed.
- Normalize runtime-critical imports first; avoid logic/threshold/training behavior changes.
