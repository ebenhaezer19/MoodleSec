# MoodleSec ML Pipeline - Production Environment Setup

## Goal
Create a reproducible, demo-safe environment that matches serialized ML artifacts.

## Environment Setup (Windows PowerShell)
1. Create and activate a clean conda env:
   - conda create -n moodlesec-ml python=3.10.15
   - conda activate moodlesec-ml

2. Install pinned production dependencies:
   - pip install -r requirements-production.txt

3. (Optional) Set an authoritative model directory:
   - $env:MOODLESEC_MODEL_DIR = "C:\Users\<user>\OneDrive\Desktop\Documents\CIT\TA\MoodleSec\proxy\ml\models"

## Environment Setup (Linux/macOS)
1. Create and activate a clean conda env:
   - conda create -n moodlesec-ml python=3.10.15
   - conda activate moodlesec-ml

2. Install pinned production dependencies:
   - pip install -r requirements-production.txt

3. (Optional) Set an authoritative model directory:
   - export MOODLESEC_MODEL_DIR="/path/to/MoodleSec/proxy/ml/models"

## Verification Steps
1. Confirm sklearn version matches artifacts:
   - python -c "import sklearn; print(sklearn.__version__)"
   - Expected: 1.4.1.post1

2. Load pipeline and verify no InconsistentVersionWarning:
   - python -c "from proxy.ml.pipeline_orchestrator import PipelineOrchestrator; PipelineOrchestrator(enable_logging=False)"

3. Verify a sample attack still triggers:
   - python -c "from proxy.ml.pipeline_orchestrator import PipelineOrchestrator; p=PipelineOrchestrator(enable_logging=False); r=p.process_request({'method':'GET','path':'/login/index.php','query_params':'q=%27%20OR%201%3D1%20--','body':'','headers':'User-Agent: Mozilla/5.0','request_raw':'GET /login/index.php?q=%27%20OR%201%3D1%20--'}); print(r['decision'], r['attack_type'], r['confidence'])"

## Notes
- If multiple model directories exist, the pipeline logs a warning and selects a single authoritative directory.
- Use MOODLESEC_MODEL_DIR to avoid stale model overrides.
