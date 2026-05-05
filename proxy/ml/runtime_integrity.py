"""
Runtime integrity checks for canonical ML runtime paths and model artifacts.

Non-fatal warnings are emitted for legacy directories, duplicate model files,
and sklearn version inconsistencies. Only raise an exception when a CRITICAL
runtime model is missing (caller may choose to treat that as fatal).
"""
from __future__ import annotations

import logging
import pickle
import warnings
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("runtime_integrity")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("[RuntimeIntegrity] %(levelname)s: %(message)s"))
    logger.addHandler(handler)


def _project_paths() -> Dict[str, Path]:
    here = Path(__file__).resolve().parent  # proxy/ml
    canonical_models = here / "models"
    project_root = here.parents[2]
    legacy_models = project_root / "ml" / "models"
    return {
        "here": here,
        "canonical_models": canonical_models,
        "legacy_models": legacy_models,
        "project_root": project_root,
    }


def _list_dir(path: Path) -> List[str]:
    if not path.exists() or not path.is_dir():
        return []
    return [p.name for p in path.iterdir() if p.is_file()]


def _extract_sklearn_version_from_meta(file_path: Path) -> Optional[str]:
    try:
        if not file_path.exists():
            return None
        # Try JSON-ish first
        if file_path.suffix.lower() in (".json", ".meta"):
            try:
                import json

                data = json.loads(file_path.read_text(encoding="utf-8"))
                for k in ("sklearn_version", "scikit_learn_version", "sklearn.version"):
                    if k in data:
                        return str(data[k])
            except Exception:
                pass

        # Try pickle
        try:
            with file_path.open("rb") as fh:
                obj = pickle.load(fh)
            # obj may be dict-like
            if isinstance(obj, dict):
                for k in ("sklearn_version", "scikit_learn_version", "sklearn.version"):
                    if k in obj:
                        return str(obj[k])
        except Exception:
            # Not a pickle or unknown structure
            return None
    except Exception:
        return None


def validate_runtime_integrity(required_models: Optional[List[str]] = None) -> Dict[str, object]:
    """Run runtime integrity checks and return a status dict.

    Emits warnings via logger for non-fatal findings.
    """
    paths = _project_paths()
    canonical = paths["canonical_models"]
    legacy = paths["legacy_models"]
    project = paths["project_root"]

    status: Dict[str, object] = {
        "canonical_models_dir": str(canonical),
        "legacy_models_dir": str(legacy),
        "canonical_exists": canonical.exists(),
        "legacy_exists": legacy.exists(),
        "duplicates": [],
        "missing_critical": [],
        "sklearn_current_version": None,
        "sklearn_training_versions_found": {},
    }

    # List files
    canonical_files = set(_list_dir(canonical))
    legacy_files = set(_list_dir(legacy))

    duplicates = sorted(list(canonical_files & legacy_files))
    if duplicates:
        logger.warning(f"Duplicate model filenames in canonical and legacy dirs: {duplicates}")
        status["duplicates"] = duplicates

    # Verify canonical directory exists
    if not canonical.exists():
        logger.warning(f"Canonical model directory missing: {canonical}")

    # Warn about legacy dir presence
    if legacy.exists():
        logger.warning(f"Legacy model directory detected (treated as legacy): {legacy}")

    # Detect references to legacy paths in repo files
    legacy_refs = []
    try:
        for p in project.rglob("*"):
            if p.is_file() and p.suffix in {".py", ".md", ".sh"}:
                try:
                    text = p.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                if "ml/models" in text and str(canonical) not in text:
                    legacy_refs.append(str(p.relative_to(project)))
    except Exception:
        pass

    if legacy_refs:
        logger.warning(f"Files referencing 'ml/models' or ambiguous model paths: {legacy_refs}")
    status["legacy_references"] = legacy_refs

    # Check critical models
    if required_models is None:
        required_models = ["fp_reducer.pkl", "anomaly_detector.pkl"]

    missing = [m for m in required_models if m not in canonical_files]
    if missing:
        logger.error(f"Missing CRITICAL runtime models in {canonical}: {missing}")
        status["missing_critical"] = missing

    # Sklearn version diagnostics
    try:
        import sklearn

        status["sklearn_current_version"] = getattr(sklearn, "__version__", None)
        logger.info(f"scikit-learn present, current runtime version: {status['sklearn_current_version']}")
    except Exception:
        logger.warning("scikit-learn not importable in runtime environment")

    # Search model meta files for training sklearn version hints
    training_versions = {}
    for fname in list(canonical_files) + list(legacy_files):
        if fname.lower().endswith(('.pkl', '.meta', '.json')):
            p = (canonical / fname) if (canonical / fname).exists() else (legacy / fname) if (legacy / fname).exists() else None
            if p:
                v = _extract_sklearn_version_from_meta(p)
                if v:
                    training_versions[fname] = v

    if training_versions:
        logger.info(f"Detected training sklearn versions in model metadata: {training_versions}")
        status["sklearn_training_versions_found"] = training_versions

    # Ensure InconsistentVersionWarning is visible
    try:
        from sklearn.exceptions import InconsistentVersionWarning

        warnings.simplefilter("default", InconsistentVersionWarning)
    except Exception:
        # sklearn not available or no such warning class
        pass

    # Summary
    status["summary"] = {
        "canonical_exists": status["canonical_exists"],
        "legacy_exists": status["legacy_exists"],
        "duplicates_count": len(status.get("duplicates", [])),
        "missing_critical_count": len(status.get("missing_critical", [])),
    }

    return status


__all__ = ["validate_runtime_integrity"]
