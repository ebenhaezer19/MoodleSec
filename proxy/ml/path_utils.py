from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


_ML_DIR = Path(__file__).resolve().parent
_PROXY_DIR = _ML_DIR.parent
_REPO_ROOT = _PROXY_DIR.parent
_MODEL_DIR = _ML_DIR / "models"
_DATA_DIR = _ML_DIR / "data"
_LEGACY_MODEL_DIR = _REPO_ROOT / "ml" / "models"
_WARNED_DUPLICATES: set[str] = set()
_WARNED_LEGACY_DIR = False


def canonical_model_dir() -> str:
    return str(_MODEL_DIR)


def canonical_data_dir() -> str:
    return str(_DATA_DIR)


def canonical_model_path(filename: str) -> str:
    return str(_MODEL_DIR / filename)


def _warn_legacy_model_dir_once() -> None:
    global _WARNED_LEGACY_DIR
    if _WARNED_LEGACY_DIR:
        return
    if _LEGACY_MODEL_DIR.is_dir():
        print(
            "[ML Path] WARNING: legacy model directory detected at "
            f"{_LEGACY_MODEL_DIR}. Runtime canonical directory is {_MODEL_DIR}"
        )
    _WARNED_LEGACY_DIR = True


def _warn_duplicate_filename_once(filename: str) -> None:
    if filename in _WARNED_DUPLICATES:
        return
    canonical_file = _MODEL_DIR / filename
    legacy_file = _LEGACY_MODEL_DIR / filename
    if canonical_file.exists() and legacy_file.exists():
        print(
            "[ML Path] WARNING: duplicate model filename detected in canonical and legacy dirs: "
            f"{filename}. Runtime will use canonical: {canonical_file}"
        )
        _WARNED_DUPLICATES.add(filename)


def normalize_model_path(model_path: Optional[str], default_filename: str) -> str:
    """
    Normalize legacy/default runtime model paths to proxy/ml/models.

    Explicit absolute paths are preserved.
    Explicit non-legacy relative paths are preserved to avoid surprising behavior
    in ad-hoc scripts, while common legacy aliases are remapped.
    """
    canonical = canonical_model_path(default_filename)
    _warn_legacy_model_dir_once()
    _warn_duplicate_filename_once(default_filename)

    if not model_path:
        return canonical

    raw = str(model_path)
    norm = os.path.normpath(raw)
    if os.path.isabs(norm):
        try:
            normalized_abs = Path(norm).resolve()
        except Exception:
            return norm
        try:
            if normalized_abs.is_relative_to(_LEGACY_MODEL_DIR.resolve()):
                return canonical
        except Exception:
            pass
        return norm

    legacy_aliases = {
        os.path.normpath(f"ml/models/{default_filename}"),
        os.path.normpath(f"proxy/ml/models/{default_filename}"),
        os.path.normpath(f"models/{default_filename}"),
        os.path.normpath(default_filename),
    }
    if norm in legacy_aliases:
        return canonical

    return norm
