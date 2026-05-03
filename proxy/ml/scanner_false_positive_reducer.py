from __future__ import annotations

from typing import Optional


class ScannerFalsePositiveReducer:
    """
    Scanner-side FP reducer placeholder.

    This intentionally keeps scanner filtering decoupled from anomaly reducer
    while preserving runtime compatibility for scanner integrations that
    attempt to load a dedicated scanner model.
    """

    @classmethod
    def load_model(cls, model_path: str) -> Optional["ScannerFalsePositiveReducer"]:
        # Scanner-specific model is not implemented yet.
        # Returning None keeps Tier-3 scanner filtering safely disabled.
        _ = model_path
        return None
