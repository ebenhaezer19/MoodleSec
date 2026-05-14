"""
utils/trace_logger.py — Structured pipeline trace logging for MoodleSec.

Format: [TRACE][<STEP>] <message>

Set DEBUG_TRACE = False to suppress all steps except DECISION and SOC.
This module contains ZERO ML logic and ZERO business logic.
"""
from __future__ import annotations

# ── Configuration ─────────────────────────────────────────────────────────
# When True  → full pipeline trace (REQUEST_IN … RESPONSE)
# When False → only DECISION + SOC are printed
DEBUG_TRACE: bool = True


# ── Core emitter ──────────────────────────────────────────────────────────

def trace(step: str, message: str) -> None:
    """Always-on trace (DECISION, SOC, RESPONSE).
    flush=True ensures output appears immediately even when stdout is piped
    or buffered (non-TTY contexts such as Docker, process managers, Windows
    terminal with output redirection).
    """
    print(f"[TRACE][{step}] {message}", flush=True)


def trace_debug(step: str, message: str) -> None:
    """Trace only when DEBUG_TRACE is True."""
    if DEBUG_TRACE:
        print(f"[TRACE][{step}] {message}", flush=True)


# ── Convenience helpers ───────────────────────────────────────────────────

def trace_request_in(method: str, norm_path: str, query: str, client_ip: str) -> None:
    qs = f"?{query}" if query else ""
    trace_debug("REQUEST_IN", f"{method} {norm_path}{qs} ip={client_ip}")


def trace_pipeline_start(norm_path: str) -> None:
    trace_debug("PIPELINE_START", f"entering ML pipeline for {norm_path}")


def trace_features(ml_result: dict) -> None:
    """Infer feature summary from ml_result — no access to raw vectors needed."""
    confidence = float(ml_result.get("confidence", 0.0))
    reason = str(ml_result.get("reason", "")).lower()
    has_strong_evidence = confidence > 0.65
    keyword_only = "keyword" in reason or (confidence > 0.0 and confidence < 0.40)
    trace_debug(
        "FEATURES",
        f"feature_count=35 has_strong_evidence={has_strong_evidence} keyword_only={keyword_only}",
    )


def trace_ml_pre(ml_result: dict) -> None:
    trace_debug(
        "ML_PRE",
        f"attack_type={ml_result.get('attack_type', 'unknown')} "
        f"confidence={float(ml_result.get('confidence', 0.0)):.2f} "
        f"anomaly_score={float(ml_result.get('anomaly_score', 0.0)):.2f}",
    )


def trace_decision(ml_result: dict, decision: str) -> None:
    reason = str(ml_result.get("reason", "")).split("(")[0].strip()[:60]
    severity = ml_result.get("severity", "LOW")
    trace("DECISION", f"{decision} reason={reason!r} severity={severity}")


def trace_soc(action: str) -> None:
    trace("SOC", action)


def trace_anomaly_post(anomaly_score: float) -> None:
    trace_debug(
        "ANOMALY_POST",
        f"anomaly_score={round(anomaly_score, 4)} note=observability_only",
    )


def trace_response(status_code: int, final_decision: str) -> None:
    trace("RESPONSE", f"HTTP {status_code} final_decision={final_decision}")


# ══════════════════════════════════════════════════════════════════════════
# Pipeline Trace Store — post-hoc explainable AI trace storage
# ══════════════════════════════════════════════════════════════════════════

import json
import os
import threading
import uuid
from collections import OrderedDict
from datetime import datetime
from pathlib import Path


def generate_request_id() -> str:
    """Generate a short, human-readable request ID."""
    return uuid.uuid4().hex[:12]


class PipelineTraceStore:
    """Thread-safe in-memory store for ML pipeline execution traces.

    Each trace is a list of stage events for a single request_id.
    FIFO eviction keeps memory bounded at ``max_traces`` entries.
    Events are also appended to a JSONL file for persistence.
    """

    STAGES_ORDER = [
        "request_received",
        "feature_extraction",
        "anomaly_detection",
        "attack_classifier",
        "fp_reducer",
        "decision_engine",
        "soc_queue",
        "enforcement",
    ]

    def __init__(self, max_traces: int = 200, log_dir: str | None = None):
        self._lock = threading.Lock()
        self._traces: OrderedDict[str, dict] = OrderedDict()
        self._max_traces = max_traces

        if log_dir is None:
            log_dir = str(Path(__file__).resolve().parents[1] / "logs")
        self._log_path = os.path.join(log_dir, "pipeline_traces.jsonl")
        os.makedirs(os.path.dirname(self._log_path), exist_ok=True)

    def emit(
        self,
        request_id: str,
        stage: str,
        status: str = "completed",
        details: str | dict = "",
    ) -> None:
        """Record a stage event for the given request."""
        event = {
            "request_id": request_id,
            "stage": stage,
            "status": status,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "details": details,
        }

        with self._lock:
            if request_id not in self._traces:
                self._traces[request_id] = {
                    "request_id": request_id,
                    "started_at": event["timestamp"],
                    "stages": [],
                }
                # FIFO eviction
                while len(self._traces) > self._max_traces:
                    self._traces.popitem(last=False)

            self._traces[request_id]["stages"].append(event)
            self._traces[request_id]["updated_at"] = event["timestamp"]
            # Move to end so latest is last
            self._traces.move_to_end(request_id)

        # Append to JSONL (fire-and-forget, never crash)
        try:
            with open(self._log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def get_trace(self, request_id: str) -> dict | None:
        """Return full trace for a request_id, or None."""
        with self._lock:
            trace_data = self._traces.get(request_id)
            if trace_data is None:
                return None
            # Return a copy
            return {
                "request_id": trace_data["request_id"],
                "started_at": trace_data.get("started_at", ""),
                "updated_at": trace_data.get("updated_at", ""),
                "stages": list(trace_data["stages"]),
            }

    def get_latest(self, limit: int = 20) -> list[dict]:
        """Return the N most recent traces (newest first)."""
        with self._lock:
            keys = list(self._traces.keys())
        # Reverse so newest is first
        keys = keys[-limit:][::-1]
        results = []
        for key in keys:
            t = self.get_trace(key)
            if t:
                results.append(t)
        return results


# ── Singleton instance ────────────────────────────────────────────────────
pipeline_traces = PipelineTraceStore()
