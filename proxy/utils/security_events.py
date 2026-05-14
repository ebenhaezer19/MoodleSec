"""
Structured security event emitter for DEMO_MODE and SOC_MODE.

Produces SIEM-ready event dicts for every detected attack and persists
them to logs/security_events.json.

When SOC_MODE is active, events include an alert_id linking them to
the admin alert queue for human-in-the-loop review.

This module is a pure logging utility — it contains ZERO ML logic
and MUST NOT import any ML modules.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


# Log destination (sibling of proxy_log.json, pipeline_results.json, etc.)
_PROXY_ROOT = Path(__file__).resolve().parents[1]
SECURITY_EVENTS_LOG_PATH = _PROXY_ROOT / "logs" / "security_events.json"


def _json_default(value: Any) -> Any:
    """Fallback serializer for non-standard types (numpy scalars, bytes, etc.)."""
    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            pass
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _append_json_entry(file_path: Path, entry: Dict[str, Any]) -> None:
    """Append a single JSON object to a file-backed JSON array (thread-safe enough)."""
    encoded = json.dumps(entry, ensure_ascii=False, default=_json_default).encode("utf-8")
    file_path.parent.mkdir(parents=True, exist_ok=True)

    with file_path.open("a+b") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()

        if size == 0:
            handle.write(b"[\n" + encoded + b"\n]\n")
            return

        # Find last non-whitespace character
        pos = size - 1
        last_char = b""
        while pos >= 0:
            handle.seek(pos)
            char = handle.read(1)
            if char not in b" \t\r\n":
                last_char = char
                break
            pos -= 1

        if pos < 0 or last_char != b"]":
            # Malformed — overwrite with fresh array
            handle.seek(0)
            handle.truncate()
            handle.write(b"[\n" + encoded + b"\n]\n")
            return

        # Peek at previous non-ws to decide comma
        prev_pos = pos - 1
        prev_char = b"["
        while prev_pos >= 0:
            handle.seek(prev_pos)
            c = handle.read(1)
            if c not in b" \t\r\n":
                prev_char = c
                break
            prev_pos -= 1

        handle.seek(pos)
        handle.truncate()
        prefix = b"\n" if prev_char == b"[" else b",\n"
        handle.write(prefix + encoded + b"\n]\n")


def emit_security_event(
    *,
    attack_type: str,
    severity: str,
    confidence: float,
    anomaly_score: float,
    url: str,
    method: str = "GET",
    path: str = "/",
    parameter: str = "",
    reason: str = "",
    source: str = "ml_pipeline",
    client_ip: str = "unknown",
    ml_result: Optional[Dict[str, Any]] = None,
    alert_id: Optional[str] = None,
    action_override: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Build and persist a structured security event.

    Args:
        alert_id: If SOC_MODE is active, links this event to the alert queue.
        action_override: Override default action (e.g. "pending_admin_action").

    Returns the event dict so callers can inspect or extend it.
    """
    action = action_override if action_override else "forwarded_in_demo_mode"

    event: Dict[str, Any] = {
        "event_type": "attack_detected",
        "attack_type": str(attack_type),
        "severity": str(severity),
        "confidence": float(confidence),
        "anomaly_score": float(anomaly_score),
        "parameter": str(parameter),
        "url": str(url),
        "method": str(method),
        "path": str(path),
        "client_ip": str(client_ip),
        "reason": str(reason),
        "source": str(source),
        "action": action,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    if alert_id:
        event["alert_id"] = str(alert_id)

    if ml_result and isinstance(ml_result, dict):
        event["ml_decision_original"] = ml_result.get("decision", "UNKNOWN")
        event["ml_attack_type"] = ml_result.get("attack_type", "unknown")

    # Persist to structured log file
    try:
        _append_json_entry(SECURITY_EVENTS_LOG_PATH, event)
    except Exception as exc:
        # Logging must never break traffic processing
        print(f"[SecurityEvent] WARNING: failed to persist event: {exc}")

    # Console output for observability
    mode_label = "SOC_MODE" if alert_id else "DEMO_MODE"
    print(
        f"[SecurityEvent] {mode_label} attack_detected | "
        f"{event['method']} {event['path']} | "
        f"type={event['attack_type']} severity={event['severity']} "
        f"conf={event['confidence']:.2f} anomaly={event['anomaly_score']:.2f} | "
        f"action={event['action']}"
    )

    return event
