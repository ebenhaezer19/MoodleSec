"""
SOC Alert Queue — In-memory alert queue with admin decision override.

Provides a PENDING_ADMIN_ACTION state machine for the MoodleSec proxy:
    ML_DETECTED -> PENDING_ADMIN_ACTION -> ADMIN_BLOCK / ADMIN_ALLOW / ADMIN_IGNORE

This module is a pure orchestration utility — it contains ZERO ML logic
and MUST NOT import any ML modules.
"""
from __future__ import annotations

import json
import os
import threading
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


# ── Constants ──────────────────────────────────────────────────────────

# Valid alert statuses (state machine)
STATUS_PENDING = "PENDING_ADMIN_ACTION"
STATUS_BLOCK = "ADMIN_BLOCK"
STATUS_ALLOW = "ADMIN_ALLOW"
STATUS_IGNORE = "ADMIN_IGNORE"
STATUS_RESET = "RESET"
VALID_ADMIN_ACTIONS = {STATUS_BLOCK, STATUS_ALLOW, STATUS_IGNORE}

# Maximum number of alerts kept in memory
MAX_ALERTS = 1000

# Persistence path
_PROXY_ROOT = Path(__file__).resolve().parents[1]
ALERT_QUEUE_LOG_PATH = _PROXY_ROOT / "logs" / "alert_queue.json"


# ── Serialization helpers ──────────────────────────────────────────────

def _json_default(value: Any) -> Any:
    if hasattr(value, "item"):
        try:
            return value.item()
        except Exception:
            pass
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _generate_alert_id() -> str:
    """Generate a unique alert ID: ALT-YYYYMMDD-HHMMSS-NNNN."""
    now = datetime.utcnow()
    # Use microseconds for uniqueness within the same second
    return f"ALT-{now.strftime('%Y%m%d')}-{now.strftime('%H%M%S')}-{now.strftime('%f')[:4]}"


class AlertQueue:
    """
    Thread-safe in-memory alert queue with file-backed persistence.

    Alerts flow through a state machine:
        PENDING_ADMIN_ACTION -> ADMIN_BLOCK / ADMIN_ALLOW / ADMIN_IGNORE

    Admin overrides are indexed by (attack_type, client_ip) for fast lookup
    on subsequent requests.
    """

    def __init__(self, max_alerts: int = MAX_ALERTS):
        self._lock = threading.Lock()
        self._alerts: deque[Dict[str, Any]] = deque(maxlen=max_alerts)
        self._alerts_by_id: Dict[str, Dict[str, Any]] = {}

        # Admin override index: (attack_type_lower, client_ip) -> action
        # This enables O(1) lookup for repeat requests
        self._overrides: Dict[tuple, str] = {}
        self._blocked_fingerprints: set[str] = set()
        # Dedup index: fingerprint -> alert_id for PENDING alerts.
        # Prevents duplicate queuing of the same attack from the same IP.
        self._pending_fingerprints: Dict[str, str] = {}

        # Counters
        self._total_added = 0
        self._total_resolved = 0

        # Load persisted alerts on startup
        self._load_persisted()

    def _load_persisted(self) -> None:
        """Load alerts from disk on startup (best-effort)."""
        try:
            if ALERT_QUEUE_LOG_PATH.exists():
                raw = ALERT_QUEUE_LOG_PATH.read_text(encoding="utf-8-sig").strip()
                if raw:
                    entries = json.loads(raw)
                    if isinstance(entries, list):
                        for entry in entries[-MAX_ALERTS:]:
                            if isinstance(entry, dict) and "alert_id" in entry:
                                self._alerts.append(entry)
                                self._alerts_by_id[entry["alert_id"]] = entry
                                # Rebuild override index for resolved alerts
                                if entry.get("status") in VALID_ADMIN_ACTIONS:
                                    key = (
                                        str(entry.get("attack_type", "")).lower(),
                                        str(entry.get("client_ip", "")),
                                    )
                                    self._overrides[key] = entry["status"]
                        self._total_added = len(self._alerts)
                        # Rebuild blocked fingerprints so enforcement survives restarts.
                        # Rebuild pending fingerprints so dedup survives restarts.
                        for entry in self._alerts:
                            stored_path = str(entry.get("path", ""))
                            if stored_path and not stored_path.startswith("/"):
                                stored_path = "/" + stored_path
                            entry_fp = (
                                f"{entry.get('method')}:"
                                f"{stored_path}:"
                                f"{entry.get('client_ip')}"
                            )
                            if entry.get("status") == STATUS_BLOCK:
                                self._blocked_fingerprints.add(entry_fp)
                            elif entry.get("status") == STATUS_PENDING:
                                self._pending_fingerprints[entry_fp] = entry["alert_id"]
        except Exception as exc:
            print(f"[AlertQueue] WARNING: failed to load persisted alerts: {exc}")

    def _persist(self) -> None:
        """Write current alert queue to disk (best-effort)."""
        try:
            ALERT_QUEUE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
            data = list(self._alerts)
            ALERT_QUEUE_LOG_PATH.write_text(
                json.dumps(data, ensure_ascii=False, default=_json_default, indent=2),
                encoding="utf-8",
            )
        except Exception as exc:
            print(f"[AlertQueue] WARNING: failed to persist alerts: {exc}")

    def add_alert(
        self,
        *,
        attack_type: str,
        severity: str,
        confidence: float,
        anomaly_score: float,
        client_ip: str,
        method: str,
        path: str,
        url: str,
        reason: str,
        ml_decision_original: str,
        source: str = "ml_pipeline",
        ml_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Add a new alert to the queue as PENDING_ADMIN_ACTION.

        Returns the created alert dict (includes alert_id).
        If a PENDING alert with the same (method, path, ip) fingerprint already
        exists, returns the existing alert unchanged (exactly-once guarantee).
        """
        # Build fingerprint for dedup check
        norm_path = str(path)
        if norm_path and not norm_path.startswith("/"):
            norm_path = "/" + norm_path
        fp = f"{str(method)}:{norm_path}:{str(client_ip)}"

        with self._lock:
            if fp in self._pending_fingerprints:
                existing_id = self._pending_fingerprints[fp]
                existing = self._alerts_by_id.get(existing_id)
                if existing and existing.get("status") == STATUS_PENDING:
                    print(
                        f"[AlertQueue] DEDUP {existing_id} | {method} {path} | "
                        f"fingerprint already pending — skipping duplicate"
                    )
                    return existing

        alert_id = _generate_alert_id()

        alert: Dict[str, Any] = {
            "alert_id": alert_id,
            "status": STATUS_PENDING,
            "attack_type": str(attack_type),
            "severity": str(severity),
            "confidence": float(confidence),
            "anomaly_score": float(anomaly_score),
            "client_ip": str(client_ip),
            "method": str(method),
            "path": str(path),
            "url": str(url),
            "reason": str(reason),
            "source": str(source),
            "ml_decision_original": str(ml_decision_original),
            "effective_decision": STATUS_PENDING,
            "admin_action": None,
            "admin_action_timestamp": None,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

        with self._lock:
            # If deque is at capacity, remove oldest from index
            if len(self._alerts) >= self._alerts.maxlen:
                evicted = self._alerts[0]
                self._alerts_by_id.pop(evicted.get("alert_id", ""), None)

            self._alerts.append(alert)
            self._alerts_by_id[alert_id] = alert
            self._pending_fingerprints[fp] = alert_id
            self._total_added += 1
            self._persist()

        print(
            f"[AlertQueue] NEW {alert_id} | {alert['method']} {alert['path']} | "
            f"type={alert['attack_type']} severity={alert['severity']} | "
            f"status={STATUS_PENDING}"
        )

        return alert

    def get_alerts(
        self,
        *,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List alerts, newest first, with optional filters."""
        with self._lock:
            alerts = list(reversed(self._alerts))

        if status:
            status_upper = status.upper()
            alerts = [a for a in alerts if a.get("status", "").upper() == status_upper]

        if severity:
            severity_upper = severity.upper()
            alerts = [a for a in alerts if a.get("severity", "").upper() == severity_upper]

        return alerts[:limit]

    def get_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get a single alert by ID."""
        with self._lock:
            return self._alerts_by_id.get(alert_id)

    def resolve_alert(self, alert_id: str, action: str) -> Optional[Dict[str, Any]]:
        """
        Admin resolves an alert: BLOCK, ALLOW, or IGNORE.

        Returns the updated alert dict, or None if not found.
        """
        action_upper = action.upper()

        # Normalize action names
        action_map = {
            "BLOCK": STATUS_BLOCK,
            "ADMIN_BLOCK": STATUS_BLOCK,
            "ALLOW": STATUS_ALLOW,
            "ADMIN_ALLOW": STATUS_ALLOW,
            "IGNORE": STATUS_IGNORE,
            "ADMIN_IGNORE": STATUS_IGNORE,
        }
        resolved_status = action_map.get(action_upper)
        if not resolved_status:
            return None

        with self._lock:
            alert = self._alerts_by_id.get(alert_id)
            if not alert:
                return None

            # Idempotency: same alert + same action = no duplicate side effects.
            if alert.get("status") == resolved_status:
                print(
                    f"[AlertQueue] IDEMPOTENT {alert_id} already {resolved_status} — no change"
                )
                return alert

            alert["status"] = resolved_status
            alert["effective_decision"] = resolved_status
            alert["admin_action"] = action_upper
            alert["admin_action_timestamp"] = datetime.utcnow().isoformat() + "Z"
            if resolved_status == STATUS_BLOCK:
                stored_path = str(alert.get("path", ""))
                # Always include leading slash so fingerprint matches middleware.
                # FastAPI /{path:path} gives "search"; middleware sees "/search".
                if stored_path and not stored_path.startswith("/"):
                    stored_path = "/" + stored_path
                fp = f"{alert.get('method')}:{stored_path}:{alert.get('client_ip')}"
                self._blocked_fingerprints.add(fp)
            elif resolved_status in (STATUS_ALLOW, STATUS_IGNORE):
                # Admin lifted the block — remove fingerprint immediately so the
                # middleware stops enforcing on the next request.
                stored_path = str(alert.get("path", ""))
                if stored_path and not stored_path.startswith("/"):
                    stored_path = "/" + stored_path
                fp = f"{alert.get('method')}:{stored_path}:{alert.get('client_ip')}"
                if fp in self._blocked_fingerprints:
                    self._blocked_fingerprints.discard(fp)
                    print(f"[TRACE][SOC_UNBLOCK] fingerprint={fp} action={resolved_status}", flush=True)

            # Remove from pending index — alert is no longer PENDING.
            norm_path = str(alert.get("path", ""))
            if norm_path and not norm_path.startswith("/"):
                norm_path = "/" + norm_path
            pending_fp = f"{alert.get('method')}:{norm_path}:{alert.get('client_ip')}"
            self._pending_fingerprints.pop(pending_fp, None)

            # Update override index for future request matching
            key = (
                str(alert.get("attack_type", "")).lower(),
                str(alert.get("client_ip", "")),
            )
            self._overrides[key] = resolved_status

            self._total_resolved += 1
            self._persist()

        print(
            f"[AlertQueue] RESOLVED {alert_id} -> {resolved_status} | "
            f"type={alert.get('attack_type')} ip={alert.get('client_ip')}"
        )

        return alert


    def is_fingerprint_blocked(self, fingerprint: str) -> bool:
        """Check if a request fingerprint is blocked."""
        with self._lock:
            return fingerprint in self._blocked_fingerprints

    def update_alert_enforcement(
        self,
        alert_id: str,
        *,
        final_decision: str = "BLOCK",
        enforcement_source: str = "enforcement_gate",
        http_status: int = 403,
        request_id: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Update an existing alert to reflect final enforcement outcome.

        This is the synchronization point between the ML prediction layer
        and the enforcement layer.  It converts a PENDING_ADMIN_ACTION alert
        into an ENFORCED_BLOCK (or ENFORCED_ALLOW) so that /soc/alerts and
        the dashboard display the *actual* enforcement result.
        """
        status_map = {
            "BLOCK": "ENFORCED_BLOCK",
            "ALLOW": "ENFORCED_ALLOW",
        }
        new_status = status_map.get(final_decision.upper(), f"ENFORCED_{final_decision.upper()}")

        with self._lock:
            alert = self._alerts_by_id.get(alert_id)
            if not alert:
                return None

            alert["status"] = new_status
            alert["effective_decision"] = final_decision.upper()
            alert["enforcement_source"] = enforcement_source
            alert["enforcement_http_status"] = http_status
            alert["enforcement_timestamp"] = datetime.utcnow().isoformat() + "Z"
            if request_id:
                alert["request_id"] = request_id

            # Update blocked fingerprints for enforcement memory
            if final_decision.upper() == "BLOCK":
                stored_path = str(alert.get("path", ""))
                if stored_path and not stored_path.startswith("/"):
                    stored_path = "/" + stored_path
                fp = f"{alert.get('method')}:{stored_path}:{alert.get('client_ip')}"
                self._blocked_fingerprints.add(fp)

            # Remove from pending index
            norm_path = str(alert.get("path", ""))
            if norm_path and not norm_path.startswith("/"):
                norm_path = "/" + norm_path
            pending_fp = f"{alert.get('method')}:{norm_path}:{alert.get('client_ip')}"
            self._pending_fingerprints.pop(pending_fp, None)

            self._total_resolved += 1
            self._persist()

        print(
            f"[AlertQueue] ENFORCED {alert_id} -> {new_status} | "
            f"source={enforcement_source} http={http_status}",
            flush=True,
        )
        return alert

    def reset_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Reset an alert to ALLOW state for re-testing / false-positive review.

        This is a DEMO/TESTING feature — it transitions an alert to RESET
        status so the same request can be re-evaluated by the ML pipeline
        without being blocked by enforcement memory.

        Preserves ml_decision_original for audit trail.
        """
        with self._lock:
            alert = self._alerts_by_id.get(alert_id)
            if not alert:
                return None

            # 1. Update alert fields
            alert["status"] = STATUS_RESET
            alert["effective_decision"] = "ALLOW"
            alert["enforcement_source"] = None
            alert["admin_action"] = "RESET"
            alert["admin_action_timestamp"] = datetime.utcnow().isoformat() + "Z"
            # ml_decision_original is intentionally NOT changed (audit trail)

            # 2. Remove blocked fingerprint so middleware stops blocking
            stored_path = str(alert.get("path", ""))
            if stored_path and not stored_path.startswith("/"):
                stored_path = "/" + stored_path
            fp = f"{alert.get('method')}:{stored_path}:{alert.get('client_ip')}"
            self._blocked_fingerprints.discard(fp)

            # 3. Remove from pending index (if somehow still there)
            self._pending_fingerprints.pop(fp, None)

            # 4. Remove override entry so ML pipeline re-evaluates fresh
            key = (
                str(alert.get("attack_type", "")).lower(),
                str(alert.get("client_ip", "")),
            )
            self._overrides.pop(key, None)

            self._persist()

        print(
            f"[AlertQueue] RESET {alert_id} -> {STATUS_RESET} | "
            f"type={alert.get('attack_type')} ip={alert.get('client_ip')} | "
            f"fingerprint cleared, override removed",
            flush=True,
        )
        return alert

    def check_admin_override(self, *, attack_type: str, client_ip: str) -> Optional[str]:
        """Return the admin override action for (attack_type, client_ip), or None.

        Returns one of: STATUS_BLOCK ("ADMIN_BLOCK"), STATUS_ALLOW ("ADMIN_ALLOW"),
        STATUS_IGNORE ("ADMIN_IGNORE"), or None if no admin decision exists yet.

        This is the single lookup point for the SOC override index.
        app.py uses the return value to short-circuit ML-pipeline decisions
        that have already been adjudicated by an admin.
        """
        key = (str(attack_type).strip().lower(), str(client_ip))
        with self._lock:
            result = self._overrides.get(key)
        if result:
            print(
                f"[TRACE][ADMIN_OVERRIDE] attack_type={attack_type} ip={client_ip} action={result}",
                flush=True,
            )
        return result

    def get_stats(self) -> Dict[str, Any]:
        """Summary counts by status."""
        with self._lock:
            alerts = list(self._alerts)

        pending = sum(1 for a in alerts if a.get("status") == STATUS_PENDING)
        blocked = sum(1 for a in alerts if a.get("status") == STATUS_BLOCK)
        allowed = sum(1 for a in alerts if a.get("status") == STATUS_ALLOW)
        ignored = sum(1 for a in alerts if a.get("status") == STATUS_IGNORE)

        return {
            "total_alerts": len(alerts),
            "pending": pending,
            "blocked": blocked,
            "allowed": allowed,
            "ignored": ignored,
            "total_added": self._total_added,
            "total_resolved": self._total_resolved,
            # Count of fingerprints the middleware is actively enforcing.
            # Uses _blocked_fingerprints (the exact set is_fingerprint_blocked reads)
            # rather than _overrides which includes ALLOW/IGNORE entries.
            "override_rules_active": len(self._blocked_fingerprints),
        }

    def reset_all(self) -> Dict[str, Any]:
        """Clear ALL alerts, overrides, and blocked fingerprints.

        Returns summary of what was cleared.
        """
        with self._lock:
            count = len(self._alerts)
            self._alerts.clear()
            self._alerts_by_id.clear()
            self._overrides.clear()
            self._blocked_fingerprints.clear()
            self._pending_fingerprints.clear()
            self._total_added = 0
            self._total_resolved = 0
            self._persist()

        print(f"[AlertQueue] RESET_ALL cleared {count} alerts", flush=True)
        return {
            "cleared_alerts": count,
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }


# ── Singleton instance ─────────────────────────────────────────────────
alert_queue = AlertQueue()
