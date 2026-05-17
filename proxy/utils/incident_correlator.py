"""
SOC Incident Correlator — Lightweight in-memory incident grouping.

Groups related alerts into incidents based on:
  - Same source IP
  - Same attack type
  - Within a configurable time window (default 5 minutes)

This module is READ-ONLY over AlertQueue data.
It MUST NOT modify alert state, enforcement, or the ML pipeline.

Incident IDs follow the format: INC-YYYYMMDD-NNNN
"""
from __future__ import annotations

import threading
from collections import OrderedDict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional


# ── Constants ──────────────────────────────────────────────────────────
CORRELATION_WINDOW_SECONDS = 300  # 5 minutes
MAX_INCIDENTS = 500

# Attack types that should NEVER create incidents
BENIGN_TYPES = {"normal", "benign", "unknown", "none", ""}

# Severity rank for comparison (higher = more severe)
SEVERITY_RANK = {
    "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
}

# Attack types that are inherently HIGH severity
HIGH_ATTACK_TYPES = {
    "xss", "sqli", "sql injection", "command injection", "rce",
    "path traversal", "directory traversal", "lfi", "rfi", "ssrf",
    "server-side request forgery",
}


def _compute_severity(
    alert_count: int,
    highest_alert_severity: str = "LOW",
    attack_type: str = "",
) -> str:
    """Compute incident severity from alert count + child severity + attack type.

    Rules:
    - Known dangerous attack types start at MEDIUM minimum
    - Any HIGH alert child => incident is at least HIGH
    - 3+ alerts => HIGH
    - 5+ alerts => CRITICAL
    - Never downgrade below the highest child severity
    """
    # Count-based severity
    if alert_count >= 5:
        count_sev = "CRITICAL"
    elif alert_count >= 3:
        count_sev = "HIGH"
    elif alert_count >= 2:
        count_sev = "MEDIUM"
    else:
        count_sev = "LOW"

    # Attack-type minimum severity
    type_sev = "MEDIUM" if attack_type.lower() in HIGH_ATTACK_TYPES else "LOW"

    # Pick the highest of: count-based, alert child severity, attack-type floor
    candidates = [
        SEVERITY_RANK.get(count_sev, 0),
        SEVERITY_RANK.get(highest_alert_severity.upper(), 0),
        SEVERITY_RANK.get(type_sev, 0),
    ]
    best_rank = max(candidates)

    # Reverse lookup
    for name, rank in SEVERITY_RANK.items():
        if rank == best_rank:
            return name
    return "LOW"


def _generate_incident_id(counter: int) -> str:
    """Generate INC-YYYYMMDD-NNNN format ID."""
    now = datetime.utcnow()
    return f"INC-{now.strftime('%Y%m%d')}-{counter:04d}"


class IncidentCorrelator:
    """
    Thread-safe in-memory incident correlator.

    Correlates alerts into incidents using a (client_ip, attack_type) key.
    Incidents are time-bounded: alerts older than the correlation window
    start a new incident for the same key.

    This class is stateless with respect to AlertQueue — it rebuilds
    incidents from the current alert list on each call to correlate().
    """

    def __init__(
        self,
        window_seconds: int = CORRELATION_WINDOW_SECONDS,
        max_incidents: int = MAX_INCIDENTS,
    ):
        self._lock = threading.Lock()
        self._window = timedelta(seconds=window_seconds)
        self._max_incidents = max_incidents
        self._counter = 0
        # Cache: correlation_key -> incident dict
        self._incidents: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        # Map alert_id -> incident_id for fast lookup
        self._alert_to_incident: Dict[str, str] = {}

    def correlate(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Build/update incidents from the current alert list.

        This is the main entry point. It processes ALL alerts and returns
        the current incident list. Safe to call on every polling cycle.

        Args:
            alerts: List of alert dicts from AlertQueue.get_alerts()

        Returns:
            List of incident dicts, newest first.
        """
        if not alerts:
            return []

        with self._lock:
            # Sort alerts by timestamp (oldest first) for correct grouping
            sorted_alerts = sorted(
                alerts,
                key=lambda a: a.get("timestamp", ""),
            )

            for alert in sorted_alerts:
                alert_id = alert.get("alert_id", "")
                if not alert_id:
                    continue

                # ── Filter out benign/normal traffic ──
                attack_type_raw = str(alert.get("attack_type", "")).strip().lower()
                status_raw = str(alert.get("status", "")).strip().upper()
                if attack_type_raw in BENIGN_TYPES:
                    continue
                if status_raw in ("IGNORED", "ADMIN_IGNORE"):
                    continue

                # Skip if already correlated
                if alert_id in self._alert_to_incident:
                    # Update existing incident with latest alert data
                    inc_id = self._alert_to_incident[alert_id]
                    if inc_id in self._incidents:
                        self._update_incident(self._incidents[inc_id], alert)
                    continue

                client_ip = str(alert.get("client_ip", "")).strip()
                attack_type = str(alert.get("attack_type", "unknown")).strip().lower()
                alert_ts = self._parse_timestamp(alert.get("timestamp", ""))

                # Build correlation key
                corr_key = f"{client_ip}|{attack_type}"

                # Try to attach to existing incident
                attached = False
                if corr_key in self._incidents:
                    incident = self._incidents[corr_key]
                    last_seen = self._parse_timestamp(incident.get("last_seen", ""))
                    if last_seen and alert_ts and (alert_ts - last_seen) <= self._window:
                        # Within window — attach to existing incident
                        self._attach_alert(incident, alert, alert_ts)
                        self._alert_to_incident[alert_id] = incident["incident_id"]
                        attached = True

                if not attached:
                    # Create new incident
                    self._counter += 1
                    inc_id = _generate_incident_id(self._counter)

                    alert_sev = str(alert.get("severity", "LOW")).upper()
                    incident = {
                        "incident_id": inc_id,
                        "correlation_key": corr_key,
                        "client_ip": client_ip,
                        "attack_type": alert.get("attack_type", "unknown"),
                        "severity": _compute_severity(1, alert_sev, attack_type),
                        "highest_alert_severity": alert_sev,
                        "alert_count": 1,
                        "alert_ids": [alert_id],
                        "first_seen": alert.get("timestamp", ""),
                        "last_seen": alert.get("timestamp", ""),
                        "status": "ACTIVE",
                        "paths": [alert.get("path", "")],
                        "methods": [alert.get("method", "")],
                        "max_confidence": float(alert.get("confidence", 0.0)),
                        "max_anomaly_score": float(alert.get("anomaly_score", 0.0)),
                    }

                    # FIFO eviction
                    if corr_key in self._incidents:
                        # Remove old incident for this key
                        old = self._incidents.pop(corr_key)
                        for aid in old.get("alert_ids", []):
                            self._alert_to_incident.pop(aid, None)

                    while len(self._incidents) >= self._max_incidents:
                        _, evicted = self._incidents.popitem(last=False)
                        for aid in evicted.get("alert_ids", []):
                            self._alert_to_incident.pop(aid, None)

                    self._incidents[corr_key] = incident
                    self._alert_to_incident[alert_id] = inc_id

            # Return incidents newest-first
            result = list(reversed(self._incidents.values()))
            return result

    def _attach_alert(
        self,
        incident: Dict[str, Any],
        alert: Dict[str, Any],
        alert_ts: Optional[datetime],
    ) -> None:
        """Attach an alert to an existing incident."""
        alert_id = alert.get("alert_id", "")
        if alert_id not in incident["alert_ids"]:
            incident["alert_ids"].append(alert_id)
        incident["alert_count"] = len(incident["alert_ids"])
        incident["last_seen"] = alert.get("timestamp", incident["last_seen"])

        # Track highest child alert severity
        alert_sev = str(alert.get("severity", "LOW")).upper()
        cur_highest = incident.get("highest_alert_severity", "LOW")
        if SEVERITY_RANK.get(alert_sev, 0) > SEVERITY_RANK.get(cur_highest, 0):
            incident["highest_alert_severity"] = alert_sev

        incident["severity"] = _compute_severity(
            incident["alert_count"],
            incident.get("highest_alert_severity", "LOW"),
            str(incident.get("attack_type", "")).lower(),
        )

        path = alert.get("path", "")
        if path and path not in incident["paths"]:
            incident["paths"].append(path)

        method = alert.get("method", "")
        if method and method not in incident["methods"]:
            incident["methods"].append(method)

        conf = float(alert.get("confidence", 0.0))
        if conf > incident["max_confidence"]:
            incident["max_confidence"] = conf

        anom = float(alert.get("anomaly_score", 0.0))
        if anom > incident["max_anomaly_score"]:
            incident["max_anomaly_score"] = anom

    def _update_incident(
        self, incident: Dict[str, Any], alert: Dict[str, Any]
    ) -> None:
        """Update incident metadata from a re-seen alert (e.g. status change)."""
        # Just refresh severity in case alert count tracking drifted
        incident["severity"] = _compute_severity(
            incident["alert_count"],
            incident.get("highest_alert_severity", "LOW"),
            str(incident.get("attack_type", "")).lower(),
        )

    @staticmethod
    def _parse_timestamp(ts_str: str) -> Optional[datetime]:
        """Parse ISO timestamp string to datetime."""
        if not ts_str:
            return None
        try:
            # Handle trailing Z
            clean = ts_str.replace("Z", "+00:00")
            return datetime.fromisoformat(clean)
        except (ValueError, TypeError):
            return None

    def get_incidents(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Return cached incidents (newest first), up to limit."""
        with self._lock:
            result = list(reversed(self._incidents.values()))
        return result[:limit]

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get a single incident by ID."""
        with self._lock:
            for inc in self._incidents.values():
                if inc.get("incident_id") == incident_id:
                    return dict(inc)
        return None

    def get_incident_for_alert(self, alert_id: str) -> Optional[str]:
        """Return the incident_id that contains this alert, or None."""
        with self._lock:
            return self._alert_to_incident.get(alert_id)

    def get_stats(self) -> Dict[str, Any]:
        """Return summary statistics."""
        with self._lock:
            incidents = list(self._incidents.values())

        active = sum(1 for i in incidents if i.get("status") == "ACTIVE")
        critical = sum(1 for i in incidents if i.get("severity") == "CRITICAL")
        high = sum(1 for i in incidents if i.get("severity") == "HIGH")
        total_correlated = sum(i.get("alert_count", 0) for i in incidents)

        return {
            "total_incidents": len(incidents),
            "active_incidents": active,
            "critical_incidents": critical,
            "high_incidents": high,
            "total_correlated_alerts": total_correlated,
        }

    def reset(self) -> None:
        """Clear all incidents (for testing/demo reset)."""
        with self._lock:
            self._incidents.clear()
            self._alert_to_incident.clear()
            self._counter = 0


# ── Singleton ──────────────────────────────────────────────────────────
incident_correlator = IncidentCorrelator()
