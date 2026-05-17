from typing import Any, Dict, List
import random


class DecisionEngine:
    def __init__(
        self,
        high_anomaly_threshold: float = 0.7,
        low_anomaly_threshold: float = 0.4,
        high_confidence_threshold: float = 0.7,
        low_confidence_threshold: float = 0.4,
        medium_anomaly_min: float = 0.5,
        medium_anomaly_max: float = 0.7,
        medium_confidence_min: float = 0.4,
        medium_confidence_max: float = 0.7,
        # Upper bound for IGNORE on normal predictions.
        anomaly_only_ignore_max: float = 0.85,
        severity_downgrade_probability: float = 0.05,
        random_seed: int = 42,
        debug_logging: bool = True,
    ):
        self.HIGH_ANOMALY_THRESHOLD = float(high_anomaly_threshold)
        self.LOW_ANOMALY_THRESHOLD = float(low_anomaly_threshold)
        self.HIGH_CONFIDENCE_THRESHOLD = float(high_confidence_threshold)
        self.LOW_CONFIDENCE_THRESHOLD = float(low_confidence_threshold)

        self.MEDIUM_ANOMALY_MIN = float(medium_anomaly_min)
        self.MEDIUM_ANOMALY_MAX = float(medium_anomaly_max)
        self.MEDIUM_CONFIDENCE_MIN = float(medium_confidence_min)
        self.MEDIUM_CONFIDENCE_MAX = float(medium_confidence_max)

        self.ANOMALY_ONLY_IGNORE_MAX = float(anomaly_only_ignore_max)

        self.SEVERITY_DOWNGRADE_PROBABILITY = float(severity_downgrade_probability)
        self._rng = random.Random(random_seed)
        self.debug_logging = bool(debug_logging)

        self._high_severity_types = {
            "sqli",
            "sql injection",
            "command injection",
            "rce",
            "remote code execution",
            "ssrf",
            "server-side request forgery",
        }
        self._medium_severity_types = {
            "xss",
            "file inclusion",
            "lfi",
            "rfi",
            "path traversal",
        }
        self._normal_types = {"normal", "benign", "legitimate", "none"}
        self._minimum_alert_types = {
            "sqli",
            "sql injection",
            "command injection",
            "rce",
            "remote code execution",
            "path traversal",
            "directory traversal",
            "lfi",
            "rfi",
            "ssrf",
            "server-side request forgery",
        }

    @staticmethod
    def _clip_score(value: Any, default: float = 0.0) -> float:
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            numeric = float(default)
        if numeric < 0.0:
            return 0.0
        if numeric > 1.0:
            return 1.0
        return numeric

    @staticmethod
    def _normalize_attack_type(attack_type: Any) -> str:
        text = "unknown" if attack_type is None else str(attack_type).strip()
        return text if text else "unknown"

    @staticmethod
    def _normalize_attack_key(attack_type: str) -> str:
        return str(attack_type).strip().lower()

    @staticmethod
    def _attack_phrase(attack_key: str, attack_type: str) -> str:
        mapping = {
            "sqli": "SQL injection",
            "sql injection": "SQL injection",
            "command injection": "command injection",
            "rce": "remote code execution",
            "remote code execution": "remote code execution",
            "path traversal": "path traversal",
            "directory traversal": "path traversal",
            "lfi": "local file inclusion",
            "rfi": "remote file inclusion",
            "xss": "cross-site scripting",
            "ssrf": "server-side request forgery",
            "server-side request forgery": "server-side request forgery",
        }
        return mapping.get(attack_key, attack_type if attack_type and attack_type != "unknown" else "suspicious activity")

    def _is_normal_prediction(self, attack_type: str) -> bool:
        return attack_type.lower() in self._normal_types

    def _is_minimum_alert_attack(self, attack_key: str) -> bool:
        return attack_key in self._minimum_alert_types

    def _has_weak_attack_evidence(self, attack_key: str, confidence: float) -> bool:
        if attack_key in self._normal_types or attack_key in {"", "unknown"}:
            return True
        return confidence < self.LOW_CONFIDENCE_THRESHOLD

    def _map_severity(self, attack_type: str) -> str:
        normalized = attack_type.lower()
        if normalized in self._high_severity_types:
            return "HIGH"
        if normalized in self._medium_severity_types:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _downgrade_severity(severity: str) -> str:
        chain = {
            "HIGH": "MEDIUM",
            "MEDIUM": "LOW",
            "LOW": "LOW",
        }
        return chain.get(severity.upper(), "LOW")

    def _is_borderline(self, anomaly_score: float, confidence: float) -> bool:
        anomaly_medium = self.MEDIUM_ANOMALY_MIN <= anomaly_score <= self.MEDIUM_ANOMALY_MAX
        confidence_medium = self.MEDIUM_CONFIDENCE_MIN <= confidence <= self.MEDIUM_CONFIDENCE_MAX
        return bool(anomaly_medium and confidence_medium)

    def _reason_for_decision(
        self,
        decision: str,
        attack_type: str,
        attack_key: str,
        anomaly_score: float,
        confidence: float,
        forced_min_alert: bool,
        weak_attack_evidence: bool,
    ) -> str:
        attack_phrase = self._attack_phrase(attack_key, attack_type)

        if decision == "BLOCK":
            return f"High anomaly + high confidence {attack_phrase}"

        if decision == "ALERT":
            if forced_min_alert and anomaly_score < self.LOW_ANOMALY_THRESHOLD:
                return f"Known high-risk type ({attack_phrase}) with low anomaly score, requires investigation"
            if anomaly_score >= self.HIGH_ANOMALY_THRESHOLD and confidence < self.HIGH_CONFIDENCE_THRESHOLD:
                return f"High anomaly but lower confidence {attack_phrase}, requires investigation"
            if anomaly_score >= self.MEDIUM_ANOMALY_MIN:
                return "Moderate anomaly, requires investigation"
            if confidence < self.LOW_CONFIDENCE_THRESHOLD:
                return "Low confidence suspicious activity, requires investigation"
            return "Suspicious activity, requires investigation"

        if weak_attack_evidence and anomaly_score >= self.HIGH_ANOMALY_THRESHOLD:
            return "High anomaly but weak/benign classifier evidence, treated as benign"

        if weak_attack_evidence and anomaly_score >= self.MEDIUM_ANOMALY_MIN:
            return "Moderate anomaly but weak attack evidence, treated as benign"

        return "Low anomaly score, likely benign"

    def decide(self, anomaly_score: float, attack_type: str, confidence: float) -> Dict[str, Any]:
        anomaly_score_value = self._clip_score(anomaly_score)
        confidence_value = self._clip_score(confidence)
        attack_type_value = self._normalize_attack_type(attack_type)
        attack_key = self._normalize_attack_key(attack_type_value)
        weak_attack_evidence = self._has_weak_attack_evidence(attack_key, confidence_value)
        is_normal_prediction = self._is_normal_prediction(attack_type_value)

        # SOC policy
        if anomaly_score_value >= self.HIGH_ANOMALY_THRESHOLD:
            if is_normal_prediction and confidence_value <= 0.35 and anomaly_score_value < self.ANOMALY_ONLY_IGNORE_MAX:
                decision = "IGNORE"
            elif confidence_value >= self.HIGH_CONFIDENCE_THRESHOLD and not is_normal_prediction:
                decision = "BLOCK"
            else:
                decision = "ALERT"
        elif anomaly_score_value >= self.MEDIUM_ANOMALY_MIN:
            if weak_attack_evidence:
                decision = "IGNORE"
            else:
                decision = "ALERT"
        elif anomaly_score_value < self.LOW_ANOMALY_THRESHOLD:
            decision = "IGNORE"
        else:
            decision = "ALERT" if not weak_attack_evidence else "IGNORE"

        # Never ignore high-risk attack classes
        forced_min_alert = False
        if decision == "IGNORE" and self._is_minimum_alert_attack(attack_key):
            decision = "ALERT"
            forced_min_alert = True

        # Guard against low-confidence false-ignore
        if (
            decision == "IGNORE"
            and confidence_value < self.LOW_CONFIDENCE_THRESHOLD
            and anomaly_score_value >= self.LOW_ANOMALY_THRESHOLD
            and not (is_normal_prediction and anomaly_score_value < self.ANOMALY_ONLY_IGNORE_MAX)
        ):
            decision = "ALERT"

        if decision == "IGNORE":
            severity = "LOW"
        else:
            severity = self._map_severity(attack_key)

        reason = self._reason_for_decision(
            decision=decision,
            attack_type=attack_type_value,
            attack_key=attack_key,
            anomaly_score=anomaly_score_value,
            confidence=confidence_value,
            forced_min_alert=forced_min_alert,
            weak_attack_evidence=weak_attack_evidence,
        )

        # Uncertainty calibration
        if decision == "ALERT" and self._rng.random() < self.SEVERITY_DOWNGRADE_PROBABILITY:
            if severity != "LOW":
                severity = "LOW"
                reason = f"{reason}; severity downgraded due to uncertainty calibration"

        if self.debug_logging:
            print(
                f"[DecisionEngine] anomaly_score={anomaly_score_value:.3f} "
                f"confidence={confidence_value:.3f} attack_type={attack_type_value} "
                f"decision={decision} weak_evidence={weak_attack_evidence} reason={reason}"
            )

        return {
            "decision": decision,
            "severity": severity,
            "attack_type": attack_type_value,
            "confidence": float(confidence_value),
            "anomaly_score": float(anomaly_score_value),
            "reason": reason,
        }

    def evaluate_decisions(self, results_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        block_count = 0
        alert_count = 0
        ignore_count = 0
        confidence_sum = 0.0
        anomaly_score_sum = 0.0

        for item in results_list:
            if isinstance(item, dict) and "decision" in item:
                decision = str(item.get("decision", "")).strip().upper()
                confidence_value = self._clip_score(item.get("confidence", 0.0))
                anomaly_score_value = self._clip_score(item.get("anomaly_score", 0.0))
            else:
                anomaly_score = item.get("anomaly_score", 0.0) if isinstance(item, dict) else 0.0
                attack_type = item.get("attack_type", "unknown") if isinstance(item, dict) else "unknown"
                confidence = item.get("confidence", 0.0) if isinstance(item, dict) else 0.0
                evaluated = self.decide(anomaly_score=anomaly_score, attack_type=attack_type, confidence=confidence)
                decision = str(evaluated.get("decision", "IGNORE")).strip().upper()
                confidence_value = self._clip_score(evaluated.get("confidence", 0.0))
                anomaly_score_value = self._clip_score(evaluated.get("anomaly_score", 0.0))

            confidence_sum += float(confidence_value)
            anomaly_score_sum += float(anomaly_score_value)

            if decision == "BLOCK":
                block_count += 1
            elif decision == "ALERT":
                alert_count += 1
            else:
                ignore_count += 1

        total = len(results_list)
        if total == 0:
            return {
                "total_requests": 0,
                "block_count": 0,
                "alert_count": 0,
                "ignore_count": 0,
                "block_percentage": 0.0,
                "alert_percentage": 0.0,
                "ignore_percentage": 0.0,
                "average_confidence": 0.0,
                "average_anomaly_score": 0.0,
            }

        return {
            "total_requests": int(total),
            "block_count": int(block_count),
            "alert_count": int(alert_count),
            "ignore_count": int(ignore_count),
            "block_percentage": float((block_count / total) * 100.0),
            "alert_percentage": float((alert_count / total) * 100.0),
            "ignore_percentage": float((ignore_count / total) * 100.0),
            "average_confidence": float(confidence_sum / total),
            "average_anomaly_score": float(anomaly_score_sum / total),
        }

    def evaluate_decision_engine(self, results_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Backward-compatible alias for existing callers."""
        return self.evaluate_decisions(results_list)