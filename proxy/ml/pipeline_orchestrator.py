from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, List
from urllib.parse import urlsplit

from .anomaly_detector import AnomalyDetector
from .attack_classifier import AttackClassifier
from .decision_engine import DecisionEngine
from .anomaly_false_positive_reducer import FalsePositiveReducer


class PipelineOrchestrator:
    def __init__(self, enable_logging: bool = True):
        self.enable_logging = bool(enable_logging)
        self.logs: List[Dict[str, Any]] = []

        self._module_dir = os.path.dirname(os.path.abspath(__file__))
        self._project_root = os.path.abspath(os.path.join(self._module_dir, "..", ".."))
        self._model_dir = self._resolve_model_dir()

        anomaly_model_path = self._resolve_model_path(
            filename="anomaly_detector.pkl",
            default_path=os.path.join(self._module_dir, "models", "anomaly_detector.pkl"),
        )
        attack_model_path = self._resolve_model_path(
            filename="attack_classifier.pkl",
            default_path=os.path.join(self._module_dir, "models", "attack_classifier.pkl"),
        )
        fp_reducer_model_path = self._resolve_model_path(
            filename="fp_reducer.pkl",
            default_path=os.path.join(self._module_dir, "models", "fp_reducer.pkl"),
        )

        self.anomaly_detector = AnomalyDetector(model_path=anomaly_model_path)
        self.attack_classifier = AttackClassifier(model_path=attack_model_path)
        self.fp_reducer = FalsePositiveReducer(model_path=fp_reducer_model_path)
        self.decision_engine = DecisionEngine()

    def _gather_model_dirs(self) -> List[str]:
        env_dir = os.getenv("MOODLESEC_MODEL_DIR", "").strip()
        candidates = []
        if env_dir:
            candidates.append(env_dir)
        candidates.extend(
            [
                os.path.join(self._module_dir, "models"),
            ]
        )

        normalized: List[str] = []
        for path in candidates:
            if not path:
                continue
            norm = os.path.normpath(path)
            if norm not in normalized:
                normalized.append(norm)
        return normalized

    def _resolve_model_dir(self) -> str:
        env_dir = os.getenv("MOODLESEC_MODEL_DIR", "").strip()
        if env_dir and not os.path.isdir(env_dir) and self.enable_logging:
            print(f"[Pipeline] WARNING: MOODLESEC_MODEL_DIR not found: {env_dir}")

        candidates = self._gather_model_dirs()
        existing = [path for path in candidates if os.path.isdir(path)]
        chosen = existing[0] if existing else (candidates[0] if candidates else "")

        legacy_dirs = [
            os.path.join(self._project_root, "ml", "models"),
        ]
        existing_legacy = [path for path in legacy_dirs if os.path.isdir(path)]
        if existing_legacy and self.enable_logging:
            print(
                "[Pipeline] WARNING: legacy model directory detected (non-canonical): "
                f"{existing_legacy}. Canonical runtime directory is: {chosen}"
            )

        if len(existing) > 1 and self.enable_logging:
            print(
                "[Pipeline] WARNING: multiple model directories found: "
                f"{existing}. Using: {chosen}"
            )

        return chosen

    def _resolve_model_path(self, filename: str, default_path: str) -> str:
        candidates: List[str] = []
        if self._model_dir:
            candidates.append(os.path.join(self._model_dir, filename))
        if default_path not in candidates:
            candidates.append(default_path)

        existing = [path for path in candidates if os.path.exists(path)]
        if len(existing) > 1 and self.enable_logging:
            print(
                f"[Pipeline] WARNING: multiple model files found for {filename}: "
                f"{existing}. Using: {existing[0]}"
            )

        resolved = existing[0] if existing else candidates[0]
        if not os.path.exists(resolved) and self.enable_logging:
            print(
                f"[Pipeline] WARNING: model file not found for {filename} at canonical path: "
                f"{resolved}"
            )
        return resolved

    @staticmethod
    def _safe_text(value: Any) -> str:
        if value is None:
            return ""
        return str(value)

    @staticmethod
    def _safe_divide(numerator: float, denominator: float) -> float:
        if denominator == 0:
            return 0.0
        return float(numerator / denominator)

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return int(default)

    @staticmethod
    def _safe_float(value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except (TypeError, ValueError):
            return float(default)

    @staticmethod
    def _is_attack_prediction(attack_type: Any) -> bool:
        normalized = str(attack_type).strip().lower()
        if not normalized:
            return False
        return normalized not in {"normal", "benign", "legitimate", "none", "unknown"}

    @staticmethod
    def _derive_fp_severity(anomaly_score: float) -> str:
        score = float(anomaly_score or 0.0)
        if score < 0.0:
            score = 0.0
        if score > 1.0:
            score = 1.0
        if score >= 0.90:
            return "critical"
        if score >= 0.75:
            return "high"
        if score >= 0.55:
            return "medium"
        if score >= 0.35:
            return "low"
        return "info"

    @staticmethod
    def _fp_category_from_attack_type(attack_type: Any) -> str:
        key = str(attack_type).strip().lower()
        mapping = {
            "sqli": "SQL Injection",
            "sql injection": "SQL Injection",
            "xss": "XSS",
            "cross-site scripting": "XSS",
            "path traversal": "Directory Listing",
            "directory traversal": "Directory Listing",
            "lfi": "Directory Listing",
            "rfi": "Directory Listing",
        }
        if key in mapping:
            return mapping[key]
        return str(attack_type).strip() or "Security Misconfiguration"

    @staticmethod
    def _normalize_true_label(raw_label: Any) -> str:
        label = str(raw_label).strip().lower()
        attack_aliases = {"attack", "anomaly", "malicious", "1", "true", "yes"}
        normal_aliases = {"normal", "benign", "legitimate", "0", "false", "no"}

        if label in attack_aliases:
            return "attack"
        if label in normal_aliases:
            return "normal"

        raise ValueError(
            "Invalid true_label value. Expected attack/normal (or supported aliases), "
            f"got: {raw_label}"
        )

    @staticmethod
    def _decision_to_label(decision: str) -> str:
        normalized = str(decision).strip().upper()
        if normalized in {"BLOCK", "ALERT"}:
            return "attack"
        return "normal"

    @staticmethod
    def _update_confusion_matrix(confusion: Dict[str, int], true_label: str, predicted_label: str) -> None:
        if true_label == "attack" and predicted_label == "attack":
            confusion["TP"] += 1
        elif true_label == "normal" and predicted_label == "attack":
            confusion["FP"] += 1
        elif true_label == "normal" and predicted_label == "normal":
            confusion["TN"] += 1
        else:
            confusion["FN"] += 1

    @classmethod
    def _compute_binary_metrics(cls, confusion: Dict[str, int], total: int) -> Dict[str, Any]:
        tp = int(confusion.get("TP", 0))
        fp = int(confusion.get("FP", 0))
        tn = int(confusion.get("TN", 0))
        fn = int(confusion.get("FN", 0))

        precision = cls._safe_divide(tp, tp + fp)
        recall = cls._safe_divide(tp, tp + fn)
        f1 = cls._safe_divide(2.0 * precision * recall, precision + recall)
        accuracy = cls._safe_divide(tp + tn, total)
        fp_rate = cls._safe_divide(fp, fp + tn)

        return {
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "accuracy": float(accuracy),
            "fp_rate": float(fp_rate),
            "confusion_matrix": {
                "TP": tp,
                "FP": fp,
                "TN": tn,
                "FN": fn,
            },
        }

    def _coerce_pipeline_request(self, request_payload: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(request_payload, dict):
            return {}

        flat_keys = {"method", "path", "query_params", "body", "headers", "request_raw"}
        if any(key in request_payload for key in flat_keys):
            return request_payload

        nested_request = request_payload.get("request")
        if not isinstance(nested_request, dict):
            return request_payload

        parsed = urlsplit(self._safe_text(nested_request.get("url", "/")))
        path = parsed.path or "/"
        query = parsed.query

        return {
            "method": self._safe_text(nested_request.get("method", "GET")).upper() or "GET",
            "path": path,
            "query_params": query,
            "body": self._safe_text(nested_request.get("body", "")),
            "headers": nested_request.get("headers", {}),
            "request_raw": self._safe_text(request_payload.get("request_raw", "")),
        }

    def _normalize_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        normalized = {
            "method": self._safe_text(request.get("method", "GET")).upper() or "GET",
            "path": self._safe_text(request.get("path", "/")) or "/",
            "query_params": self._safe_text(request.get("query_params", "")),
            "body": self._safe_text(request.get("body", "")),
            "headers": request.get("headers", ""),
            "request_raw": self._safe_text(request.get("request_raw", "")),
        }

        if not normalized["path"].startswith("/"):
            normalized["path"] = "/" + normalized["path"]

        if not normalized["request_raw"]:
            query_suffix = f"?{normalized['query_params']}" if normalized["query_params"] else ""
            body_suffix = f" BODY:{normalized['body']}" if normalized["body"] else ""
            normalized["request_raw"] = (
                f"{normalized['method']} {normalized['path']}{query_suffix}{body_suffix}"
            ).strip()

        return normalized

    def _parse_headers(self, headers: Any) -> Dict[str, str]:
        if isinstance(headers, dict):
            return {self._safe_text(k): self._safe_text(v) for k, v in headers.items()}

        text = self._safe_text(headers).strip()
        if not text:
            return {}

        parsed: Dict[str, str] = {}
        for part in text.replace("\n", ";").split(";"):
            segment = part.strip()
            if not segment or ":" not in segment:
                continue
            key, value = segment.split(":", 1)
            key = key.strip()
            value = value.strip()
            if key:
                parsed[key] = value
        return parsed

    def _build_request_url(self, request: Dict[str, Any]) -> str:
        path = self._safe_text(request.get("path", "/")) or "/"
        query = self._safe_text(request.get("query_params", "")).strip()
        if query.startswith("?"):
            query = query[1:]
        return f"{path}?{query}" if query else path

    def _build_fp_reducer_entry(
        self,
        request: Dict[str, Any],
        anomaly_score: float,
        anomaly_reason: str,
        attack_type: str,
    ) -> Dict[str, Any]:
        url = self._build_request_url(request)
        body = self._safe_text(request.get("body", ""))
        payload = f"{url} {body}".strip()

        finding = {
            "severity": self._derive_fp_severity(anomaly_score),
            "category": self._fp_category_from_attack_type(attack_type),
            "evidence": payload[:600],
            "description": "Stage-1 classifier prediction on anomalous request.",
            "url": url,
            "cvss_score": round(float(max(0.0, min(10.0, anomaly_score * 10.0))), 2),
            "risk_score": round(float(max(0.0, min(10.0, anomaly_score * 10.0))), 2),
        }

        context = {
            "status_code": self._safe_int(request.get("response_status_code", 200), 200),
            "response_time": self._safe_float(request.get("response_time", 0.0), 0.0),
            "occurrence_count": self._safe_int(request.get("request_count_last_minute", 1), 1),
            "days_since_first_seen": self._safe_int(request.get("days_since_first_seen", 0), 0),
        }

        return {"finding": finding, "context": context, "reason": anomaly_reason}

    def _to_anomaly_input(self, request: Dict[str, Any]) -> Dict[str, Any]:
        headers = self._parse_headers(request.get("headers", ""))
        url = self._build_request_url(request)

        return {
            "request": {
                "url": url,
                "method": self._safe_text(request.get("method", "GET")).upper(),
                "headers": headers,
                "body": self._safe_text(request.get("body", "")),
            },
            "response": {
                "status_code": int(request.get("response_status_code", 200) or 200),
                "size": int(request.get("response_size", 0) or 0),
                "time": float(request.get("response_time", 0.0) or 0.0),
                "headers": request.get("response_headers", {}) or {},
            },
            "finding": request.get("finding", {}) or {},
            "request_count_last_minute": int(request.get("request_count_last_minute", 1) or 1),
            "unique_ips_last_minute": int(request.get("unique_ips_last_minute", 1) or 1),
            "error_rate_last_minute": float(request.get("error_rate_last_minute", 0.0) or 0.0),
        }

    def _log_decision(self, request_path: str, result: Dict[str, Any]) -> None:
        fp_reducer_confidence = result.get("fp_reducer_confidence")
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "path": request_path,
            "decision": result.get("decision", "UNKNOWN"),
            "attack_type": result.get("attack_type", "unknown"),
            "severity": result.get("severity", "LOW"),
            "confidence": float(result.get("confidence", 0.0) or 0.0),
            "anomaly_score": float(result.get("anomaly_score", 0.0) or 0.0),
            "reason": self._safe_text(result.get("reason", "")),
            "fp_reducer_applied": bool(result.get("fp_reducer_applied", False)),
            "fp_reducer_is_false_positive": result.get("fp_reducer_is_false_positive"),
            "fp_reducer_confidence": (
                float(fp_reducer_confidence) if fp_reducer_confidence is not None else None
            ),
            "fp_reducer_reason": self._safe_text(result.get("fp_reducer_reason", "")),
        }
        self.logs.append(entry)

        if self.enable_logging:
            fp_suffix = ""
            if entry["fp_reducer_applied"]:
                fp_conf = entry["fp_reducer_confidence"]
                conf_text = f"{fp_conf:.3f}" if isinstance(fp_conf, float) else "n/a"
                fp_suffix = f" fp_reducer={entry['fp_reducer_is_false_positive']} fp_conf={conf_text}"
            print(
                f"[Pipeline] path={entry['path']} decision={entry['decision']} "
                f"attack_type={entry['attack_type']} severity={entry['severity']} "
                f"conf={entry['confidence']:.3f} anomaly={entry['anomaly_score']:.3f} "
                f"reason={entry['reason']}" + fp_suffix
            )

    def process_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        normalized_request = self._normalize_request(request)
        request_path = normalized_request.get("path", "/")

        anomaly_input = self._to_anomaly_input(normalized_request)

        try:
            is_anomaly, anomaly_score, anomaly_reason = self.anomaly_detector.detect(anomaly_input)
        except Exception as error:
            try:
                heuristic_is_anomaly, heuristic_score, heuristic_reason = self.anomaly_detector._heuristic_detection(
                    anomaly_input
                )
                is_anomaly = bool(heuristic_is_anomaly)
                anomaly_score = float(heuristic_score)
                anomaly_reason = (
                    f"{heuristic_reason}; heuristic fallback used because anomaly detector error: {error}"
                )
                self.anomaly_detector.is_trained = False
            except Exception as fallback_error:
                result = {
                    "decision": "ALERT",
                    "severity": "LOW",
                    "reason": f"Anomaly detector error: {error}; fallback failed: {fallback_error}",
                    "attack_type": "unknown",
                    "confidence": 0.0,
                    "anomaly_score": 0.0,
                }
                self._log_decision(request_path=request_path, result=result)
                return result

        if not is_anomaly:
            result = {
                "decision": "IGNORE",
                "severity": "LOW",
                "reason": "Not anomalous",
                "attack_type": "normal",
                "confidence": 0.0,
                "anomaly_score": float(anomaly_score),
            }
            self._log_decision(request_path=request_path, result=result)
            return result

        try:
            attack_type, confidence = self.attack_classifier.predict(normalized_request)
            classifier_debug_info = getattr(self.attack_classifier, "last_debug_info", {})
            if not isinstance(classifier_debug_info, dict):
                classifier_debug_info = {}
        except Exception as error:
            attack_type = "unknown"
            confidence = 0.0
            classifier_debug_info = {}
            anomaly_reason = f"{anomaly_reason}; attack classifier error: {error}"

        classifier_context_reason = self._safe_text(classifier_debug_info.get("explanation", "")).strip()
        if classifier_context_reason:
            anomaly_reason = f"{anomaly_reason}; classifier_context={classifier_context_reason}"

        fp_reducer_applied = False
        fp_reducer_is_fp = None
        fp_reducer_confidence = None
        fp_reducer_reason = ""
        raw_confidence = float(confidence)
        adjusted_confidence = float(confidence)

        if self.fp_reducer and self._is_attack_prediction(attack_type):
            fp_entry = self._build_fp_reducer_entry(
                request=normalized_request,
                anomaly_score=float(anomaly_score),
                anomaly_reason=anomaly_reason,
                attack_type=str(attack_type),
            )
            try:
                is_fp, fp_confidence = self.fp_reducer.predict(
                    fp_entry["finding"],
                    fp_entry["context"],
                )
                fp_reducer_applied = True
                fp_reducer_is_fp = bool(is_fp)
                fp_reducer_confidence = float(fp_confidence)
                if fp_reducer_is_fp and fp_reducer_confidence >= 0.60:
                    suppression_multiplier = max(0.35, 1.0 - (0.5 * fp_reducer_confidence))
                    adjusted_confidence = max(0.0, raw_confidence * suppression_multiplier)
                    fp_reducer_reason = (
                        f"fp_reducer_suppressed confidence_multiplier={suppression_multiplier:.2f}"
                    )
            except Exception as error:
                fp_reducer_applied = True
                fp_reducer_reason = f"fp_reducer_error: {error}"

        confidence = adjusted_confidence

        decision_result = self.decision_engine.decide(
            anomaly_score=float(anomaly_score),
            attack_type=attack_type,
            confidence=float(confidence),
        )

        decision_result["fp_reducer_applied"] = fp_reducer_applied
        decision_result["fp_reducer_is_false_positive"] = fp_reducer_is_fp
        decision_result["fp_reducer_confidence"] = fp_reducer_confidence
        decision_result["fp_reducer_reason"] = fp_reducer_reason
        if fp_reducer_applied:
            decision_result["confidence_before_fp_reducer"] = raw_confidence

        if anomaly_reason and anomaly_reason != "Normal behavior":
            decision_result["reason"] = f"{decision_result['reason']} ({anomaly_reason})"

        self._log_decision(request_path=request_path, result=decision_result)
        return decision_result

    def process_batch(self, requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [self.process_request(request) for request in requests]

    def evaluate_full_pipeline(self, dataset: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Evaluate end-to-end pipeline performance against labeled requests.

        Expected dataset item format:
        {
            "request": {...},
            "true_label": "attack" | "normal"
        }
        """
        if not isinstance(dataset, list):
            raise ValueError("dataset must be a list of labeled request items")

        if len(dataset) == 0:
            return {
                "pipeline_metrics": {
                    "precision": 0.0,
                    "recall": 0.0,
                    "f1": 0.0,
                    "accuracy": 0.0,
                    "confusion_matrix": {"TP": 0, "FP": 0, "TN": 0, "FN": 0},
                },
                "decision_distribution": {
                    "BLOCK": 0.0,
                    "ALERT": 0.0,
                    "IGNORE": 0.0,
                },
                "comparison": {
                    "anomaly_recall": 0.0,
                    "pipeline_recall": 0.0,
                    "anomaly_fp_rate": 0.0,
                    "pipeline_fp_rate": 0.0,
                    "fp_reduction": 0.0,
                    "recall_drop": 0.0,
                },
            }

        pipeline_confusion = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
        anomaly_confusion = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
        decision_counts = {"BLOCK": 0, "ALERT": 0, "IGNORE": 0}

        original_enable_logging = self.enable_logging
        original_decision_debug = getattr(self.decision_engine, "debug_logging", None)
        original_anomaly_debug = getattr(self.anomaly_detector, "debug_feature_logging", None)
        self.enable_logging = False
        if original_decision_debug is not None:
            self.decision_engine.debug_logging = False
        if original_anomaly_debug is not None:
            self.anomaly_detector.debug_feature_logging = False

        try:
            for index, item in enumerate(dataset):
                if not isinstance(item, dict):
                    raise ValueError(f"dataset item at index {index} must be a dict")

                request_payload = item.get("request", {})
                true_label = self._normalize_true_label(item.get("true_label", ""))

                pipeline_request = self._coerce_pipeline_request(request_payload)
                if not isinstance(pipeline_request, dict):
                    raise ValueError(f"request at index {index} must be a dict")

                decision_result = self.process_request(pipeline_request)
                decision = self._safe_text(decision_result.get("decision", "IGNORE")).strip().upper() or "IGNORE"
                if decision not in decision_counts:
                    decision = "IGNORE"

                decision_counts[decision] += 1
                pipeline_predicted_label = self._decision_to_label(decision)
                self._update_confusion_matrix(pipeline_confusion, true_label, pipeline_predicted_label)

                normalized_request = self._normalize_request(pipeline_request)
                anomaly_input = self._to_anomaly_input(normalized_request)

                try:
                    baseline_is_anomaly, _, _ = self.anomaly_detector.detect(anomaly_input)
                except Exception:
                    try:
                        baseline_is_anomaly, _, _ = self.anomaly_detector._heuristic_detection(anomaly_input)
                    except Exception:
                        baseline_is_anomaly = False

                anomaly_predicted_label = "attack" if bool(baseline_is_anomaly) else "normal"
                self._update_confusion_matrix(anomaly_confusion, true_label, anomaly_predicted_label)
        finally:
            self.enable_logging = original_enable_logging
            if original_decision_debug is not None:
                self.decision_engine.debug_logging = original_decision_debug
            if original_anomaly_debug is not None:
                self.anomaly_detector.debug_feature_logging = original_anomaly_debug

        total = len(dataset)
        pipeline_metrics_all = self._compute_binary_metrics(pipeline_confusion, total)
        anomaly_metrics_all = self._compute_binary_metrics(anomaly_confusion, total)

        decision_distribution = {
            "BLOCK": float(self._safe_divide(decision_counts["BLOCK"], total) * 100.0),
            "ALERT": float(self._safe_divide(decision_counts["ALERT"], total) * 100.0),
            "IGNORE": float(self._safe_divide(decision_counts["IGNORE"], total) * 100.0),
        }

        comparison = {
            "anomaly_recall": float(anomaly_metrics_all["recall"]),
            "pipeline_recall": float(pipeline_metrics_all["recall"]),
            "anomaly_fp_rate": float(anomaly_metrics_all["fp_rate"]),
            "pipeline_fp_rate": float(pipeline_metrics_all["fp_rate"]),
            "fp_reduction": float(anomaly_metrics_all["fp_rate"] - pipeline_metrics_all["fp_rate"]),
            "recall_drop": float(anomaly_metrics_all["recall"] - pipeline_metrics_all["recall"]),
        }

        return {
            "pipeline_metrics": {
                "precision": float(pipeline_metrics_all["precision"]),
                "recall": float(pipeline_metrics_all["recall"]),
                "f1": float(pipeline_metrics_all["f1"]),
                "accuracy": float(pipeline_metrics_all["accuracy"]),
                "confusion_matrix": dict(pipeline_metrics_all["confusion_matrix"]),
            },
            "decision_distribution": decision_distribution,
            "comparison": comparison,
        }


def evaluate_full_pipeline(dataset: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Convenience function for end-to-end pipeline evaluation."""
    pipeline = PipelineOrchestrator(enable_logging=False)
    return pipeline.evaluate_full_pipeline(dataset)


def test_pipeline() -> None:
    pipeline = PipelineOrchestrator(enable_logging=True)
    sample_request = {
        "method": "GET",
        "path": "/login/index.php",
        "query_params": "q=%3Csvg/onload=alert(1)%3E&id=10",
        "body": "",
        "headers": "User-Agent: Mozilla/5.0; Content-Type: application/x-www-form-urlencoded",
        "request_raw": "GET /login/index.php?q=%3Csvg/onload=alert(1)%3E&id=10",
    }
    result = pipeline.process_request(sample_request)
    print(result)


if __name__ == "__main__":
    test_pipeline()
