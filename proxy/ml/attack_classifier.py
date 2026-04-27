"""
Attack type classifier for web requests flagged as anomalous.
"""

import os
import pickle
import re
import csv
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, unquote_plus

import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler


class AttackClassifier:
    """
    Attack type classifier module for stage-2 categorization after anomaly detection.
    """

    def __init__(self, model_path: str = "ml/models/attack_classifier.pkl"):
        self.model_path = model_path
        self.model: Optional[Any] = None
        self.scaler: Optional[StandardScaler] = None
        self.label_encoder: Optional[LabelEncoder] = None
        self.is_trained = False

        self.feature_names = [
            "request_length",
            "path_depth",
            "num_params",
            "body_length",
            "special_char_count",
            "special_char_ratio",
            "url_encoded_count",
            "double_encoding_present",
            "query_entropy",
            "body_entropy",
            "suspicious_keyword_count",
            "suspicious_keyword_density",
            "method_encoded",
            "header_count",
            "unique_char_ratio",
            "digit_ratio",
            "alpha_ratio",
            "avg_param_value_length",
            "max_param_value_length",
            "path_segment_count",
        ]

        self.suspicious_keywords = [
            "script",
            "select",
            "union",
            "insert",
            "update",
            "delete",
            "drop",
            "exec",
            "cmd",
            "javascript",
            "onerror",
            "onload",
            "../",
            "..\\",
        ]

        self.model_blueprints = {
            "random_forest": RandomForestClassifier(
                n_estimators=200,
                class_weight="balanced",
                random_state=42,
                n_jobs=-1,
            ),
            "logistic_regression": LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                solver="lbfgs",
                multi_class="auto",
            ),
        }
        self.default_model_name = "random_forest"
        self.debug_logging = str(os.getenv("ATTACK_CLASSIFIER_DEBUG", "1")).strip().lower() not in {
            "0",
            "false",
            "no",
        }
        self.last_debug_info: Dict[str, Any] = {}
        # Educational / natural-language phrases that commonly contain SQL/XSS
        # keywords but carry no exploit intent.  Used by the contextual
        # postprocessor to suppress false positives on search/navigation text.
        self.educational_context_terms = [
            "how to",
            "how to use",
            "course materials",
            "union of sets",
            "union of",
            "sets in math",
            "script in python",
            "use script",
            "in python",
            "in math",
            "python",
            "math",
            "overview",
            "assignment",
            "materials",
            "drop by",
            "drop in",
            "drop off",
            "later",
            "lecture",
            "course",
            "tutorial",
            "lesson",
            "study",
        ]

        # Structural markers that indicate exploit intent rather than natural language.
        # If NONE of these appear near a keyword hit, the keyword is almost certainly
        # being used in its everyday English meaning.
        self._exploit_structure_markers = re.compile(
            r"""(?x)
            ['";=<>(){}\[\]]       # quote / bracket / operator characters
            | --                     # SQL line-comment
            | /\*                    # SQL block-comment open
            | \*/                    # SQL block-comment close
            | %[0-9a-fA-F]{2}       # URL-encoded character
            | \\x[0-9a-fA-F]{2}    # hex escape
            | <\s*\w                # HTML/XML tag opening
            | \.\.[\\/]            # path traversal
            | \b(0x[0-9a-fA-F]+)\b # hex literal
            """
        )

        self.load_model()

    def _safe_text(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="ignore")
        if isinstance(value, dict):
            return "&".join(f"{self._safe_text(k)}={self._safe_text(v)}" for k, v in value.items())
        if isinstance(value, (list, tuple, set)):
            return "&".join(self._safe_text(v) for v in value)
        return str(value)

    def _parse_query_params(self, query_params: Any) -> Dict[str, str]:
        if query_params is None:
            return {}

        if isinstance(query_params, dict):
            return {self._safe_text(k): self._safe_text(v) for k, v in query_params.items()}

        if isinstance(query_params, (list, tuple)):
            params: Dict[str, str] = {}
            for item in query_params:
                if isinstance(item, (list, tuple)) and len(item) == 2:
                    key = self._safe_text(item[0])
                    value = self._safe_text(item[1])
                    params[key] = value
                else:
                    key = self._safe_text(item)
                    params[key] = ""
            return params

        query_text = self._safe_text(query_params).strip()
        if not query_text:
            return {}
        if query_text.startswith("?"):
            query_text = query_text[1:]

        return {k: v for k, v in parse_qsl(query_text, keep_blank_values=True)}

    @staticmethod
    def _entropy(text: str) -> float:
        if not text:
            return 0.0
        counts = Counter(text)
        length = float(len(text))
        probabilities = np.array([count / length for count in counts.values()], dtype=float)
        entropy = -np.sum(probabilities * np.log2(probabilities))
        return float(entropy)

    @staticmethod
    def _method_encoding(method: str) -> float:
        method_map = {
            "GET": 0,
            "POST": 1,
            "PUT": 2,
            "DELETE": 3,
            "PATCH": 4,
            "OPTIONS": 5,
            "HEAD": 6,
        }
        return float(method_map.get(method, 7))

    @staticmethod
    def _count_headers(headers: Any) -> float:
        if headers is None:
            return 0.0
        if isinstance(headers, dict):
            return float(len(headers))

        text = str(headers)
        if not text.strip():
            return 0.0

        separators = ["\n", ";"]
        header_lines = [text]
        for sep in separators:
            if sep in text:
                header_lines = [line for line in text.split(sep) if line.strip()]
                break

        count = sum(1 for line in header_lines if ":" in line)
        return float(count)

    def _count_special_chars(self, text: str) -> int:
        special_chars = set("<>'\";()=")
        return sum(1 for ch in text if ch in special_chars)

    def _count_url_encoded(self, text: str) -> int:
        return len(re.findall(r"%[0-9a-fA-F]{2}", text))

    def _has_double_encoding(self, text: str) -> float:
        return 1.0 if re.search(r"%25[0-9a-fA-F]{2}", text) else 0.0

    def _keyword_signal_count(self, text: str) -> int:
        """Count raw keyword hits (used for feature extraction — must stay
        stable to avoid invalidating the trained model)."""
        text_lower = text.lower()
        total = 0
        for keyword in self.suspicious_keywords:
            total += len(re.findall(re.escape(keyword), text_lower))
        return total

    # ------------------------------------------------------------------
    # Natural-language context detection
    # ------------------------------------------------------------------

    def _is_natural_language_context(self, text: str) -> bool:
        """Return True when *text* looks like a natural English sentence/query
        rather than an exploit payload.

        Heuristic:
        1. Decode the text fully.
        2. Check for structural exploit markers (quotes, operators, HTML tags,
           path traversal, URL-encoding, etc.).
        3. If NONE are present the text is almost certainly benign prose.

        This is intentionally conservative — the presence of *any* structural
        marker returns False, letting the existing exploit-pattern detectors
        handle it.
        """
        decoded = self._multi_url_decode(text).strip()
        if not decoded:
            return False

        # If the decoded text contains ANY structural exploit marker it is
        # NOT a simple natural-language sentence.
        if self._exploit_structure_markers.search(decoded):
            return False

        # Extra guard: short strings that are just a keyword by themselves
        # (e.g., path segment "/select") are ambiguous — treat as NL only if
        # there are at least two space-separated words.
        words = decoded.split()
        if len(words) < 2:
            return False

        return True

    @staticmethod
    def _multi_url_decode(text: str, rounds: int = 3) -> str:
        decoded = str(text or "")
        for _ in range(max(1, int(rounds))):
            next_decoded = unquote_plus(decoded)
            if next_decoded == decoded:
                break
            decoded = next_decoded
        return decoded

    @staticmethod
    def _normalize_attack_key(attack_type: str) -> str:
        key = str(attack_type or "").strip().lower()
        mapping = {
            "sql injection": "sqli",
            "sqli": "sqli",
            "cross-site scripting": "xss",
            "cross site scripting": "xss",
            "xss": "xss",
            "directory traversal": "path traversal",
            "path traversal": "path traversal",
            "cmd injection": "command injection",
            "command injection": "command injection",
        }
        return mapping.get(key, key)

    def _extract_contextual_signals(self, request: Dict[str, Any]) -> Dict[str, Any]:
        method = self._safe_text(request.get("method", "GET")).upper()
        path = self._safe_text(request.get("path", ""))
        query = self._safe_text(request.get("query_params", ""))
        body = self._safe_text(request.get("body", ""))
        request_raw = self._safe_text(request.get("request_raw", ""))

        if not request_raw:
            request_raw = f"{method} {path}?{query} {body}".strip()

        merged_text = " ".join([path, query, body, request_raw]).strip()
        decoded_text = self._multi_url_decode(merged_text).lower()

        sqli_signals: List[str] = []
        if re.search(r"\bunion\b\s+(all\s+)?\bselect\b", decoded_text):
            sqli_signals.append("union+select")
        if re.search(r"\b(or|and)\b\s+['\"]?\s*\d+\s*=\s*\d+", decoded_text):
            sqli_signals.append("boolean-condition")
        if re.search(r"\bselect\b[\s\S]{1,120}\bfrom\b", decoded_text):
            sqli_signals.append("select-from")
        if re.search(r"(--|/\*|\*/|#)", decoded_text) and re.search(
            r"\b(select|union|or|and|drop|insert|delete|update)\b",
            decoded_text,
        ):
            sqli_signals.append("sql-comment-marker")
        if re.search(r"['\"][^'\"]{0,50}\b(or|and|union|select|drop)\b", decoded_text):
            sqli_signals.append("quoted-sql-pattern")

        xss_signals: List[str] = []
        if re.search(r"<\s*script\b", decoded_text):
            xss_signals.append("script-tag")
        if re.search(r"\bonerror\s*=", decoded_text):
            xss_signals.append("onerror-handler")
        if re.search(r"\bonload\s*=", decoded_text):
            xss_signals.append("onload-handler")
        if re.search(r"javascript\s*:", decoded_text):
            xss_signals.append("javascript-uri")

        path_signals: List[str] = []
        if "../" in decoded_text or "..\\" in decoded_text:
            path_signals.append("relative-traversal")
        if any(marker in decoded_text for marker in ["/etc/passwd", "windows/system32", "boot.ini", "proc/self"]):
            path_signals.append("sensitive-path-target")

        command_signals: List[str] = []
        if re.search(r"(;|&&|\|\|)\s*(cat|ls|id|whoami|uname|cmd\.exe|powershell|bash|sh|wget|curl)\b", decoded_text):
            command_signals.append("command-chain")
        if re.search(r"\$\(|`[^`]+`", decoded_text):
            command_signals.append("shell-execution-syntax")

        keyword_hits = {
            "select": bool(re.search(r"\bselect\b", decoded_text)),
            "union": bool(re.search(r"\bunion\b", decoded_text)),
            "script": bool(re.search(r"\bscript\b", decoded_text)),
            "drop": bool(re.search(r"\bdrop\b", decoded_text)),
        }
        educational_hits = [term for term in self.educational_context_terms if term in decoded_text]

        has_strong_evidence = bool(sqli_signals or xss_signals or path_signals or command_signals)
        keyword_only = bool(any(keyword_hits.values()) and not has_strong_evidence)

        return {
            "decoded_payload": decoded_text,
            "sqli_signals": sqli_signals,
            "xss_signals": xss_signals,
            "path_signals": path_signals,
            "command_signals": command_signals,
            "keyword_hits": keyword_hits,
            "educational_hits": educational_hits,
            "keyword_only": keyword_only,
            "has_strong_evidence": has_strong_evidence,
        }

    def _contextual_postprocess_prediction(
        self,
        request: Dict[str, Any],
        attack_type: str,
        confidence: float,
    ) -> Tuple[str, float, Dict[str, Any]]:
        normalized_attack_key = self._normalize_attack_key(attack_type)
        adjusted_attack_type = self._safe_text(attack_type).strip() or "unknown"
        adjusted_confidence = float(np.clip(confidence, 0.0, 1.0))

        signals = self._extract_contextual_signals(request)
        notes: List[str] = []

        # Strong exploit structures should preserve recall and raise confidence floor.
        if signals["sqli_signals"] and not signals["xss_signals"]:
            adjusted_attack_type = "SQLi"
            adjusted_confidence = max(adjusted_confidence, 0.72)
            notes.append("Strong SQLi structure detected")
        elif signals["xss_signals"] and not signals["sqli_signals"]:
            adjusted_attack_type = "XSS"
            adjusted_confidence = max(adjusted_confidence, 0.72)
            notes.append("Strong XSS execution structure detected")

        if signals["path_signals"]:
            adjusted_attack_type = "Path Traversal"
            adjusted_confidence = max(adjusted_confidence, 0.72)
            notes.append("Path traversal structure detected")

        if signals["command_signals"]:
            adjusted_attack_type = "Command Injection"
            adjusted_confidence = max(adjusted_confidence, 0.72)
            notes.append("Command injection structure detected")

        if not signals["has_strong_evidence"]:
            # --- Natural-language detection for the merged payload text ---
            # If the full decoded payload reads like a normal English sentence
            # (no SQL operators, no HTML tags, no path traversal markers) AND
            # the only reason it was flagged is keyword overlap, we can
            # confidently suppress the alert.
            payload_is_nl = self._is_natural_language_context(
                signals.get("decoded_payload", "")
            )

            if signals["keyword_only"] and (signals["educational_hits"] or payload_is_nl):
                # WHY downgraded: the request contains everyday English words
                # ("select", "union", "drop", "script") in a sentence-like
                # context with zero exploit-structure markers.  Keeping it as
                # an alert would be a false positive.
                adjusted_attack_type = "normal"
                adjusted_confidence = min(adjusted_confidence, 0.08)
                reason_detail = (
                    "educational context" if signals["educational_hits"]
                    else "natural-language sentence"
                )
                notes.append(
                    f"Keyword-only hit in {reason_detail}; "
                    f"no exploit structure detected — suppressing attack label"
                )
            elif signals["keyword_only"]:
                # Keywords present but no NL match and no educational hit.
                # Still suspicious but not enough for a strong prediction.
                adjusted_confidence = min(adjusted_confidence * 0.45, 0.35)
                if adjusted_confidence < 0.40:
                    adjusted_attack_type = "normal"
                notes.append("Keyword-only signal without exploit structure")
            elif normalized_attack_key in {"sqli", "xss", "path traversal", "command injection"} and adjusted_confidence < 0.60:
                adjusted_attack_type = "normal"
                adjusted_confidence = min(adjusted_confidence, 0.30)
                notes.append("Low confidence without exploit structure; treating as benign")

        if not notes:
            notes.append("Model prediction retained")

        debug_info = {
            "raw_attack_type": self._safe_text(attack_type),
            "adjusted_attack_type": adjusted_attack_type,
            "raw_confidence": float(np.clip(confidence, 0.0, 1.0)),
            "adjusted_confidence": float(np.clip(adjusted_confidence, 0.0, 1.0)),
            "signals": {
                "sqli": list(signals["sqli_signals"]),
                "xss": list(signals["xss_signals"]),
                "path": list(signals["path_signals"]),
                "command": list(signals["command_signals"]),
            },
            "keyword_hits": dict(signals["keyword_hits"]),
            "educational_hits": list(signals["educational_hits"]),
            "keyword_only": bool(signals["keyword_only"]),
            "has_strong_evidence": bool(signals["has_strong_evidence"]),
            "explanation": "; ".join(notes),
        }

        return adjusted_attack_type, float(np.clip(adjusted_confidence, 0.0, 1.0)), debug_info

    def _decode_label(self, prediction: Any) -> str:
        if self.label_encoder is not None:
            try:
                decoded = self.label_encoder.inverse_transform(np.array([prediction]))[0]
                return self._safe_text(decoded)
            except Exception:
                pass
        return self._safe_text(prediction)

    def _predict_confidence(self, feature_vector: np.ndarray) -> float:
        if self.model is None:
            return 0.0

        if hasattr(self.model, "predict_proba"):
            probabilities = self.model.predict_proba(feature_vector)
            return float(np.clip(np.max(probabilities[0]), 0.0, 1.0))

        if hasattr(self.model, "decision_function"):
            decision = self.model.decision_function(feature_vector)
            if isinstance(decision, np.ndarray):
                if decision.ndim == 2:
                    scores = decision[0].astype(float)
                    shifted = scores - np.max(scores)
                    exp_scores = np.exp(shifted)
                    probs = exp_scores / np.sum(exp_scores)
                    return float(np.clip(np.max(probs), 0.0, 1.0))
                if decision.ndim == 1:
                    score = float(decision[0])
                    prob = 1.0 / (1.0 + np.exp(-np.clip(score, -500, 500)))
                    return float(max(prob, 1.0 - prob))

            score = float(decision)
            prob = 1.0 / (1.0 + np.exp(-np.clip(score, -500, 500)))
            return float(max(prob, 1.0 - prob))

        return 1.0

    def extract_features(self, request: Dict) -> np.ndarray:
        method = self._safe_text(request.get("method", "GET")).upper()
        path = self._safe_text(request.get("path", ""))
        body = self._safe_text(request.get("body", ""))
        headers_raw = request.get("headers", {})

        query_params = request.get("query_params", "")
        parsed_params = self._parse_query_params(query_params)
        query_text = self._safe_text(query_params)
        if not query_text and parsed_params:
            query_text = "&".join(f"{k}={v}" for k, v in parsed_params.items())

        request_raw = self._safe_text(request.get("request_raw", ""))
        if not request_raw:
            request_raw = f"{method} {path}?{query_text} {body}".strip()

        merged_text = " ".join([
            request_raw,
            path,
            query_text,
            body,
            self._safe_text(headers_raw),
        ]).strip()

        request_length = float(len(request_raw))
        path_depth = float(path.count("/"))
        num_params = float(len(parsed_params))
        body_length = float(len(body))

        special_char_count = float(self._count_special_chars(merged_text))
        special_char_ratio = special_char_count / max(1.0, float(len(merged_text)))

        url_encoded_count = float(self._count_url_encoded(merged_text))
        double_encoding_present = self._has_double_encoding(merged_text)

        query_entropy = self._entropy(query_text)
        body_entropy = self._entropy(body)

        suspicious_keyword_count = float(self._keyword_signal_count(merged_text))
        token_count = max(1.0, float(len(merged_text.split())))
        suspicious_keyword_density = suspicious_keyword_count / token_count

        method_encoded = self._method_encoding(method)
        header_count = self._count_headers(headers_raw)

        unique_char_ratio = float(len(set(merged_text)) / max(1, len(merged_text)))
        digit_ratio = float(sum(ch.isdigit() for ch in merged_text) / max(1, len(merged_text)))
        alpha_ratio = float(sum(ch.isalpha() for ch in merged_text) / max(1, len(merged_text)))

        if parsed_params:
            param_value_lengths = [len(v) for v in parsed_params.values()]
            avg_param_value_length = float(np.mean(param_value_lengths))
            max_param_value_length = float(np.max(param_value_lengths))
        else:
            avg_param_value_length = 0.0
            max_param_value_length = 0.0

        path_segment_count = float(len([segment for segment in path.split("/") if segment]))

        feature_vector = np.array(
            [
                request_length,
                path_depth,
                num_params,
                body_length,
                special_char_count,
                special_char_ratio,
                url_encoded_count,
                double_encoding_present,
                query_entropy,
                body_entropy,
                suspicious_keyword_count,
                suspicious_keyword_density,
                method_encoded,
                header_count,
                unique_char_ratio,
                digit_ratio,
                alpha_ratio,
                avg_param_value_length,
                max_param_value_length,
                path_segment_count,
            ],
            dtype=float,
        )

        return feature_vector

    def predict(self, request: Dict) -> Tuple[str, float]:
        self.last_debug_info = {}

        if self.model is None or not self.is_trained:
            return "unknown", 0.0

        try:
            feature_vector = self.extract_features(request).reshape(1, -1)

            if self.scaler is not None:
                feature_vector = self.scaler.transform(feature_vector)

            prediction = self.model.predict(feature_vector)[0]
            attack_type = self._decode_label(prediction)
            confidence = self._predict_confidence(feature_vector)

            attack_type, confidence, debug_info = self._contextual_postprocess_prediction(
                request=request,
                attack_type=attack_type,
                confidence=confidence,
            )
            self.last_debug_info = debug_info

            if self.debug_logging:
                print(
                    "[AttackClassifier] "
                    f"raw={debug_info.get('raw_attack_type', 'unknown')} "
                    f"adj={debug_info.get('adjusted_attack_type', 'unknown')} "
                    f"conf={float(debug_info.get('raw_confidence', 0.0)):.3f}"
                    f"->{float(debug_info.get('adjusted_confidence', 0.0)):.3f} "
                    f"notes={debug_info.get('explanation', '')}"
                )

            return attack_type, confidence
        except Exception as error:
            self.last_debug_info = {
                "raw_attack_type": "unknown",
                "adjusted_attack_type": "unknown",
                "raw_confidence": 0.0,
                "adjusted_confidence": 0.0,
                "signals": {},
                "keyword_hits": {},
                "educational_hits": [],
                "keyword_only": False,
                "has_strong_evidence": False,
                "explanation": f"Classifier error: {error}",
            }
            if self.debug_logging:
                print(f"[AttackClassifier] prediction failed: {error}")
            return "unknown", 0.0

    def load_dataset(self, csv_path: str) -> List[Dict[str, str]]:
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"Dataset file not found: {csv_path}")

        rows: List[Dict[str, str]] = []
        required_columns = [
            "request_raw",
            "method",
            "path",
            "query_params",
            "body",
            "headers",
            "label",
            "attack_type",
        ]

        with open(csv_path, "r", encoding="utf-8", errors="ignore", newline="") as csv_file:
            reader = csv.DictReader(csv_file)
            if reader.fieldnames is None:
                raise ValueError("CSV file has no header row.")

            missing_columns = [col for col in required_columns if col not in reader.fieldnames]
            if missing_columns:
                raise ValueError(f"CSV missing required columns: {missing_columns}")

            for row in reader:
                rows.append({col: self._safe_text(row.get(col, "")).strip() for col in required_columns})

        return rows

    def _normalize_attack_type(self, attack_type: str) -> str:
        normalized = self._safe_text(attack_type).strip().lower()
        mapping = {
            "xss": "XSS",
            "cross-site scripting": "XSS",
            "cross site scripting": "XSS",
            "sqli": "SQLi",
            "sql injection": "SQLi",
            "sqli attack": "SQLi",
            "path traversal": "Path Traversal",
            "directory traversal": "Path Traversal",
            "command injection": "Command Injection",
            "cmd injection": "Command Injection",
            "os command injection": "Command Injection",
            "ssrf": "SSRF",
            "server-side request forgery": "SSRF",
            "server side request forgery": "SSRF",
        }
        return mapping.get(normalized, self._safe_text(attack_type).strip())

    def filter_classes(self, rows: List[Dict[str, str]]) -> List[Dict[str, str]]:
        allowed_classes = {
            "XSS",
            "SQLi",
            "Path Traversal",
            "Command Injection",
            "SSRF",
        }

        filtered_rows: List[Dict[str, str]] = []
        for row in rows:
            if self._safe_text(row.get("label", "")).strip().lower() != "attack":
                continue

            normalized_attack_type = self._normalize_attack_type(row.get("attack_type", ""))
            if normalized_attack_type not in allowed_classes:
                continue

            cleaned = dict(row)
            cleaned["attack_type"] = normalized_attack_type
            filtered_rows.append(cleaned)

        return filtered_rows

    def build_requests(self, rows: List[Dict[str, str]]) -> Tuple[List[Dict[str, str]], List[str]]:
        requests: List[Dict[str, str]] = []
        labels: List[str] = []

        for row in rows:
            request = {
                "request_raw": self._safe_text(row.get("request_raw", "")),
                "method": self._safe_text(row.get("method", "")),
                "path": self._safe_text(row.get("path", "")),
                "query_params": self._safe_text(row.get("query_params", "")),
                "body": self._safe_text(row.get("body", "")),
                "headers": self._safe_text(row.get("headers", "")),
            }
            requests.append(request)
            labels.append(self._safe_text(row.get("attack_type", "")).strip())

        return requests, labels

    def extract_features_batch(self, requests: List[Dict[str, str]]) -> np.ndarray:
        if not requests:
            return np.empty((0, len(self.feature_names)), dtype=float)

        feature_rows = [self.extract_features(request) for request in requests]
        return np.vstack(feature_rows)

    def train_model(self, X_train: np.ndarray, y_train: np.ndarray, model_name: str = "random_forest") -> Any:
        selected_model_name = model_name if model_name in self.model_blueprints else "random_forest"
        model = clone(self.model_blueprints[selected_model_name])

        if selected_model_name == "logistic_regression":
            self.scaler = StandardScaler()
            X_train_input = self.scaler.fit_transform(X_train)
        else:
            self.scaler = None
            X_train_input = X_train

        model.fit(X_train_input, y_train)
        return model

    def evaluate_model(
        self,
        model: Any,
        X_test: np.ndarray,
        y_test: np.ndarray,
        class_names: np.ndarray,
    ) -> Dict[str, Any]:
        if self.scaler is not None:
            X_test_input = self.scaler.transform(X_test)
        else:
            X_test_input = X_test

        y_pred = model.predict(X_test_input)

        labels_idx = np.arange(len(class_names))
        precision, recall, f1, support = precision_recall_fscore_support(
            y_test,
            y_pred,
            labels=labels_idx,
            zero_division=0,
        )

        per_class_precision: Dict[str, float] = {}
        per_class_recall: Dict[str, float] = {}
        per_class_f1: Dict[str, float] = {}
        per_class_support: Dict[str, int] = {}

        for idx, class_name in enumerate(class_names):
            class_label = self._safe_text(class_name)
            per_class_precision[class_label] = float(precision[idx])
            per_class_recall[class_label] = float(recall[idx])
            per_class_f1[class_label] = float(f1[idx])
            per_class_support[class_label] = int(support[idx])

        _, _, f1_weighted, _ = precision_recall_fscore_support(
            y_test,
            y_pred,
            average="weighted",
            zero_division=0,
        )

        cm = confusion_matrix(y_test, y_pred, labels=labels_idx)

        return {
            "accuracy": float(accuracy_score(y_test, y_pred)),
            "precision_per_class": per_class_precision,
            "recall_per_class": per_class_recall,
            "f1_score_per_class": per_class_f1,
            "f1_score": float(f1_weighted),
            "support_per_class": per_class_support,
            "confusion_matrix": cm.astype(int).tolist(),
            "classes": [self._safe_text(name) for name in class_names],
        }

    def _resolve_csv_path(self, csv_path: str) -> str:
        candidates = [
            csv_path,
            os.path.join(os.path.dirname(__file__), csv_path),
            os.path.join(os.path.dirname(__file__), "training_data", csv_path),
        ]
        for candidate in candidates:
            if os.path.exists(candidate):
                return candidate
        raise FileNotFoundError(f"Dataset file not found: {csv_path}")

    def train_from_csv(self, csv_path: str) -> Dict[str, Any]:
        resolved_path = self._resolve_csv_path(csv_path)
        data = pd.read_csv(resolved_path)

        required_columns = [
            "request_raw",
            "method",
            "path",
            "query_params",
            "body",
            "headers",
            "label",
            "attack_type",
        ]
        missing_columns = [column for column in required_columns if column not in data.columns]
        if missing_columns:
            raise ValueError(f"CSV missing required columns: {missing_columns}")

        attack_data = data[data["label"].astype(str).str.strip().str.lower() == "attack"].copy()
        if attack_data.empty:
            raise ValueError("No rows found where label == 'attack'.")

        request_columns = ["request_raw", "method", "path", "query_params", "body", "headers"]
        attack_data[request_columns] = attack_data[request_columns].fillna("").astype(str)
        attack_data["attack_type"] = attack_data["attack_type"].fillna("").astype(str).str.strip()
        attack_data = attack_data[attack_data["attack_type"] != ""].copy()
        if attack_data.empty:
            raise ValueError("No valid attack_type labels found in attack rows.")

        attack_data = attack_data.sample(frac=1.0, random_state=42).reset_index(drop=True)
        attack_data["_signature"] = attack_data[request_columns].agg("||".join, axis=1)
        attack_data = attack_data.drop_duplicates(subset=["_signature", "attack_type"]).reset_index(drop=True)

        request_records = attack_data[request_columns].to_dict(orient="records")
        X = self.extract_features_batch(request_records)
        y_raw = attack_data["attack_type"].to_numpy()
        signatures = attack_data["_signature"].to_numpy()

        self.label_encoder = LabelEncoder()
        y = self.label_encoder.fit_transform(y_raw)

        if len(np.unique(y)) < 2:
            raise ValueError("At least two attack_type classes are required for training.")

        X_train, X_test, y_train, y_test, sig_train, sig_test = train_test_split(
            X,
            y,
            signatures,
            test_size=0.20,
            random_state=42,
            stratify=y,
            shuffle=True,
        )

        overlap = set(sig_train).intersection(set(sig_test))
        if overlap:
            raise ValueError("Data leakage detected: overlapping samples between train and test sets.")

        self.model = RandomForestClassifier(
            n_estimators=200,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        self.scaler = None

        self.model.fit(X_train, y_train)
        y_pred = self.model.predict(X_test)

        accuracy = accuracy_score(y_test, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(
            y_test,
            y_pred,
            average="weighted",
            zero_division=0,
        )
        cm = confusion_matrix(y_test, y_pred, labels=np.arange(len(self.label_encoder.classes_)))

        class_names = self.label_encoder.classes_
        full_counts = np.bincount(y, minlength=len(class_names))
        train_counts = np.bincount(y_train, minlength=len(class_names))
        test_counts = np.bincount(y_test, minlength=len(class_names))

        print("[AttackClassifier] Samples per class:", {class_names[i]: int(full_counts[i]) for i in range(len(class_names))})
        print(f"[AttackClassifier] Train size: {len(y_train)} | Test size: {len(y_test)}")
        print("[AttackClassifier] Train class distribution:", {class_names[i]: int(train_counts[i]) for i in range(len(class_names))})
        print("[AttackClassifier] Test class distribution:", {class_names[i]: int(test_counts[i]) for i in range(len(class_names))})

        self.is_trained = True
        self.save_model()

        return {
            "accuracy": float(accuracy),
            "precision": float(precision),
            "recall": float(recall),
            "f1": float(f1),
            "confusion_matrix": cm.astype(int).tolist(),
        }

    def predict_with_topk(self, request: Dict, k: int = 3) -> List[Dict[str, Any]]:
        if self.model is None or not self.is_trained or not hasattr(self.model, "predict_proba"):
            return []

        try:
            feature_vector = self.extract_features(request).reshape(1, -1)
            if self.scaler is not None:
                feature_vector = self.scaler.transform(feature_vector)

            probabilities = self.model.predict_proba(feature_vector)[0]
            k_safe = max(1, min(int(k), len(probabilities)))
            top_indices = np.argsort(probabilities)[::-1][:k_safe]

            if self.label_encoder is not None:
                labels = self.label_encoder.inverse_transform(top_indices)
            else:
                labels = [str(index) for index in top_indices]

            return [
                {
                    "attack_type": self._safe_text(label),
                    "probability": float(probabilities[index]),
                }
                for label, index in zip(labels, top_indices)
            ]
        except Exception:
            return []

    def train(self, X, y):
        raise NotImplementedError("Training logic is intentionally left as a placeholder.")

    def save_model(self) -> bool:
        if self.model is None:
            return False

        model_dir = os.path.dirname(self.model_path)
        if model_dir:
            os.makedirs(model_dir, exist_ok=True)

        payload = {
            "model": self.model,
            "scaler": self.scaler,
            "label_encoder": self.label_encoder,
            "is_trained": self.is_trained,
            "feature_names": self.feature_names,
            "default_model_name": self.default_model_name,
        }

        with open(self.model_path, "wb") as model_file:
            pickle.dump(payload, model_file)

        return True

    def load_model(self) -> bool:
        if not os.path.exists(self.model_path):
            self.model = None
            self.scaler = None
            self.label_encoder = None
            self.is_trained = False
            return False

        try:
            with open(self.model_path, "rb") as model_file:
                payload = pickle.load(model_file)

            if isinstance(payload, dict):
                self.model = payload.get("model")
                self.scaler = payload.get("scaler")
                self.label_encoder = payload.get("label_encoder")
                self.is_trained = bool(payload.get("is_trained", self.model is not None))

                feature_names = payload.get("feature_names")
                if isinstance(feature_names, list) and feature_names:
                    self.feature_names = feature_names

                model_name = payload.get("default_model_name")
                if isinstance(model_name, str) and model_name:
                    self.default_model_name = model_name
            else:
                self.model = payload
                self.scaler = None
                self.label_encoder = None
                self.is_trained = True

            if self.model is None:
                self.is_trained = False

            return bool(self.model is not None and self.is_trained)
        except Exception:
            self.model = None
            self.scaler = None
            self.label_encoder = None
            self.is_trained = False
            return False