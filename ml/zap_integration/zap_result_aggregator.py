"""
ZAPResultAggregator: Collects ZAP findings and applies ML-based filtering.

Implements 3-tier filtering:
- Tier 1: Rule-based false positive removal
- Tier 2: Rarity calculation
- Tier 3: ML-based false positive prediction
"""

import logging
import time
import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from .zap_client import ZAPClient
from .zap_ascan_manager import ZAPActiveScanManager


class ZAPAggregatorError(Exception):
    """Raised when aggregation fails."""
    pass


class ZAPMLPredictionError(Exception):
    """Raised when ML prediction fails."""
    pass


class ZAPFeatureExtractionError(Exception):
    """Raised when feature extraction fails."""
    pass


class ZAPResultAggregator:
    """Aggregates ZAP findings and applies ML-based filtering."""
    
    # Keywords for feature extraction
    TP_KEYWORDS = [
        "injection", "xss", "csrf", "overflow", "execute", "exploit",
        "vulnerability", "malicious", "payload", "attack", "infiltrate",
        "unauthorized", "decrypt", "bypass", "escalate", "control"
    ]
    
    FP_KEYWORDS = [
        "missing", "not set", "header", "information", "recommendation",
        "deprecated", "best practice", "suggested", "consider", "should"
    ]
    
    SEVERITY_MAPPING = {
        "Critical": 4,
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "Informational": 0
    }
    
    def __init__(
        self,
        zap_client: ZAPClient,
        ascan_manager: Optional[ZAPActiveScanManager] = None,
        ml_model_path: Optional[str] = None
    ):
        """Initialize result aggregator.
        
        Args:
            zap_client: ZAPClient instance
            ascan_manager: ZAPActiveScanManager instance
            ml_model_path: Optional path to ML model
        """
        self.client = zap_client
        self.ascan_manager = ascan_manager or ZAPActiveScanManager(zap_client)
        self.ml_model = None
        self.logger = logging.getLogger("ZAPResultAggregator")
        
        if ml_model_path:
            try:
                # Attempt to load ML model (optional)
                from ml.false_positive_reducer import FalsePositiveReducer
                self.ml_model = FalsePositiveReducer.load_model(ml_model_path)
                self.logger.info(f"ML model loaded from {ml_model_path}")
            except Exception as exc:
                self.logger.warning(f"Failed to load ML model: {exc}. Tier 3 filtering disabled")
    
    def get_raw_findings(self, scan_id: Optional[str] = None) -> List[Dict]:
        """Get raw findings from ZAP.
        
        Args:
            scan_id: Specific scan ID (optional)
            
        Returns:
            List of raw alerts
        """
        try:
            alerts = self.ascan_manager.get_alerts(scan_id=scan_id)
            self.logger.info(f"Retrieved {len(alerts)} raw findings")
            return alerts
        except Exception as exc:
            self.logger.error(f"Error retrieving raw findings: {exc}")
            return []
    
    def normalize_alert(self, raw_alert: Dict) -> Dict:
        """Normalize alert to ML-friendly format.
        
        Args:
            raw_alert: Raw ZAP alert
            
        Returns:
            Normalized alert dictionary
        """
        return {
            "id": raw_alert.get("id", ""),
            "category": raw_alert.get("type", "Unknown"),
            "severity": raw_alert.get("risk", "Low"),
            "url": raw_alert.get("url", ""),
            "method": raw_alert.get("method", "GET"),
            "param": raw_alert.get("param", ""),
            "description": raw_alert.get("description", ""),
            "evidence": raw_alert.get("evidence", ""),
            "cwe": raw_alert.get("cwe", 0),
            "wascid": raw_alert.get("wascid", 0),
            "cvss_score": 0.0,
            "scanner": "zap",
            "timestamp": datetime.now().isoformat(),
            "confidence": raw_alert.get("confidence", "Low")
        }
    
    def apply_tier1_filtering(self, findings: List[Dict]) -> Tuple[List[Dict], Dict]:
        """Apply Tier 1: Rule-based filtering.
        
        Args:
            findings: List of findings
            
        Returns:
            Tuple of (filtered_findings, statistics)
        """
        filtered = []
        stats = {"removed_count": 0, "removed_reasons": {}}
        
        for finding in findings:
            reason = None
            
            # Rule 1: Remove informational
            if finding.get("severity") == "Informational":
                reason = "informational"
            
            # Rule 2: Remove FP keywords without evidence
            elif any(kw in finding.get("description", "").lower() for kw in self.FP_KEYWORDS):
                if not finding.get("evidence") or len(finding.get("evidence", "")) < 3:
                    reason = "fp_keyword_no_evidence"
            
            # Rule 3: Empty evidence
            elif not finding.get("evidence") or len(finding.get("evidence", "")) < 3:
                if finding.get("severity") not in ["High", "Critical"]:
                    reason = "empty_evidence"
            
            if reason:
                stats["removed_count"] += 1
                stats["removed_reasons"][reason] = stats["removed_reasons"].get(reason, 0) + 1
            else:
                filtered.append(finding)
        
        self.logger.info(f"Tier 1: Removed {stats['removed_count']}/{len(findings)} findings")
        return filtered, stats
    
    def calculate_rarity_score(self, finding: Dict, all_findings: List[Dict]) -> float:
        """Calculate rarity score for finding.
        
        Args:
            finding: Single finding
            all_findings: All findings for comparison
            
        Returns:
            Rarity score (0.0-1.0)
        """
        category = finding.get("category", "")
        url = finding.get("url", "")
        
        # Count similar findings
        similar_count = sum(
            1 for f in all_findings
            if f.get("category") == category and url in f.get("url", "")
        )
        
        if similar_count == 1:
            rarity = 1.0
        elif similar_count <= 5:
            rarity = 0.7
        else:
            rarity = 0.3
        
        # Adjust by severity
        severity = finding.get("severity", "Low")
        if severity in ["High", "Critical"]:
            rarity = min(1.0, rarity + 0.2)
        elif severity in ["Low", "Informational"]:
            rarity = max(0.0, rarity - 0.2)
        
        return rarity
    
    def apply_tier2_filtering(
        self,
        findings: List[Dict],
        rarity_threshold: float = 0.5
    ) -> Tuple[List[Dict], Dict]:
        """Apply Tier 2: Rarity-based filtering.
        
        Args:
            findings: List of findings
            rarity_threshold: Minimum rarity score to keep
            
        Returns:
            Tuple of (filtered_findings, statistics)
        """
        rarity_map = {}
        filtered = []
        
        for finding in findings:
            rarity = self.calculate_rarity_score(finding, findings)
            rarity_map[finding.get("id", "")] = rarity
            
            if rarity >= rarity_threshold:
                filtered.append(finding)
        
        stats = {
            "removed_count": len(findings) - len(filtered),
            "rarity_map": rarity_map
        }
        
        self.logger.info(f"Tier 2: Removed {stats['removed_count']}/{len(findings)} findings")
        return filtered, stats
    
    def extract_ml_features(self, finding: Dict) -> Dict:
        """Extract ML features from finding.
        
        Args:
            finding: Finding dictionary
            
        Returns:
            Feature dictionary for ML model
            
        Raises:
            ZAPFeatureExtractionError: If extraction fails
        """
        try:
            severity = finding.get("severity", "Low")
            severity_encoded = self.SEVERITY_MAPPING.get(severity, 0)
            
            evidence = finding.get("evidence", "")
            description = finding.get("description", "")
            
            evidence_length = len(evidence)
            description_length = len(description)
            
            url = finding.get("url", "")
            url_complexity = len(url.split("/"))
            has_params = 1 if "?" in url else 0
            
            tp_count = sum(1 for kw in self.TP_KEYWORDS if kw in description.lower())
            fp_count = sum(1 for kw in self.FP_KEYWORDS if kw in description.lower())
            keyword_ratio = tp_count / (tp_count + fp_count + 1)
            
            is_informational = 1 if severity == "Informational" else 0
            
            features = {
                "severity_encoded": severity_encoded,
                "evidence_length": min(evidence_length, 500),
                "description_length": min(description_length, 500),
                "url_complexity": min(url_complexity, 20),
                "has_params": has_params,
                "tp_keyword_count": min(tp_count, 10),
                "fp_keyword_count": min(fp_count, 10),
                "keyword_ratio": keyword_ratio,
                "is_informational": is_informational,
                "category_hash": hash(finding.get("category", "")) % 100
            }
            
            return features
            
        except Exception as exc:
            raise ZAPFeatureExtractionError(f"Feature extraction failed: {exc}") from exc
    
    def apply_tier3_ml_filtering(
        self,
        findings: List[Dict],
        confidence_threshold: float = 0.75
    ) -> Tuple[List[Dict], Dict]:
        """Apply Tier 3: ML-based filtering.
        
        Args:
            findings: List of findings
            confidence_threshold: Minimum TP confidence to keep
            
        Returns:
            Tuple of (filtered_findings, statistics)
        """
        if not self.ml_model:
            self.logger.warning("ML model not loaded, skipping Tier 3")
            return findings, {"removed_count": 0, "model_predictions": {}}
        
        predictions = {}
        filtered = []
        
        for finding in findings:
            try:
                features = self.extract_ml_features(finding)
                # Mock prediction (would call real model in production)
                tp_probability = 0.8 if finding.get("severity") == "High" else 0.6
                predictions[finding.get("id", "")] = tp_probability
                
                if tp_probability >= confidence_threshold:
                    filtered.append(finding)
                    
            except ZAPFeatureExtractionError as exc:
                self.logger.warning(f"Feature extraction failed: {exc}, skipping finding")
                continue
        
        stats = {
            "removed_count": len(findings) - len(filtered),
            "model_predictions": predictions,
            "confidence_threshold_used": confidence_threshold
        }
        
        self.logger.info(f"Tier 3: Removed {stats['removed_count']}/{len(findings)} findings")
        return filtered, stats
    
    def aggregate_and_filter(
        self,
        findings: List[Dict],
        apply_tier1: bool = True,
        apply_tier2: bool = True,
        apply_tier3: bool = True
    ) -> Dict:
        """Run complete filtering pipeline.
        
        Args:
            findings: List of findings to filter
            apply_tier1: Enable Tier 1 filtering
            apply_tier2: Enable Tier 2 filtering
            apply_tier3: Enable Tier 3 ML filtering
            
        Returns:
            Complete aggregation result with statistics
        """
        start_time = time.time()
        
        # Normalize all findings
        normalized = [self.normalize_alert(f) for f in findings]
        input_count = len(normalized)
        
        # Tier 1
        tier1_removed = 0
        tier1_stats = {}
        if apply_tier1:
            normalized, tier1_stats = self.apply_tier1_filtering(normalized)
            tier1_removed = tier1_stats.get("removed_count", 0)
        
        # Tier 2
        tier2_removed = 0
        tier2_stats = {}
        if apply_tier2:
            normalized, tier2_stats = self.apply_tier2_filtering(normalized)
            tier2_removed = tier2_stats.get("removed_count", 0)
        
        # Tier 3
        tier3_removed = 0
        tier3_stats = {}
        if apply_tier3:
            normalized, tier3_stats = self.apply_tier3_ml_filtering(normalized)
            tier3_removed = tier3_stats.get("removed_count", 0)
        
        processing_time = time.time() - start_time
        total_removed = tier1_removed + tier2_removed + tier3_removed
        filtering_pct = (total_removed / input_count * 100) if input_count > 0 else 0
        
        return {
            "input_count": input_count,
            "tier1_removed": tier1_removed,
            "tier2_removed": tier2_removed,
            "tier3_removed": tier3_removed,
            "output_count": len(normalized),
            "filtered_findings": normalized,
            "statistics": {
                "by_tier": {
                    "tier1": tier1_removed,
                    "tier2": tier2_removed,
                    "tier3": tier3_removed
                },
                "processing_time_seconds": processing_time,
                "filtering_percentage": filtering_pct
            }
        }
    
    def export_findings(
        self,
        findings: List[Dict],
        format: str = "json",
        filepath: Optional[str] = None
    ) -> str:
        """Export findings to file or string.
        
        Args:
            findings: Findings to export
            format: Output format (json/csv)
            filepath: Optional filepath to save to
            
        Returns:
            JSON string or filepath
        """
        if format == "json":
            content = json.dumps(findings, indent=2)
            if filepath:
                with open(filepath, "w") as f:
                    f.write(content)
                return filepath
            return content
        return ""
