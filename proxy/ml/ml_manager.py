"""
Centralized ML manager for detection modules.
"""

from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import json
import numpy as np

from .false_positive_reducer import FalsePositiveReducer
from .anomaly_detector import AnomalyDetector
from .phishing_detector import PhishingDetector

try:
    from .severity_predictor import SeverityPredictor
    _SEVERITY_IMPORT_ERROR = None
except Exception as severity_import_error:
    SeverityPredictor = None
    _SEVERITY_IMPORT_ERROR = severity_import_error

try:
    from .rate_limiter import MLRateLimiter
    _RATE_LIMITER_IMPORT_ERROR = None
except Exception as rate_limiter_import_error:
    MLRateLimiter = None
    _RATE_LIMITER_IMPORT_ERROR = rate_limiter_import_error


class MLManager:
    """Centralized ML manager for security scanning."""
    
    def __init__(self, enable_ml: bool = True):
        """Initialize with lazy model loading."""
        import time as _time
        self._init_start = _time.perf_counter()
        self.enable_ml = enable_ml
        
        # Lazy-load slots (None = not yet loaded)
        self._fp_reducer = None
        self._anomaly_detector = None
        self._severity_predictor = None
        self._rate_limiter = None
        self._phishing_detector = None
        self._models_loaded = False
        
        # Performance timing
        self._load_times = {}
        
        # Learning suppression tracker (tracks patterns for future weighting)
        self._suppression_patterns = {
            'repeated_false_positive_pattern': {},
            'informational_noise_cluster': {},
            'exploitable_edge_case': {},
        }
        # Category frequency tracker for dynamic threshold
        self._category_seen_count = {}
        self._endpoint_seen_set = set()
        
        elapsed = (_time.perf_counter() - self._init_start) * 1000
        print(f"[ML Manager] Initialized in {elapsed:.0f}ms (ML {'enabled' if enable_ml else 'disabled'}, models=DEFERRED)")
    
    def _load_module(self, name, factory):
        """Load a single ML module with timing and error handling."""
        import time as _time
        import warnings
        start = _time.perf_counter()
        try:
            # Suppress sklearn version warnings during load
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=FutureWarning)
                try:
                    from sklearn.exceptions import InconsistentVersionWarning
                    warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
                except ImportError:
                    pass
                module = factory()
        except Exception as e:
            print(f"[ML Manager] ERROR loading {name}: {e}")
            module = None
        elapsed = (_time.perf_counter() - start) * 1000
        self._load_times[name] = elapsed
        trained = getattr(module, 'is_trained', False) if module else False
        print(f"[ML Manager] {name}: loaded in {elapsed:.0f}ms ({'trained' if trained else 'not trained'})")
        return module
    
    def _ensure_models_loaded(self):
        """Load all models on first access (lazy singleton)."""
        if self._models_loaded or not self.enable_ml:
            return
        import time as _time
        start = _time.perf_counter()
        print("[ML Manager] Loading models (first access)...")
        
        self._fp_reducer = self._load_module("FP Reducer", FalsePositiveReducer)
        self._anomaly_detector = self._load_module("Anomaly Detector", AnomalyDetector)
        self._severity_predictor = self._load_module(
            "Severity Predictor",
            SeverityPredictor if SeverityPredictor else lambda: None)
        self._rate_limiter = self._load_module(
            "Rate Limiter",
            MLRateLimiter if MLRateLimiter else lambda: None)
        self._phishing_detector = self._load_module("Phishing Detector", PhishingDetector)
        
        self._models_loaded = True
        total = (_time.perf_counter() - start) * 1000
        print(f"[ML Manager] All models loaded in {total:.0f}ms")
    
    # ── Lazy-load properties (singleton cache) ───────────────────────
    @property
    def fp_reducer(self):
        self._ensure_models_loaded()
        return self._fp_reducer
    
    @property
    def anomaly_detector(self):
        self._ensure_models_loaded()
        return self._anomaly_detector
    
    @property
    def severity_predictor(self):
        self._ensure_models_loaded()
        return self._severity_predictor
    
    @property
    def rate_limiter(self):
        self._ensure_models_loaded()
        return self._rate_limiter
    
    @property
    def phishing_detector(self):
        self._ensure_models_loaded()
        return self._phishing_detector
    
    def _print_model_status(self):
        """Print status of all ML models (triggers lazy load)."""
        self._ensure_models_loaded()
        fp = self._fp_reducer
        ad = self._anomaly_detector
        sp = self._severity_predictor
        rl = self._rate_limiter
        print(f"[ML Manager] FP Reducer: {'trained' if fp and fp.is_trained else 'not trained'}")
        print(f"[ML Manager] Anomaly Detector: {'trained' if ad and ad.is_trained else 'not trained'}")
        print(f"[ML Manager] Severity Predictor: {'trained' if sp and sp.is_trained else 'not trained/unavailable'}")
        print(f"[ML Manager] Rate Limiter: {'trained' if rl and rl.is_trained else 'not trained/unavailable'}")
    
    # ================================================================
    # ADVANCED HYBRID AI SECURITY ENGINE — Helper Methods
    # ================================================================

    def _compute_dynamic_threshold(self, finding: Dict[str, Any],
                                   findings_batch: Optional[List] = None) -> float:
        """Compute per-finding dynamic ML confidence threshold.

        Base values:
            Critical/High  -> 0.65
            Medium         -> 0.75
            Low/Info       -> 0.85

        Adjustments applied:
            - endpoint novelty   (+/- 0.05)
            - duplicate density  (+/- 0.05)
            - category frequency (+/- 0.05)
        """
        severity = finding.get('severity', '').lower()
        if severity in ('critical', 'high'):
            base = 0.65
        elif severity == 'medium':
            base = 0.75
        else:
            base = 0.85

        adjust = 0.0

        # Endpoint novelty: never-seen endpoint -> lower threshold (trust ML more)
        url = finding.get('url', '')
        endpoint = url.split('?')[0] if url else ''
        if endpoint and endpoint not in self._endpoint_seen_set:
            adjust -= 0.05  # novel endpoint -> trust ML
            self._endpoint_seen_set.add(endpoint)

        # Category frequency: very common category -> raise threshold slightly
        category = finding.get('category', 'Unknown')
        cat_count = self._category_seen_count.get(category, 0)
        self._category_seen_count[category] = cat_count + 1
        if cat_count > 10:
            adjust += 0.05  # high frequency -> more skeptical

        # Duplicate density: if same description seen often, raise threshold
        desc = finding.get('description', '')
        fp_key = f"{category}:{desc[:40]}"
        dup_count = self._suppression_patterns['repeated_false_positive_pattern'].get(fp_key, 0)
        if dup_count > 3:
            adjust += 0.05

        threshold = max(0.50, min(0.95, base + adjust))
        return round(threshold, 2)

    def _compute_risk_score(self, finding: Dict[str, Any],
                            context: Optional[Dict[str, Any]] = None) -> float:
        """Compute risk_score 0-100 from CVSS + contextual signals."""
        score = 0.0

        # CVSS base contribution (0-40 points)
        cvss = float(finding.get('cvss_score', 0) or 0)
        score += min(cvss * 4.0, 40.0)

        # Severity contribution (0-20 points)
        sev_map = {'critical': 20, 'high': 15, 'medium': 10, 'low': 5, 'info': 0}
        score += sev_map.get(finding.get('severity', '').lower(), 5)

        # Parameter sensitivity (0-15 points)
        url = finding.get('url', '').lower()
        desc = finding.get('description', '').lower()
        sensitive_params = ['password', 'sesskey', 'token', 'auth', 'session',
                           'username', 'login', 'admin']
        param_hits = sum(1 for p in sensitive_params if p in url or p in desc)
        score += min(param_hits * 5, 15)

        # Exploitability evidence (0-15 points)
        evidence = str(finding.get('evidence', '')).lower()
        if 'reflected' in evidence or 'payload' in evidence:
            score += 8
        if 'error' in evidence and 'database' in evidence:
            score += 7
        if 'timeout' in evidence or 'sleep' in evidence:
            score += 7

        # Injection/reflection presence (0-10 points)
        category = finding.get('category', '').lower()
        if 'injection' in category:
            score += 10
        elif 'xss' in category or 'scripting' in category:
            score += 8
        elif 'csrf' in category:
            score += 6

        return min(round(score, 1), 100.0)

    def _recalibrate_severity(self, risk_score: float) -> str:
        """Map risk_score to recalibrated severity level."""
        if risk_score >= 85:
            return 'Critical'
        elif risk_score >= 70:
            return 'High'
        elif risk_score >= 40:
            return 'Medium'
        else:
            return 'Low'

    def _determine_decision_mode(self, is_fp: bool, confidence: float,
                                  threshold: float, risk_score: float) -> str:
        """Determine 4-mode ML decision.

        Returns one of: ML_KEEP, ML_DROP, ML_BORDERLINE, ML_ESCALATE
        """
        if confidence >= threshold:
            if is_fp:
                return 'ML_DROP'
            # High risk_score + TP with high confidence -> escalate
            if risk_score >= 70 and confidence >= 0.85:
                return 'ML_ESCALATE'
            return 'ML_KEEP'
        else:
            # Below threshold -> borderline (will defer to rules)
            return 'ML_BORDERLINE'

    def _update_suppression_tracker(self, finding: Dict[str, Any],
                                     decision: str):
        """Track patterns for learning suppression system."""
        category = finding.get('category', 'Unknown')
        desc = finding.get('description', '')[:40]
        fp_key = f"{category}:{desc}"

        if decision == 'ML_DROP':
            tracker = self._suppression_patterns['repeated_false_positive_pattern']
            tracker[fp_key] = tracker.get(fp_key, 0) + 1
        elif decision in ('ML_KEEP', 'ML_ESCALATE') and finding.get('severity', '').lower() in ('critical', 'high'):
            tracker = self._suppression_patterns['exploitable_edge_case']
            tracker[fp_key] = tracker.get(fp_key, 0) + 1

        # Track informational noise clusters
        if finding.get('severity', '').lower() == 'info':
            tracker = self._suppression_patterns['informational_noise_cluster']
            tracker[category] = tracker.get(category, 0) + 1

    def process_finding(self, finding: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Advanced Hybrid AI Security Engine — per-finding pipeline.

        Execution order (strict):
          1. Tier gate (confirmed / informational)
          2. ML prediction (primary authority)
          3. Dynamic threshold computation
          4. Decision mode determination (ML_KEEP/ML_DROP/ML_BORDERLINE/ML_ESCALATE)
          5. Rule-based fallback (ONLY if ML_BORDERLINE)
          6. Risk score computation
          7. Severity recalibration (post-ML)
          8. Output contract assembly

        Returns:
            Enhanced finding with full ML decision metadata
        """
        if not self.enable_ml:
            return finding
        
        enhanced = finding.copy()
        ml_meta = {}
        reasoning_chain = []
        confidence_tier = finding.get('confidence_tier', 'heuristic')
        
        # ════════════════════════════════════════════════════════════════
        # TIER GATE: Confirmed findings bypass FP reduction
        # ════════════════════════════════════════════════════════════════
        if confidence_tier == 'confirmed':
            risk_score = self._compute_risk_score(finding, context)
            recal_sev = self._recalibrate_severity(risk_score)
            ml_meta['false_positive'] = {
                'is_false_positive': False, 'confidence': 0.0,
                'method': 'tier_bypass', 'decision': 'ML_ESCALATE',
                'risk_score': risk_score,
                'dynamic_threshold': 0.0,
                'note': 'Confirmed exploit -- FP reduction bypassed'
            }
            enhanced['risk_score'] = risk_score
            enhanced['original_severity'] = finding.get('severity')
            enhanced['severity'] = recal_sev
            enhanced['severity_recalibrated'] = True
            reasoning_chain.append('TIER_BYPASS(confirmed)')
            reasoning_chain.append(f'RISK={risk_score:.0f}')
            reasoning_chain.append(f'SEV_RECAL={recal_sev}')
            ml_meta['reasoning_chain'] = ' -> '.join(reasoning_chain)
            ml_meta['decision_origin'] = 'ML'
            print(f"[ML Engine] TIER_BYPASS: cat={finding.get('category','?')[:30]} "
                  f"risk={risk_score:.0f} sev={recal_sev}")
            enhanced['ml_metadata'] = ml_meta
            enhanced['ml_processed'] = True
            enhanced['ml_timestamp'] = datetime.utcnow().isoformat() + 'Z'
            self._update_suppression_tracker(finding, 'ML_ESCALATE')
            return enhanced
        
        # ════════════════════════════════════════════════════════════════
        # TIER GATE: Informational auto-suppress
        # ════════════════════════════════════════════════════════════════
        if confidence_tier == 'informational':
            ml_meta['false_positive'] = {
                'is_false_positive': True, 'confidence': 1.0,
                'method': 'tier_suppress', 'decision': 'ML_DROP',
                'risk_score': 0.0, 'dynamic_threshold': 0.0,
                'note': 'Informational -- auto-suppressed'
            }
            enhanced['filtered'] = True
            enhanced['filter_reason'] = 'Informational tier: not exploitable'
            enhanced['risk_score'] = 0.0
            reasoning_chain.append('TIER_SUPPRESS(informational)')
            ml_meta['reasoning_chain'] = ' -> '.join(reasoning_chain)
            ml_meta['decision_origin'] = 'ML'
            enhanced['ml_metadata'] = ml_meta
            enhanced['ml_processed'] = True
            enhanced['ml_timestamp'] = datetime.utcnow().isoformat() + 'Z'
            self._update_suppression_tracker(finding, 'ML_DROP')
            return enhanced
        
        # ════════════════════════════════════════════════════════════════
        # STAGE 1: ML Prediction (always runs first)
        # ════════════════════════════════════════════════════════════════
        is_fp, fp_confidence = self.fp_reducer.predict(finding, context)
        ml_used = self.fp_reducer.is_trained
        reasoning_chain.append(f'ML(is_fp={is_fp}, conf={fp_confidence:.2f})')
        
        # STAGE 2: Dynamic threshold
        dyn_threshold = self._compute_dynamic_threshold(finding)
        reasoning_chain.append(f'THRESH={dyn_threshold:.2f}')
        
        # STAGE 3: Risk score
        risk_score = self._compute_risk_score(finding, context)
        reasoning_chain.append(f'RISK={risk_score:.0f}')
        
        # STAGE 4: Decision mode
        if ml_used:
            decision_mode = self._determine_decision_mode(
                is_fp, fp_confidence, dyn_threshold, risk_score)
        else:
            decision_mode = 'NO_MODEL'
        reasoning_chain.append(f'MODE={decision_mode}')
        
        ml_meta['false_positive'] = {
            'is_false_positive': is_fp,
            'confidence': fp_confidence,
            'method': 'ml_model' if ml_used else 'heuristic',
            'decision': decision_mode,
            'risk_score': risk_score,
            'dynamic_threshold': dyn_threshold,
        }
        enhanced['risk_score'] = risk_score
        
        # ════════════════════════════════════════════════════════════════
        # STAGE 5: Apply decision
        # ════════════════════════════════════════════════════════════════
        decision_origin = 'ML'
        
        if decision_mode == 'ML_DROP':
            enhanced['filtered'] = True
            enhanced['filter_reason'] = (
                f'ML model: false positive ({fp_confidence:.0%} conf, '
                f'thresh={dyn_threshold:.0%})')
            ml_meta['false_positive']['filtered_by'] = 'ml_model'
        
        elif decision_mode == 'ML_KEEP':
            pass  # keep as-is
        
        elif decision_mode == 'ML_ESCALATE':
            enhanced['ml_escalated'] = True
        
        elif decision_mode == 'ML_BORDERLINE':
            # ── RULE-BASED FALLBACK ──────────────────────────────────
            decision_origin = 'RULE'
            reasoning_chain.append('RULE_FALLBACK')
            desc_lower = finding.get('description', '').lower()
            category = finding.get('category', '')
            sev_lower = finding.get('severity', '').lower()
            
            is_rule_fp = False
            rule_reason = ''
            
            if category == 'Cross-Site Scripting (XSS)':
                xss_patterns = [
                    'dangerous html tag', 'potentially dangerous html tag',
                    'dangerous tag detected', 'verify xss protection',
                    'input fields detected without proper encoding']
                if any(p in desc_lower for p in xss_patterns):
                    is_rule_fp = True
                    rule_reason = 'Rule: Moodle HTML/form fields (known FP)'
            
            if not is_rule_fp and sev_lower == 'info':
                info_patterns = [
                    'server version disclosed', 'technology stack detected',
                    'email address found in page', 'internal ip address found']
                if any(p in desc_lower for p in info_patterns):
                    is_rule_fp = True
                    rule_reason = 'Rule: Informational (not exploitable)'
            
            if not is_rule_fp and sev_lower == 'info' and 'header' in category.lower():
                header_patterns = [
                    'x-frame-options', 'x-content-type-options',
                    'strict-transport-security', 'referrer-policy',
                    'permissions-policy']
                if any(p in desc_lower for p in header_patterns):
                    is_rule_fp = True
                    rule_reason = 'Rule: Header recommendation'
            
            if is_rule_fp:
                enhanced['filtered'] = True
                enhanced['filter_reason'] = rule_reason
                ml_meta['false_positive']['filtered_by'] = 'rule_pattern'
                ml_meta['false_positive']['decision'] = 'RULE_DROP'
                decision_mode = 'RULE_DROP'
                reasoning_chain.append('RULE_DROP')
            else:
                ml_meta['false_positive']['decision'] = 'RULE_KEEP'
                decision_mode = 'RULE_KEEP'
                reasoning_chain.append('RULE_KEEP')
        
        elif decision_mode == 'NO_MODEL':
            ml_meta['false_positive']['note'] = 'Model not trained'
            decision_origin = 'NONE'
        
        ml_meta['decision_origin'] = decision_origin
        
        # ════════════════════════════════════════════════════════════════
        # STAGE 6: Severity Recalibration (post-ML, always runs)
        # ════════════════════════════════════════════════════════════════
        recal_sev = self._recalibrate_severity(risk_score)
        original_sev = finding.get('severity', 'Unknown')
        
        if recal_sev.lower() != original_sev.lower():
            enhanced['severity_recalibrated'] = True
            enhanced['original_severity'] = original_sev
            enhanced['severity'] = recal_sev
            sev_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
            if sev_order.get(recal_sev.lower(), 0) > sev_order.get(original_sev.lower(), 0):
                enhanced['severity_upgraded'] = True
            else:
                enhanced['severity_downgraded'] = True
            reasoning_chain.append(f'SEV_RECAL({original_sev}->{recal_sev})')
        
        ml_meta['severity_recalibration'] = {
            'original': original_sev,
            'recalibrated': recal_sev,
            'risk_score': risk_score,
        }
        
        # Assemble reasoning chain
        ml_meta['reasoning_chain'] = ' -> '.join(reasoning_chain)
        
        # Log decision
        print(
            f"[ML Engine] {decision_mode}: "
            f"sev={enhanced.get('severity','?'):8s} "
            f"cat={finding.get('category','?')[:30]:30s} "
            f"conf={fp_confidence:.0%} thresh={dyn_threshold:.0%} "
            f"risk={risk_score:.0f} origin={decision_origin}"
        )
        
        # Update learning suppression
        self._update_suppression_tracker(finding, decision_mode)
        
        # Final metadata
        enhanced['ml_metadata'] = ml_meta
        enhanced['ml_processed'] = True
        enhanced['ml_timestamp'] = datetime.utcnow().isoformat() + 'Z'
        
        return enhanced
    
    def detect_anomaly(self, data: Dict[str, Any]) -> Tuple[bool, float, str]:
        """
        Detect anomalous behavior.
        
        Args:
            data: Request/response/finding data
            
        Returns:
            Tuple of (is_anomaly, score, reason)
        """
        if not self.enable_ml or not self.anomaly_detector:
            return False, 0.0, "ML disabled"
        
        return self.anomaly_detector.detect(data)
    
    def check_rate_limit(self, request_data: Dict[str, Any], ip: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Check rate limiting with ML-enhanced scoring.
        
        Args:
            request_data: Request information
            ip: Client IP address
            
        Returns:
            Tuple of (should_limit, reason, details)
        """
        if not self.enable_ml or not self.rate_limiter:
            return False, "ML disabled", {}
        
        return self.rate_limiter.check_rate_limit(request_data, ip)
    
    def filter_findings(self, findings: List[Dict[str, Any]], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Process and filter a list of findings.
        
        Args:
            findings: List of security findings
            context: Additional context
            
        Returns:
            Dictionary with filtered findings and statistics
        """
        if not self.enable_ml:
            return {
                'findings': findings,
                'filtered_count': 0,
                'severity_adjusted_count': 0,
                'ml_enabled': False
            }
        
        processed_findings = []
        filtered_count = 0
        
        # Mandatory metrics
        ml_kept = 0
        ml_dropped = 0
        ml_borderline = 0
        ml_escalated = 0
        rule_fallback_used = 0
        rule_based_kept = 0
        rule_based_dropped = 0
        tier_suppressed = 0
        tier_bypassed = 0
        severity_upgraded = 0
        severity_downgraded = 0
        no_model_passthrough = 0
        
        for finding in findings:
            enhanced = self.process_finding(finding, context)
            
            fp_meta = enhanced.get('ml_metadata', {}).get('false_positive', {})
            decision = fp_meta.get('decision', '')
            tier_method = fp_meta.get('method', '')
            is_filtered = enhanced.get('filtered', False)
            
            if decision == 'ML_DROP':
                ml_dropped += 1
                filtered_count += 1
            elif decision == 'ML_KEEP':
                ml_kept += 1
            elif decision == 'ML_ESCALATE':
                ml_escalated += 1
                if tier_method == 'tier_bypass':
                    tier_bypassed += 1
            elif decision == 'RULE_DROP':
                rule_based_dropped += 1
                rule_fallback_used += 1
                filtered_count += 1
            elif decision == 'RULE_KEEP':
                rule_based_kept += 1
                rule_fallback_used += 1
            elif tier_method == 'tier_suppress':
                tier_suppressed += 1
                filtered_count += 1
            elif decision == 'NO_MODEL':
                no_model_passthrough += 1
            
            # ML_BORDERLINE = deferred to rules (count separately)
            if decision in ('RULE_DROP', 'RULE_KEEP'):
                ml_borderline += 1
            
            # Severity recalibration tracking
            if enhanced.get('severity_upgraded'):
                severity_upgraded += 1
            if enhanced.get('severity_downgraded'):
                severity_downgraded += 1
            
            if not is_filtered:
                processed_findings.append(enhanced)
        
        # Summary
        total = len(findings)
        ml_decided = ml_kept + ml_dropped + ml_escalated
        ml_pct = (ml_decided / total * 100) if total > 0 else 0
        
        print(f"[ML Pipeline] ================================================")
        print(f"[ML Pipeline] INPUT:  {total} findings")
        print(f"[ML Pipeline] ")
        print(f"[ML Pipeline] ML DECISIONS (primary):  {ml_decided} ({ml_pct:.0f}%)")
        print(f"[ML Pipeline]   ML kept:               {ml_kept}")
        print(f"[ML Pipeline]   ML dropped:            {ml_dropped}")
        print(f"[ML Pipeline]   ML escalated:          {ml_escalated}")
        print(f"[ML Pipeline]   ML borderline:         {ml_borderline}")
        print(f"[ML Pipeline] ")
        print(f"[ML Pipeline] RULE FALLBACK:           {rule_fallback_used}")
        print(f"[ML Pipeline]   Rule kept:             {rule_based_kept}")
        print(f"[ML Pipeline]   Rule dropped:          {rule_based_dropped}")
        print(f"[ML Pipeline] ")
        print(f"[ML Pipeline] TIER GATES:")
        print(f"[ML Pipeline]   Confirmed bypass:      {tier_bypassed}")
        print(f"[ML Pipeline]   Informational suppress: {tier_suppressed}")
        print(f"[ML Pipeline] ")
        print(f"[ML Pipeline] SEVERITY RECALIBRATION:")
        print(f"[ML Pipeline]   Upgraded:              {severity_upgraded}")
        print(f"[ML Pipeline]   Downgraded:            {severity_downgraded}")
        if no_model_passthrough > 0:
            print(f"[ML Pipeline]   No-model passthrough:  {no_model_passthrough}")
        print(f"[ML Pipeline] ")
        print(f"[ML Pipeline] OUTPUT: {len(processed_findings)} findings (dropped {filtered_count})")
        print(f"[ML Pipeline] ================================================")
        
        # Compute backward-compatible severity_adjusted_count
        severity_adjusted_count = severity_upgraded + severity_downgraded
        
        # ── METRICS GUARD: Centralized schema with defaults ──────────
        # Prevents KeyError from any consumer accessing missing keys.
        _METRICS_SCHEMA = {
            'findings': processed_findings,
            'original_count': total,
            'filtered_count': filtered_count,
            'final_count': len(processed_findings),
            'ml_kept': ml_kept,
            'ml_dropped': ml_dropped,
            'ml_borderline': ml_borderline,
            'ml_escalated': ml_escalated,
            'rule_fallback_used': rule_fallback_used,
            'rule_based_kept': rule_based_kept,
            'rule_based_dropped': rule_based_dropped,
            'tier_bypassed': tier_bypassed,
            'tier_suppressed': tier_suppressed,
            'severity_upgraded': severity_upgraded,
            'severity_downgraded': severity_downgraded,
            'severity_adjusted_count': severity_adjusted_count,
            'ml_enabled': True,
            'ml_dominance_pct': ml_pct,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
        }
        
        # Defensive guarantee: any key accessed but missing → 0
        class _MetricsGuard(dict):
            """Dict subclass that auto-initializes missing metric keys."""
            def __missing__(self, key):
                print(f"[Metrics Guard] Missing key auto-initialized: {key}")
                self[key] = 0
                return 0
        
        return _MetricsGuard(_METRICS_SCHEMA)
    
    def train_false_positive_reducer(self, training_data: List[Dict[str, Any]], labels: List[int]) -> Dict[str, Any]:
        """
        Train the false positive reduction model.
        
        Args:
            training_data: List of findings with context
            labels: List of labels (0 = TP, 1 = FP)
            
        Returns:
            Training results
        """
        if not self.enable_ml or not self.fp_reducer:
            return {'error': 'ML disabled'}
        
        return self.fp_reducer.train(training_data, labels)
    
    def train_anomaly_detector(self, training_data: List[Dict[str, Any]], contamination: float = 0.1) -> Dict[str, Any]:
        """
        Train the anomaly detection model.
        
        Args:
            training_data: List of normal behavior samples
            contamination: Expected anomaly proportion
            
        Returns:
            Training results
        """
        if not self.enable_ml or not self.anomaly_detector:
            return {'error': 'ML disabled'}
        
        return self.anomaly_detector.train(training_data, contamination)
    
    def train_severity_predictor(self, training_data: List[Dict[str, Any]], labels: List[str]) -> Dict[str, Any]:
        """
        Train the severity prediction model.
        
        Args:
            training_data: List of findings with context
            labels: List of actual severity labels
            
        Returns:
            Training results
        """
        if not self.enable_ml or not self.severity_predictor:
            return {'error': 'ML disabled'}
        
        return self.severity_predictor.train(training_data, labels)
    
    def train_rate_limiter(self, training_data: List[Dict[str, Any]], risk_scores: List[float]) -> Dict[str, Any]:
        """
        Train the rate limiter model.
        
        Args:
            training_data: List of request data with IP
            risk_scores: Actual risk scores (0-100)
            
        Returns:
            Training results
        """
        if not self.enable_ml or not self.rate_limiter:
            return {'error': 'ML disabled'}
        
        return self.rate_limiter.train(training_data, risk_scores)
    
    def provide_feedback(self, finding: Dict[str, Any], is_false_positive: bool, context: Optional[Dict[str, Any]] = None):
        """
        Provide user feedback for incremental learning.
        
        Args:
            finding: Security finding
            is_false_positive: User feedback
            context: Additional context
        """
        if not self.enable_ml or not self.fp_reducer:
            return
        
        self.fp_reducer.update_with_feedback(finding, is_false_positive, context)
    
    def get_ip_stats(self, ip: str) -> Dict[str, Any]:
        """
        Get rate limiting statistics for an IP.
        
        Args:
            ip: IP address
            
        Returns:
            IP statistics
        """
        if not self.enable_ml or not self.rate_limiter:
            return {'error': 'ML disabled'}
        
        return self.rate_limiter.get_ip_stats(ip)
    
    def whitelist_ip(self, ip: str):
        """Add IP to whitelist."""
        if self.enable_ml and self.rate_limiter:
            self.rate_limiter.add_to_whitelist(ip)
    
    def blacklist_ip(self, ip: str):
        """Add IP to blacklist."""
        if self.enable_ml and self.rate_limiter:
            self.rate_limiter.add_to_blacklist(ip)
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get status of all ML modules.
        
        Returns:
            Status dictionary
        """
        if not self.enable_ml:
            return {
                'ml_enabled': False,
                'message': 'ML features are disabled'
            }
        
        return {
            'ml_enabled': True,
            'modules': {
                'false_positive_reducer': self.fp_reducer.get_model_info(),
                'anomaly_detector': self.anomaly_detector.get_model_info(),
                'severity_predictor': self.severity_predictor.get_model_info() if self.severity_predictor else {
                    'trained': False,
                    'message': f'Severity predictor unavailable: {_SEVERITY_IMPORT_ERROR}' if _SEVERITY_IMPORT_ERROR else 'Severity predictor unavailable'
                },
                'rate_limiter': self.rate_limiter.get_model_info() if self.rate_limiter else {
                    'trained': False,
                    'message': f'Rate limiter unavailable: {_RATE_LIMITER_IMPORT_ERROR}' if _RATE_LIMITER_IMPORT_ERROR else 'Rate limiter unavailable'
                }
            },
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
    
    def export_models_info(self) -> Dict[str, Any]:
        """
        Export detailed information about all models.
        
        Returns:
            Detailed model information
        """
        return {
            'ml_enabled': self.enable_ml,
            'models': {
                'false_positive_reducer': {
                    'trained': self.fp_reducer.is_trained if self.fp_reducer else False,
                    'info': self.fp_reducer.get_model_info() if self.fp_reducer else {}
                },
                'anomaly_detector': {
                    'trained': self.anomaly_detector.is_trained if self.anomaly_detector else False,
                    'info': self.anomaly_detector.get_model_info() if self.anomaly_detector else {}
                },
                'severity_predictor': {
                    'trained': self.severity_predictor.is_trained if self.severity_predictor else False,
                    'info': self.severity_predictor.get_model_info() if self.severity_predictor else {}
                },
                'rate_limiter': {
                    'trained': self.rate_limiter.is_trained if self.rate_limiter else False,
                    'info': self.rate_limiter.get_model_info() if self.rate_limiter else {}
                }
            },
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
