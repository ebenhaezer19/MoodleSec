"""
Training Data Aggregator

Collects scan findings from recent scans and ZAP JSON reports, formatting them for ML model retraining.
Integrates with ScanHistoryDB to fetch native scanner findings and loads ZAP findings from JSON reports.
"""

import json
import os
import glob
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import sys
import numpy as np

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.scan_history import ScanHistoryDB


class TrainingDataAggregator:
    """Aggregates recent scan findings for ML model retraining."""
    
    def __init__(self, days_back: int = 7):
        """
        Initialize Training Data Aggregator.
        
        Args:
            days_back: Number of days to look back for scans
        """
        self.scan_db = ScanHistoryDB()
        self.days_back = days_back
        self.collected_scans = []
        self.aggregated_data = {
            'false_positive': {'data': [], 'labels': []},
            'severity': {'data': [], 'labels': []},
            'anomaly': {'data': [], 'labels': []},
            'rate_limiter': {'data': [], 'labels': []}
        }
    
    def collect_recent_scans(self, limit: int = 100) -> Dict[str, Any]:
        """
        Collect recent scan findings from database AND ZAP JSON reports.
        
        Args:
            limit: Maximum number of native scans to collect (ZAP scans all loaded)
            
        Returns:
            Dictionary with collected scans data
        """
        print(f"[Aggregator] Collecting scans from last {self.days_back} days...")
        
        try:
            # Get recent scans using get_scan_history
            scan_list = self.scan_db.get_scan_history(limit=limit)
            
            if not scan_list:
                print("[Aggregator] No native scans found in database")
                scan_list = []
            else:
                print(f"[Aggregator] Found {len(scan_list)} native scans, now loading findings for each...")
            
            # Group scans by type for diagnostics
            scan_types = {}
            for scan in scan_list:
                scan_type = scan.get('scan_type', 'unknown')
                scan_types[scan_type] = scan_types.get(scan_type, 0) + 1
            
            print(f"[Aggregator] Native scan types distribution: {scan_types}")
            
            all_scans = []
            total_findings = 0
            findings_by_type = {}
            
            # Step 1: Load native scanner findings
            print("[Aggregator] Loading native scanner findings...")
            for scan_meta in scan_list:
                scan_id = scan_meta.get('scan_id', 'unknown')
                scan_type = scan_meta.get('scan_type', 'unknown')
                
                # Get complete scan data with findings
                scan_with_findings = self.scan_db.get_scan_with_findings(scan_id)
                
                if scan_with_findings:
                    findings = scan_with_findings.get('findings', [])
                    all_scans.append(scan_with_findings)
                    total_findings += len(findings)
                    
                    # Track findings by scan type
                    if scan_type not in findings_by_type:
                        findings_by_type[scan_type] = 0
                    findings_by_type[scan_type] += len(findings)
                    
                    print(f"[Aggregator] Processing native scan {scan_id} (type: {scan_type}) with {len(findings)} findings")
                    
                    # Extract training data from findings
                    for finding in findings:
                        self._process_finding(finding, scan_id, 'native_scanner')
            
            # Step 2: Load ZAP findings from JSON reports
            print("[Aggregator] Loading ZAP JSON findings...")
            zap_findings_count = self._load_zap_findings()
            
            self.collected_scans = all_scans
            
            print(f"[Aggregator] Loaded findings from {len(all_scans)} native scans, total: {total_findings}")
            print(f"[Aggregator] Loaded {zap_findings_count} ZAP findings")
            print(f"[Aggregator] Native findings by scan type: {findings_by_type}")
            print(f"[Aggregator] TOTAL FINDINGS: {total_findings + zap_findings_count} (native: {total_findings}, ZAP: {zap_findings_count})")
            
            return {
                'success': True,
                'message': f'Collected {len(all_scans)} native scans with {total_findings + zap_findings_count} total findings',
                'scans_count': len(all_scans),
                'native_findings_count': total_findings,
                'zap_findings_count': zap_findings_count,
                'findings_count': total_findings + zap_findings_count,
                'scans_by_type': scan_types,
                'findings_by_type': findings_by_type,
                'datasets': {
                    'false_positive': len(self.aggregated_data['false_positive']['data']),
                    'severity': len(self.aggregated_data['severity']['data']),
                    'anomaly': len(self.aggregated_data['anomaly']['data']),
                    'rate_limiter': len(self.aggregated_data['rate_limiter']['data'])
                }
            }
        
        except Exception as e:
            print(f"[Aggregator] Error collecting scans: {str(e)}")
            import traceback
            traceback.print_exc()
            return {'success': False, 'message': f'Error: {str(e)}', 'scans_count': 0}
    
    def _process_finding(self, finding: Dict[str, Any], scan_id: str, source: str = 'native_scanner'):
        """
        Process a single finding and extract training data.
        
        Args:
            finding: Finding dictionary from scan
            scan_id: ID of the parent scan
            source: Source of finding ('native_scanner' or 'zap')
        """
        # Validate finding has required fields
        if not finding.get('severity') and not finding.get('cvss_score'):
            return
        
        # Normalize severity to standard format
        severity = finding.get('severity', 'medium').lower()
        if isinstance(severity, int):
            # Convert int risk codes to severity strings
            severity_map = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical', 0: 'info'}
            severity = severity_map.get(severity, 'medium')
        
        # 1. False Positive Reducer Training Data
        # Label: 0 = True Positive, 1 = False Positive
        # For ZAP findings, estimate if likely false positive based on type
        is_false_positive = finding.get('is_false_positive', 0)
        if source == 'zap':
            # Mark high-confidence ZAP findings as true positives
            # Low-confidence or informational ZAP alerts may be false positives
            confidence = finding.get('confidence', 0)
            if isinstance(confidence, str):
                confidence = int(confidence) if confidence.isdigit() else 50
            is_false_positive = 1 if confidence < 50 else 0
        
        self.aggregated_data['false_positive']['data'].append(finding)
        self.aggregated_data['false_positive']['labels'].append(is_false_positive)
        
        # 2. Severity Predictor Training Data
        # Keep severity as string for label encoding in train()
        # The severity_predictor.train() expects: labels as severity strings
        
        self.aggregated_data['severity']['data'].append(finding)
        # Append severity string (not integer) for proper label encoding
        self.aggregated_data['severity']['labels'].append(severity)
        
        # 3. Anomaly Detection Training Data
        # For unsupervised learning, still pass full finding dict for consistency
        self.aggregated_data['anomaly']['data'].append(finding)
        self.aggregated_data['anomaly']['labels'].append(0)  # Unsupervised, use 0 as placeholder
        
        # 4. Rate Limiter Training Data
        # Risk scoring based on CVSS and other factors
        cvss_score = finding.get('cvss_score', 0)
        if isinstance(cvss_score, str):
            try:
                cvss_score = float(cvss_score)
            except:
                cvss_score = 0
        
        self.aggregated_data['rate_limiter']['data'].append(finding)
        self.aggregated_data['rate_limiter']['labels'].append(float(cvss_score))
    
    def _load_zap_findings(self) -> int:
        """
        Load findings from OWASP ZAP JSON reports.
        
        Returns:
            Total number of ZAP findings loaded
        """
        try:
            # Find ZAP JSON directory - try multiple possible locations
            script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            
            # Try paths in order of likelihood
            possible_paths = [
                os.path.join(script_dir, 'training_data/OWASP_ZAP_Data'),  # Direct from proxy/ml
                os.path.join(script_dir, 'ml/training_data/OWASP_ZAP_Data'),  # From proxy
                os.path.join(script_dir, 'ml/training_data/real_data/OWASP_ZAP_Data'),  # With real_data subfolder
            ]
            
            zap_dir = None
            for path in possible_paths:
                if os.path.exists(path):
                    zap_dir = path
                    print(f"[Aggregator] Found ZAP directory at: {path}")
                    break
            
            if not zap_dir:
                print(f"[Aggregator] ZAP data directory not found. Tried: {possible_paths}")
                return 0
            
            # Find all ZAP JSON files
            zap_files = glob.glob(os.path.join(zap_dir, '*.json'))
            print(f"[Aggregator] Found {len(zap_files)} ZAP JSON files")
            
            total_findings = 0
            
            for zap_file in zap_files:
                try:
                    with open(zap_file, 'r') as f:
                        data = json.load(f)
                    
                    # Extract findings from ZAP report structure
                    sites = data.get('site', [])
                    if not isinstance(sites, list):
                        sites = [sites] if sites else []
                    
                    for site in sites:
                        alerts = site.get('alerts', [])
                        for alert in alerts:
                            # Each alert can have multiple instances (occurrences)
                            instances = alert.get('instances', [])
                            for instance in instances:
                                # Convert ZAP alert to standardized finding format
                                finding = self._convert_zap_alert_to_finding(alert, instance)
                                if finding:
                                    self._process_finding(finding, zap_file, 'zap')
                                    total_findings += 1
                    
                    print(f"[Aggregator] Loaded {total_findings} findings from {os.path.basename(zap_file)}")
                
                except Exception as e:
                    print(f"[Aggregator] Error loading ZAP file {zap_file}: {str(e)}")
                    continue
            
            return total_findings
        
        except Exception as e:
            print(f"[Aggregator] Error loading ZAP findings: {str(e)}")
            return 0
    
    def _convert_zap_alert_to_finding(self, alert: Dict, instance: Dict) -> Optional[Dict[str, Any]]:
        """
        Convert OWASP ZAP alert to standardized finding format.
        
        Args:
            alert: ZAP alert structure
            instance: Individual instance of the alert
            
        Returns:
            Standardized finding dictionary
        """
        try:
            # Map ZAP risk codes to severity: 3=high, 2=medium, 1=low, 0=info
            risk_code = alert.get('riskcode', 0)
            if isinstance(risk_code, str):
                risk_code = int(risk_code) if risk_code.isdigit() else 0
            
            risk_desc = alert.get('riskdesc', 'INFORMATION GATHERING').upper()
            severity_map = {
                3: 'high',
                2: 'medium', 
                1: 'low',
                0: 'info'
            }
            severity = severity_map.get(risk_code, 'medium')
            
            # Extract confidence
            confidence = alert.get('confidence', 0)
            if isinstance(confidence, str):
                confidence = int(confidence) if confidence.isdigit() else 0
            
            # Estimate CVSS score from ZAP risk/confidence
            cvss_score = max(1.0, (risk_code * 2.5 + (confidence / 100 * 2.5)))
            cvss_score = min(10.0, cvss_score)  # Cap at 10.0
            
            # Build standardized finding
            finding = {
                'title': alert.get('name', 'Unknown Finding'),
                'severity': severity,
                'description': alert.get('desc', ''),
                'cvss_score': cvss_score,
                'risk_score': cvss_score,  # Use CVSS as risk score
                'endpoint': instance.get('uri', ''),
                'url': instance.get('uri', ''),
                'category': alert.get('name', 'unknown'),
                'cwe': alert.get('cweid', 'N/A'),
                'request_method': instance.get('method', 'GET'),
                'evidence': instance.get('evidence', ''),
                'confidence': confidence,
                'metadata': json.dumps({
                    'zap_pluginid': alert.get('pluginid'),
                    'zap_alertRef': alert.get('alertRef'),
                    'zap_risk': risk_desc
                }),
                'is_false_positive': 0,  # Assume true positive, will be adjusted in _process_finding
                'priority': 5 - risk_code  # Higher priority for higher risk
            }
            
            return finding
        
        except Exception as e:
            print(f"[Aggregator] Error converting ZAP alert: {str(e)}")
            return None
    
    def _extract_features(self, finding: Dict[str, Any]) -> Optional[Dict[str, List]]:
        """
        Extract machine learning features from a finding.
        
        Args:
            finding: Finding dictionary
            
        Returns:
            Dictionary with feature lists for each model
        """
        try:
            # Extract basic attributes
            title = finding.get('title', '')
            description = finding.get('description', '')
            severity = finding.get('severity', 'low').lower()
            cwe = finding.get('cwe', 'N/A')
            cvss_score = finding.get('cvss_score', 0.0)
            endpoint = finding.get('endpoint', '').lower()
            request_method = finding.get('request_method', 'GET').upper()
            
            # Calculate feature vectors
            # 1. FP Reducer Features (16 features)
            fp_features = [
                len(title),                              # 0: Title length
                len(description),                        # 1: Description length
                cvss_score,                              # 2: CVSS Score
                1 if severity == 'critical' else 0,    # 3: Is Critical
                1 if severity == 'high' else 0,        # 4: Is High
                1 if severity == 'medium' else 0,      # 5: Is Medium
                1 if severity == 'low' else 0,         # 6: Is Low
                1 if 'sql' in title.lower() else 0,    # 7: SQL Injection pattern
                1 if 'xss' in title.lower() else 0,    # 8: XSS pattern
                1 if 'csrf' in title.lower() else 0,   # 9: CSRF pattern
                1 if 'path' in title.lower() else 0,   # 10: Path Traversal pattern
                1 if request_method == 'POST' else 0,  # 11: POST method
                1 if request_method == 'GET' else 0,   # 12: GET method
                1 if cwe != 'N/A' else 0,              # 13: Has CWE
                endpoint.count('/'),                    # 14: Endpoint depth
                1 if 'login' in endpoint else 0        # 15: Login endpoint
            ]
            
            # 2. Severity Predictor Features (20 features)
            severity_features = fp_features + [
                1 if 'authenticated' in description.lower() else 0,  # 16: Auth required
                1 if 'impact' in description.lower() else 0,        # 17: Impact mentioned
                title.count(' '),                                     # 18: Title word count
                description.count(' ') if description else 0         # 19: Description word count
            ]
            
            # 3. Anomaly Detection Features (24 features)
            anomaly_features = severity_features + [
                hash(title) % 100,                      # 20: Title hash
                hash(endpoint) % 100,                   # 21: Endpoint hash
                len(cwe),                               # 22: CWE length
                1 if cvss_score > 7.0 else 0          # 23: High risk score
            ]
            
            # 4. Rate Limiter Features (8 features)
            rate_limiter_features = [
                cvss_score,                             # 0: CVSS Score
                1 if severity == 'critical' else 0,    # 1: Is Critical
                1 if severity == 'high' else 0,        # 2: Is High
                1 if 'authenticated' in description.lower() else 0,  # 3: Auth required
                1 if request_method == 'POST' else 0,  # 4: POST method
                endpoint.count('/'),                    # 5: Endpoint depth
                len(title),                             # 6: Title length
                1 if finding.get('is_false_positive', 0) else 0      # 7: Is FP
            ]
            
            return {
                'fp_features': fp_features,
                'severity_features': severity_features,
                'anomaly_features': anomaly_features,
                'rate_limiter_features': rate_limiter_features
            }
        
        except Exception as e:
            print(f"[Aggregator] Error extracting features: {str(e)}")
            return None
    
    def get_aggregated_data(self) -> Dict[str, Dict[str, List]]:
        """
        Get aggregated training data.
        
        Returns:
            Dictionary with training data for all models
        """
        return self.aggregated_data
    
    def save_aggregated_data(self, output_file: str = 'ml/training_data/recent_scans_data.json') -> bool:
        """
        Save aggregated data to file.
        
        Args:
            output_file: Path to save aggregated data
            
        Returns:
            Success status
        """
        try:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            # Custom JSON encoder to handle non-serializable objects
            class NumpyEncoder(json.JSONEncoder):
                def default(self, obj):
                    if isinstance(obj, np.ndarray):
                        return obj.tolist()
                    elif isinstance(obj, (np.integer, np.floating)):
                        return float(obj)
                    elif hasattr(obj, '__dict__'):
                        return str(obj)
                    return super().default(obj)
            
            # Prepare data for JSON serialization
            # Limit data to summaries to avoid huge JSON files
            summary_data = {
                'false_positive': {
                    'count': len(self.aggregated_data['false_positive']['data']),
                    'labels': self.aggregated_data['false_positive']['labels'][:100]  # Limit to first 100
                },
                'severity': {
                    'count': len(self.aggregated_data['severity']['data']),
                    'labels': self.aggregated_data['severity']['labels'][:100]  # Limit to first 100
                },
                'anomaly': {
                    'count': len(self.aggregated_data['anomaly']['data']),
                    'labels': self.aggregated_data['anomaly']['labels'][:100]  # Limit to first 100
                },
                'rate_limiter': {
                    'count': len(self.aggregated_data['rate_limiter']['data']),
                    'labels': self.aggregated_data['rate_limiter']['labels'][:100]  # Limit to first 100
                }
            }
            
            data_to_save = {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'scans_count': len(self.collected_scans),
                'summary': summary_data,
                'data_sources': 'native_scanner + ZAP JSON reports'
            }
            
            with open(output_file, 'w') as f:
                json.dump(data_to_save, f, indent=2, cls=NumpyEncoder)
            
            print(f"[Aggregator] Saved aggregated data to {output_file}")
            return True
        
        except Exception as e:
            print(f"[Aggregator] Error saving aggregated data: {str(e)}")
            import traceback
            traceback.print_exc()
            return False
