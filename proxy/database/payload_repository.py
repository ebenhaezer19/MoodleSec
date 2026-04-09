"""
Payload Repository Manager

Manages vulnerable payload database for intelligent reuse during scanning.
- Extracts vulnerable payloads from previous scans
- Tracks success metrics
- Auto-loads high-success payloads
- Integrates with custom scanners for smart payload testing
"""

import sqlite3
import hashlib
from datetime import datetime
from typing import List, Dict, Optional, Any
from pathlib import Path


class PayloadRepositoryManager:
    """Centralized payload management system for custom scanners."""
    
    def __init__(self, db_path: str = "data/payload_repository.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _init_db(self):
        """Initialize payload repository database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Main payload repository table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS payloads (
                id INTEGER PRIMARY KEY,
                payload_hash TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                payload_type TEXT NOT NULL,
                payload_text TEXT NOT NULL,
                description TEXT,
                severity TEXT,
                source TEXT NOT NULL,
                success_count INTEGER DEFAULT 0,
                failure_count INTEGER DEFAULT 0,
                total_uses INTEGER DEFAULT 0,
                success_rate REAL DEFAULT 0.0,
                effectiveness_score REAL DEFAULT 0.5,
                is_vulnerable INTEGER DEFAULT 1,
                first_discovered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP,
                last_successful TIMESTAMP,
                found_in_scan_id TEXT,
                found_in_url TEXT,
                notes TEXT
            )
        ''')
        
        # Payload usage tracking
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS payload_usage_log (
                id INTEGER PRIMARY KEY,
                payload_id INTEGER,
                scan_id TEXT,
                target_url TEXT,
                parameter_name TEXT,
                success BOOLEAN,
                response_snippet TEXT,
                execution_time REAL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (payload_id) REFERENCES payloads(id)
            )
        ''')
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_category ON payloads(category)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_eff ON payloads(effectiveness_score DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln ON payloads(is_vulnerable)")
        
        conn.commit()
        conn.close()
    
    def _normalize_category(self, category: str) -> str:
        """Normalize category name for consistency."""
        # Mapping to standard categories
        category_map = {
            'Cross-Site Scripting (XSS)': 'XSS',
            'Cross Site Scripting': 'XSS',
            'Reflected XSS': 'XSS',
            'Stored XSS': 'XSS',
            'Cross-Site Request Forgery (CSRF)': 'CSRF',
            'Cross-Site Request Forgery': 'CSRF',
            'Directory Traversal': 'Path Traversal',
            'OS Command Injection': 'OS Command Injection',
        }
        return category_map.get(category, category)
    
    def _calculate_payload_hash(self, payload_text: str, category: str) -> str:
        """Calculate unique hash for payload."""
        combined = f"{payload_text}:{category}"
        return hashlib.md5(combined.encode()).hexdigest()
    
    def add_payload(self, payload_text: str, category: str, 
                   payload_type: str, severity: str = "Medium",
                   source: str = "custom", description: str = "",
                   scan_id: str = "", url: str = "") -> int:
        """Add payload to repository."""
        # Normalize category
        category = self._normalize_category(category)
        
        payload_hash = self._calculate_payload_hash(payload_text, category)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("""
                INSERT INTO payloads 
                (payload_hash, category, payload_type, payload_text, 
                 severity, source, found_in_scan_id, found_in_url)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (payload_hash, category, payload_type, payload_text,
                  severity, source, scan_id, url))
            payload_id = cursor.lastrowid
        except sqlite3.IntegrityError:
            payload_id = cursor.execute(
                "SELECT id FROM payloads WHERE payload_hash = ?",
                (payload_hash,)
            ).fetchone()[0]
        
        conn.commit()
        conn.close()
        return payload_id
    
    def extract_from_findings(self, findings: List[Dict], scan_id: str) -> List[int]:
        """Extract and save vulnerable payloads dari findings."""
        added = []
        
        for finding in findings:
            category = finding.get("category", "")
            evidence = finding.get("evidence", "")
            severity = finding.get("severity", "Medium")
            url = finding.get("url", "")
            
            if not evidence or len(evidence) < 3:
                continue
            
            payloads_to_add = self._extract_payloads_from_evidence(evidence, category)
            
            for payload in payloads_to_add:
                pid = self.add_payload(
                    payload_text=payload,
                    category=category,
                    payload_type=self._detect_type(evidence),
                    severity=severity,
                    source="scan_extraction",
                    scan_id=scan_id,
                    url=url
                )
                added.append(pid)
        
        return added
    
    def _extract_payloads_from_evidence(self, evidence: str, category: str) -> List[str]:
        """Extract actual payloads dari evidence string."""
        payloads = []
        
        if "xss" in category.lower():
            if any(x in evidence for x in ["<", "script", "onerror", "javascript"]):
                payloads.append(evidence[:500])
            else:
                payloads.extend([
                    '<img src=x onerror="alert(\'xss\')">',
                    '"><script>alert("xss")</script>',
                    '<svg onload=alert("xss")>'
                ])
        
        elif "sql" in category.lower():
            payloads.extend(["\' OR \'1\'=\'1", "1 UNION SELECT NULL--"])
        
        elif "csrf" in category.lower():
            payloads.append("missing_csrf_token")
        
        elif "path" in category.lower():
            payloads.extend(["../../../etc/passwd", "..\\..\\..\\windows\\win.ini"])
        
        return [p for p in payloads if p]
    
    def _detect_type(self, evidence: str) -> str:
        """Detect payload type."""
        if "<script" in evidence or "onerror" in evidence:
            return "reflected"
        elif "stored" in evidence:
            return "stored"
        return "other"
    
    def get_top_payloads(self, category: str, limit: int = 10) -> List[Dict]:
        """Get top performing payloads for category."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, payload_text, payload_type, severity,
                   success_rate, total_uses, effectiveness_score
            FROM payloads
            WHERE category = ? AND is_vulnerable = 1
            ORDER BY effectiveness_score DESC, success_rate DESC
            LIMIT ?
        """, (category, limit))
        
        payloads = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return payloads

    def get_all_payloads(self, limit: int = 500) -> List[Dict]:
        """Get all payloads from repository."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, payload_text as payload, category, payload_type,
                   severity, success_rate, total_uses as used_count,
                   effectiveness_score as effectiveness, last_used,
                   first_discovered as created_at, is_vulnerable
            FROM payloads
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        
        payloads = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return payloads
    
    def record_usage(self, payload_id: int, scan_id: str, 
                    target_url: str, parameter: str, 
                    success: bool, response: str = ""):
        """Record payload usage and update effectiveness score."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Log usage
        cursor.execute("""
            INSERT INTO payload_usage_log
            (payload_id, scan_id, target_url, parameter_name, success, response_snippet)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (payload_id, scan_id, target_url, parameter, success, response[:500]))
        
        # Update metrics
        cursor.execute("""
            SELECT success_count, failure_count, total_uses, severity
            FROM payloads WHERE id = ?
        """, (payload_id,))
        
        row = cursor.fetchone()
        if row is None:
            conn.close()
            return
        
        success_count, failure_count, total_uses, severity = row
        
        if success:
            success_count += 1
            cursor.execute(
                "UPDATE payloads SET last_successful = CURRENT_TIMESTAMP WHERE id = ?",
                (payload_id,)
            )
        else:
            failure_count += 1
        
        total_uses += 1
        success_rate = (success_count / total_uses * 100) if total_uses > 0 else 0
        
        severity_score = {
            "Critical": 1.0, "High": 0.8, "Medium": 0.6, "Low": 0.4
        }.get(severity, 0.5)
        
        effectiveness = (success_rate / 100) * 0.6 + severity_score * 0.4
        
        cursor.execute("""
            UPDATE payloads
            SET success_count = ?, failure_count = ?, total_uses = ?,
                success_rate = ?, effectiveness_score = ?, last_used = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (success_count, failure_count, total_uses, success_rate, effectiveness, payload_id))
        
        conn.commit()
        conn.close()
    
    def get_stats(self) -> Dict:
        """Get repository statistics."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        total = cursor.execute("SELECT COUNT(*) FROM payloads").fetchone()[0]
        vulnerable = cursor.execute("SELECT COUNT(*) FROM payloads WHERE is_vulnerable = 1").fetchone()[0]
        
        cursor.execute("""
            SELECT category, COUNT(*) as count, AVG(success_rate) as avg_rate
            FROM payloads
            GROUP BY category
        """)
        
        by_category = {row[0]: {"count": row[1], "avg_rate": row[2]} for row in cursor.fetchall()}
        
        conn.close()
        
        return {
            "total_payloads": total,
            "vulnerable_payloads": vulnerable,
            "by_category": by_category
        }
    
    def reload_payloads_by_category(self, category: str, force_reload: bool = True) -> Dict[str, int]:
        """Reload and refresh payloads for category without restart.
        
        Args:
            category: Category to reload (XSS, SQL Injection, CSRF, etc.)
            force_reload: If True, clear cache and reload from DB
        
        Returns:
            Count of reloaded payloads by effectiveness status
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get all payloads for category ordered by effectiveness
        cursor.execute("""
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN is_vulnerable = 1 THEN 1 ELSE 0 END) as vulnerable,
                   SUM(CASE WHEN effectiveness_score >= 0.7 THEN 1 ELSE 0 END) as high_effectiveness,
                   SUM(CASE WHEN effectiveness_score >= 0.5 AND effectiveness_score < 0.7 THEN 1 ELSE 0 END) as medium_effectiveness
            FROM payloads
            WHERE category = ?
        """, (category,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return {"total": 0, "vulnerable": 0, "high_effectiveness": 0, "medium_effectiveness": 0}
        
        total, vulnerable, high_eff, medium_eff = row
        
        return {
            "total": total or 0,
            "vulnerable": vulnerable or 0,
            "high_effectiveness": high_eff or 0,
            "medium_effectiveness": medium_eff or 0
        }
    
    def reload_all_payloads(self) -> Dict[str, Any]:
        """Reload all payloads from database. Useful after ZAP import.
        
        Returns:
            Summary of reloaded payloads by category
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT category, COUNT(*) as count, 
                   SUM(CASE WHEN is_vulnerable = 1 THEN 1 ELSE 0 END) as vulnerable
            FROM payloads
            GROUP BY category
            ORDER BY count DESC
        """)
        
        by_category = {}
        for category, count, vulnerable in cursor.fetchall():
            by_category[category] = {
                "total": count,
                "vulnerable": vulnerable or 0
            }
        
        conn.close()
        
        return {
            "status": "reloaded",
            "timestamp": datetime.now().isoformat(),
            "by_category": by_category
        }
    
    def import_from_zap_api(self, zap_host: str = "localhost", zap_port: int = 8080, 
                           limit: int = 200) -> Dict[str, Any]:
        """Import payloads from ZAP API directly.
        
        Args:
            zap_host: ZAP API host
            zap_port: ZAP API port
            limit: Max alerts to import
        
        Returns:
            Import result with statistics
        """
        try:
            import requests
            import json
            
            # Connect to ZAP
            zap_url = f"http://{zap_host}:{zap_port}"
            version_response = requests.get(f"{zap_url}/JSON/core/view/version", timeout=10)
            
            if version_response.status_code != 200:
                return {"status": "error", "message": f"ZAP not accessible at {zap_url}"}
            
            zap_version = version_response.json().get('version', 'unknown')
            print(f"[ZAP Import] Connected to ZAP v{zap_version}")
            
            # Fetch alerts
            alerts_response = requests.get(
                f"{zap_url}/JSON/core/view/alerts",
                params={"zapapiformat": "JSON", "count": limit},
                timeout=30
            )
            
            if alerts_response.status_code != 200:
                return {"status": "error", "message": "Failed to fetch ZAP alerts"}
            
            alerts = alerts_response.json().get('alerts', [])
            imported = 0
            by_category = {}
            
            # Process each alert
            for alert in alerts:
                try:
                    category = alert.get('alert', 'Unknown')
                    severity = alert.get('riskcode', '2')
                    evidence = alert.get('evidence', '')
                    url = alert.get('url', '')
                    
                    if not evidence or len(evidence) < 2:
                        continue
                    
                    # Normalize category
                    if 'XSS' in category or 'Cross' in category:
                        norm_cat = 'XSS'
                    elif 'SQL' in category:
                        norm_cat = 'SQL Injection'
                    elif 'CSRF' in category:
                        norm_cat = 'CSRF'
                    else:
                        norm_cat = category
                    
                    severity_map = {'0': 'Low', '1': 'Low', '2': 'Medium', '3': 'High', '4': 'Critical', '5': 'Critical'}
                    severity_str = severity_map.get(str(severity), 'Medium')
                    
                    # Add payload
                    self.add_payload(
                        payload_text=evidence[:1000],
                        category=norm_cat,
                        payload_type=category,
                        severity=severity_str,
                        source="ZAP_API_import",
                        description=f"From ZAP: {category}",
                        url=url
                    )
                    
                    imported += 1
                    by_category[norm_cat] = by_category.get(norm_cat, 0) + 1
                
                except Exception as e:
                    continue
            
            return {
                "status": "success",
                "zap_version": zap_version,
                "alerts_fetched": len(alerts),
                "payloads_imported": imported,
                "by_category": by_category
            }
        
        except Exception as e:
            return {"status": "error", "message": str(e)}
