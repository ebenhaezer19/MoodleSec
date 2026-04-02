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
from typing import List, Dict, Optional
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
    
    def _calculate_payload_hash(self, payload_text: str, category: str) -> str:
        """Calculate unique hash for payload."""
        combined = f"{payload_text}:{category}"
        return hashlib.md5(combined.encode()).hexdigest()
    
    def add_payload(self, payload_text: str, category: str, 
                   payload_type: str, severity: str = "Medium",
                   source: str = "custom", description: str = "",
                   scan_id: str = "", url: str = "") -> int:
        """Add payload to repository."""
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
