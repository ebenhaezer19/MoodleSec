"""
Scan History Database for Trend Tracking and Regression Detection

Uses SQLite for simplicity, can be upgraded to PostgreSQL/MySQL for production.
"""

import sqlite3
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from pathlib import Path


class ScanHistoryDB:
    """Database for storing and analyzing scan history."""
    
    def __init__(self, db_path: str = "data/scan_history.db"):
        """
        Initialize database connection.
        
        Args:
            db_path: Path to SQLite database file
        """
        # Ensure data directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()
    
    def _create_tables(self):
        """Create database tables if they don't exist."""
        cursor = self.conn.cursor()
        
        # Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT UNIQUE NOT NULL,
                scan_type TEXT NOT NULL,
                target_url TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                endpoints_discovered INTEGER DEFAULT 0,
                endpoints_scanned INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                scan_duration REAL DEFAULT 0,
                metadata TEXT
            )
        """)
        
        # Findings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                finding_hash TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT,
                evidence TEXT,
                url TEXT,
                cvss_score REAL DEFAULT 0,
                risk_score REAL DEFAULT 0,
                priority INTEGER DEFAULT 5,
                first_seen DATETIME NOT NULL,
                last_seen DATETIME NOT NULL,
                status TEXT DEFAULT 'open',
                fixed_date DATETIME,
                metadata TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
            )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(finding_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)")
        
        self.conn.commit()
    
    def save_scan(self, scan_data: Dict[str, Any]) -> int:
        """
        Save scan results to database.
        
        Args:
            scan_data: Scan result dictionary
            
        Returns:
            Database ID of saved scan
        """
        cursor = self.conn.cursor()
        
        summary = scan_data.get('summary', {})
        
        cursor.execute("""
            INSERT INTO scans (
                scan_id, scan_type, target_url, timestamp,
                endpoints_discovered, endpoints_scanned, total_findings,
                critical_count, high_count, medium_count, low_count, info_count,
                metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_data.get('scan_id'),
            scan_data.get('scan_type', 'full'),
            scan_data.get('target_url', ''),
            scan_data.get('timestamp'),
            scan_data.get('endpoints_discovered', 0),
            scan_data.get('endpoints_scanned', 0),
            scan_data.get('total_findings', 0),
            summary.get('critical', 0),
            summary.get('high', 0),
            summary.get('medium', 0),
            summary.get('low', 0),
            summary.get('info', 0),
            json.dumps(scan_data.get('metadata', {}))
        ))
        
        scan_db_id = cursor.lastrowid
        
        # Save findings
        findings = scan_data.get('findings', [])
        print(f"\n[DB] ==> SAVING {len(findings)} FINDINGS FOR SCAN: {scan_data['scan_id']}")
        
        for i, finding in enumerate(findings, 1):
            print(f"\n[DB] Finding {i}/{len(findings)}:")
            self._save_finding(scan_data['scan_id'], finding)
        
        self.conn.commit()
        
        # Summary
        cursor.execute("SELECT COUNT(*) FROM findings WHERE scan_id = ?", (scan_data['scan_id'],))
        actual_count = cursor.fetchone()[0]
        reported_count = scan_data.get('total_findings', 0)
        
        print(f"\n[DB] ==> SAVE SUMMARY")
        print(f"[DB]     Reported findings: {reported_count}")
        print(f"[DB]     Actual findings in DB: {actual_count}")
        
        if reported_count == actual_count:
            print(f"[DB]     ✓ MATCH! All findings stored correctly")
        else:
            print(f"[DB]     ⚠️ MISMATCH: {reported_count - actual_count} findings missing!")
        
        print(f"[DB] \n")
        
        return scan_db_id
    
    def _save_finding(self, scan_id: str, finding: Dict[str, Any]):
        """Save individual finding to database."""
        cursor = self.conn.cursor()
        
        # DEBUG: Show what we're saving
        print(f"\n[DB] ==> SAVING FINDING")
        print(f"[DB]     Category: {finding.get('category')}")
        print(f"[DB]     Description: {finding.get('description', '')[:60]}...")
        print(f"[DB]     URL: {finding.get('url', '')}")
        print(f"[DB]     Severity: {finding.get('severity', 'Unknown')}")
        
        # DEBUG: Check evidence field
        evidence = finding.get('evidence', '')
        if evidence:
            print(f"[DB]     Evidence: {evidence[:80]}...")
        else:
            print(f"[DB]     Evidence: ⚠️ MISSING/EMPTY")
        
        # Generate finding hash for deduplication
        finding_hash = self._generate_finding_hash(finding)
        print(f"[DB]     Hash: {finding_hash}")
        
        # Check if THIS EXACT finding already exists in THIS SCAN
        # Include scan_id in the check to allow same finding across multiple scans
        cursor.execute(
            "SELECT id, first_seen FROM findings WHERE finding_hash = ? AND scan_id = ?",
            (finding_hash, scan_id)
        )
        existing = cursor.fetchone()
        
        if existing:
            # Update last_seen, metadata, and risk scores for same finding in same scan
            print(f"[DB]     → COLLISION: Hash already exists in this scan (ID={existing[0]}), updating...")
            
            # Prepare metadata - include PoC if present
            metadata = finding.get('metadata', {})
            if 'poc' in finding:
                metadata['poc'] = finding['poc']
                print(f"[DB] Added PoC to existing finding metadata")
            if 'recommendation' in finding:
                metadata['recommendation'] = finding['recommendation']
            
            # Update with risk scores
            cursor.execute("""
                UPDATE findings 
                SET last_seen = ?, metadata = ?,
                    risk_score = ?, cvss_score = ?, priority = ?
                WHERE finding_hash = ? AND scan_id = ?
            """, (
                datetime.utcnow().isoformat(), 
                json.dumps(metadata),
                finding.get('risk_score', 0),
                finding.get('cvss_score', 0),
                finding.get('priority', 5),
                finding_hash,
                scan_id
            ))
            print(f"[DB] Updated risk_score={finding.get('risk_score', 0)}, cvss_score={finding.get('cvss_score', 0)}, priority={finding.get('priority', 5)}")
        else:
            # Insert new finding
            print(f"[DB]     → NEW: Inserting new finding (hash not seen before)")
            
            # Prepare metadata - include PoC if present
            metadata = finding.get('metadata', {})
            if 'poc' in finding:
                metadata['poc'] = finding['poc']
            if 'recommendation' in finding:
                metadata['recommendation'] = finding['recommendation']
            
            cursor.execute("""
                INSERT INTO findings (
                    scan_id, finding_hash, severity, category, description,
                    evidence, url, cvss_score, risk_score, priority,
                    first_seen, last_seen, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_id,
                finding_hash,
                finding.get('severity', 'Info'),
                finding.get('category', 'Unknown'),
                finding.get('description', ''),
                finding.get('evidence', ''),
                finding.get('url', ''),
                finding.get('cvss_score', 0),
                finding.get('risk_score', 0),
                finding.get('priority', 5),
                datetime.utcnow().isoformat(),
                datetime.utcnow().isoformat(),
                json.dumps(metadata)
            ))
            print(f"[DB]     ✓ Inserted successfully")
    
    def _generate_finding_hash(self, finding: Dict[str, Any]) -> str:
        """Generate unique hash for finding deduplication."""
        import hashlib
        
        # Use category + description + url + evidence for better uniqueness
        # This prevents identical vulnerability types on different pages from collapsing into one
        cat = finding.get('category', '')
        desc = finding.get('description', '')
        url = finding.get('url', '')
        evidence = finding.get('evidence', '')
        
        key = f"{cat}:{desc}:{url}:{evidence}"
        hash_val = hashlib.md5(key.encode()).hexdigest()
        
        # DEBUG: Show hash input composition
        print(f"[DB]     Hash input: {cat[:30]}... : {desc[:30]}... : {url[:40]}... : {evidence[:40] if evidence else 'EMPTY'}...")
        
        return hash_val
    
    def get_trend_data(self, days: int = 30) -> Dict[str, Any]:
        """
        Get vulnerability trend data for the last N days.
        
        Args:
            days: Number of days to analyze
            
        Returns:
            Trend data with daily counts
        """
        cursor = self.conn.cursor()
        
        start_date = datetime.utcnow() - timedelta(days=days)
        
        cursor.execute("""
            SELECT 
                DATE(timestamp) as date,
                SUM(critical_count) as critical,
                SUM(high_count) as high,
                SUM(medium_count) as medium,
                SUM(low_count) as low,
                SUM(info_count) as info,
                SUM(total_findings) as total
            FROM scans
            WHERE timestamp >= ?
            GROUP BY DATE(timestamp)
            ORDER BY date
        """, (start_date.isoformat(),))
        
        rows = cursor.fetchall()
        
        return {
            'period_days': days,
            'start_date': start_date.isoformat(),
            'end_date': datetime.utcnow().isoformat(),
            'data_points': [dict(row) for row in rows]
        }
    
    def detect_regressions(self, lookback_scans: int = 5) -> List[Dict[str, Any]]:
        """
        Detect new vulnerabilities (regressions) in recent scans.
        
        Args:
            lookback_scans: Number of recent scans to compare
            
        Returns:
            List of new findings
        """
        cursor = self.conn.cursor()
        
        # Get recent scan IDs
        cursor.execute("""
            SELECT scan_id FROM scans
            ORDER BY timestamp DESC
            LIMIT ?
        """, (lookback_scans,))
        
        scan_ids = [row['scan_id'] for row in cursor.fetchall()]
        
        if len(scan_ids) < 2:
            return []
        
        latest_scan = scan_ids[0]
        previous_scans = scan_ids[1:]
        
        # Find findings in latest scan that weren't in previous scans
        placeholders = ','.join(['?' for _ in previous_scans])
        cursor.execute(f"""
            SELECT f.*
            FROM findings f
            WHERE f.scan_id = ?
            AND f.finding_hash NOT IN (
                SELECT finding_hash FROM findings
                WHERE scan_id IN ({placeholders})
            )
        """, [latest_scan] + previous_scans)
        
        regressions = [dict(row) for row in cursor.fetchall()]
        
        return regressions
    
    def get_fix_rate(self, days: int = 30) -> Dict[str, Any]:
        """
        Calculate vulnerability fix rate.
        
        Args:
            days: Period to analyze
            
        Returns:
            Fix rate statistics
        """
        cursor = self.conn.cursor()
        
        start_date = datetime.utcnow() - timedelta(days=days)
        
        # Total findings in period
        cursor.execute("""
            SELECT COUNT(*) as total
            FROM findings
            WHERE first_seen >= ?
        """, (start_date.isoformat(),))
        
        total = cursor.fetchone()['total']
        
        # Fixed findings
        cursor.execute("""
            SELECT COUNT(*) as fixed
            FROM findings
            WHERE first_seen >= ?
            AND status = 'fixed'
        """, (start_date.isoformat(),))
        
        fixed = cursor.fetchone()['fixed']
        
        # Open findings
        cursor.execute("""
            SELECT COUNT(*) as open
            FROM findings
            WHERE first_seen >= ?
            AND status = 'open'
        """, (start_date.isoformat(),))
        
        open_count = cursor.fetchone()['open']
        
        fix_rate = (fixed / total * 100) if total > 0 else 0
        
        return {
            'period_days': days,
            'total_findings': total,
            'fixed': fixed,
            'open': open_count,
            'fix_rate_percent': round(fix_rate, 2),
            'avg_time_to_fix_days': self._calculate_avg_fix_time(days)
        }
    
    def _calculate_avg_fix_time(self, days: int) -> float:
        """Calculate average time to fix vulnerabilities."""
        cursor = self.conn.cursor()
        
        start_date = datetime.utcnow() - timedelta(days=days)
        
        cursor.execute("""
            SELECT 
                AVG(JULIANDAY(fixed_date) - JULIANDAY(first_seen)) as avg_days
            FROM findings
            WHERE first_seen >= ?
            AND status = 'fixed'
            AND fixed_date IS NOT NULL
        """, (start_date.isoformat(),))
        
        result = cursor.fetchone()
        return round(result['avg_days'] or 0, 2)
    
    def get_scan_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent scan history."""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            SELECT * FROM scans
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        
        return [dict(row) for row in cursor.fetchall()]
    
    def get_scan_with_findings(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """
        Get complete scan data with all findings.
        
        Args:
            scan_id: Scan ID to retrieve
            
        Returns:
            Complete scan data with findings array
        """
        cursor = self.conn.cursor()
        
        # Get scan metadata
        cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
        scan_row = cursor.fetchone()
        
        if not scan_row:
            return None
        
        scan_data = dict(scan_row)
        
        # Get all findings for this scan
        cursor.execute("""
            SELECT * FROM findings 
            WHERE scan_id = ?
            ORDER BY priority ASC, risk_score DESC
        """, (scan_id,))
        
        findings = [dict(row) for row in cursor.fetchall()]
        
        # Parse metadata for each finding to extract PoC and recommendation
        for finding in findings:
            if finding.get('metadata'):
                try:
                    metadata = json.loads(finding['metadata'])
                    if 'poc' in metadata:
                        finding['poc'] = metadata['poc']
                    if 'recommendation' in metadata:
                        finding['recommendation'] = metadata['recommendation']
                except json.JSONDecodeError:
                    pass  # Keep original metadata if not valid JSON
        
        # Add findings to scan data
        scan_data['findings'] = findings
        
        # Build summary from findings
        scan_data['summary'] = {
            'critical': scan_data.get('critical_count', 0),
            'high': scan_data.get('high_count', 0),
            'medium': scan_data.get('medium_count', 0),
            'low': scan_data.get('low_count', 0),
            'info': scan_data.get('info_count', 0)
        }
        
        # Add top risks (top 10 by risk score)
        scan_data['top_risks'] = sorted(
            findings, 
            key=lambda x: x.get('risk_score', 0), 
            reverse=True
        )[:10]
        
        return scan_data
    
    def mark_finding_fixed(self, finding_hash: str):
        """Mark a finding as fixed."""
        cursor = self.conn.cursor()
        
        cursor.execute("""
            UPDATE findings
            SET status = 'fixed', fixed_date = ?
            WHERE finding_hash = ?
        """, (datetime.utcnow().isoformat(), finding_hash))
        
        self.conn.commit()
    
    def close(self):
        """Close database connection."""
        self.conn.close()


# Example usage
if __name__ == "__main__":
    db = ScanHistoryDB()
    
    # Example scan data
    scan_data = {
        'scan_id': 'test_scan_001',
        'scan_type': 'full',
        'target_url': 'http://localhost:8998',
        'timestamp': datetime.utcnow().isoformat(),
        'endpoints_discovered': 20,
        'endpoints_scanned': 20,
        'total_findings': 5,
        'summary': {
            'critical': 0,
            'high': 2,
            'medium': 3,
            'low': 0,
            'info': 0
        },
        'findings': [
            {
                'severity': 'High',
                'category': 'XSS',
                'description': 'XSS vulnerability detected',
                'url': 'http://localhost:8998/test',
                'cvss_score': 6.5,
                'risk_score': 8.2,
                'priority': 2
            }
        ]
    }
    
    # Save scan
    db.save_scan(scan_data)
    
    # Get trends
    trends = db.get_trend_data(30)
    print("Trends:", json.dumps(trends, indent=2))
    
    # Get fix rate
    fix_rate = db.get_fix_rate(30)
    print("Fix Rate:", json.dumps(fix_rate, indent=2))
    
    db.close()
