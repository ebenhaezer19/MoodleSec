"""
Payload Debug Logger - Tracks payload injection and reuse

Logs detailed information about:
- Which payloads are loaded
- Where payloads are injected (parameters, headers, body)
- Success/failure of injections
- Error tracking
"""

import json
import sqlite3
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path


class PayloadDebugLogger:
    """Centralized debug logging for payload injection tracking."""
    
    def __init__(self, db_path: str = "data/debug_logs.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        
    def _init_db(self):
        """Initialize debug log database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS debug_logs (
                id INTEGER PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                scan_id TEXT,
                event_type TEXT NOT NULL,
                category TEXT,
                payload_text TEXT,
                injection_point TEXT,
                target_url TEXT,
                status TEXT,
                error_message TEXT,
                details TEXT,
                response_code INTEGER
            )
        ''')
        
        # Create index for efficient queries
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan ON debug_logs(scan_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON debug_logs(timestamp DESC)")
        
        conn.commit()
        conn.close()
    
    def log_payload_loaded(self, category: str, count: int, payload_list: List[str] = None):
        """Log when payloads are loaded from repository."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            details = {
                'category': category,
                'count': count,
                'sample_payloads': payload_list[:3] if payload_list else []
            }
            
            cursor.execute('''
                INSERT INTO debug_logs 
                (event_type, category, details, status)
                VALUES (?, ?, ?, ?)
            ''', (
                'PAYLOAD_LOADED',
                category,
                json.dumps(details),
                'SUCCESS'
            ))
            
            conn.commit()
            conn.close()
            
            print(f"[Debug] Logged: {count} {category} payloads loaded")
        except Exception as e:
            print(f"[Debug Error] Failed to log payload load: {e}")
    
    def log_injection_attempt(self, scan_id: str, target_url: str, category: str, 
                            payload_text: str, injection_point: str, 
                            status: str = 'ATTEMPT', error: str = None, response_code: int = None):
        """Log when a payload is injected into a request."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Truncate long payloads for logging
            payload_display = payload_text[:100] if len(payload_text) > 100 else payload_text
            
            cursor.execute('''
                INSERT INTO debug_logs 
                (scan_id, event_type, category, payload_text, injection_point, target_url, status, error_message, response_code)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                'PAYLOAD_INJECTED',
                category,
                payload_display,
                injection_point,
                target_url,
                status,
                error,
                response_code
            ))
            
            conn.commit()
            conn.close()
            
            print(f"[Debug] Logged injection: {category} → {injection_point} (Status: {status})")
        except Exception as e:
            print(f"[Debug Error] Failed to log injection: {e}")
    
    def log_scan_start(self, scan_id: str, scan_type: str, target_url: str):
        """Log scan initialization."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            details = {
                'scan_type': scan_type,
                'target_url': target_url
            }
            
            cursor.execute('''
                INSERT INTO debug_logs 
                (scan_id, event_type, target_url, status, details)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                scan_id,
                'SCAN_START',
                target_url,
                'STARTED',
                json.dumps(details)
            ))
            
            conn.commit()
            conn.close()
            
            print(f"[Debug] Scan started: {scan_id} ({scan_type})")
        except Exception as e:
            print(f"[Debug Error] Failed to log scan start: {e}")
    
    def log_scan_complete(self, scan_id: str, findings_count: int, status: str = 'SUCCESS'):
        """Log scan completion."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            details = {
                'findings_count': findings_count
            }
            
            cursor.execute('''
                INSERT INTO debug_logs 
                (scan_id, event_type, status, details)
                VALUES (?, ?, ?, ?)
            ''', (
                scan_id,
                'SCAN_COMPLETE',
                status,
                json.dumps(details)
            ))
            
            conn.commit()
            conn.close()
            
            print(f"[Debug] Scan complete: {scan_id} (Found {findings_count} issues)")
        except Exception as e:
            print(f"[Debug Error] Failed to log scan complete: {e}")
    
    def get_scan_debug_log(self, scan_id: str) -> Dict[str, Any]:
        """Retrieve debug log for a specific scan."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT 
                    id, timestamp, event_type, category, payload_text, 
                    injection_point, target_url, status, error_message, response_code
                FROM debug_logs
                WHERE scan_id = ?
                ORDER BY timestamp ASC
            ''', (scan_id,))
            
            rows = cursor.fetchall()
            conn.close()
            
            logs = []
            for row in rows:
                logs.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'event_type': row[2],
                    'category': row[3],
                    'payload_text': row[4],
                    'injection_point': row[5],
                    'target_url': row[6],
                    'status': row[7],
                    'error_message': row[8],
                    'response_code': row[9]
                })
            
            return {
                'scan_id': scan_id,
                'total_events': len(logs),
                'logs': logs
            }
        except Exception as e:
            print(f"[Debug Error] Failed to retrieve debug log: {e}")
            return {'error': str(e)}
    
    def get_recent_debug_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieve recent debug logs across all scans."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT 
                    id, timestamp, scan_id, event_type, category, payload_text, 
                    injection_point, target_url, status, error_message, response_code
                FROM debug_logs
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            logs = []
            for row in rows:
                logs.append({
                    'id': row[0],
                    'timestamp': row[1],
                    'scan_id': row[2],
                    'event_type': row[3],
                    'category': row[4],
                    'payload_text': row[5],
                    'injection_point': row[6],
                    'target_url': row[7],
                    'status': row[8],
                    'error_message': row[9],
                    'response_code': row[10]
                })
            
            return logs
        except Exception as e:
            print(f"[Debug Error] Failed to retrieve recent logs: {e}")
            return []
    
    def get_payload_injection_statistics(self, scan_id: str = None) -> Dict[str, Any]:
        """Get statistics about payload injections."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Filter by scan_id if provided
            where_clause = "WHERE scan_id = ?" if scan_id else "WHERE 1=1"
            params = (scan_id,) if scan_id else ()
            
            # Get injection stats
            cursor.execute(f'''
                SELECT 
                    event_type,
                    status,
                    COUNT(*) as count
                FROM debug_logs
                {where_clause}
                GROUP BY event_type, status
            ''', params)
            
            stats = {
                'by_event_type': {},
                'by_status': {}
            }
            
            for row in cursor.fetchall():
                event_type = row[0]
                status = row[1]
                count = row[2]
                
                if event_type not in stats['by_event_type']:
                    stats['by_event_type'][event_type] = 0
                stats['by_event_type'][event_type] += count
                
                if status not in stats['by_status']:
                    stats['by_status'][status] = 0
                stats['by_status'][status] += count
            
            conn.close()
            
            return {
                'scan_id': scan_id,
                'statistics': stats
            }
        except Exception as e:
            print(f"[Debug Error] Failed to get statistics: {e}")
            return {'error': str(e)}
    
    def clear_old_logs(self, days: int = 7):
        """Clear debug logs older than specified days."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                DELETE FROM debug_logs 
                WHERE timestamp < datetime('now', '-' || ? || ' days')
            ''', (days,))
            
            deleted = cursor.rowcount
            conn.commit()
            conn.close()
            
            print(f"[Debug] Cleared {deleted} old debug logs")
            return deleted
        except Exception as e:
            print(f"[Debug Error] Failed to clear old logs: {e}")
            return 0
