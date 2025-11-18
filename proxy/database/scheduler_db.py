"""
Scheduler Database Management

Manages scheduled scans in SQLite database.
"""

import sqlite3
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from pathlib import Path


class SchedulerDB:
    """Manage scheduled scans database."""
    
    def __init__(self, db_path: str = "data/scheduler.db"):
        """
        Initialize scheduler database.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        
        # Ensure data directory exists
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize database
        self._init_db()
    
    def _init_db(self):
        """Create database tables if they don't exist."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Schedules table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                schedule_id TEXT UNIQUE NOT NULL,
                target_url TEXT NOT NULL,
                cron_expression TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                priority TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                next_run DATETIME NOT NULL,
                last_run DATETIME,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL
            )
        """)
        
        # Schedule execution history
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schedule_executions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                schedule_id TEXT NOT NULL,
                scan_id TEXT,
                started_at DATETIME NOT NULL,
                completed_at DATETIME,
                status TEXT NOT NULL,
                findings_count INTEGER DEFAULT 0,
                error_message TEXT,
                FOREIGN KEY (schedule_id) REFERENCES schedules(schedule_id)
            )
        """)
        
        conn.commit()
        conn.close()
    
    def create_schedule(self, schedule_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new schedule.
        
        Args:
            schedule_data: Schedule information
            
        Returns:
            Created schedule data
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        now = datetime.utcnow().isoformat()
        
        try:
            cursor.execute("""
                INSERT INTO schedules (
                    schedule_id, target_url, cron_expression, scan_type,
                    priority, enabled, next_run, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                schedule_data['schedule_id'],
                schedule_data['target_url'],
                schedule_data['cron_expression'],
                schedule_data['scan_type'],
                schedule_data['priority'],
                1,  # enabled
                schedule_data['next_run'],
                now,
                now
            ))
            
            conn.commit()
            
            # Return created schedule
            return self.get_schedule(schedule_data['schedule_id'])
        
        except sqlite3.IntegrityError:
            return {'error': 'Schedule ID already exists'}
        finally:
            conn.close()
    
    def get_schedule(self, schedule_id: str) -> Optional[Dict[str, Any]]:
        """
        Get schedule by ID.
        
        Args:
            schedule_id: Schedule ID
            
        Returns:
            Schedule data or None
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM schedules WHERE schedule_id = ?
        """, (schedule_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return dict(row)
        return None
    
    def get_all_schedules(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        """
        Get all schedules.
        
        Args:
            enabled_only: Only return enabled schedules
            
        Returns:
            List of schedules
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if enabled_only:
            cursor.execute("""
                SELECT * FROM schedules WHERE enabled = 1 ORDER BY next_run ASC
            """)
        else:
            cursor.execute("""
                SELECT * FROM schedules ORDER BY created_at DESC
            """)
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def update_schedule(self, schedule_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update schedule.
        
        Args:
            schedule_id: Schedule ID
            updates: Fields to update
            
        Returns:
            Success status
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Build update query
        set_clause = ", ".join([f"{key} = ?" for key in updates.keys()])
        values = list(updates.values())
        values.append(datetime.utcnow().isoformat())
        values.append(schedule_id)
        
        cursor.execute(f"""
            UPDATE schedules 
            SET {set_clause}, updated_at = ?
            WHERE schedule_id = ?
        """, values)
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        return success
    
    def delete_schedule(self, schedule_id: str) -> bool:
        """
        Delete schedule.
        
        Args:
            schedule_id: Schedule ID
            
        Returns:
            Success status
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            DELETE FROM schedules WHERE schedule_id = ?
        """, (schedule_id,))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        
        return success
    
    def update_next_run(self, schedule_id: str, next_run: str) -> bool:
        """
        Update next run time for schedule.
        
        Args:
            schedule_id: Schedule ID
            next_run: Next run timestamp
            
        Returns:
            Success status
        """
        return self.update_schedule(schedule_id, {
            'next_run': next_run,
            'last_run': datetime.utcnow().isoformat()
        })
    
    def record_execution(self, schedule_id: str, scan_id: str, 
                        status: str, findings_count: int = 0,
                        error_message: str = None) -> int:
        """
        Record schedule execution.
        
        Args:
            schedule_id: Schedule ID
            scan_id: Scan ID that was executed
            status: Execution status (success, failed, running)
            findings_count: Number of findings
            error_message: Error message if failed
            
        Returns:
            Execution ID
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        now = datetime.utcnow().isoformat()
        
        cursor.execute("""
            INSERT INTO schedule_executions (
                schedule_id, scan_id, started_at, completed_at,
                status, findings_count, error_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            schedule_id,
            scan_id,
            now,
            now if status != 'running' else None,
            status,
            findings_count,
            error_message
        ))
        
        execution_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return execution_id
    
    def get_execution_history(self, schedule_id: str, 
                             limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get execution history for schedule.
        
        Args:
            schedule_id: Schedule ID
            limit: Maximum number of records
            
        Returns:
            List of executions
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM schedule_executions 
            WHERE schedule_id = ?
            ORDER BY started_at DESC
            LIMIT ?
        """, (schedule_id, limit))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def get_due_schedules(self) -> List[Dict[str, Any]]:
        """
        Get schedules that are due to run.
        
        Returns:
            List of due schedules
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        now = datetime.utcnow().isoformat()
        
        cursor.execute("""
            SELECT * FROM schedules 
            WHERE enabled = 1 AND next_run <= ?
            ORDER BY priority DESC, next_run ASC
        """, (now,))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [dict(row) for row in rows]
    
    def calculate_next_run(self, cron_expression: str, 
                          from_time: datetime = None) -> str:
        """
        Calculate next run time based on cron expression.
        
        Args:
            cron_expression: Cron expression (hourly, daily, weekly, monthly)
            from_time: Calculate from this time (default: now)
            
        Returns:
            Next run timestamp
        """
        if from_time is None:
            from_time = datetime.utcnow()
        
        if cron_expression == "hourly":
            next_run = from_time + timedelta(hours=1)
        elif cron_expression == "daily":
            next_run = from_time + timedelta(days=1)
        elif cron_expression == "weekly":
            next_run = from_time + timedelta(weeks=1)
        elif cron_expression == "monthly":
            next_run = from_time + timedelta(days=30)
        else:
            next_run = from_time + timedelta(days=1)
        
        return next_run.isoformat() + 'Z'


# Example usage
if __name__ == "__main__":
    db = SchedulerDB()
    
    # Create a test schedule
    schedule_data = {
        'schedule_id': 'test-schedule-001',
        'target_url': 'http://localhost:8998',
        'cron_expression': 'daily',
        'scan_type': 'full',
        'priority': 'normal',
        'next_run': datetime.utcnow().isoformat() + 'Z'
    }
    
    result = db.create_schedule(schedule_data)
    print(f"Created schedule: {result}")
    
    # Get all schedules
    schedules = db.get_all_schedules()
    print(f"All schedules: {schedules}")
