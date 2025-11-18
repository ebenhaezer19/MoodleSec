"""
Scan Scheduler for Automated Security Scanning

Supports cron-based scheduling, event-triggered scans, and queue management.
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
from enum import Enum
import uuid


class ScanPriority(Enum):
    """Scan priority levels."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


class ScanStatus(Enum):
    """Scan status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanJob:
    """Represents a scan job."""
    
    def __init__(self, target_url: str, scan_type: str = "full", 
                 priority: ScanPriority = ScanPriority.NORMAL,
                 parameters: Optional[Dict[str, Any]] = None):
        """
        Initialize scan job.
        
        Args:
            target_url: URL to scan
            scan_type: Type of scan (full, quick, targeted)
            priority: Job priority
            parameters: Additional scan parameters
        """
        self.job_id = str(uuid.uuid4())
        self.target_url = target_url
        self.scan_type = scan_type
        self.priority = priority
        self.parameters = parameters or {}
        
        self.status = ScanStatus.PENDING
        self.created_at = datetime.utcnow()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.result: Optional[Dict[str, Any]] = None
        self.error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert job to dictionary."""
        return {
            'job_id': self.job_id,
            'target_url': self.target_url,
            'scan_type': self.scan_type,
            'priority': self.priority.name,
            'status': self.status.value,
            'created_at': self.created_at.isoformat(),
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'parameters': self.parameters
        }


class ScanQueue:
    """Priority queue for scan jobs."""
    
    def __init__(self, max_size: int = 1000):
        """
        Initialize scan queue.
        
        Args:
            max_size: Maximum queue size
        """
        self.max_size = max_size
        self.jobs: List[ScanJob] = []
        self.running_jobs: Dict[str, ScanJob] = {}
        self.completed_jobs: List[ScanJob] = []
    
    def add_job(self, job: ScanJob) -> bool:
        """
        Add job to queue.
        
        Args:
            job: Scan job to add
            
        Returns:
            True if added successfully, False if queue is full
        """
        if len(self.jobs) >= self.max_size:
            return False
        
        # Insert job based on priority
        inserted = False
        for i, existing_job in enumerate(self.jobs):
            if job.priority.value > existing_job.priority.value:
                self.jobs.insert(i, job)
                inserted = True
                break
        
        if not inserted:
            self.jobs.append(job)
        
        return True
    
    def get_next_job(self) -> Optional[ScanJob]:
        """Get next job from queue."""
        if not self.jobs:
            return None
        
        job = self.jobs.pop(0)
        self.running_jobs[job.job_id] = job
        return job
    
    def complete_job(self, job_id: str, result: Optional[Dict[str, Any]] = None, 
                    error: Optional[str] = None):
        """
        Mark job as completed.
        
        Args:
            job_id: Job ID
            result: Scan result
            error: Error message if failed
        """
        if job_id in self.running_jobs:
            job = self.running_jobs.pop(job_id)
            job.completed_at = datetime.utcnow()
            
            if error:
                job.status = ScanStatus.FAILED
                job.error = error
            else:
                job.status = ScanStatus.COMPLETED
                job.result = result
            
            self.completed_jobs.append(job)
            
            # Keep only last 100 completed jobs
            if len(self.completed_jobs) > 100:
                self.completed_jobs = self.completed_jobs[-100:]
    
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job status."""
        # Check pending jobs
        for job in self.jobs:
            if job.job_id == job_id:
                return job.to_dict()
        
        # Check running jobs
        if job_id in self.running_jobs:
            return self.running_jobs[job_id].to_dict()
        
        # Check completed jobs
        for job in self.completed_jobs:
            if job.job_id == job_id:
                return job.to_dict()
        
        return None
    
    def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        return {
            'pending': len(self.jobs),
            'running': len(self.running_jobs),
            'completed': len(self.completed_jobs),
            'total_capacity': self.max_size,
            'utilization': (len(self.jobs) / self.max_size) * 100
        }


class ScanScheduler:
    """Scheduler for automated security scans."""
    
    def __init__(self, max_concurrent_scans: int = 3):
        """
        Initialize scan scheduler.
        
        Args:
            max_concurrent_scans: Maximum number of concurrent scans
        """
        self.max_concurrent_scans = max_concurrent_scans
        self.queue = ScanQueue()
        self.schedules: Dict[str, Dict[str, Any]] = {}
        self.is_running = False
        self.scan_executor: Optional[Callable] = None
    
    def set_scan_executor(self, executor: Callable):
        """
        Set the function that executes scans.
        
        Args:
            executor: Async function that takes a ScanJob and returns results
        """
        self.scan_executor = executor
    
    def schedule_scan(self, target_url: str, cron_expression: str, 
                     scan_type: str = "full", priority: ScanPriority = ScanPriority.NORMAL,
                     parameters: Optional[Dict[str, Any]] = None) -> str:
        """
        Schedule a recurring scan.
        
        Args:
            target_url: URL to scan
            cron_expression: Cron expression (simplified: "daily", "weekly", "hourly")
            scan_type: Type of scan
            priority: Scan priority
            parameters: Additional parameters
            
        Returns:
            Schedule ID
        """
        schedule_id = str(uuid.uuid4())
        
        schedule = {
            'schedule_id': schedule_id,
            'target_url': target_url,
            'cron_expression': cron_expression,
            'scan_type': scan_type,
            'priority': priority,
            'parameters': parameters or {},
            'enabled': True,
            'last_run': None,
            'next_run': self._calculate_next_run(cron_expression),
            'created_at': datetime.utcnow()
        }
        
        self.schedules[schedule_id] = schedule
        return schedule_id
    
    def trigger_scan(self, target_url: str, scan_type: str = "full",
                    priority: ScanPriority = ScanPriority.NORMAL,
                    parameters: Optional[Dict[str, Any]] = None) -> str:
        """
        Trigger an immediate scan.
        
        Args:
            target_url: URL to scan
            scan_type: Type of scan
            priority: Scan priority
            parameters: Additional parameters
            
        Returns:
            Job ID
        """
        job = ScanJob(target_url, scan_type, priority, parameters)
        
        if self.queue.add_job(job):
            return job.job_id
        else:
            raise Exception("Queue is full")
    
    def trigger_event_scan(self, event_type: str, target_url: str,
                          parameters: Optional[Dict[str, Any]] = None) -> str:
        """
        Trigger scan based on event.
        
        Args:
            event_type: Type of event (deploy, config_change, etc.)
            target_url: URL to scan
            parameters: Additional parameters
            
        Returns:
            Job ID
        """
        # Event-triggered scans get higher priority
        priority_map = {
            'deploy': ScanPriority.HIGH,
            'config_change': ScanPriority.HIGH,
            'security_alert': ScanPriority.CRITICAL,
            'manual': ScanPriority.NORMAL
        }
        
        priority = priority_map.get(event_type, ScanPriority.NORMAL)
        
        params = parameters or {}
        params['event_type'] = event_type
        params['triggered_at'] = datetime.utcnow().isoformat()
        
        return self.trigger_scan(target_url, "event_triggered", priority, params)
    
    async def start(self):
        """Start the scheduler."""
        if self.is_running:
            return
        
        if not self.scan_executor:
            raise Exception("Scan executor not set. Call set_scan_executor() first.")
        
        self.is_running = True
        print("[Scheduler] Started")
        
        # Start worker tasks
        workers = [
            asyncio.create_task(self._worker(i))
            for i in range(self.max_concurrent_scans)
        ]
        
        # Start schedule checker
        schedule_checker = asyncio.create_task(self._check_schedules())
        
        # Wait for all tasks
        await asyncio.gather(*workers, schedule_checker)
    
    async def stop(self):
        """Stop the scheduler."""
        self.is_running = False
        print("[Scheduler] Stopped")
    
    async def _worker(self, worker_id: int):
        """Worker that processes scan jobs."""
        print(f"[Scheduler] Worker {worker_id} started")
        
        while self.is_running:
            # Get next job
            job = self.queue.get_next_job()
            
            if job:
                print(f"[Scheduler] Worker {worker_id} processing job {job.job_id}")
                
                job.status = ScanStatus.RUNNING
                job.started_at = datetime.utcnow()
                
                try:
                    # Execute scan
                    result = await self.scan_executor(job)
                    self.queue.complete_job(job.job_id, result=result)
                    print(f"[Scheduler] Job {job.job_id} completed successfully")
                
                except Exception as e:
                    self.queue.complete_job(job.job_id, error=str(e))
                    print(f"[Scheduler] Job {job.job_id} failed: {str(e)}")
            
            else:
                # No jobs, wait a bit
                await asyncio.sleep(1)
    
    async def _check_schedules(self):
        """Check and trigger scheduled scans."""
        while self.is_running:
            now = datetime.utcnow()
            
            for schedule_id, schedule in self.schedules.items():
                if not schedule['enabled']:
                    continue
                
                next_run = schedule['next_run']
                if next_run and now >= next_run:
                    # Trigger scan
                    try:
                        job_id = self.trigger_scan(
                            target_url=schedule['target_url'],
                            scan_type=schedule['scan_type'],
                            priority=schedule['priority'],
                            parameters=schedule['parameters']
                        )
                        
                        # Update schedule
                        schedule['last_run'] = now
                        schedule['next_run'] = self._calculate_next_run(
                            schedule['cron_expression'], 
                            from_time=now
                        )
                        
                        print(f"[Scheduler] Triggered scheduled scan: {job_id}")
                    
                    except Exception as e:
                        print(f"[Scheduler] Failed to trigger scheduled scan: {str(e)}")
            
            # Check every minute
            await asyncio.sleep(60)
    
    def _calculate_next_run(self, cron_expression: str, 
                           from_time: Optional[datetime] = None) -> datetime:
        """Calculate next run time from cron expression."""
        base_time = from_time or datetime.utcnow()
        
        # Simplified cron expressions
        if cron_expression == "hourly":
            return base_time + timedelta(hours=1)
        elif cron_expression == "daily":
            return base_time + timedelta(days=1)
        elif cron_expression == "weekly":
            return base_time + timedelta(weeks=1)
        elif cron_expression == "monthly":
            return base_time + timedelta(days=30)
        else:
            # Default to daily
            return base_time + timedelta(days=1)
    
    def get_schedule(self, schedule_id: str) -> Optional[Dict[str, Any]]:
        """Get schedule details."""
        return self.schedules.get(schedule_id)
    
    def enable_schedule(self, schedule_id: str) -> bool:
        """Enable a schedule."""
        if schedule_id in self.schedules:
            self.schedules[schedule_id]['enabled'] = True
            return True
        return False
    
    def disable_schedule(self, schedule_id: str) -> bool:
        """Disable a schedule."""
        if schedule_id in self.schedules:
            self.schedules[schedule_id]['enabled'] = False
            return True
        return False
    
    def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a schedule."""
        if schedule_id in self.schedules:
            del self.schedules[schedule_id]
            return True
        return False
    
    def get_all_schedules(self) -> List[Dict[str, Any]]:
        """Get all schedules."""
        return list(self.schedules.values())
    
    def get_queue_stats(self) -> Dict[str, Any]:
        """Get queue statistics."""
        return self.queue.get_queue_stats()
    
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get job status."""
        return self.queue.get_job_status(job_id)
