"""
Logger utility for safely appending JSON logs to files.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List
from threading import Lock

# Thread-safe lock for file operations
_log_lock = Lock()


def ensure_log_directory(log_dir: str) -> None:
    """
    Ensure the log directory exists.
    
    Args:
        log_dir: Path to the log directory
    """
    Path(log_dir).mkdir(parents=True, exist_ok=True)


def append_log(log_dir: str, log_entry: Dict[str, Any]) -> None:
    """
    Append a log entry to the JSON log file in a thread-safe manner.
    
    Args:
        log_dir: Directory where log files are stored
        log_entry: Dictionary containing log data to append
    """
    ensure_log_directory(log_dir)
    
    # Add timestamp if not present
    if "timestamp" not in log_entry:
        log_entry["timestamp"] = datetime.utcnow().isoformat() + "Z"
    
    # Use date-based log file naming
    log_file = os.path.join(log_dir, f"proxy_{datetime.utcnow().strftime('%Y%m%d')}.jsonl")
    
    with _log_lock:
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")


def read_logs(log_dir: str, max_entries: int = 100) -> List[Dict[str, Any]]:
    """
    Read the most recent log entries from all log files.
    
    Args:
        log_dir: Directory where log files are stored
        max_entries: Maximum number of entries to return
        
    Returns:
        List of log entries (most recent first)
    """
    if not os.path.exists(log_dir):
        return []
    
    all_logs: List[Dict[str, Any]] = []
    
    # Get all log files sorted by modification time (newest first)
    log_files = sorted(
        [f for f in Path(log_dir).glob("*.jsonl")],
        key=lambda x: x.stat().st_mtime,
        reverse=True
    )
    
    # Read logs from files until we have enough entries
    for log_file in log_files:
        try:
            with open(log_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
                # Read from end of file backwards
                for line in reversed(lines):
                    if line.strip():
                        try:
                            all_logs.append(json.loads(line))
                            if len(all_logs) >= max_entries:
                                break
                        except json.JSONDecodeError:
                            continue
            
            if len(all_logs) >= max_entries:
                break
        except Exception:
            continue
    
    return all_logs[:max_entries]
