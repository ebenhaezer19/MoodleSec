#!/usr/bin/env python3
"""
Database Migration Script
Adds missing columns to existing database
"""

import sqlite3
import os
from pathlib import Path

def migrate_database(db_path='data/scan_history.db'):
    """Migrate database schema to latest version."""
    
    if not os.path.exists(db_path):
        print(f"✅ Database doesn't exist yet, will be created fresh")
        return
    
    print(f"🔄 Migrating database: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check if findings table exists
    cursor.execute("""
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='findings'
    """)
    
    if not cursor.fetchone():
        print("✅ Findings table doesn't exist, will be created fresh")
        conn.close()
        return
    
    # Get current columns
    cursor.execute("PRAGMA table_info(findings)")
    columns = [row[1] for row in cursor.fetchall()]
    
    print(f"📋 Current columns: {', '.join(columns)}")
    
    # Add missing columns
    migrations = []
    
    if 'finding_hash' not in columns:
        migrations.append(("finding_hash", "TEXT NOT NULL DEFAULT ''"))
    
    if 'status' not in columns:
        migrations.append(("status", "TEXT DEFAULT 'open'"))
    
    if 'fixed_date' not in columns:
        migrations.append(("fixed_date", "DATETIME"))
    
    if 'metadata' not in columns:
        migrations.append(("metadata", "TEXT"))
    
    # Apply migrations
    if migrations:
        print(f"\n🔧 Applying {len(migrations)} migrations:")
        for col_name, col_type in migrations:
            try:
                cursor.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_type}")
                print(f"  ✅ Added column: {col_name}")
            except sqlite3.OperationalError as e:
                if "duplicate column" in str(e).lower():
                    print(f"  ⚠️  Column {col_name} already exists")
                else:
                    print(f"  ❌ Error adding {col_name}: {e}")
        
        conn.commit()
        
        # Generate finding_hash for existing records
        if 'finding_hash' in [m[0] for m in migrations]:
            print("\n🔄 Generating hashes for existing findings...")
            cursor.execute("""
                UPDATE findings 
                SET finding_hash = 
                    substr(
                        hex(randomblob(16)), 
                        1, 32
                    )
                WHERE finding_hash = '' OR finding_hash IS NULL
            """)
            updated = cursor.rowcount
            conn.commit()
            print(f"  ✅ Updated {updated} records with hashes")
        
        print("\n✅ Migration complete!")
    else:
        print("\n✅ Database schema is up to date")
    
    # Verify indexes
    print("\n🔍 Checking indexes...")
    cursor.execute("""
        SELECT name FROM sqlite_master 
        WHERE type='index' AND tbl_name='findings'
    """)
    indexes = [row[0] for row in cursor.fetchall()]
    print(f"📋 Current indexes: {', '.join(indexes)}")
    
    # Create missing indexes
    index_migrations = [
        ("idx_findings_hash", "CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(finding_hash)"),
        ("idx_findings_status", "CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)"),
        ("idx_findings_scan_id", "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)")
    ]
    
    for idx_name, idx_sql in index_migrations:
        if idx_name not in indexes:
            try:
                cursor.execute(idx_sql)
                print(f"  ✅ Created index: {idx_name}")
            except sqlite3.OperationalError as e:
                print(f"  ⚠️  Index {idx_name}: {e}")
    
    conn.commit()
    conn.close()
    
    print("\n✅ Database migration complete!")

if __name__ == '__main__':
    # Get database path
    db_path = Path(__file__).parent.parent / 'data' / 'scan_history.db'
    migrate_database(str(db_path))
