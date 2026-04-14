#!/usr/bin/env python3
import sqlite3

try:
    conn = sqlite3.connect('data/payload_repository.db')
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(payloads)")
    cols = cursor.fetchall()
    
    print("Database Schema Columns:")
    print("=" * 60)
    for c in cols:
        print(f"{c[1]:<30} {c[2]}")
    
    print("\n" + "=" * 60)
    
    # Check if new columns exist
    col_names = [c[1] for c in cols]
    new_cols = ['confidence_score', 'confidence_tier', 'validation_status', 
                'validated_by', 'validated_at', 'created_method', 'source_metadata']
    
    existing = [col for col in new_cols if col in col_names]
    missing = [col for col in new_cols if col not in col_names]
    
    print(f"\n✅ NEW COLUMNS FOUND: {len(existing)}")
    for col in existing:
        print(f"   ✓ {col}")
    
    if missing:
        print(f"\n❌ MISSING COLUMNS: {len(missing)}")
        for col in missing:
            print(f"   ✗ {col}")
    
    conn.close()
except Exception as e:
    print(f"Error: {e}")
