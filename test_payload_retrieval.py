#!/usr/bin/env python3
"""
Test script to verify payload storage and retrieval functionality.
Tests both custom payload addition and the get_all_payloads() retrieval.
"""

import sys
import sqlite3
from pathlib import Path

# Add proxy directory to path
sys.path.insert(0, str(Path(__file__).parent / "proxy"))

from database.payload_repository import PayloadRepositoryManager

def test_custom_payload_addition():
    """Test adding a custom payload and retrieving it."""
    print("\n" + "="*60)
    print("TEST 1: Custom Payload Addition and Retrieval")
    print("="*60)
    
    # Initialize repository
    repo = PayloadRepositoryManager()
    print("[✓] Repository initialized")
    
    # Add a test custom payload
    test_payload = "<img src=x onerror=alert('XSS')>"
    result = repo.add_custom_payload(
        category="XSS",
        payload=test_payload,
        description="Test XSS payload",
        tags=["test", "xss"],
        priority=3
    )
    
    print(f"\n[ADD PAYLOAD] Result: {result}")
    
    if result["status"] == "success":
        payload_id = result["payload_id"]
        print(f"[✓] Custom payload added with ID: {payload_id}")
        
        # Retrieve all payloads and verify
        payloads = repo.get_all_payloads()
        print(f"\n[RETRIEVE] Found {len(payloads)} total payloads in repository")
        
        # Find our test payload
        test_payload_found = False
        for payload in payloads:
            if payload.get('id') == payload_id:
                test_payload_found = True
                print(f"\n[FOUND] Test payload details:")
                for key, value in payload.items():
                    if key == 'payload':
                        print(f"  {key}: {value[:50]}...")
                    else:
                        print(f"  {key}: {value}")
                break
        
        if test_payload_found:
            print("\n[✓✓] SUCCESS: Custom payload retrieved successfully!")
        else:
            print("\n[✗✗] FAILED: Custom payload not found in retrieval!")
            return False
    else:
        print(f"[✗] Failed to add custom payload: {result['message']}")
        return False
    
    return True

def test_database_schema():
    """Verify database schema has all required columns."""
    print("\n" + "="*60)
    print("TEST 2: Database Schema Verification")
    print("="*60)
    
    db_path = "proxy/data/payload_repository.db"
    if not Path(db_path).exists():
        print(f"[!] Database not found at {db_path}")
        return False
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get table info
    cursor.execute("PRAGMA table_info(payloads)")
    columns = cursor.fetchall()
    
    required_columns = [
        'id', 'payload_hash', 'category', 'payload_type', 'payload_text',
        'description', 'severity', 'source', 'success_count', 'failure_count',
        'total_uses', 'success_rate', 'effectiveness_score', 'is_vulnerable',
        'first_discovered', 'last_used', 'last_successful', 'found_in_scan_id',
        'found_in_url', 'notes', 'confidence_score', 'confidence_tier',
        'validation_status', 'validated_by', 'validated_at', 'created_method',
        'source_metadata'
    ]
    
    existing_columns = [col[1] for col in columns]
    
    print(f"\nDatabase columns ({len(existing_columns)} total):")
    for col in existing_columns:
        status = "✓" if col in required_columns else "?"
        print(f"  {status} {col}")
    
    missing = set(required_columns) - set(existing_columns)
    if missing:
        print(f"\n[✗] Missing columns: {missing}")
        return False
    else:
        print(f"\n[✓] All required columns present")
    
    conn.close()
    return True

def test_payload_count():
    """Test that payloads are properly counted."""
    print("\n" + "="*60)
    print("TEST 3: Payload Statistics")
    print("="*60)
    
    repo = PayloadRepositoryManager()
    stats = repo.get_stats()
    
    print(f"\nRepository Statistics:")
    print(f"  Total Payloads: {stats.get('total_payloads', 0)}")
    print(f"  Vulnerable: {stats.get('vulnerable_payloads', 0)}")
    print(f"  By Category: {stats.get('by_category', {})}")
    print(f"  Avg Effectiveness: {stats.get('avg_effectiveness', 0):.2f}%")
    print(f"  Avg Success Rate: {stats.get('avg_success_rate', 0):.2f}%")
    
    if stats.get('total_payloads', 0) > 0:
        print("\n[✓] Repository contains payloads")
        
        # Verify get_all_payloads() returns the correct count
        payloads = repo.get_all_payloads()
        if len(payloads) == stats.get('total_payloads', 0):
            print(f"[✓] get_all_payloads() returns correct count: {len(payloads)}")
            return True
        else:
            print(f"[✗] Count mismatch: stats={stats.get('total_payloads')}, actual={len(payloads)}")
            return False
    else:
        print("\n[!] Repository is empty")
        return True

def main():
    """Run all tests."""
    print("\n╔" + "="*58 + "╗")
    print("║" + " "*15 + "Payload Retrieval Test Suite" + " "*15 + "║")
    print("╚" + "="*58 + "╝")
    
    results = {
        "Schema": test_database_schema(),
        "Statistics": test_payload_count(),
        "Custom Payload": test_custom_payload_addition()
    }
    
    print("\n" + "="*60)
    print("TEST SUMMARY")
    print("="*60)
    
    for test_name, passed in results.items():
        status = "PASS ✓" if passed else "FAIL ✗"
        print(f"{test_name}: {status}")
    
    all_passed = all(results.values())
    print("\n" + ("="*60))
    if all_passed:
        print("ALL TESTS PASSED ✓✓✓")
    else:
        print("SOME TESTS FAILED ✗✗✗")
    print("="*60 + "\n")
    
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
