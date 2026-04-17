"""
Test Payload Reuse & Injection System

Tests payload injection, detection, and logging functionality.
"""

import asyncio
import sys
from pathlib import Path

# Add paths
sys.path.insert(0, str(Path(__file__).parent / "proxy"))
sys.path.insert(0, str(Path(__file__).parent / "proxy" / "scanners"))

from scanners.payload_injector import PayloadInjector
from scanners.scanner_engine import ScannerEngine
from database.payload_repository import PayloadRepositoryManager
from utils.payload_debug_logger import PayloadDebugLogger


class TestPayloadReuse:
    """Test payload reuse and injection system."""
    
    def __init__(self):
        """Initialize test environment."""
        print("\n" + "="*70)
        print("PAYLOAD REUSE & INJECTION SYSTEM - TEST SUITE")
        print("="*70 + "\n")
        
        self.payload_repo = PayloadRepositoryManager()
        self.debug_logger = PayloadDebugLogger()
        self.injector = PayloadInjector(self.payload_repo, self.debug_logger)
        self.scanner_engine = ScannerEngine(self.payload_repo, self.debug_logger)
        
        print("✓ Test environment initialized\n")
    
    def test_payload_loading(self):
        """Test loading payloads from repository."""
        print("TEST 1: Load Payloads from Repository")
        print("-" * 70)
        
        categories = ["SQL Injection", "XSS", "CSRF"]
        
        for category in categories:
            payloads = self.payload_repo.get_top_payloads(category, limit=5)
            print(f"  {category}: {len(payloads)} payloads loaded")
            
            if payloads:
                for i, payload in enumerate(payloads[:2], 1):
                    payload_text = payload.get('payload_text', '')[:50]
                    print(f"    [{i}] {payload_text}...")
        
        print()
    
    def test_payload_injector_initialization(self):
        """Test PayloadInjector initialization."""
        print("TEST 2: PayloadInjector Initialization")
        print("-" * 70)
        
        print(f"  Payload Repository: {self.injector.payload_repo is not None}")
        print(f"  Debug Logger: {self.injector.debug_logger is not None}")
        print(f"  SQL Patterns: {len(self.injector.compiled_sql_patterns)} compiled")
        print(f"  XSS Patterns: {len(self.injector.compiled_xss_patterns)} compiled")
        
        print()
    
    def test_scanner_engine_integration(self):
        """Test ScannerEngine integration with PayloadInjector."""
        print("TEST 3: ScannerEngine Integration")
        print("-" * 70)
        
        print(f"  Payload Repository: {self.scanner_engine.payload_repo is not None}")
        print(f"  Debug Logger: {self.scanner_engine.debug_logger is not None}")
        print(f"  Payload Injector: {self.scanner_engine.payload_injector is not None}")
        
        scanners = self.scanner_engine.get_scanner_status()
        for scanner_id, status in scanners.items():
            enabled = "✓" if status['enabled'] else "✗"
            print(f"  [{enabled}] {status['name']}")
        
        print()
    
    def test_payload_statistics(self):
        """Test payload statistics across categories."""
        print("TEST 4: Payload Statistics")
        print("-" * 70)
        
        # Get statistics for each category
        categories = {
            "SQL Injection": self.payload_repo.get_top_payloads("SQL Injection", limit=100),
            "XSS": self.payload_repo.get_top_payloads("XSS", limit=100),
            "CSRF": self.payload_repo.get_top_payloads("CSRF", limit=100),
        }
        
        for category, payloads in categories.items():
            if payloads:
                avg_effectiveness = sum(p.get('effectiveness_score', 0) for p in payloads) / len(payloads)
                avg_success_rate = sum(p.get('success_rate', 0) for p in payloads) / len(payloads)
                print(f"  {category}:")
                print(f"    Count: {len(payloads)}")
                print(f"    Avg Effectiveness: {avg_effectiveness:.1f}%")
                print(f"    Avg Success Rate: {avg_success_rate:.1f}%")
            else:
                print(f"  {category}: No payloads found")
        
        print()
    
    def test_debug_logging(self):
        """Test debug logger functionality."""
        print("TEST 5: Debug Logger Functionality")
        print("-" * 70)
        
        scan_id = "test_scan_001"
        
        # Log a few injection attempts
        test_injections = [
            {
                "target_url": "http://example.com/user?id=1",
                "category": "SQL Injection",
                "payload_text": "' OR '1'='1",
                "injection_point": "parameter:id",
                "status": "ATTEMPT",
                "response_code": 200
            },
            {
                "target_url": "http://example.com/search?q=test",
                "category": "XSS",
                "payload_text": "<img src=x onerror=\"alert('xss')\">",
                "injection_point": "parameter:search",
                "status": "ATTEMPT",
                "response_code": 200
            },
        ]
        
        for injection in test_injections:
            self.debug_logger.log_injection_attempt(
                scan_id=scan_id,
                **injection
            )
            print(f"  ✓ Logged {injection['category']} injection")
        
        # Get statistics
        stats = self.debug_logger.get_payload_injection_statistics(scan_id)
        print(f"\n  Injection Statistics for {scan_id}:")
        print(f"    Total Injections: {stats.get('total_events', 0)}")
        print(f"    Success: {stats.get('success_count', 0)}")
        print(f"    Failed: {stats.get('error_count', 0)}")
        
        print()
    
    def test_scan_with_payload_injection(self):
        """Test full scan with payload injection."""
        print("TEST 6: Full Scan with Payload Injection")
        print("-" * 70)
        
        # Simulate a scan
        url = "http://localhost:8998/api/test"
        params = {"id": "1", "search": "test"}
        
        print(f"  Target URL: {url}")
        print(f"  Parameters: {list(params.keys())}")
        print(f"  Expected Flow:")
        print(f"    1. Load payloads for each category")
        print(f"    2. Test parameters with SQL Injection payloads")
        print(f"    3. Test parameters with XSS payloads")
        print(f"    4. Log all injection attempts")
        print(f"    5. Return findings with detection results")
        
        print(f"\n  Note: Full scan requires live target endpoint")
        print(f"        Testing payload loading only in this test")
        
        # Test payload loading for scan
        for category in ["SQL Injection", "XSS", "CSRF"]:
            payloads = self.payload_repo.get_top_payloads(category, limit=10)
            print(f"\n  [{category}] {len(payloads)} payloads ready for injection")
            print(f"    Would test across {len(params)} parameters")
            print(f"    Total requests: {len(payloads) * len(params)}")
        
        print()
    
    def run_all_tests(self):
        """Run all tests."""
        try:
            self.test_payload_loading()
            self.test_payload_injector_initialization()
            self.test_scanner_engine_integration()
            self.test_payload_statistics()
            self.test_debug_logging()
            self.test_scan_with_payload_injection()
            
            print("="*70)
            print("✓ ALL TESTS COMPLETED SUCCESSFULLY")
            print("="*70 + "\n")
            
        except Exception as e:
            print(f"\n✗ TEST FAILED: {e}")
            import traceback
            traceback.print_exc()


def main():
    """Run test suite."""
    tester = TestPayloadReuse()
    tester.run_all_tests()


if __name__ == "__main__":
    main()
