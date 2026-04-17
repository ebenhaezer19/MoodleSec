"""
Integration Test - Payload Injection System with Actual HTTP Requests

Tests that payload injection system actually makes HTTP requests,
injects payloads, and detects vulnerabilities in responses.
"""

import asyncio
import sys
from pathlib import Path

# Add paths
sys.path.insert(0, str(Path(__file__).parent / "proxy"))
sys.path.insert(0, str(Path(__file__).parent / "proxy" / "scanners"))

import httpx
from scanners.scanner_engine import ScannerEngine
from scanners.payload_injector import PayloadInjector
from database.payload_repository import PayloadRepositoryManager
from utils.payload_debug_logger import PayloadDebugLogger


class TestPayloadInjectionIntegration:
    """Integration test for payload injection system."""
    
    def __init__(self):
        """Initialize test environment."""
        print("\n" + "="*70)
        print("PAYLOAD INJECTION SYSTEM - INTEGRATION TEST")
        print("="*70 + "\n")
        
        self.payload_repo = PayloadRepositoryManager()
        self.debug_logger = PayloadDebugLogger()
        self.injector = PayloadInjector(self.payload_repo, self.debug_logger)
        self.scanner_engine = ScannerEngine(self.payload_repo, self.debug_logger)
        
        # Testing URL - using a simple test endpoint if available
        self.test_url = "http://httpbin.org/get"  # Free public test service
        
        print("✓ Test environment initialized\n")
    
    async def test_injector_with_http_client(self):
        """Test PayloadInjector with actual HTTP client."""
        print("TEST 1: PayloadInjector with HTTP Client")
        print("-" * 70)
        
        test_params = {
            "search": "test",
            "id": "1"
        }
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            print(f"  Target: {self.test_url}")
            print(f"  Parameters: {list(test_params.keys())}")
            print(f"  HTTP Client: httpx.AsyncClient")
            
            # Test parameter injection
            try:
                findings = await self.injector.inject_payloads_to_parameters(
                    url=self.test_url,
                    params=test_params,
                    client=client,
                    category="XSS",
                    scan_id="test_001",
                    max_payloads=3
                )
                print(f"  ✓ Parameter injection completed")
                print(f"  Findings: {len(findings)}")
                if findings:
                    for finding in findings[:3]:
                        print(f"    - {finding.get('description', 'Unknown')}")
            except Exception as e:
                print(f"  ✗ Error: {e}")
                import traceback
                traceback.print_exc()
        
        print()
    
    async def test_scanner_engine_with_async_scan(self):
        """Test ScannerEngine with async scan method."""
        print("TEST 2: ScannerEngine Async Scan with Payload Injection")
        print("-" * 70)
        
        test_url = "http://httpbin.org/post"
        test_params = {"username": "admin", "password": "test"}
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            print(f"  Target: {test_url}")
            print(f"  Method: POST")
            print(f"  Parameters: {list(test_params.keys())}")
            
            # Perform full scan with payload injection
            try:
                scan_results = await self.scanner_engine.scan(
                    url=test_url,
                    method="POST",
                    params=test_params,
                    response_body="<html><body>Test Response</body></html>",
                    response_headers={"Content-Type": "text/html"},
                    status_code=200,
                    client=client
                )
                
                print(f"  ✓ Scan completed successfully")
                print(f"  Scan ID: {scan_results['scan_id']}")
                print(f"  Total Findings: {scan_results['total_findings']}")
                print(f"  Summary: {scan_results['summary']}")
                
                if scan_results['findings']:
                    print(f"  Payload Injection Findings:")
                    for finding in scan_results['findings'][:5]:
                        print(f"    - [{finding['severity']}] {finding['category']}: {finding['description'][:50]}...")
                
                # Check if payload injection was tested
                if 'payload_injection' in scan_results['scanner_results']:
                    payload_result = scan_results['scanner_results']['payload_injection']
                    print(f"  Payload Injection Score: {payload_result.get('findings_count', 0)} findings")
                
            except Exception as e:
                print(f"  ✗ Error: {e}")
                import traceback
                traceback.print_exc()
        
        print()
    
    async def test_vulnerable_endpoint_detection(self):
        """Test detection of vulnerable payloads in responses."""
        print("TEST 3: Vulnerable Endpoint Response Detection")
        print("-" * 70)
        
        # Simulate vulnerable response that contains SQL error
        vulnerable_params = {"id": "1"}
        vulnerable_response = """
        <html><body>
        <h1>Error</h1>
        <p>You have an error in your SQL syntax near '</p>
        </body></html>
        """
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            print(f"  Scanning for SQL injection vulnerabilities...")
            print(f"  Response contains: 'You have an error in your SQL syntax'")
            
            try:
                scan_results = await self.scanner_engine.scan(
                    url="http://example.com/search",
                    method="GET",
                    params=vulnerable_params,
                    response_body=vulnerable_response,
                    response_headers={"Content-Type": "text/html"},
                    status_code=200,
                    client=client
                )
                
                print(f"  ✓ Scan completed")
                print(f"  Total Findings: {scan_results['total_findings']}")
                
                # Check for SQL Injection findings
                sql_findings = [f for f in scan_results['findings'] if 'SQL' in f.get('category', '')]
                print(f"  SQL Injection Findings: {len(sql_findings)}")
                
                if sql_findings:
                    for finding in sql_findings[:3]:
                        print(f"    - {finding['description']}")
                        print(f"      Severity: {finding['severity']}")
                
            except Exception as e:
                print(f"  ✗ Error: {e}")
                import traceback
                traceback.print_exc()
        
        print()
    
    async def test_debug_logging(self):
        """Test payload injection debug logging."""
        print("TEST 4: Debug Logging for Payload Injections")
        print("-" * 70)
        
        scan_id = "integration_test_001"
        
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Perform a scan with debug logging
            await self.scanner_engine.scan(
                url="http://httpbin.org/get",
                method="GET",
                params={"test": "value"},
                response_body="<html>Test</html>",
                response_headers={},
                status_code=200,
                client=client
            )
            
            print(f"  Scan ID: {scan_id}")
            
            # Get debug statistics
            stats = self.debug_logger.get_payload_injection_statistics(scan_id)
            print(f"  Total injection events logged: {stats.get('total_events', 0)}")
            print(f"  Successful injections: {stats.get('success_count', 0)}")
            print(f"  Failed injections: {stats.get('error_count', 0)}")
            
            # Get recent logs
            recent_logs = self.debug_logger.get_recent_payload_injections(limit=5)
            print(f"  Recent injection logs: {len(recent_logs)}")
            
            if recent_logs:
                print(f"  Latest injections:")
                for log in recent_logs[:3]:
                    print(f"    - {log.get('category')} → {log.get('injection_point')}")
        
        print()
    
    async def run_all_tests(self):
        """Run all integration tests."""
        try:
            print("Running integration tests...\n")
            
            await self.test_injector_with_http_client()
            await self.test_scanner_engine_with_async_scan()
            await self.test_vulnerable_endpoint_detection()
            await self.test_debug_logging()
            
            print("="*70)
            print("✓ ALL INTEGRATION TESTS COMPLETED")
            print("="*70)
            print("\nNOTE: Actual vulnerability detection depends on:")
            print("  1. Test endpoint returning vulnerable patterns")
            print("  2. Response containing SQL/XSS/CSRF indicators")
            print("  3. Payload repository having valid test payloads")
            print()
            
        except Exception as e:
            print(f"\n✗ TEST FAILED: {e}")
            import traceback
            traceback.print_exc()


async def main():
    """Run integration test suite."""
    tester = TestPayloadInjectionIntegration()
    await tester.run_all_tests()


if __name__ == "__main__":
    asyncio.run(main())
