"""
Basic scan example: Demonstrates complete ZAP integration workflow.

This example shows how to use ZAPIntegrationManager for:
1. Authenticated scanning of Moodle instance
2. Automatic spider and active scanning
3. ML-based false positive filtering
4. Results export
"""

import logging
import json
from ml.zap_integration.zap_integration_manager import ZAPIntegrationManager


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)


def basic_scan_example():
    """Example 1: Basic unauthenticated scan."""
    print("\n" + "="*60)
    print("EXAMPLE 1: Basic Unauthenticated Scan")
    print("="*60)
    
    try:
        # Initialize manager
        manager = ZAPIntegrationManager(
            host="localhost",
            port=8080,
            api_key="1qlbij76v3j9c6ail8d0locm24"
        )
        
        # Validate connection
        if not manager.initialize():
            print("ERROR: Failed to initialize ZAP manager")
            return
        
        # Run unauthenticated scan
        target_url = "http://localhost/juice-shop"
        
        print(f"\nScanning target: {target_url}")
        print("Phases: Spider (depth=2) → Active Scan (medium policy) → ML Filter")
        
        results = manager.scan_unauthenticated(
            target_url=target_url,
            spider_depth=2,
            scan_policy="medium"
        )
        
        # Display results
        print("\n" + "-"*60)
        print("SCAN RESULTS")
        print("-"*60)
        print(f"Success: {results['success']}")
        print(f"Duration: {results['duration_seconds']:.1f}s")
        print(f"Total Findings: {results['total_findings']}")
        print(f"After ML Filter: {results['filtered_findings']}")
        print(f"False Positives Removed: {results['total_findings'] - results['filtered_findings']}")
        
        # Show statistics
        if results['statistics']:
            stats = results['statistics']
            print(f"\nFiltering Statistics:")
            print(f"  Tier 1 Removed: {stats.get('by_tier', {}).get('tier1', 0)}")
            print(f"  Tier 2 Removed: {stats.get('by_tier', {}).get('tier2', 0)}")
            print(f"  Tier 3 Removed: {stats.get('by_tier', {}).get('tier3', 0)}")
            print(f"  Total Filtering: {stats.get('filtering_percentage', 0):.1f}%")
        
        # Show top findings
        if results['alerts']:
            print(f"\nTop {min(5, len(results['alerts']))} Filtered Findings:")
            for i, alert in enumerate(results['alerts'][:5], 1):
                print(f"  {i}. [{alert.get('severity', 'N/A')}] {alert.get('category', 'Unknown')}")
                print(f"     URL: {alert.get('url', 'N/A')}")
        
        # Show errors if any
        if results['errors']:
            print(f"\nWarnings/Errors ({len(results['errors'])}):")
            for error in results['errors']:
                print(f"  - {error}")
        
        return results
        
    except Exception as exc:
        print(f"ERROR: {exc}")
        import traceback
        traceback.print_exc()
        return None


def authenticated_scan_example():
    """Example 2: Authenticated scan of Moodle."""
    print("\n" + "="*60)
    print("EXAMPLE 2: Moodle Authenticated Scan")
    print("="*60)
    
    try:
        manager = ZAPIntegrationManager(
            host="localhost",
            port=8080,
            api_key="1qlbij76v3j9c6ail8d0locm24"
        )
        
        if not manager.initialize():
            print("ERROR: Failed to initialize")
            return
        
        target_url = "http://localhost/moodle"
        username = "admin"
        password = "admin"
        
        print(f"\nScanning: {target_url}")
        print(f"Authentication: {username}")
        print("Phases: Auth → Spider → Active Scan → ML Filter")
        
        results = manager.scan_with_authentication(
            target_url=target_url,
            spider_depth=3,
            scan_policy="medium",
            username=username,
            password=password
        )
        
        print("\n" + "-"*60)
        print("AUTHENTICATED SCAN RESULTS")
        print("-"*60)
        print(f"Success: {results['success']}")
        print(f"Duration: {results['duration_seconds']:.1f}s")
        print(f"Total Findings: {results['total_findings']}")
        print(f"Filtered Findings: {results['filtered_findings']}")
        
        if results['errors']:
            print(f"\nIssues: {len(results['errors'])}")
            for error in results['errors']:
                print(f"  - {error}")
        
        return results
        
    except Exception as exc:
        print(f"ERROR: {exc}")
        return None


def manual_workflow_example():
    """Example 3: Manual control of each phase."""
    print("\n" + "="*60)
    print("EXAMPLE 3: Manual Workflow Control")
    print("="*60)
    
    try:
        manager = ZAPIntegrationManager(
            host="localhost",
            port=8080,
            api_key="1qlbij76v3j9c6ail8d0locm24"
        )
        
        if not manager.initialize():
            print("ERROR: Failed to initialize")
            return
        
        target_url = "http://localhost/dvwa"
        
        # Phase 1: Spider
        print(f"\n[PHASE 1] Spidering {target_url}...")
        spider_id, discovered_urls = manager.spider_target(target_url, depth=2)
        print(f"  Spider ID: {spider_id}")
        print(f"  URLs Found: {len(discovered_urls)}")
        if discovered_urls:
            print(f"  Sample URLs:\n    - " + "\n    - ".join(discovered_urls[:3]))
        
        # Phase 2: Active Scan
        print(f"\n[PHASE 2] Active Scanning discovered pages...")
        scan_id, alerts = manager.scan_discovered_urls(discovered_urls, 1, 1, "medium")
        print(f"  Scan ID: {scan_id}")
        print(f"  Raw Alerts: {len(alerts)}")
        
        # Phase 3: Filter
        print(f"\n[PHASE 3] Filtering alerts with ML pipeline...")
        filter_result = manager.filter_results(alerts, apply_ml=True)
        print(f"  Input: {filter_result['input_count']}")
        print(f"  Tier 1 Removed: {filter_result['tier1_removed']}")
        print(f"  Tier 2 Removed: {filter_result['tier2_removed']}")
        print(f"  Tier 3 Removed: {filter_result['tier3_removed']}")
        print(f"  Output: {filter_result['output_count']}")
        
        # Phase 4: Export
        print(f"\n[PHASE 4] Exporting results...")
        filtered_findings = filter_result['filtered_findings']
        
        # Export to JSON
        export_path = "/tmp/zap_scan_results.json"
        manager.result_aggregator.export_findings(
            filtered_findings,
            format="json",
            filepath=export_path
        )
        print(f"  Exported to: {export_path}")
        print(f"  Findings: {len(filtered_findings)}")
        
        # Print summary
        print(f"\n" + "-"*60)
        print("MANUAL WORKFLOW COMPLETE")
        print(f"Total Duration: N/A (phases run sequentially)")
        print(f"Final Results: {len(filtered_findings)} high-confidence findings")
        
        return filter_result
        
    except Exception as exc:
        print(f"ERROR: {exc}")
        import traceback
        traceback.print_exc()
        return None


def main():
    """Run all examples."""
    print("\n" + "="*60)
    print("ZAP INTEGRATION - USAGE EXAMPLES")
    print("="*60)
    print("\nThis demonstrates the complete ZAP scanning pipeline with:")
    print("  - Unauthenticated scanning")
    print("  - Authenticated scanning (Moodle)")
    print("  - Manual phase control")
    print("  - ML-based false positive filtering")
    
    print("\n" + "!"*60)
    print("NOTE: Requires running ZAP instance on localhost:8080")
    print("!"*60)
    
    try:
        # Example 1
        result1 = basic_scan_example()
        
        # Example 2 (if needed)
        # result2 = authenticated_scan_example()
        
        # Example 3 (if needed)
        # result3 = manual_workflow_example()
        
        print("\n" + "="*60)
        print("EXAMPLES COMPLETED")
        print("="*60)
        
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as exc:
        print(f"\n\nFATAL ERROR: {exc}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
