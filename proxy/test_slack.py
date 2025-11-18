#!/usr/bin/env python3
"""
Test Slack Integration
"""

import asyncio
import sys
from utils.slack_notifier import SlackNotifier


async def test_slack(webhook_url):
    """Test Slack notification."""
    
    print("🧪 Testing Slack Integration...")
    print(f"Webhook URL: {webhook_url[:50]}...")
    print()
    
    notifier = SlackNotifier(webhook_url)
    
    # Test 1: Simple message
    print("Test 1: Sending simple message...")
    result1 = await notifier.send_simple_message("🎉 Test from MoodleSec Scanner!")
    print(f"Result: {'✅ SUCCESS' if result1 else '❌ FAILED'}")
    print()
    
    # Test 2: Scan complete notification
    print("Test 2: Sending scan complete notification...")
    scan_data = {
        'scan_id': 'test_scan_001',
        'target_url': 'http://localhost:8998',
        'endpoints_scanned': 15,
        'total_findings': 5,
        'summary': {
            'critical': 1,
            'high': 2,
            'medium': 1,
            'low': 1,
            'info': 0
        }
    }
    result2 = await notifier.send_scan_complete(scan_data)
    print(f"Result: {'✅ SUCCESS' if result2 else '❌ FAILED'}")
    print()
    
    # Test 3: Critical vulnerability alert
    print("Test 3: Sending critical vulnerability alert...")
    finding = {
        'category': 'SQL Injection',
        'severity': 'Critical',
        'url': 'http://localhost:8998/login',
        'risk_score': 9.8,
        'description': 'SQL injection vulnerability detected in login form',
        'evidence': "' OR '1'='1"
    }
    result3 = await notifier.send_critical_alert(finding, 'test_scan_001')
    print(f"Result: {'✅ SUCCESS' if result3 else '❌ FAILED'}")
    print()
    
    await notifier.close()
    
    # Summary
    print("="*50)
    print("📊 Test Summary:")
    print(f"Simple Message: {'✅' if result1 else '❌'}")
    print(f"Scan Complete: {'✅' if result2 else '❌'}")
    print(f"Critical Alert: {'✅' if result3 else '❌'}")
    print("="*50)
    
    if result1 and result2 and result3:
        print("\n🎉 All tests PASSED! Check your Slack channel.")
        return 0
    else:
        print("\n❌ Some tests FAILED. Check webhook URL and network.")
        return 1


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_slack.py <webhook_url>")
        print("Example: python test_slack.py https://hooks.slack.com/services/YOUR/WEBHOOK/URL")
        sys.exit(1)
    
    webhook_url = sys.argv[1]
    exit_code = asyncio.run(test_slack(webhook_url))
    sys.exit(exit_code)
