"""
Slack Notification Helper

Simple helper for sending notifications to Slack.
"""

import httpx
from typing import Dict, Any, Optional
from datetime import datetime


class SlackNotifier:
    """Send notifications to Slack via webhook."""
    
    def __init__(self, webhook_url: str):
        """
        Initialize Slack notifier.
        
        Args:
            webhook_url: Slack webhook URL
        """
        self.webhook_url = webhook_url
        self.client = httpx.AsyncClient(timeout=10.0)
    
    async def send_scan_complete(self, scan_data: Dict[str, Any]) -> bool:
        """
        Send scan completion notification.
        
        Args:
            scan_data: Scan result data
            
        Returns:
            Success status
        """
        try:
            summary = scan_data.get('summary', {})
            critical = summary.get('critical', 0)
            high = summary.get('high', 0)
            medium = summary.get('medium', 0)
            low = summary.get('low', 0)
            total = scan_data.get('total_findings', 0)
            
            # Determine severity emoji
            if critical > 0:
                emoji = "🚨"
                color = "#dc3545"
            elif high > 0:
                emoji = "⚠️"
                color = "#ffc107"
            elif medium > 0:
                emoji = "ℹ️"
                color = "#17a2b8"
            else:
                emoji = "✅"
                color = "#28a745"
            
            # Build message
            message = {
                "text": f"{emoji} Security Scan Complete",
                "attachments": [
                    {
                        "color": color,
                        "blocks": [
                            {
                                "type": "header",
                                "text": {
                                    "type": "plain_text",
                                    "text": f"{emoji} Security Scan Complete"
                                }
                            },
                            {
                                "type": "section",
                                "fields": [
                                    {
                                        "type": "mrkdwn",
                                        "text": f"*Scan ID:*\n`{scan_data.get('scan_id', 'N/A')}`"
                                    },
                                    {
                                        "type": "mrkdwn",
                                        "text": f"*Target:*\n{scan_data.get('target_url', 'N/A')}"
                                    },
                                    {
                                        "type": "mrkdwn",
                                        "text": f"*Endpoints Scanned:*\n{scan_data.get('endpoints_scanned', 0)}"
                                    },
                                    {
                                        "type": "mrkdwn",
                                        "text": f"*Total Findings:*\n{total}"
                                    }
                                ]
                            },
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": f"*Vulnerability Breakdown:*\n🔴 Critical: {critical}\n🟠 High: {high}\n🟡 Medium: {medium}\n🟢 Low: {low}"
                                }
                            },
                            {
                                "type": "context",
                                "elements": [
                                    {
                                        "type": "mrkdwn",
                                        "text": f"MoodleSec Scanner | {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
            
            response = await self.client.post(self.webhook_url, json=message)
            return response.status_code == 200
        
        except Exception as e:
            print(f"[Slack] Error sending notification: {str(e)}")
            return False
    
    async def send_critical_alert(self, finding: Dict[str, Any], scan_id: str) -> bool:
        """
        Send alert for critical vulnerability.
        
        Args:
            finding: Vulnerability finding
            scan_id: Scan ID
            
        Returns:
            Success status
        """
        try:
            message = {
                "text": "🚨 CRITICAL VULNERABILITY DETECTED",
                "attachments": [
                    {
                        "color": "#dc3545",
                        "blocks": [
                            {
                                "type": "header",
                                "text": {
                                    "type": "plain_text",
                                    "text": "🚨 CRITICAL VULNERABILITY DETECTED"
                                }
                            },
                            {
                                "type": "section",
                                "fields": [
                                    {
                                        "type": "mrkdwn",
                                        "text": f"*Category:*\n{finding.get('category', 'N/A')}"
                                    },
                                    {
                                        "type": "mrkdwn",
                                        "text": f"*Severity:*\n🔴 {finding.get('severity', 'N/A')}"
                                    },
                                    {
                                        "type": "mrkdwn",
                                        "text": f"*URL:*\n{finding.get('url', 'N/A')}"
                                    },
                                    {
                                        "type": "mrkdwn",
                                        "text": f"*Risk Score:*\n{finding.get('risk_score', 'N/A')}"
                                    }
                                ]
                            },
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": f"*Description:*\n{finding.get('description', 'N/A')}"
                                }
                            },
                            {
                                "type": "section",
                                "text": {
                                    "type": "mrkdwn",
                                    "text": f"*Evidence:*\n```{finding.get('evidence', 'N/A')}```"
                                }
                            },
                            {
                                "type": "context",
                                "elements": [
                                    {
                                        "type": "mrkdwn",
                                        "text": f"Scan ID: `{scan_id}` | MoodleSec Scanner"
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
            
            response = await self.client.post(self.webhook_url, json=message)
            return response.status_code == 200
        
        except Exception as e:
            print(f"[Slack] Error sending alert: {str(e)}")
            return False
    
    async def send_simple_message(self, text: str) -> bool:
        """
        Send simple text message.
        
        Args:
            text: Message text
            
        Returns:
            Success status
        """
        try:
            message = {"text": text}
            response = await self.client.post(self.webhook_url, json=message)
            return response.status_code == 200
        
        except Exception as e:
            print(f"[Slack] Error sending message: {str(e)}")
            return False
    
    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()


# Example usage
if __name__ == "__main__":
    import asyncio
    
    async def test():
        # Replace with your webhook URL
        webhook = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
        notifier = SlackNotifier(webhook)
        
        # Test simple message
        await notifier.send_simple_message("🎉 MoodleSec Scanner is online!")
        
        # Test scan complete
        scan_data = {
            'scan_id': 'test_scan_001',
            'target_url': 'http://localhost:8998',
            'endpoints_scanned': 15,
            'total_findings': 5,
            'summary': {
                'critical': 1,
                'high': 2,
                'medium': 1,
                'low': 1
            }
        }
        await notifier.send_scan_complete(scan_data)
        
        await notifier.close()
    
    # asyncio.run(test())
    print("Slack notifier ready!")
