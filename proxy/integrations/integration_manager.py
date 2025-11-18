"""
Integration Manager for SIEM, Ticketing Systems, and Webhooks

Supports:
- SIEM: Splunk, ELK Stack, QRadar
- Ticketing: Jira, ServiceNow, GitHub Issues
- Webhooks: Slack, Microsoft Teams, Discord, Custom
"""

import httpx
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
from enum import Enum


class IntegrationType(Enum):
    """Integration types."""
    SIEM = "siem"
    TICKETING = "ticketing"
    WEBHOOK = "webhook"


class SIEMType(Enum):
    """SIEM system types."""
    SPLUNK = "splunk"
    ELK = "elk"
    QRADAR = "qradar"


class TicketingType(Enum):
    """Ticketing system types."""
    JIRA = "jira"
    SERVICENOW = "servicenow"
    GITHUB = "github"


class WebhookType(Enum):
    """Webhook types."""
    SLACK = "slack"
    TEAMS = "teams"
    DISCORD = "discord"
    CUSTOM = "custom"


class IntegrationManager:
    """Manage integrations with external systems."""
    
    def __init__(self):
        """Initialize integration manager."""
        self.integrations: Dict[str, Dict[str, Any]] = {}
        self.client = httpx.AsyncClient(timeout=30.0)
    
    def register_integration(self, name: str, integration_type: str,
                           config: Dict[str, Any]):
        """
        Register a new integration.
        
        Args:
            name: Integration name
            integration_type: Type of integration
            config: Integration configuration
        """
        self.integrations[name] = {
            'type': integration_type,
            'config': config,
            'enabled': True,
            'created_at': datetime.utcnow().isoformat()
        }
    
    async def send_to_siem(self, siem_type: str, event_data: Dict[str, Any],
                          config: Dict[str, Any]) -> bool:
        """
        Send event to SIEM system.
        
        Args:
            siem_type: SIEM system type
            event_data: Event data to send
            config: SIEM configuration
            
        Returns:
            Success status
        """
        if siem_type == SIEMType.SPLUNK.value:
            return await self._send_to_splunk(event_data, config)
        elif siem_type == SIEMType.ELK.value:
            return await self._send_to_elk(event_data, config)
        elif siem_type == SIEMType.QRADAR.value:
            return await self._send_to_qradar(event_data, config)
        else:
            return False
    
    async def _send_to_splunk(self, event_data: Dict[str, Any],
                             config: Dict[str, Any]) -> bool:
        """Send event to Splunk HEC."""
        try:
            url = config.get('hec_url')
            token = config.get('hec_token')
            
            if not url or not token:
                return False
            
            # Format for Splunk HEC
            payload = {
                'event': event_data,
                'sourcetype': 'security_scan',
                'source': 'moodlesec',
                'time': datetime.utcnow().timestamp()
            }
            
            headers = {
                'Authorization': f'Splunk {token}',
                'Content-Type': 'application/json'
            }
            
            response = await self.client.post(url, json=payload, headers=headers)
            return response.status_code == 200
        
        except Exception as e:
            print(f"[SIEM] Splunk error: {str(e)}")
            return False
    
    async def _send_to_elk(self, event_data: Dict[str, Any],
                          config: Dict[str, Any]) -> bool:
        """Send event to Elasticsearch."""
        try:
            url = config.get('elasticsearch_url')
            index = config.get('index', 'security-scans')
            
            if not url:
                return False
            
            # Add timestamp
            event_data['@timestamp'] = datetime.utcnow().isoformat()
            
            # Send to Elasticsearch
            index_url = f"{url}/{index}/_doc"
            
            headers = {'Content-Type': 'application/json'}
            
            if config.get('api_key'):
                headers['Authorization'] = f"ApiKey {config['api_key']}"
            
            response = await self.client.post(index_url, json=event_data, headers=headers)
            return response.status_code in [200, 201]
        
        except Exception as e:
            print(f"[SIEM] ELK error: {str(e)}")
            return False
    
    async def _send_to_qradar(self, event_data: Dict[str, Any],
                             config: Dict[str, Any]) -> bool:
        """Send event to IBM QRadar."""
        try:
            url = config.get('api_url')
            token = config.get('sec_token')
            
            if not url or not token:
                return False
            
            # Format for QRadar
            headers = {
                'SEC': token,
                'Content-Type': 'application/json'
            }
            
            response = await self.client.post(
                f"{url}/api/siem/offenses",
                json=event_data,
                headers=headers
            )
            
            return response.status_code in [200, 201]
        
        except Exception as e:
            print(f"[SIEM] QRadar error: {str(e)}")
            return False
    
    async def create_ticket(self, ticketing_type: str, ticket_data: Dict[str, Any],
                          config: Dict[str, Any]) -> Optional[str]:
        """
        Create ticket in ticketing system.
        
        Args:
            ticketing_type: Ticketing system type
            ticket_data: Ticket information
            config: Ticketing system configuration
            
        Returns:
            Ticket ID if successful
        """
        if ticketing_type == TicketingType.JIRA.value:
            return await self._create_jira_ticket(ticket_data, config)
        elif ticketing_type == TicketingType.SERVICENOW.value:
            return await self._create_servicenow_ticket(ticket_data, config)
        elif ticketing_type == TicketingType.GITHUB.value:
            return await self._create_github_issue(ticket_data, config)
        else:
            return None
    
    async def _create_jira_ticket(self, ticket_data: Dict[str, Any],
                                 config: Dict[str, Any]) -> Optional[str]:
        """Create Jira ticket."""
        try:
            url = config.get('jira_url')
            email = config.get('email')
            api_token = config.get('api_token')
            project_key = config.get('project_key')
            
            if not all([url, email, api_token, project_key]):
                return None
            
            # Format Jira issue
            issue = {
                'fields': {
                    'project': {'key': project_key},
                    'summary': ticket_data.get('title', 'Security Finding'),
                    'description': ticket_data.get('description', ''),
                    'issuetype': {'name': 'Bug'},
                    'priority': {'name': self._map_priority_to_jira(ticket_data.get('priority', 3))},
                    'labels': ['security', 'vulnerability']
                }
            }
            
            response = await self.client.post(
                f"{url}/rest/api/3/issue",
                json=issue,
                auth=(email, api_token)
            )
            
            if response.status_code == 201:
                result = response.json()
                return result.get('key')
            
            return None
        
        except Exception as e:
            print(f"[Ticketing] Jira error: {str(e)}")
            return None
    
    async def _create_servicenow_ticket(self, ticket_data: Dict[str, Any],
                                       config: Dict[str, Any]) -> Optional[str]:
        """Create ServiceNow incident."""
        try:
            url = config.get('instance_url')
            username = config.get('username')
            password = config.get('password')
            
            if not all([url, username, password]):
                return None
            
            # Format ServiceNow incident
            incident = {
                'short_description': ticket_data.get('title', 'Security Finding'),
                'description': ticket_data.get('description', ''),
                'urgency': str(ticket_data.get('priority', 3)),
                'category': 'Security',
                'subcategory': 'Vulnerability'
            }
            
            response = await self.client.post(
                f"{url}/api/now/table/incident",
                json=incident,
                auth=(username, password),
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 201:
                result = response.json()
                return result.get('result', {}).get('number')
            
            return None
        
        except Exception as e:
            print(f"[Ticketing] ServiceNow error: {str(e)}")
            return None
    
    async def _create_github_issue(self, ticket_data: Dict[str, Any],
                                   config: Dict[str, Any]) -> Optional[str]:
        """Create GitHub issue."""
        try:
            token = config.get('token')
            repo = config.get('repo')  # format: owner/repo
            
            if not all([token, repo]):
                return None
            
            # Format GitHub issue
            issue = {
                'title': ticket_data.get('title', 'Security Finding'),
                'body': ticket_data.get('description', ''),
                'labels': ['security', 'vulnerability']
            }
            
            response = await self.client.post(
                f"https://api.github.com/repos/{repo}/issues",
                json=issue,
                headers={
                    'Authorization': f'token {token}',
                    'Accept': 'application/vnd.github.v3+json'
                }
            )
            
            if response.status_code == 201:
                result = response.json()
                return str(result.get('number'))
            
            return None
        
        except Exception as e:
            print(f"[Ticketing] GitHub error: {str(e)}")
            return None
    
    async def send_webhook(self, webhook_type: str, message_data: Dict[str, Any],
                          config: Dict[str, Any]) -> bool:
        """
        Send webhook notification.
        
        Args:
            webhook_type: Webhook type
            message_data: Message content
            config: Webhook configuration
            
        Returns:
            Success status
        """
        if webhook_type == WebhookType.SLACK.value:
            return await self._send_slack_webhook(message_data, config)
        elif webhook_type == WebhookType.TEAMS.value:
            return await self._send_teams_webhook(message_data, config)
        elif webhook_type == WebhookType.DISCORD.value:
            return await self._send_discord_webhook(message_data, config)
        elif webhook_type == WebhookType.CUSTOM.value:
            return await self._send_custom_webhook(message_data, config)
        else:
            return False
    
    async def _send_slack_webhook(self, message_data: Dict[str, Any],
                                  config: Dict[str, Any]) -> bool:
        """Send Slack webhook."""
        try:
            webhook_url = config.get('webhook_url')
            
            if not webhook_url:
                return False
            
            # Format Slack message
            payload = {
                'text': message_data.get('title', 'Security Alert'),
                'attachments': [{
                    'color': self._severity_to_color(message_data.get('severity', 'info')),
                    'fields': [
                        {'title': 'Severity', 'value': message_data.get('severity', 'N/A'), 'short': True},
                        {'title': 'Category', 'value': message_data.get('category', 'N/A'), 'short': True},
                        {'title': 'Description', 'value': message_data.get('description', 'N/A'), 'short': False}
                    ],
                    'footer': 'MoodleSec Security Scanner',
                    'ts': int(datetime.utcnow().timestamp())
                }]
            }
            
            response = await self.client.post(webhook_url, json=payload)
            return response.status_code == 200
        
        except Exception as e:
            print(f"[Webhook] Slack error: {str(e)}")
            return False
    
    async def _send_teams_webhook(self, message_data: Dict[str, Any],
                                  config: Dict[str, Any]) -> bool:
        """Send Microsoft Teams webhook."""
        try:
            webhook_url = config.get('webhook_url')
            
            if not webhook_url:
                return False
            
            # Format Teams message
            payload = {
                '@type': 'MessageCard',
                '@context': 'https://schema.org/extensions',
                'summary': message_data.get('title', 'Security Alert'),
                'themeColor': self._severity_to_color(message_data.get('severity', 'info')),
                'title': message_data.get('title', 'Security Alert'),
                'sections': [{
                    'facts': [
                        {'name': 'Severity', 'value': message_data.get('severity', 'N/A')},
                        {'name': 'Category', 'value': message_data.get('category', 'N/A')},
                        {'name': 'Description', 'value': message_data.get('description', 'N/A')}
                    ]
                }]
            }
            
            response = await self.client.post(webhook_url, json=payload)
            return response.status_code == 200
        
        except Exception as e:
            print(f"[Webhook] Teams error: {str(e)}")
            return False
    
    async def _send_discord_webhook(self, message_data: Dict[str, Any],
                                    config: Dict[str, Any]) -> bool:
        """Send Discord webhook."""
        try:
            webhook_url = config.get('webhook_url')
            
            if not webhook_url:
                return False
            
            # Format Discord message
            payload = {
                'embeds': [{
                    'title': message_data.get('title', 'Security Alert'),
                    'description': message_data.get('description', 'N/A'),
                    'color': int(self._severity_to_color(message_data.get('severity', 'info')).replace('#', ''), 16),
                    'fields': [
                        {'name': 'Severity', 'value': message_data.get('severity', 'N/A'), 'inline': True},
                        {'name': 'Category', 'value': message_data.get('category', 'N/A'), 'inline': True}
                    ],
                    'footer': {'text': 'MoodleSec Security Scanner'},
                    'timestamp': datetime.utcnow().isoformat()
                }]
            }
            
            response = await self.client.post(webhook_url, json=payload)
            return response.status_code in [200, 204]
        
        except Exception as e:
            print(f"[Webhook] Discord error: {str(e)}")
            return False
    
    async def _send_custom_webhook(self, message_data: Dict[str, Any],
                                   config: Dict[str, Any]) -> bool:
        """Send custom webhook."""
        try:
            webhook_url = config.get('webhook_url')
            
            if not webhook_url:
                return False
            
            headers = config.get('headers', {})
            
            response = await self.client.post(
                webhook_url,
                json=message_data,
                headers=headers
            )
            
            return response.status_code in [200, 201, 202, 204]
        
        except Exception as e:
            print(f"[Webhook] Custom error: {str(e)}")
            return False
    
    def _map_priority_to_jira(self, priority: int) -> str:
        """Map priority number to Jira priority name."""
        mapping = {
            1: 'Highest',
            2: 'High',
            3: 'Medium',
            4: 'Low',
            5: 'Lowest'
        }
        return mapping.get(priority, 'Medium')
    
    def _severity_to_color(self, severity: str) -> str:
        """Map severity to color code."""
        colors = {
            'critical': '#8b0000',
            'high': '#dc3545',
            'medium': '#ffc107',
            'low': '#28a745',
            'info': '#17a2b8'
        }
        return colors.get(severity.lower(), '#6c757d')
    
    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()


# Example usage
if __name__ == "__main__":
    import asyncio
    
    async def test_integrations():
        manager = IntegrationManager()
        
        # Test Slack webhook
        slack_config = {
            'webhook_url': 'https://hooks.slack.com/services/YOUR/WEBHOOK/URL'
        }
        
        message = {
            'title': 'Critical Vulnerability Detected',
            'severity': 'critical',
            'category': 'SQL Injection',
            'description': 'SQL injection vulnerability found in login form'
        }
        
        # result = await manager.send_webhook('slack', message, slack_config)
        # print(f"Slack webhook sent: {result}")
        
        await manager.close()
    
    # asyncio.run(test_integrations())
    print("Integration manager ready!")
