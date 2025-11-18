"""
REST API Security Testing Module

This module provides comprehensive REST API security testing:
- API endpoint discovery
- Authentication bypass
- Input validation
- Rate limiting
- Mass assignment
"""

from .rest_scanner import RESTScanner
from .api_discovery import APIDiscovery

__all__ = ['RESTScanner', 'APIDiscovery']
