"""
API Endpoint Discovery

Discovers REST API endpoints through various techniques:
- Known path enumeration
- Documentation parsing
- Response analysis
- Link extraction
"""

import httpx
import asyncio
import re
from typing import Dict, List, Any, Set
from datetime import datetime
from urllib.parse import urljoin, urlparse


class APIDiscovery:
    """Discover API endpoints."""
    
    # Common API path patterns
    API_PATTERNS = [
        r'/api/v\d+/',
        r'/webservice/',
        r'/rest/',
        r'/graphql',
        r'/ajax/'
    ]
    
    # Common API file extensions
    API_EXTENSIONS = ['.json', '.xml', '.api']
    
    # API documentation paths
    DOC_PATHS = [
        '/api/docs',
        '/api/documentation',
        '/swagger',
        '/swagger.json',
        '/swagger-ui',
        '/api-docs',
        '/openapi.json',
        '/redoc'
    ]
    
    def __init__(self, base_url: str):
        """
        Initialize API discovery.
        
        Args:
            base_url: Base URL to discover APIs from
        """
        self.base_url = base_url.rstrip('/')
        self.client = httpx.AsyncClient(timeout=30.0, follow_redirects=True)
        self.discovered = set()
    
    async def discover_all(self) -> Dict[str, Any]:
        """
        Run all discovery techniques.
        
        Returns:
            Dictionary of discovered endpoints
        """
        print("[API Discovery] Starting endpoint discovery...")
        
        results = {
            'discovery_timestamp': datetime.utcnow().isoformat() + 'Z',
            'base_url': self.base_url,
            'methods': {}
        }
        
        # Method 1: Known paths
        print("[API Discovery] Checking known API paths...")
        results['methods']['known_paths'] = await self.discover_known_paths()
        
        # Method 2: Documentation
        print("[API Discovery] Looking for API documentation...")
        results['methods']['documentation'] = await self.discover_from_docs()
        
        # Method 3: Response analysis
        print("[API Discovery] Analyzing responses...")
        results['methods']['response_analysis'] = await self.analyze_responses()
        
        # Method 4: Pattern matching
        print("[API Discovery] Pattern matching...")
        results['methods']['pattern_matching'] = await self.discover_by_patterns()
        
        # Compile all discovered endpoints
        results['discovered_endpoints'] = list(self.discovered)
        results['total_discovered'] = len(self.discovered)
        
        print(f"[API Discovery] Complete! Discovered {len(self.discovered)} endpoints")
        
        return results
    
    async def discover_known_paths(self) -> Dict[str, Any]:
        """
        Discover APIs from known common paths.
        """
        result = {
            'method': 'Known Paths',
            'endpoints_found': []
        }
        
        # Moodle-specific API paths
        known_paths = [
            '/webservice/rest/server.php',
            '/webservice/xmlrpc/server.php',
            '/webservice/soap/server.php',
            '/lib/ajax/service.php',
            '/lib/ajax/service-nologin.php',
            '/admin/webservice/service.php',
            '/local/*/webservice.php'
        ]
        
        for path in known_paths:
            try:
                url = f"{self.base_url}{path}"
                response = await self.client.get(url)
                
                if response.status_code != 404:
                    endpoint_info = {
                        'path': path,
                        'status_code': response.status_code,
                        'content_type': response.headers.get('content-type', '')
                    }
                    result['endpoints_found'].append(endpoint_info)
                    self.discovered.add(path)
            
            except:
                pass
        
        return result
    
    async def discover_from_docs(self) -> Dict[str, Any]:
        """
        Discover APIs from documentation pages.
        """
        result = {
            'method': 'Documentation',
            'docs_found': [],
            'endpoints_extracted': []
        }
        
        for doc_path in self.DOC_PATHS:
            try:
                url = f"{self.base_url}{doc_path}"
                response = await self.client.get(url)
                
                if response.status_code == 200:
                    result['docs_found'].append(doc_path)
                    
                    # Try to parse as JSON (Swagger/OpenAPI)
                    try:
                        data = response.json()
                        
                        # Extract paths from Swagger/OpenAPI
                        if 'paths' in data:
                            for path in data['paths'].keys():
                                self.discovered.add(path)
                                result['endpoints_extracted'].append(path)
                    
                    except:
                        # Parse HTML for API endpoints
                        endpoints = re.findall(r'(/api/[^\s<>"\']+)', response.text)
                        for endpoint in endpoints:
                            self.discovered.add(endpoint)
                            result['endpoints_extracted'].append(endpoint)
            
            except:
                pass
        
        return result
    
    async def analyze_responses(self) -> Dict[str, Any]:
        """
        Analyze responses for API endpoint hints.
        """
        result = {
            'method': 'Response Analysis',
            'endpoints_found': []
        }
        
        try:
            # Get homepage
            response = await self.client.get(self.base_url)
            
            # Look for API endpoints in HTML
            api_links = re.findall(r'href=["\']([^"\']*(?:api|webservice|rest)[^"\']*)["\']', 
                                  response.text, re.IGNORECASE)
            
            for link in api_links:
                # Convert relative to absolute
                full_url = urljoin(self.base_url, link)
                path = urlparse(full_url).path
                
                if path and path not in self.discovered:
                    self.discovered.add(path)
                    result['endpoints_found'].append(path)
            
            # Look for API endpoints in JavaScript
            js_apis = re.findall(r'["\'](/(?:api|webservice|rest)/[^"\']+)["\']', 
                                response.text, re.IGNORECASE)
            
            for api in js_apis:
                if api not in self.discovered:
                    self.discovered.add(api)
                    result['endpoints_found'].append(api)
        
        except:
            pass
        
        return result
    
    async def discover_by_patterns(self) -> Dict[str, Any]:
        """
        Discover APIs by testing common patterns.
        """
        result = {
            'method': 'Pattern Matching',
            'endpoints_found': []
        }
        
        # Test API versioning patterns
        versions = ['v1', 'v2', 'v3']
        resources = ['users', 'courses', 'grades', 'assignments']
        
        for version in versions:
            for resource in resources:
                path = f"/api/{version}/{resource}"
                
                try:
                    url = f"{self.base_url}{path}"
                    response = await self.client.get(url)
                    
                    if response.status_code != 404:
                        self.discovered.add(path)
                        result['endpoints_found'].append({
                            'path': path,
                            'status_code': response.status_code
                        })
                
                except:
                    pass
        
        return result
    
    async def close(self):
        """Close HTTP client."""
        await self.client.aclose()


# Example usage
if __name__ == "__main__":
    async def test():
        discovery = APIDiscovery("http://localhost:8998")
        results = await discovery.discover_all()
        
        print("\n" + "="*50)
        print("API DISCOVERY RESULTS")
        print("="*50)
        print(f"Total Discovered: {results['total_discovered']}")
        print(f"Endpoints: {results['discovered_endpoints']}")
        print("="*50)
        
        await discovery.close()
    
    asyncio.run(test())
