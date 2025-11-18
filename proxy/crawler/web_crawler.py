"""
Web Crawler for Automatic Endpoint Discovery

Crawls web applications to discover all endpoints, forms, and parameters.
"""

import re
import asyncio
from typing import Set, Dict, List, Optional, Any
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import httpx


class WebCrawler:
    """Crawl web applications to discover endpoints and forms."""
    
    def __init__(self, base_url: str, max_depth: int = 3, max_pages: int = 100):
        """
        Initialize web crawler.
        
        Args:
            base_url: Base URL to start crawling from
            max_depth: Maximum depth to crawl
            max_pages: Maximum number of pages to crawl
        """
        self.base_url = base_url.rstrip('/')
        self.max_depth = max_depth
        self.max_pages = max_pages
        
        # Parsed base URL
        self.base_domain = urlparse(base_url).netloc
        
        # Tracking
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: List[Dict[str, Any]] = []
        self.discovered_forms: List[Dict[str, Any]] = []
        self.site_map: Dict[str, Any] = {}
        
        # Exclusions
        self.excluded_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
            '.css', '.js', '.woff', '.woff2', '.ttf', '.eot',
            '.pdf', '.zip', '.tar', '.gz', '.mp4', '.mp3'
        }
        
        self.excluded_patterns = [
            r'/logout',
            r'/signout',
            r'/delete',
            r'/remove',
        ]
    
    async def crawl(self) -> Dict[str, Any]:
        """
        Start crawling from base URL.
        
        Returns:
            Dictionary containing discovered endpoints, forms, and site map
        """
        print(f"[Crawler] Starting crawl of {self.base_url}")
        print(f"[Crawler] Max depth: {self.max_depth}, Max pages: {self.max_pages}")
        
        # Start crawling from base URL
        await self._crawl_url(self.base_url, depth=0)
        
        print(f"[Crawler] Crawl complete!")
        print(f"[Crawler] Visited {len(self.visited_urls)} pages")
        print(f"[Crawler] Discovered {len(self.discovered_endpoints)} endpoints")
        print(f"[Crawler] Found {len(self.discovered_forms)} forms")
        
        return {
            'base_url': self.base_url,
            'visited_urls': list(self.visited_urls),
            'endpoints': self.discovered_endpoints,
            'forms': self.discovered_forms,
            'site_map': self.site_map,
            'statistics': {
                'total_pages': len(self.visited_urls),
                'total_endpoints': len(self.discovered_endpoints),
                'total_forms': len(self.discovered_forms)
            }
        }
    
    async def _crawl_url(self, url: str, depth: int):
        """
        Crawl a single URL and extract links.
        
        Args:
            url: URL to crawl
            depth: Current crawl depth
        """
        # Check limits
        if depth > self.max_depth:
            return
        
        if len(self.visited_urls) >= self.max_pages:
            return
        
        # Normalize URL
        url = url.split('#')[0]  # Remove fragments
        
        # Check if already visited
        if url in self.visited_urls:
            return
        
        # Check if should be excluded
        if self._should_exclude(url):
            return
        
        # Check if same domain
        if not self._is_same_domain(url):
            return
        
        print(f"[Crawler] Crawling: {url} (depth: {depth})")
        
        # Mark as visited
        self.visited_urls.add(url)
        
        try:
            # Fetch page
            async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
                response = await client.get(url)
                
                if response.status_code != 200:
                    return
                
                content_type = response.headers.get('content-type', '')
                if 'text/html' not in content_type:
                    return
                
                html_content = response.text
            
            # Parse HTML
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # Extract endpoint info
            self._extract_endpoint_info(url, response, soup)
            
            # Extract forms
            self._extract_forms(url, soup)
            
            # Extract links and crawl recursively
            links = self._extract_links(url, soup)
            
            # Crawl discovered links
            for link in links:
                await self._crawl_url(link, depth + 1)
        
        except Exception as e:
            print(f"[Crawler] Error crawling {url}: {str(e)}")
    
    def _extract_endpoint_info(self, url: str, response: httpx.Response, soup: BeautifulSoup):
        """Extract endpoint information."""
        parsed = urlparse(url)
        
        endpoint_info = {
            'url': url,
            'path': parsed.path,
            'query_params': parse_qs(parsed.query),
            'method': 'GET',
            'status_code': response.status_code,
            'title': soup.title.string if soup.title else None,
            'forms_count': len(soup.find_all('form')),
            'links_count': len(soup.find_all('a')),
            'inputs_count': len(soup.find_all('input')),
        }
        
        self.discovered_endpoints.append(endpoint_info)
        
        # Add to site map
        if parsed.path not in self.site_map:
            self.site_map[parsed.path] = {
                'url': url,
                'title': endpoint_info['title'],
                'forms': [],
                'parameters': list(endpoint_info['query_params'].keys())
            }
    
    def _extract_forms(self, url: str, soup: BeautifulSoup):
        """Extract all forms from page."""
        forms = soup.find_all('form')
        
        for form in forms:
            form_info = {
                'page_url': url,
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'inputs': [],
                'has_file_upload': False
            }
            
            # Make action absolute
            if form_info['action']:
                form_info['action'] = urljoin(url, form_info['action'])
            else:
                form_info['action'] = url
            
            # Extract inputs
            inputs = form.find_all(['input', 'textarea', 'select'])
            for input_elem in inputs:
                input_info = {
                    'type': input_elem.get('type', 'text'),
                    'name': input_elem.get('name', ''),
                    'value': input_elem.get('value', ''),
                    'required': input_elem.has_attr('required')
                }
                
                if input_info['type'] == 'file':
                    form_info['has_file_upload'] = True
                
                if input_info['name']:
                    form_info['inputs'].append(input_info)
            
            self.discovered_forms.append(form_info)
            
            # Add to site map
            parsed = urlparse(url)
            if parsed.path in self.site_map:
                self.site_map[parsed.path]['forms'].append(form_info)
    
    def _extract_links(self, base_url: str, soup: BeautifulSoup) -> List[str]:
        """Extract all links from page."""
        links = set()
        
        # Extract from <a> tags
        for link in soup.find_all('a', href=True):
            href = link['href']
            absolute_url = urljoin(base_url, href)
            links.add(absolute_url)
        
        # Extract from <form> actions
        for form in soup.find_all('form', action=True):
            action = form['action']
            absolute_url = urljoin(base_url, action)
            links.add(absolute_url)
        
        return list(links)
    
    def _should_exclude(self, url: str) -> bool:
        """Check if URL should be excluded."""
        # Check file extensions
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        for ext in self.excluded_extensions:
            if path.endswith(ext):
                return True
        
        # Check patterns
        for pattern in self.excluded_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        return False
    
    def _is_same_domain(self, url: str) -> bool:
        """Check if URL is from same domain."""
        parsed = urlparse(url)
        return parsed.netloc == self.base_domain or parsed.netloc == ''
    
    def get_endpoints_for_scanning(self) -> List[Dict[str, Any]]:
        """
        Get list of endpoints ready for scanning.
        
        Returns:
            List of endpoint dictionaries with URL, method, and parameters
        """
        scan_targets = []
        
        # Add discovered endpoints
        for endpoint in self.discovered_endpoints:
            scan_targets.append({
                'url': endpoint['url'],
                'path': endpoint['path'],
                'method': 'GET',
                'parameters': endpoint['query_params']
            })
        
        # Add form submissions
        for form in self.discovered_forms:
            # Create parameter dict from form inputs
            params = {}
            for input_field in form['inputs']:
                if input_field['name']:
                    # Use default value or placeholder
                    params[input_field['name']] = input_field['value'] or 'test'
            
            scan_targets.append({
                'url': form['action'],
                'path': urlparse(form['action']).path,
                'method': form['method'],
                'parameters': params,
                'is_form': True
            })
        
        return scan_targets
    
    def export_site_map(self, format: str = 'json') -> str:
        """
        Export site map in specified format.
        
        Args:
            format: Export format ('json', 'text', 'xml')
            
        Returns:
            Formatted site map string
        """
        if format == 'json':
            import json
            return json.dumps(self.site_map, indent=2)
        
        elif format == 'text':
            output = []
            output.append(f"Site Map for {self.base_url}")
            output.append("=" * 50)
            
            for path, info in sorted(self.site_map.items()):
                output.append(f"\n{path}")
                if info['title']:
                    output.append(f"  Title: {info['title']}")
                if info['parameters']:
                    output.append(f"  Parameters: {', '.join(info['parameters'])}")
                if info['forms']:
                    output.append(f"  Forms: {len(info['forms'])}")
            
            return '\n'.join(output)
        
        else:
            raise ValueError(f"Unsupported format: {format}")


async def main():
    """Example usage."""
    crawler = WebCrawler(
        base_url="http://localhost:8998",
        max_depth=2,
        max_pages=50
    )
    
    results = await crawler.crawl()
    
    print("\n" + "="*50)
    print("CRAWL RESULTS")
    print("="*50)
    print(f"Total pages visited: {results['statistics']['total_pages']}")
    print(f"Total endpoints: {results['statistics']['total_endpoints']}")
    print(f"Total forms: {results['statistics']['total_forms']}")
    
    print("\n" + "="*50)
    print("SITE MAP")
    print("="*50)
    print(crawler.export_site_map(format='text'))
    
    print("\n" + "="*50)
    print("SCAN TARGETS")
    print("="*50)
    targets = crawler.get_endpoints_for_scanning()
    for i, target in enumerate(targets[:10], 1):
        print(f"{i}. {target['method']} {target['url']}")


if __name__ == "__main__":
    asyncio.run(main())
