"""
Authentication Manager for Moodle Vulnerability Scanning

Handles:
- Extracting logintoken from Moodle login form
- Performing authenticated login
- Creating and maintaining authenticated HTTP clients
- Session management
"""

import re
import asyncio
import logging
from typing import Optional, Tuple
import httpx
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


class MoodleSession(httpx.AsyncClient):
    """Extended AsyncClient that maintains Moodle authentication session."""
    
    def __init__(self, moodle_url: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.moodle_url = moodle_url
        self.is_authenticated = False
        self.logintoken = None
        self.username = None
    
    async def login(self, username: str, password: str) -> bool:
        """
        Perform Moodle login with credentials.
        
        Args:
            username: Moodle username
            password: Moodle password
            
        Returns:
            True if login successful, False otherwise
        """
        try:
            # Step 1: Get login form and extract logintoken
            login_page_url = urljoin(self.moodle_url, "/login/index.php")
            logger.debug(f"Fetching login form from {login_page_url}")
            
            form_response = await self.get(login_page_url, timeout=10.0)
            form_response.raise_for_status()
            form_html = form_response.text
            
            # Extract logintoken from form HTML
            token_match = re.search(
                r'name=["\']logintoken["\'].*?value=["\']([^"\']+)["\']',
                form_html,
                re.DOTALL | re.IGNORECASE
            )
            
            if not token_match:
                logger.warning("Failed to extract logintoken from login form")
                return False
            
            self.logintoken = token_match.group(1)
            logger.debug(f"Extracted logintoken: {self.logintoken[:20]}...")
            
            # Step 2: Perform login with extracted token
            login_url = urljoin(self.moodle_url, "/login/index.php")
            login_data = {
                'username': username,
                'password': password,
                'logintoken': self.logintoken
            }
            
            logger.debug(f"Attempting login for user: {username}")
            login_response = await self.post(login_url, data=login_data, timeout=10.0)
            
            # Moodle redirects to dashboard after login
            if login_response.status_code in [200, 302, 303, 307, 308]:
                # Check if we're logged in by looking for logout link
                if 'logout' in login_response.text.lower() or login_response.history:
                    self.is_authenticated = True
                    self.username = username
                    logger.info(f"Successfully authenticated as {username}")
                    return True
            
            logger.warning(f"Login failed with status code: {login_response.status_code}")
            return False
            
        except asyncio.TimeoutError:
            logger.error("Login request timed out")
            return False
        except httpx.RequestError as e:
            logger.error(f"Login request error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during login: {e}")
            return False
    
    async def verify_authentication(self, check_url: str = None) -> bool:
        """
        Verify that current session is authenticated.
        
        Args:
            check_url: URL to verify authentication (defaults to dashboard)
            
        Returns:
            True if authenticated, False otherwise
        """
        try:
            if not self.is_authenticated:
                return False
            
            # Verify by accessing a protected page
            if check_url is None:
                check_url = urljoin(self.moodle_url, "/my/")
            
            response = await self.get(check_url, timeout=5.0, follow_redirects=True)
            
            # If we get redirected to login, we're not authenticated
            if '/login/index.php' in response.url.path:
                logger.warning("Session verification failed - redirected to login")
                self.is_authenticated = False
                return False
            
            if response.status_code != 200:
                logger.warning(f"Session verification returned {response.status_code}")
                return False
            
            logger.debug("Session verification successful")
            return True
            
        except Exception as e:
            logger.error(f"Error verifying authentication: {e}")
            return False


class AuthenticationManager:
    """
    Manages authentication for vulnerability scanning.
    
    Handles:
    - Creating authenticated sessions for Moodle
    - Extracting and managing login tokens
    - Session validation and refresh
    """
    
    def __init__(self, moodle_url: str, timeout: float = 10.0):
        """
        Initialize authentication manager.
        
        Args:
            moodle_url: Base URL of Moodle installation
            timeout: Request timeout in seconds
        """
        self.moodle_url = moodle_url
        self.timeout = timeout
        self.authenticated_session: Optional[MoodleSession] = None
        self.last_auth_user: Optional[str] = None
    
    async def get_authenticated_client(
        self,
        username: str,
        password: str,
        force_new: bool = False
    ) -> Optional[MoodleSession]:
        """
        Get an authenticated HTTP client for Moodle.
        
        Args:
            username: Moodle username
            password: Moodle password
            force_new: Force creation of new session even if one exists
            
        Returns:
            Authenticated MoodleSession or None if authentication fails
        """
        try:
            # Reuse existing session if authenticated and same user
            if (not force_new and 
                self.authenticated_session and 
                self.last_auth_user == username):
                
                if await self.authenticated_session.verify_authentication():
                    logger.debug(f"Reusing existing authenticated session for {username}")
                    return self.authenticated_session
                else:
                    logger.warning("Existing session is no longer valid, creating new one")
                    await self.authenticated_session.aclose()
            
            # Create new authenticated session
            logger.info(f"Creating new authenticated session for {username}")
            
            session = MoodleSession(
                self.moodle_url,
                timeout=self.timeout,
                follow_redirects=True,
                verify=False  # Disable SSL verification for testing
            )
            
            # Attempt login
            if not await session.login(username, password):
                await session.aclose()
                logger.error(f"Failed to authenticate {username}")
                return None
            
            # Close old session if exists
            if self.authenticated_session:
                await self.authenticated_session.aclose()
            
            # Store new session
            self.authenticated_session = session
            self.last_auth_user = username
            
            logger.info(f"Successfully created authenticated session for {username}")
            return session
            
        except Exception as e:
            logger.error(f"Error creating authenticated client: {e}")
            return None
    
    async def get_unauthenticated_client(self) -> httpx.AsyncClient:
        """
        Get an unauthenticated HTTP client (for comparison tests).
        
        Returns:
            Unauthenticated httpx.AsyncClient
        """
        return httpx.AsyncClient(
            timeout=self.timeout,
            verify=False,
            follow_redirects=True
        )
    
    async def cleanup(self):
        """Close and cleanup all sessions."""
        if self.authenticated_session:
            await self.authenticated_session.aclose()
            self.authenticated_session = None
            self.last_auth_user = None
        logger.debug("Authentication manager cleaned up")
    
    def __del__(self):
        """Ensure cleanup on deletion."""
        if self.authenticated_session:
            try:
                asyncio.get_event_loop().run_until_complete(self.cleanup())
            except:
                pass


# Singleton instance for global use
_auth_manager: Optional[AuthenticationManager] = None


def get_auth_manager(moodle_url: str = None) -> AuthenticationManager:
    """Get or create global authentication manager instance."""
    global _auth_manager
    
    if _auth_manager is None:
        if moodle_url is None:
            moodle_url = "http://localhost:8000"
        _auth_manager = AuthenticationManager(moodle_url)
    
    return _auth_manager


async def cleanup_auth_manager():
    """Cleanup global authentication manager."""
    global _auth_manager
    if _auth_manager:
        await _auth_manager.cleanup()
        _auth_manager = None
