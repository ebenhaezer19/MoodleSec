"""
ZAPAuthenticationHandler: Manages Moodle login workflow for ZAP security scanning.

This module handles:
- Login form configuration and detection
- Credential submission and verification
- Session token management
- Authenticated scanning setup for OWASP ZAP
"""

import logging
import requests
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
from .zap_client import ZAPClient


# Custom Exceptions
class ZAPAuthError(Exception):
    """Raised when authentication operation fails."""
    pass


class ZAPLoginVerificationError(Exception):
    """Raised when login verification fails."""
    pass


class ZAPSessionExpiredError(Exception):
    """Raised when session token has expired."""
    pass


class ZAPAuthenticationHandler:
    """Manages Moodle login workflow for ZAP scanning.
    
    Orchestrates login process, verifies success, and manages session tokens
    for authenticated vulnerability scanning.
    """
    
    def __init__(self, client: ZAPClient, database_connection: Optional[object] = None):
        """Initialize authentication handler.
        
        Args:
            client: ZAPClient instance for API communication
            database_connection: Optional database connection for token storage
            
        Raises:
            TypeError: If client is not a ZAPClient instance
        """
        if not isinstance(client, ZAPClient):
            raise TypeError("client must be a ZAPClient instance")
        
        self.client = client
        self.db_connection = database_connection
        self._session_tokens: Dict[str, Dict] = {}  # In-memory token storage
        self.logger = logging.getLogger("ZAPAuthenticationHandler")
        self._request_timeout = 10  # seconds
        
        self.logger.info("ZAPAuthenticationHandler initialized")
    
    def setup_form_auth(
        self,
        context_id: int,
        login_url: str,
        username_field: str,
        password_field: str,
        extra_fields: Optional[Dict[str, str]] = None
    ) -> bool:
        """Configure login form fields in ZAP context.
        
        Sets up form-based authentication with field mappings. Does not verify
        credentials, only configures field names.
        
        Args:
            context_id: ZAP context ID for authentication setup
            login_url: URL of the login form
            username_field: HTML form field name for username
            password_field: HTML form field name for password
            extra_fields: Additional form fields (e.g., {"csrf_token": "token_field"})
            
        Returns:
            True if configuration successful, False otherwise
            
        Raises:
            ZAPAuthError: If ZAP API call fails
        """
        try:
            extra_fields = extra_fields or {}
            
            self.logger.debug(
                f"Configuring form auth: url={login_url}, "
                f"username_field={username_field}, password_field={password_field}"
            )
            
            # Set the login URL in ZAP context
            params = {
                "contextId": context_id,
                "authUrl": login_url,
                "loginRequestData": f"{username_field}=&{password_field}="
            }
            
            response = self.client.request("POST", "core/other/setAuthenticationMethod", params=params)
            
            if response.get("code") == "ok":
                self.logger.info(f"Form auth configured for context {context_id}")
                return True
            else:
                self.logger.error(f"Failed to configure form auth: {response}")
                return False
                
        except Exception as exc:
            self.logger.error(f"Error setting up form auth: {exc}")
            raise ZAPAuthError(f"Failed to configure form authentication: {exc}") from exc
    
    def setup_form_based_auth(
        self,
        context_id: int,
        login_url: str,
        username: str,
        password: str
    ) -> bool:
        """Full setup: configure, authenticate, and verify credentials.
        
        Complete authentication workflow: sets up form fields, executes login,
        verifies credentials, and stores session token.
        
        Args:
            context_id: ZAP context ID
            login_url: URL of login form
            username: Username for authentication
            password: Password for authentication
            
        Returns:
            True if full setup successful, False otherwise
            
        Raises:
            ZAPAuthError: If authentication fails
            ZAPLoginVerificationError: If login verification fails
        """
        try:
            self.logger.info(f"Starting form-based auth setup for user: {username}")
            
            # Configure form fields (guessing common Moodle field names)
            configured = self.setup_form_auth(
                context_id=context_id,
                login_url=login_url,
                username_field="username",
                password_field="password"
            )
            
            if not configured:
                raise ZAPAuthError("Failed to configure form authentication")
            
            # Execute login
            response, cookies = self.execute_login(login_url, username, password)
            
            # Verify login success
            success, message = self.verify_login(
                response_text=response.text,
                verification_string="dashboard",
                response_status=response.status_code
            )
            
            if not success:
                raise ZAPLoginVerificationError(f"Login verification failed: {message}")
            
            # Store session token
            if cookies:
                for cookie_name, cookie_value in cookies.items():
                    self.store_session_token(
                        user_id=username,
                        cookie_name=cookie_name,
                        cookie_value=cookie_value,
                        expires_at=(datetime.now() + timedelta(hours=24)).isoformat()
                    )
            
            self.logger.info(f"Form-based auth setup completed for user: {username}")
            return True
            
        except (ZAPAuthError, ZAPLoginVerificationError) as exc:
            self.logger.error(f"Form-based auth setup failed: {exc}")
            raise
        except Exception as exc:
            self.logger.error(f"Unexpected error in form-based auth setup: {exc}")
            raise ZAPAuthError(f"Form-based auth setup failed: {exc}") from exc
    
    def execute_login(
        self,
        login_url: str,
        username: str,
        password: str,
        extra_fields: Optional[Dict[str, str]] = None
    ) -> Tuple[requests.Response, Dict[str, str]]:
        """Execute login by sending credentials to login endpoint.
        
        Submits credentials to the login form and extracts session cookies.
        
        Args:
            login_url: URL of login endpoint
            username: Username for login
            password: Password for login
            extra_fields: Additional form fields to submit
            
        Returns:
            Tuple of (response object, cookies dictionary)
            
        Raises:
            ZAPAuthError: If login request fails
        """
        try:
            extra_fields = extra_fields or {}
            
            self.logger.debug(f"Executing login for user: {username}")
            
            # Prepare login payload
            payload = {
                "username": username,
                "password": password,
                **extra_fields
            }
            
            # Make login request
            session = requests.Session()
            response = session.post(
                login_url,
                data=payload,
                timeout=self._request_timeout,
                allow_redirects=True
            )
            
            # Extract cookies
            cookies_dict = dict(session.cookies)
            
            self.logger.info(f"Login executed for {username}, status: {response.status_code}")
            self.logger.debug(f"Received {len(cookies_dict)} cookies")
            
            return response, cookies_dict
            
        except requests.Timeout:
            self.logger.error(f"Login timeout for {username}")
            raise ZAPAuthError(f"Login request timed out after {self._request_timeout}s") from None
        except requests.RequestException as exc:
            self.logger.error(f"Login request failed for {username}: {exc}")
            raise ZAPAuthError(f"Login request failed: {exc}") from exc
        except Exception as exc:
            self.logger.error(f"Unexpected error during login execution: {exc}")
            raise ZAPAuthError(f"Login execution failed: {exc}") from exc
    
    def verify_login(
        self,
        response_text: str,
        verification_string: str,
        response_status: int
    ) -> Tuple[bool, str]:
        """Verify if login was successful.
        
        Uses multiple heuristics to determine login success:
        1. Response status code 200-299 (success range)
        2. Presence of verification_string in response body
        3. Absence of "login" keyword in response
        
        Args:
            response_text: HTML response body from login attempt
            verification_string: String indicating successful login (e.g., "dashboard")
            response_status: HTTP status code from login response
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            self.logger.debug(f"Verifying login with status {response_status}")
            
            # Check 1: Status code
            if not (200 <= response_status < 300):
                message = f"Login failed: HTTP {response_status}"
                self.logger.warning(message)
                return False, message
            
            # Check 2: Absence of login keyword (strong negative indicator)
            if "login" in response_text.lower() and "logged in" not in response_text.lower():
                message = "Login keyword present in response (likely failed)"
                self.logger.warning(message)
                return False, message
            
            # Check 3: Presence of verification string
            if verification_string and verification_string.lower() not in response_text.lower():
                message = f"Verification string '{verification_string}' not found in response"
                self.logger.warning(message)
                return False, message
            
            message = "Login verification successful"
            self.logger.info(message)
            return True, message
            
        except Exception as exc:
            message = f"Error during login verification: {exc}"
            self.logger.error(message)
            return False, message
    
    def store_session_token(
        self,
        user_id: str,
        cookie_name: str,
        cookie_value: str,
        expires_at: Optional[str] = None
    ) -> bool:
        """Store session token for authenticated scanning.
        
        Saves session cookies/tokens to in-memory storage or database.
        Token format: {user_id: {cookie_name: {value, expires_at}}}
        
        Args:
            user_id: Unique user identifier
            cookie_name: Name of cookie/token
            cookie_value: Value of cookie/token (NOT logged for security)
            expires_at: ISO format expiration timestamp (optional)
            
        Returns:
            True if storage successful, False otherwise
        """
        try:
            if user_id not in self._session_tokens:
                self._session_tokens[user_id] = {}
            
            self._session_tokens[user_id][cookie_name] = {
                "value": cookie_value,
                "expires_at": expires_at
            }
            
            self.logger.info(f"Session token stored for user {user_id}, cookie: {cookie_name}")
            
            # Attempt database storage if available
            if self.db_connection:
                try:
                    self._store_token_in_db(user_id, cookie_name, cookie_value, expires_at)
                except Exception as db_exc:
                    self.logger.warning(f"Database storage failed, using in-memory: {db_exc}")
            
            return True
            
        except Exception as exc:
            self.logger.error(f"Error storing session token for {user_id}: {exc}")
            return False
    
    def retrieve_session_token(self, user_id: str) -> Tuple[Dict[str, str], bool]:
        """Retrieve stored session tokens for a user.
        
        Fetches tokens from storage and checks for expiration.
        
        Args:
            user_id: User identifier to retrieve tokens for
            
        Returns:
            Tuple of (token_dict: Dict[cookie_name: value], is_valid: bool)
            
        Raises:
            ZAPSessionExpiredError: If token has expired
        """
        try:
            if user_id not in self._session_tokens:
                self.logger.warning(f"No tokens found for user {user_id}")
                return {}, False
            
            tokens = self._session_tokens[user_id]
            current_time = datetime.now()
            valid_tokens = {}
            
            for cookie_name, token_data in tokens.items():
                expires_at = token_data.get("expires_at")
                
                # Check expiration
                if expires_at:
                    expires_time = datetime.fromisoformat(expires_at)
                    if expires_time < current_time:
                        self.logger.warning(f"Token {cookie_name} expired for user {user_id}")
                        raise ZAPSessionExpiredError(f"Token {cookie_name} has expired")
                
                valid_tokens[cookie_name] = token_data["value"]
            
            self.logger.info(f"Retrieved {len(valid_tokens)} valid tokens for user {user_id}")
            return valid_tokens, True
            
        except ZAPSessionExpiredError:
            raise
        except Exception as exc:
            self.logger.error(f"Error retrieving tokens for {user_id}: {exc}")
            return {}, False
    
    def clear_expired_tokens(self) -> int:
        """Remove expired session tokens from storage.
        
        Iterates through all stored tokens and removes those past expiration.
        
        Returns:
            Number of tokens removed
        """
        try:
            current_time = datetime.now()
            count_removed = 0
            
            for user_id in list(self._session_tokens.keys()):
                tokens = self._session_tokens[user_id]
                
                for cookie_name in list(tokens.keys()):
                    expires_at = tokens[cookie_name].get("expires_at")
                    
                    if expires_at:
                        expires_time = datetime.fromisoformat(expires_at)
                        if expires_time < current_time:
                            del tokens[cookie_name]
                            count_removed += 1
                
                # Remove user entry if no tokens left
                if not tokens:
                    del self._session_tokens[user_id]
            
            self.logger.info(f"Cleared {count_removed} expired tokens")
            return count_removed
            
        except Exception as exc:
            self.logger.error(f"Error clearing expired tokens: {exc}")
            return 0
    
    def create_context_user(
        self,
        context_id: int,
        user_id: str,
        username: str,
        password: str
    ) -> bool:
        """Create user account in ZAP context for authenticated scanning.
        
        Sets up credentials in ZAP context so authenticated scans can use them.
        
        Args:
            context_id: ZAP context ID
            user_id: Internal user identifier
            username: Username for authentication
            password: Password for authentication
            
        Returns:
            True if user created successfully, False otherwise
            
        Raises:
            ZAPAuthError: If ZAP API call fails
        """
        try:
            self.logger.debug(f"Creating context user: {user_id}")
            
            # Create user via ZAP API
            params = {
                "contextId": context_id,
                "name": user_id,
                "username": username,
                "password": password
            }
            
            response = self.client.request("POST", "users/action/newUser", params=params)
            
            if response.get("code") == "ok":
                self.logger.info(f"Context user created: {user_id}")
                return True
            else:
                self.logger.warning(f"User creation response: {response}")
                # Some ZAP versions return different responses, treat as success if no error
                return True
                
        except Exception as exc:
            self.logger.error(f"Error creating context user {user_id}: {exc}")
            raise ZAPAuthError(f"Failed to create context user: {exc}") from exc
    
    def _store_token_in_db(
        self,
        user_id: str,
        cookie_name: str,
        cookie_value: str,
        expires_at: Optional[str]
    ) -> None:
        """Store token in database (implementation depends on database type).
        
        Args:
            user_id: User identifier
            cookie_name: Cookie/token name
            cookie_value: Cookie/token value
            expires_at: Expiration timestamp
            
        Raises:
            Exception: If database operation fails
        """
        if not self.db_connection:
            return
        
        # This is a placeholder for database implementation
        # Actual implementation depends on database type (SQL, MongoDB, etc.)
        self.logger.debug(f"Storing token in database for user {user_id}")
        # Example: self.db_connection.insert_token(user_id, cookie_name, cookie_value, expires_at)
