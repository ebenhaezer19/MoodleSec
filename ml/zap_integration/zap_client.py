import logging
import time
import re
from typing import Dict, List, Optional, Any

import requests


class ZAPConnectionError(Exception):
    """Raised when connection to ZAP API fails after retries."""


class ZAPTimeoutError(Exception):
    """Raised when a request to ZAP times out."""


class ZAPConfigError(Exception):
    """Raised when invalid configuration is provided to ZAPClient."""


class ZAPClient:
    """Lightweight OWASP ZAP API client with retry/backoff and logging.

    Args:
        host: ZAP host (default: "localhost").
        port: ZAP HTTP API port (default: 8080).
        api_key: Optional API key for ZAP.

    Attributes:
        base_url: Full base URL for ZAP API (http://host:port)
        session: requests.Session instance for connection pooling
        logger: logging.Logger instance
        retry_config: Dict with keys: base_delay, multiplier, max_retries
        timeout: default per-request timeout (seconds)
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 8080,
        api_key: str = "1qlbij76v3j9c6ail8d0locm24",
        timeout: int = 30,
    ) -> None:
        self.logger = logging.getLogger("ZAPClient")
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
        )
        if not self.logger.handlers:
            self.logger.addHandler(handler)
        self.logger.setLevel(logging.DEBUG)

        # Validate parameters
        if not isinstance(host, str) or not host:
            raise ZAPConfigError("host must be a non-empty string")
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ZAPConfigError("port must be an integer between 1 and 65535")
        if api_key and not re.match(r"^[A-Za-z0-9_-]{8,128}$", api_key):
            # allow empty api_key, otherwise simple validation
            raise ZAPConfigError("api_key appears invalid (must be alphanumeric/_/-)")

        self.base_url = f"http://{host}:{port}"
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/json"})
        self.retry_config = {"base_delay": 1, "multiplier": 2, "max_retries": 3}
        self.timeout = timeout
        self.api_key = api_key

        # Validate connection during initialization
        try:
            self._validate_connection()
            self.logger.info("ZAPClient initialized and connection validated")
        except Exception:
            self.logger.error("Failed to validate connection to ZAP during init")
            raise

    def set_timeout(self, seconds: int) -> None:
        """Set per-request timeout in seconds.

        Args:
            seconds: Timeout in seconds (positive int)
        """
        if not isinstance(seconds, int) or seconds <= 0:
            raise ZAPConfigError("timeout must be a positive integer")
        self.timeout = seconds
        self.logger.debug("Timeout set to %s seconds", seconds)

    def _validate_connection(self) -> Dict[str, Any]:
        """Validate connection by requesting ZAP version.

        Returns:
            Parsed response from `get_version()`.

        Raises:
            ZAPConnectionError: if validation fails after retries
        """
        try:
            version = self.get_version()
            self.logger.debug("ZAP version: %s", version)
            return version
        except Exception as exc:
            raise ZAPConnectionError(f"ZAP validation failed: {exc}") from exc

    def get_status(self) -> Dict[str, str]:
        """Return connection status and ZAP version.

        Returns:
            Dict with keys `status` and `version`.
        """
        try:
            v = self.get_version()
            return {"status": "connected", "version": v.get("version", "unknown")}
        except Exception:
            return {"status": "disconnected", "version": "unknown"}

    def get_version(self) -> Dict[str, Any]:
        """Get ZAP version.

        Returns:
            Dict parsed from ZAP API version endpoint.
        """
        # Standard ZAP API endpoint for version: /JSON/core/view/version
        resp = self.request("GET", "core/view/version", retry_count=2)
        return resp

    def request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        retry_count: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Make HTTP request to ZAP API with automatic retry.

        Args:
            method: HTTP method (GET, POST, etc)
            endpoint: ZAP API endpoint (e.g., "core/other/version" or "core/action/newSession")
            params: Query parameters
            data: Request body (JSON-serializable)
            retry_count: Optional override for maximum retries

        Returns:
            Parsed JSON response from ZAP API, or a dict with 'text' if JSON parsing fails.

        Raises:
            ZAPConnectionError: If connection fails after retries
            ZAPTimeoutError: If request times out
        """
        method = method.upper()
        if retry_count is None:
            retry_count = self.retry_config["max_retries"]

        url = endpoint
        # If user passed e.g. 'core/view/version' or 'core/action/newSession', build path
        if not endpoint.startswith("http"):
            url = f"{self.base_url}/JSON/{endpoint.lstrip('/') }"

        # attach api key automatically if provided
        params = dict(params) if params else {}
        if self.api_key:
            params.setdefault("apikey", self.api_key)

        last_exc = None
        base_delay = self.retry_config["base_delay"]
        multiplier = self.retry_config["multiplier"]

        for attempt in range(1, retry_count + 1):
            try:
                self.logger.debug(
                    "Request attempt %s: %s %s params=%s data=%s",
                    attempt,
                    method,
                    url,
                    params,
                    None if data is None else "<payload>",
                )

                resp = self.session.request(
                    method, url, params=params if method == "GET" else None,
                    json=data if method in ("POST", "PUT", "PATCH") else None,
                    timeout=self.timeout,
                )

                self.logger.debug(
                    "Response status: %s for %s %s", resp.status_code, method, url
                )

                # treat 5xx as retryable
                if 500 <= resp.status_code < 600 and attempt < retry_count:
                    last_exc = ZAPConnectionError(
                        f"Server error {resp.status_code} on attempt {attempt}"
                    )
                    delay = base_delay * (multiplier ** (attempt - 1))
                    self.logger.debug("Retrying after %ss due to server error", delay)
                    time.sleep(delay)
                    continue

                # try parse JSON, fallback to text
                try:
                    return resp.json()
                except ValueError:
                    self.logger.debug("JSON parse failed, returning text snippet")
                    return {"text": resp.text, "status_code": resp.status_code}

            except requests.Timeout as exc:
                last_exc = exc
                self.logger.error("Request timed out on attempt %s: %s", attempt, exc)
                if attempt < retry_count:
                    delay = base_delay * (multiplier ** (attempt - 1))
                    time.sleep(delay)
                    continue
                raise ZAPTimeoutError(f"Request timed out after {attempt} attempts") from exc
            except requests.RequestException as exc:
                last_exc = exc
                self.logger.error("Request exception on attempt %s: %s", attempt, exc)
                if attempt < retry_count:
                    delay = base_delay * (multiplier ** (attempt - 1))
                    time.sleep(delay)
                    continue
                raise ZAPConnectionError(
                    f"Failed to connect to ZAP after {attempt} attempts: {exc}"
                ) from exc

        # if we exit loop with last_exc
        raise ZAPConnectionError(f"Exhausted retries: {last_exc}")

    # ------------------ Basic API convenience methods ------------------
    def new_session(self, session_name: str) -> Dict[str, Any]:
        """Create new ZAP session.

        Args:
            session_name: Name for the new session

        Returns:
            Parsed response from ZAP API
        """
        self.logger.info("Creating new session: %s", session_name)
        return self.request("GET", f"core/action/newSession/?name={session_name}")

    def save_session(self, session_name: str) -> Dict[str, Any]:
        """Save current ZAP session to disk with given name.

        Args:
            session_name: Filename to save session as
        """
        self.logger.info("Saving session as: %s", session_name)
        return self.request("GET", f"core/action/saveSession/?name={session_name}")

    def load_session(self, session_name: str) -> Dict[str, Any]:
        """Load an existing ZAP session file.

        Args:
            session_name: Filename of the session to load
        """
        self.logger.info("Loading session: %s", session_name)
        return self.request("GET", f"core/action/loadSession/?name={session_name}")

    def list_sessions(self) -> Dict[str, Any]:
        """List session information (metadata) from ZAP.

        Returns:
            Parsed response with sessions list
        """
        self.logger.info("Listing sessions")
        return self.request("GET", "core/view/sessions/")


__all__ = ["ZAPClient", "ZAPConnectionError", "ZAPTimeoutError", "ZAPConfigError"]
