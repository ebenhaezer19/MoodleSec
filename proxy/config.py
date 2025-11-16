"""
Configuration constants for the Moodle proxy service.
"""

# Target Moodle instance base URL
MOODLE_URL: str = "http://localhost:8080"

# Port for the proxy service to listen on
LISTEN_PORT: int = 8000

# Directory for storing log files
LOG_DIR: str = "logs"

# Maximum number of log entries to return
MAX_LOG_ENTRIES: int = 100
