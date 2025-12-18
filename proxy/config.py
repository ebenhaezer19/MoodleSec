"""
Configuration constants for the Moodle proxy service.
"""

# Target Moodle instance base URL
# MOODLE_URL: str = "http://localhost:8998"
MOODLE_URL: str = "http://localhost:9000"

# Port for the proxy service to listen on
LISTEN_PORT: int = 8999

# Directory for storing log files
LOG_DIR: str = "logs"

# Maximum number of log entries to return
MAX_LOG_ENTRIES: int = 100

# Slack Integration (Optional - for notifications)
SLACK_WEBHOOK_URL: str = ""  # Add your Slack webhook URL here
SLACK_ENABLED: bool = False  # Set to True to enable Slack notifications
