"""
Configuration constants for the Moodle proxy service.

Environment variables (set in ~/.bashrc or .env):
  MOODLE_BASE_URL  — Moodle instance URL (default: http://localhost:8998)
                     krisopras: http://localhost:8998
                     natha    : http://localhost
"""
import os

# Target Moodle instance base URL
# Each developer sets MOODLE_BASE_URL in their shell/env — no hardcoded conflict.
MOODLE_URL: str = os.environ.get("MOODLE_BASE_URL", "http://localhost:8998").rstrip("/")

# Port for the proxy service to listen on
LISTEN_PORT: int = int(os.environ.get("PROXY_LISTEN_PORT", "8999"))

# Directory for storing log files
LOG_DIR: str = "logs"

# Maximum number of log entries to return
MAX_LOG_ENTRIES: int = 100

# Slack Integration (Optional - for notifications)
SLACK_WEBHOOK_URL: str = ""  # Add your Slack webhook URL here
SLACK_ENABLED: bool = False  # Set to True to enable Slack notifications

# Anomaly Detector Runtime Controls
ANOMALY_DETECTION_ENABLED: bool = True
ANOMALY_LOOKBACK_SECONDS: int = 60
ANOMALY_MIN_SCORE_TO_LOG: float = 0.5

# Optional hard block mode (default off for safer rollout)
ANOMALY_BLOCK_ON_DETECTION: bool = False
ANOMALY_BLOCK_THRESHOLD: float = 0.95
