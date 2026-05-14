"""
Configuration constants for the Moodle proxy service.
"""

# ── Demo Mode ──────────────────────────────────────────────────────────
# When True, the proxy detects attacks but NEVER blocks (monitoring-only).
# All ML detection, scoring, and logging remain fully active.
# Set to False for production enforcement (full blocking).
DEMO_MODE: bool = True

# ── SOC Interactive Mode ───────────────────────────────────────────────
# When True (requires DEMO_MODE=True), detected attacks are queued for
# admin review via /soc/alerts endpoints. Admins can BLOCK, ALLOW, or
# IGNORE specific threats. Future matching requests follow admin decisions.
SOC_MODE: bool = True

# Target Moodle instance base URL
MOODLE_URL: str = "http://localhost/"
# MOODLE_URL: str = "http://localhost:9000"
# MOODLE_URL: str = "https://sdecdtsepas2024.gnomio.com"

# Port for the proxy service to listen on
LISTEN_PORT: int = 8999

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
