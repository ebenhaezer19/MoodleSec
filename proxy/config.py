"""
Proxy configuration.
"""

# Monitor-only mode: detects but never blocks.
DEMO_MODE: bool = True

# Queue detected attacks for admin review (requires DEMO_MODE).
SOC_MODE: bool = True

# Dashboard access token (localhost always allowed).
SOC_ADMIN_TOKEN: str = "moodlesec2024"

# Moodle backend URL
MOODLE_URL: str = "http://localhost/"
# MOODLE_URL: str = "http://localhost:9000"
# MOODLE_URL: str = "https://sdecdtsepas2024.gnomio.com"

LISTEN_PORT: int = 8999

LOG_DIR: str = "logs"
MAX_LOG_ENTRIES: int = 100

# Slack (optional)
SLACK_WEBHOOK_URL: str = ""
SLACK_ENABLED: bool = False

# Anomaly detector
ANOMALY_DETECTION_ENABLED: bool = True
ANOMALY_LOOKBACK_SECONDS: int = 60
ANOMALY_MIN_SCORE_TO_LOG: float = 0.5

ANOMALY_BLOCK_ON_DETECTION: bool = False
ANOMALY_BLOCK_THRESHOLD: float = 0.95
