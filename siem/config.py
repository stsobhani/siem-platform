"""
Centralized configuration for the SIEM platform.
All values can be overridden via environment variables (see .env.example).
"""
import os


class Config:
    # --- PostgreSQL ---
    PG_HOST = os.getenv("PG_HOST", "localhost")
    PG_PORT = os.getenv("PG_PORT", "5432")
    PG_DB = os.getenv("PG_DB", "siem")
    PG_USER = os.getenv("PG_USER", "siem_user")
    PG_PASSWORD = os.getenv("PG_PASSWORD", "siem_password")

    @property
    def sqlalchemy_uri(self) -> str:
        return (
            f"postgresql+psycopg2://{self.PG_USER}:{self.PG_PASSWORD}"
            f"@{self.PG_HOST}:{self.PG_PORT}/{self.PG_DB}"
        )

    # --- Detection thresholds (tunable without touching rule code) ---
    BRUTE_FORCE_ATTEMPT_THRESHOLD = int(os.getenv("BRUTE_FORCE_ATTEMPT_THRESHOLD", 5))
    BRUTE_FORCE_WINDOW_MINUTES = int(os.getenv("BRUTE_FORCE_WINDOW_MINUTES", 5))

    IMPOSSIBLE_TRAVEL_MAX_KMH = int(os.getenv("IMPOSSIBLE_TRAVEL_MAX_KMH", 900))  # ~commercial flight speed

    UNUSUAL_HOUR_START = int(os.getenv("UNUSUAL_HOUR_START", 6))   # 06:00
    UNUSUAL_HOUR_END = int(os.getenv("UNUSUAL_HOUR_END", 22))      # 22:00

    MULTI_FAIL_THRESHOLD = int(os.getenv("MULTI_FAIL_THRESHOLD", 10))
    MULTI_FAIL_WINDOW_MINUTES = int(os.getenv("MULTI_FAIL_WINDOW_MINUTES", 60))

    # --- ML ---
    ISOLATION_FOREST_CONTAMINATION = float(os.getenv("ISOLATION_FOREST_CONTAMINATION", 0.05))

    # --- Splunk HEC ---
    SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "https://localhost:8088/services/collector")
    SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
    SPLUNK_VERIFY_SSL = os.getenv("SPLUNK_VERIFY_SSL", "false").lower() == "true"
    SPLUNK_INDEX = os.getenv("SPLUNK_INDEX", "siem")


config = Config()
