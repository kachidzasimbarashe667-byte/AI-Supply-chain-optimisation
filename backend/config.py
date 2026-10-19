"""Central configuration. Everything sensitive comes from environment variables."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    DATABASE_URL = os.environ.get("LEENGATE_DATABASE_URL") or f"sqlite:///{BASE_DIR / 'instance' / 'leengate.db'}"
    COOKIE_NAME = "leengate_session"
    COOKIE_SECURE = os.environ.get("LEENGATE_COOKIE_SECURE", "0") == "1"
    SESSION_ABSOLUTE_HOURS = 8          # hard limit, then sign in again
    SESSION_IDLE_MINUTES = 480          # signed out only after 8 hours of inactivity (was 30 min)
    MAX_FAILED_LOGINS = 5               # then the account is locked
    LOCKOUT_MINUTES = 15
    RATE_LIMIT_AUTH = (30, 60)          # 30 sign-in requests per 60 s per IP
    MAX_CONTENT_LENGTH = 64 * 1024      # reject request bodies over 64 KB
    SEED_ACCOUNTS = os.environ.get("LEENGATE_SEED_ACCOUNTS", "1") == "1"
    SEED_PASSWORD = os.environ.get("LEENGATE_SEED_PASSWORD", "12345simba")           # every account except admin
    ADMIN_PASSWORD = os.environ.get("LEENGATE_ADMIN_PASSWORD", "nyasimba")  # IT / AI Management (admin)
    FRONTEND_DIR = BASE_DIR / "frontend"
    TESTING = False
