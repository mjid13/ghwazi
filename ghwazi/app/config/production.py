"""
Production configuration settings.
"""

import os

from .base import Config


class ProductionConfig(Config):
    """Production configuration."""

    DEBUG = False
    TESTING = False

    SECURITY_HEADERS = {
        'FRAME_OPTIONS': 'SAMEORIGIN',
    }

    # Clean CSP configuration that works with nonces
    CSP_DOMAINS = {
        'default_src': ["'self'"],
        'script_src': [
            "'self'",
            "https://cdn.jsdelivr.net",
            "https://code.jquery.com",
            "https://cdn.datatables.net",
        ],
        'style_src': [
            "'self'",
            "https://cdn.jsdelivr.net",
            "https://fonts.googleapis.com",
        ],
        'img_src': [
            "'self'",
            "data:",
            "https:",
        ],
        'font_src': [
            "'self'",
            "https://fonts.gstatic.com",
        ],
        'connect_src': [
            "'self'",
        ]
    }

    # Production database
    SQLALCHEMY_DATABASE_URI = (
        os.environ.get("DATABASE_URL")
        or "postgresql://user:password@localhost/production_db"
    ).replace("postgres://", "postgresql://")

    DATABASE_URL = os.getenv("DATABASE_URL", "").replace("postgres://", "postgresql://")

    # Production logging
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "WARNING")

    # File uploads on Heroku's ephemeral filesystem
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "/tmp/uploads")

    # Redis-backed server-side sessions
    REDIS_URL = os.environ.get("REDISCLOUD_URL") or os.environ.get("REDIS_URL")
    SESSION_TYPE = "redis" if REDIS_URL else "filesystem"
    SESSION_USE_SIGNER = True
    SESSION_PERMANENT = True

    # Enhanced security settings for production
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "None")

    # Session timeouts for production
    PERMANENT_SESSION_LIFETIME = int(os.environ.get("PERMANENT_SESSION_LIFETIME", 1800))  # 30 minutes
    SESSION_IDLE_TIMEOUT = int(os.environ.get("SESSION_IDLE_TIMEOUT", 900))  # 15 minutes

    # OAuth configuration
    GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
    GOOGLE_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI")
    GMAIL_FIRST_SYNC_DAYS = os.environ.get("GMAIL_FIRST_SYNC_DAYS", 180)
    GMAIL_SYNC_STUCK_MINUTES = int(os.environ.get("GMAIL_SYNC_STUCK_MINUTES", 15))
    GMAIL_SYNC_COOLDOWN_SECONDS = int(os.environ.get("GMAIL_SYNC_COOLDOWN_SECONDS", 60))
    # CSRF protection enabled
    WTF_CSRF_ENABLED = True

    @staticmethod
    def init_app(app):
        """Initialize production-specific settings."""
        Config.init_app(app)

        # Production logging is now handled in _configure_logging()
        # This method can be used for additional production-specific setup
        pass