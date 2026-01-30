"""
Development configuration settings.
"""

import os

from .base import Config


class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = True
    TESTING = False
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")
    SECURITY_HEADERS = {
        'FRAME_OPTIONS': 'SAMEORIGIN',
    }
    CSP_DOMAINS = {
        'default_src': ["'self'"],
        'script_src': [
            "'self'",
            'https://cdn.jsdelivr.net',
            'https://code.jquery.com',
            'https://cdn.datatables.net',
            'http://localhost:5000',
            'http://localhost:3000',
            'ws://localhost:3000',
            'ws://localhost:5000',
        ],
        'style_src': [
            "'self'",
            'https://cdn.jsdelivr.net',
            'https://fonts.googleapis.com',
            'https://cdn.datatables.net',
        ],
        'img_src': [
            "'self'",
            'data:',
            'https:',
        ],
        'font_src': [
            "'self'",
            'https://fonts.gstatic.com',
        ],
        'connect_src': [
            "'self'",
            'http://localhost:5000',
            'http://localhost:3000',
            'ws://localhost:3000',
            'ws://localhost:5000',
        ],
    }
        # Development database (can be overridden by environment variable)
    SQLALCHEMY_DATABASE_URI = (
        os.environ.get("DEV_DATABASE_URL") or "sqlite:///dev_transactions.db"
    ).replace(
    "postgres://", "postgresql://"
)

    # Google OAuth client ID and secret (can be overridden by environment variable)
    GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
    GOOGLE_REDIRECT_URI = "http://localhost:5000/oauth/google/callback"

    # Development logging
    LOG_LEVEL = "DEBUG"

    # Disable CSRF for development (optional)
    WTF_CSRF_ENABLED = False

    @staticmethod
    def init_app(app):
        """Initialize development-specific settings."""
        Config.init_app(app)

        # Enable SQL query logging in development
        import logging

        logging.basicConfig()
        logging.getLogger("sqlalchemy.engine").setLevel(logging.INFO)
