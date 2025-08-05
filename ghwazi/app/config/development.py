"""
Development configuration settings.
"""

import os

from .base import Config


class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = True
    TESTING = False

    # Development database (can be overridden by environment variable)
    SQLALCHEMY_DATABASE_URI = (
        os.environ.get("DEV_DATABASE_URL") or "sqlite:///dev_transactions.db"
    )

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
