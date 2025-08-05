"""
Testing configuration settings.
"""

import os

from .base import Config


class TestingConfig(Config):
    """Testing configuration."""

    DEBUG = False
    TESTING = True

    # Use in-memory SQLite database for testing
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"

    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False

    # Disable email sending during tests
    MAIL_SUPPRESS_SEND = True

    # Testing logging
    LOG_LEVEL = "DEBUG"

    # Faster password hashing for tests
    BCRYPT_LOG_ROUNDS = 4

    # Disable rate limiting for tests
    RATELIMIT_ENABLED = False

    @staticmethod
    def init_app(app):
        """Initialize testing-specific settings."""
        Config.init_app(app)

        # Suppress logging during tests
        import logging

        logging.disable(logging.CRITICAL)
