"""
Production configuration settings.
"""

import os

from .base import Config


class ProductionConfig(Config):
    """Production configuration."""

    DEBUG = False
    TESTING = False

    # Production database (must be set via environment variable)
    SQLALCHEMY_DATABASE_URI = (
        os.environ.get("DATABASE_URL")
        or "postgresql://user:password@localhost/production_db"
    ).replace(
        "postgres://", "postgresql://"
    )
    DATABASE_URL = os.getenv("DATABASE_URL", "").replace("postgres://", "postgresql://")

    # Production logging
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "WARNING")

    # File uploads on Heroku's ephemeral filesystem
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "/tmp/uploads")

    # Redis-backed server-side sessions
    REDIS_URL = os.environ.get("REDIS_URL")
    SESSION_TYPE = "redis" if REDIS_URL else os.environ.get("SESSION_TYPE", "filesystem")
    SESSION_USE_SIGNER = True
    SESSION_PERMANENT = True

    # Enhanced security settings for production
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Strict"  # Stricter for production
    
    # Shorter timeouts for production
    PERMANENT_SESSION_LIFETIME = int(os.environ.get("PERMANENT_SESSION_LIFETIME", 1800))  # 30 minutes
    SESSION_IDLE_TIMEOUT = int(os.environ.get("SESSION_IDLE_TIMEOUT", 900))  # 15 minutes
    SESSION_ROTATION_INTERVAL = int(os.environ.get("SESSION_ROTATION_INTERVAL", 600))  # 10 minutes
    MAX_SESSIONS_PER_USER = int(os.environ.get("MAX_SESSIONS_PER_USER", 2))  # Fewer concurrent sessions

    GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
    GOOGLE_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI")

    # CSRF protection enabled
    WTF_CSRF_ENABLED = True

    @staticmethod
    def init_app(app):
        """Initialize production-specific settings."""
        Config.init_app(app)

        # Configure logging to stdout for Heroku
        import logging
        import sys
        for h in list(app.logger.handlers):
            app.logger.removeHandler(h)
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setLevel(getattr(logging, app.config.get("LOG_LEVEL", "WARNING")))
        formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]")
        stream_handler.setFormatter(formatter)
        app.logger.addHandler(stream_handler)
        app.logger.setLevel(getattr(logging, app.config.get("LOG_LEVEL", "WARNING")))

        # Optionally email errors to administrators
        if app.config.get("MAIL_SERVER"):
            from logging.handlers import SMTPHandler

            auth = None
            if app.config.get("MAIL_USERNAME") or app.config.get("MAIL_PASSWORD"):
                auth = (
                    app.config.get("MAIL_USERNAME"),
                    app.config.get("MAIL_PASSWORD"),
                )
            secure = None
            if app.config.get("MAIL_USE_TLS"):
                secure = ()
            mail_handler = SMTPHandler(
                mailhost=(app.config.get("MAIL_SERVER"), app.config.get("MAIL_PORT")),
                fromaddr=app.config.get("MAIL_DEFAULT_SENDER"),
                toaddrs=app.config.get("ADMINS", []),
                subject="Application Error",
                credentials=auth,
                secure=secure,
            )
            mail_handler.setLevel(logging.ERROR)
            app.logger.addHandler(mail_handler)
