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
    )

    # Production logging
    LOG_LEVEL = "WARNING"

    # Security settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"

    # CSRF protection enabled
    WTF_CSRF_ENABLED = True

    @staticmethod
    def init_app(app):
        """Initialize production-specific settings."""
        Config.init_app(app)

        # Log to syslog in production
        import logging
        from logging.handlers import SysLogHandler

        syslog_handler = SysLogHandler()
        syslog_handler.setLevel(logging.WARNING)
        app.logger.addHandler(syslog_handler)

        # Email errors to administrators
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
