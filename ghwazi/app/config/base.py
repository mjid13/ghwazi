"""
Base configuration settings for the Flask application.
"""

import os

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Base configuration class."""

    # Flask settings
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-secret-key-change-in-production"

    # Database settings
    SQLALCHEMY_DATABASE_URI = (
        os.environ.get("DATABASE_URL") or "sqlite:///transactions.db"
    ).replace(
    "postgres://", "postgresql://"
)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Email settings
    EMAIL_HOST = os.environ.get("EMAIL_HOST", "imap.gmail.com")
    EMAIL_PORT = int(os.environ.get("EMAIL_PORT", 993))
    EMAIL_USERNAME = os.environ.get("EMAIL_USERNAME", "")
    EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD", "")
    EMAIL_USE_SSL = os.environ.get("EMAIL_USE_SSL", "True").lower() in (
        "true",
        "1",
        "t",
    )

    # Bank email filter settings
    BANK_EMAIL_ADDRESSES = os.environ.get(
        "BANK_EMAIL_ADDRESSES", "bankmuscat@bankmuscat.com"
    ).split(",")
    BANK_EMAIL_SUBJECTS = os.environ.get(
        "BANK_EMAIL_SUBJECTS", "transaction,alert,notification"
    ).split(",")

    # Application settings
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    FETCH_INTERVAL = int(os.environ.get("FETCH_INTERVAL", 3600))  # Default: 1 hour

    # File upload settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "uploads")

    # Session settings
    # Permanent session absolute lifetime (in seconds). Can be overridden via env.
    PERMANENT_SESSION_LIFETIME = int(os.environ.get("PERMANENT_SESSION_LIFETIME", 3600))  # default: 1 hour
    # Idle timeout (seconds) - user will be logged out after this period of inactivity
    SESSION_IDLE_TIMEOUT = int(os.environ.get("SESSION_IDLE_TIMEOUT", 1800))  # default: 30 minutes
    # Secure cookie flags (override via env if needed)
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "False").lower() in ("true", "1", "t")

    # Pagination
    POSTS_PER_PAGE = int(os.environ.get("POSTS_PER_PAGE", 25))

    # Google OAuth settings
    GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
    GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
    GOOGLE_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI")
    
    # OAuth security settings
    OAUTH_CREDENTIAL_SECRETS = {
        'google': {
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
        }
    }

    @staticmethod
    def init_app(app):
        """Initialize application with this configuration."""
        pass
