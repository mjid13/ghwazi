"""
Configuration settings for the Bank Email Parser & Account Tracker.

This module loads configuration from environment variables or a .env file.
"""

import os

from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Email settings
EMAIL_HOST = os.getenv("EMAIL_HOST", "imap.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 993))
EMAIL_USERNAME = os.getenv("EMAIL_USERNAME", "")
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
EMAIL_USE_SSL = os.getenv("EMAIL_USE_SSL", "True").lower() in ("true", "1", "t")

# Bank email filter settings
BANK_EMAIL_ADDRESSES = os.getenv(
    "BANK_EMAIL_ADDRESSES", "bankmuscat@bankmuscat.com"
).split(",")
BANK_EMAIL_SUBJECTS = os.getenv(
    "BANK_EMAIL_SUBJECTS", "transaction,alert,notification"
).split(",")

# Database settings
# Replace 'postgres://' with 'postgresql://' to ensure compatibility with PostgreSQL libraries like SQLAlchemy and other tools.
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///transactions.db").replace(
    "postgres://", "postgresql://"
)

# Application settings
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
FETCH_INTERVAL = int(os.getenv("FETCH_INTERVAL", 3600))  # Default: 1 hour
