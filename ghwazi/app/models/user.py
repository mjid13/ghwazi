import enum
import logging
import random
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import (Boolean, Column, DateTime, Enum, Float, ForeignKey,
                        Integer, String, Text, UniqueConstraint)
from sqlalchemy.orm import Session, relationship
from werkzeug.security import check_password_hash, generate_password_hash

from .database import Base

logger = logging.getLogger(__name__)


class User(Base):
    """User model representing a user profile."""

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(200), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    accounts = relationship("Account", back_populates="user")
    email_configs = relationship("EmailConfiguration", back_populates="user")

    def set_password(self, password):
        """Set password hash."""
        try:
            logger.info(f"Setting password hash for user: {self.username}")
            if not password:
                logger.error("Password is empty or None")
                raise ValueError("Password cannot be empty")

            # Check if werkzeug.security is properly imported
            if not hasattr(generate_password_hash, "__call__"):
                logger.error("generate_password_hash is not callable")
                raise ImportError("generate_password_hash is not properly imported")

            # Generate password hash
            password_hash = generate_password_hash(password)
            logger.info(
                f"Password hash generated successfully: {password_hash[:10]}..."
            )

            # Set password hash
            self.password_hash = password_hash
            logger.info("Password hash set successfully")
        except Exception as e:
            logger.error(f"Error in set_password: {str(e)}")
            import traceback

            logger.error(f"Traceback: {traceback.format_exc()}")
            raise

    def check_password(self, password):
        """Check password against hash."""
        try:
            logger.info(f"Checking password for user: {self.username}")
            if not password:
                logger.error("Password is empty or None")
                return False

            if not self.password_hash:
                logger.error("Password hash is empty or None")
                return False

            # Check if werkzeug.security is properly imported
            if not hasattr(check_password_hash, "__call__"):
                logger.error("check_password_hash is not callable")
                raise ImportError("check_password_hash is not properly imported")

            # Check password
            result = check_password_hash(self.password_hash, password)
            logger.info(f"Password check result: {result}")
            return result
        except Exception as e:
            logger.error(f"Error in check_password: {str(e)}")
            import traceback

            logger.error(f"Traceback: {traceback.format_exc()}")
            return False
