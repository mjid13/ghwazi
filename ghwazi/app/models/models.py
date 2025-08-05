"""
Database models for the Bank Email Parser & Account Tracker.
"""

import enum
import logging
from datetime import datetime

from sqlalchemy import (Boolean, Column, DateTime, Enum, Float, ForeignKey,
                        Integer, String, Text, UniqueConstraint)
from sqlalchemy.orm import relationship

from .database import Base

logger = logging.getLogger(__name__)


class EmailServiceProvider(Base):
    """Email service provider model for storing predefined email provider settings."""

    __tablename__ = "email_service_providers"

    id = Column(Integer, primary_key=True)
    provider_name = Column(
        String(100), nullable=False, unique=True
    )  # e.g., gmail, outlook
    host = Column(String(100), nullable=False)  # e.g., imap.gmail.com
    port = Column(Integer, nullable=False)  # e.g., 993
    use_ssl = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    email_configs = relationship(
        "EmailConfiguration", back_populates="service_provider"
    )


class EmailConfigBank(Base):
    """Junction table for many-to-many relationship between EmailConfiguration and Bank."""

    __tablename__ = "email_config_banks"

    email_config_id = Column(
        Integer, ForeignKey("email_configurations.id"), primary_key=True
    )
    bank_id = Column(Integer, ForeignKey("banks.id"), primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    email_config = relationship(
        "EmailConfiguration", back_populates="email_config_banks"
    )
    bank = relationship("Bank", back_populates="email_config_banks")


class EmailConfiguration(Base):
    """Email configuration model for storing user's email settings."""

    __tablename__ = "email_configurations"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(
        String(100), nullable=False, default="Default"
    )  # Name to identify this configuration
    email_host = Column(String(100), nullable=False)
    email_port = Column(Integer, nullable=False)
    email_username = Column(String(100), nullable=False)
    email_password = Column(
        String(200), nullable=False
    )  # Should be encrypted in production
    email_use_ssl = Column(Boolean, default=True)
    service_provider_id = Column(
        Integer, ForeignKey("email_service_providers.id"), nullable=True
    )
    bank_id = Column(
        Integer, ForeignKey("banks.id"), nullable=True
    )  # Reference to the Bank model (kept for backward compatibility)
    bank_email_addresses = Column(
        Text
    )  # Comma-separated list (kept for backward compatibility)
    bank_email_subjects = Column(
        Text
    )  # Comma-separated list (kept for backward compatibility)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="email_configs")
    accounts = relationship("Account", back_populates="email_config")
    service_provider = relationship(
        "EmailServiceProvider", back_populates="email_configs"
    )
    bank = relationship(
        "Bank", foreign_keys=[bank_id]
    )  # Kept for backward compatibility
    email_config_banks = relationship(
        "EmailConfigBank", back_populates="email_config", cascade="all, delete-orphan"
    )
    banks = relationship("Bank", secondary="email_config_banks", viewonly=True)


class EmailMetadata(Base):
    """Email metadata model for storing email information."""

    __tablename__ = "email_metadata"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    email_id = Column(String(100))
    subject = Column(String(500))
    sender = Column(String(200))
    recipient = Column(String(200))
    date = Column(String(200))
    body = Column(Text)
    cleaned_body = Column(Text)  # Added field for cleaned email content
    processed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User")
    transactions = relationship("Transaction", back_populates="email_metadata")


class Bank(Base):
    """Bank model for storing bank information."""

    __tablename__ = "banks"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    email_address = Column(String(200), nullable=False)
    email_subjects = Column(
        Text, nullable=False
    )  # Comma-separated list of subject keywords
    currency = Column(String(10), default="OMR")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    accounts = relationship("Account", back_populates="bank")
    email_configs = relationship(
        "EmailConfiguration", foreign_keys="EmailConfiguration.bank_id", overlaps="bank"
    )
    email_config_banks = relationship(
        "EmailConfigBank", back_populates="bank", cascade="all, delete-orphan"
    )
    email_configurations = relationship(
        "EmailConfiguration", secondary="email_config_banks", viewonly=True
    )

    # Ensure bank names are unique
    __table_args__ = (UniqueConstraint("name", name="_bank_name_uc"),)


class Account(Base):
    """Account model representing a bank account."""

    __tablename__ = "accounts"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    email_config_id = Column(
        Integer, ForeignKey("email_configurations.id"), nullable=True
    )
    bank_id = Column(
        Integer, ForeignKey("banks.id"), nullable=True
    )  # Reference to the Bank model
    account_number = Column(String(50), nullable=False)
    bank_name = Column(String(100), nullable=False)  # Kept for backward compatibility
    account_holder = Column(String(100))
    branch = Column(String(200), nullable=True)
    balance = Column(Float, default=0.0)
    currency = Column(String(10), default="OMR")  # Kept for backward compatibility
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="accounts")
    email_config = relationship("EmailConfiguration", back_populates="accounts")
    bank = relationship("Bank", back_populates="accounts")  # Relationship to Bank model
    transactions = relationship("Transaction", back_populates="account")

    # Composite unique constraint for user_id, email_config_id, and account_number
    # This ensures an account number can only be in one email configuration
    __table_args__ = (
        UniqueConstraint("user_id", "account_number", name="_user_account_uc"),
    )


class TransactionType(enum.Enum):
    """Enum for transaction types."""

    INCOME = "income"
    EXPENSE = "expense"
    TRANSFER = "transfer"
    UNKNOWN = "unknown"


class Transaction(Base):
    """Transaction model representing a financial transaction."""

    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True)
    account_id = Column(Integer, ForeignKey("accounts.id"), nullable=False)
    email_metadata_id = Column(Integer, ForeignKey("email_metadata.id"), nullable=True)
    transaction_type = Column(Enum(TransactionType), nullable=False)
    amount = Column(Float, nullable=False)
    currency = Column(String(10), default="OMR")
    value_date = Column(DateTime, nullable=True)
    transaction_id = Column(String(100))  # Bank's transaction reference
    category_id = Column(Integer, ForeignKey("categories.id"), nullable=True)

    # New counterparty relationship
    counterparty_id = Column(Integer, ForeignKey("counterparties.id"), nullable=True)

    # Legacy counterparty information (kept for migration purposes)
    transaction_sender = Column(String(200))
    transaction_receiver = Column(String(200))
    counterparty_name = Column(String(200))

    transaction_details = Column(String(500))

    # Additional fields
    country = Column(String(100))

    # Email tracking (deprecated, use email_metadata relationship instead)
    post_date = Column(String(200))

    # Cleaned email content for hover display
    transaction_content = Column(Text)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    account = relationship("Account", back_populates="transactions")
    email_metadata = relationship("EmailMetadata", back_populates="transactions")
    category = relationship("Category")
    counterparty = relationship("Counterparty", back_populates="transactions")

    # Properties for backward compatibility
    @property
    def date_time(self):
        """Backward compatibility property for value_date."""
        return self.value_date

    @property
    def email_date(self):
        """Backward compatibility property for post_date."""
        return self.post_date

    @property
    def description(self):
        """Backward compatibility property for description.
        Returns transaction_details or counterparty name as fallback."""
        if self.transaction_details:
            return self.transaction_details
        elif self.counterparty:
            return self.counterparty.name
        elif self.counterparty_name:  # Legacy fallback
            return self.counterparty_name
        return None

    @property
    def email_id(self):
        """Backward compatibility property for email_id.
        Returns email_id from email_metadata if available."""
        if self.email_metadata:
            return self.email_metadata.email_id
        return None

    @property
    def bank_name(self):
        """Backward compatibility property for bank_name.
        Returns bank_name from account if available."""
        if self.account:
            return self.account.bank_name
        return None


class CounterpartyCategory(Base):
    """Model for mapping counterparties to categories per user."""

    __tablename__ = "counterparty_categories"

    id = Column(Integer, primary_key=True)
    counterparty_id = Column(Integer, ForeignKey("counterparties.id"), nullable=False)
    category_id = Column(Integer, ForeignKey("categories.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    counterparty = relationship("Counterparty", back_populates="category_mappings")
    category = relationship("Category")
    user = relationship("User")

    # Ensure mappings are unique per user, counterparty, and category
    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "counterparty_id",
            "category_id",
            name="_user_counterparty_category_uc",
        ),
    )


class CategoryType(enum.Enum):
    """Enum for category types."""

    COUNTERPARTY = "counterparty"
    DESCRIPTION = "transaction_details"


class Category(Base):
    """Category model for transaction categorization."""

    __tablename__ = "categories"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    color = Column(String(7), nullable=True)  # Store color as hex code (e.g., #FF5733)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User")
    mappings = relationship(
        "CategoryMapping", back_populates="category", cascade="all, delete-orphan"
    )

    # Ensure category names are unique per user
    __table_args__ = (UniqueConstraint("user_id", "name", name="_user_category_uc"),)


class Counterparty(Base):
    """Counterparty model representing entities involved in transactions."""

    __tablename__ = "counterparties"

    id = Column(Integer, primary_key=True)
    name = Column(String(200), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    transactions = relationship("Transaction", back_populates="counterparty")
    category_mappings = relationship(
        "CounterpartyCategory",
        back_populates="counterparty",
        cascade="all, delete-orphan",
    )

    # Ensure counterparty names are unique
    __table_args__ = (UniqueConstraint("name", name="_counterparty_name_uc"),)


class CategoryMapping(Base):
    """Model for mapping transactions to categories based on counterparty or description."""

    __tablename__ = "category_mappings"

    id = Column(Integer, primary_key=True)
    category_id = Column(Integer, ForeignKey("categories.id"), nullable=False)
    mapping_type = Column(Enum(CategoryType), nullable=False)
    pattern = Column(
        String(500), nullable=False
    )  # counterparty_name or description pattern
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    category = relationship("Category", back_populates="mappings")

    # Ensure patterns are unique per category and type
    __table_args__ = (
        UniqueConstraint(
            "category_id", "mapping_type", "pattern", name="_category_mapping_uc"
        ),
    )
