"""
Database models for the Bank Email Parser & Account Tracker.
"""

import enum
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Enum, Float, Text, Boolean, UniqueConstraint
from sqlalchemy.orm import relationship, Session
from money_tracker.models.database import Base
from werkzeug.security import generate_password_hash, check_password_hash

logger = logging.getLogger(__name__)

class CategoryType(enum.Enum):
    """Enum for category types."""
    COUNTERPARTY = 'counterparty'
    DESCRIPTION = 'description'

class TransactionType(enum.Enum):
    """Enum for transaction types."""
    INCOME = 'income'
    EXPENSE = 'expense'
    TRANSFER = 'transfer'
    UNKNOWN = 'unknown'

class User(Base):
    """User model representing a user profile."""
    __tablename__ = 'users'

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
            if not hasattr(generate_password_hash, '__call__'):
                logger.error("generate_password_hash is not callable")
                raise ImportError("generate_password_hash is not properly imported")

            # Generate password hash
            password_hash = generate_password_hash(password)
            logger.info(f"Password hash generated successfully: {password_hash[:10]}...")

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
            if not hasattr(check_password_hash, '__call__'):
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

class EmailConfiguration(Base):
    """Email configuration model for storing user's email settings."""
    __tablename__ = 'email_configurations'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    name = Column(String(100), nullable=False, default="Default")  # Name to identify this configuration
    email_host = Column(String(100), nullable=False)
    email_port = Column(Integer, nullable=False)
    email_username = Column(String(100), nullable=False)
    email_password = Column(String(200), nullable=False)  # Should be encrypted in production
    email_use_ssl = Column(Boolean, default=True)
    bank_email_addresses = Column(Text)  # Comma-separated list
    bank_email_subjects = Column(Text)  # Comma-separated list
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="email_configs")
    accounts = relationship("Account", back_populates="email_config")

class Account(Base):
    """Account model representing a bank account."""
    __tablename__ = 'accounts'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    email_config_id = Column(Integer, ForeignKey('email_configurations.id'), nullable=True)
    account_number = Column(String(50), nullable=False)
    bank_name = Column(String(100), nullable=False)
    account_holder = Column(String(100))
    balance = Column(Float, default=0.0)
    currency = Column(String(10), default='OMR')
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="accounts")
    email_config = relationship("EmailConfiguration", back_populates="accounts")
    transactions = relationship("Transaction", back_populates="account")

    # Composite unique constraint for user_id, email_config_id, and account_number
    # This ensures an account number can only be in one email configuration
    __table_args__ = (
        UniqueConstraint('user_id', 'account_number', name='_user_account_uc'),
    )

class EmailMetadata(Base):
    """Email metadata model for storing email information."""
    __tablename__ = 'email_metadata'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
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

class Category(Base):
    """Category model for transaction categorization."""
    __tablename__ = 'categories'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User")
    mappings = relationship("CategoryMapping", back_populates="category", cascade="all, delete-orphan")

    # Ensure category names are unique per user
    __table_args__ = (
        UniqueConstraint('user_id', 'name', name='_user_category_uc'),
    )

class CategoryMapping(Base):
    """Model for mapping transactions to categories based on counterparty or description."""
    __tablename__ = 'category_mappings'

    id = Column(Integer, primary_key=True)
    category_id = Column(Integer, ForeignKey('categories.id'), nullable=False)
    mapping_type = Column(Enum(CategoryType), nullable=False)
    pattern = Column(String(500), nullable=False)  # counterparty_name or description pattern
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    category = relationship("Category", back_populates="mappings")

    # Ensure patterns are unique per category and type
    __table_args__ = (
        UniqueConstraint('category_id', 'mapping_type', 'pattern', name='_category_mapping_uc'),
    )

class Transaction(Base):
    """Transaction model representing a financial transaction."""
    __tablename__ = 'transactions'

    id = Column(Integer, primary_key=True)
    account_id = Column(Integer, ForeignKey('accounts.id'), nullable=False)
    email_metadata_id = Column(Integer, ForeignKey('email_metadata.id'), nullable=True)
    transaction_type = Column(Enum(TransactionType), nullable=False)
    amount = Column(Float, nullable=False)
    currency = Column(String(10), default='OMR')
    value_date = Column(DateTime, nullable=True)
    description = Column(Text)
    transaction_id = Column(String(100))  # Bank's transaction reference
    category_id = Column(Integer, ForeignKey('categories.id'), nullable=True)

    # Bank-specific fields
    bank_name = Column(String(100))
    branch = Column(String(200))

    # Counterparty information
    transaction_sender = Column(String(200))
    transaction_receiver = Column(String(200))
    counterparty_name = Column(String(200))

    # New fields from your function
    from_party = Column(String(200))  # 'me' or actual name
    to_party = Column(String(200))    # 'me' or actual name
    transaction_details = Column(String(500))  # TRANSFER, Cash Dep, SALARY, etc.

    # Additional fields
    country = Column(String(100))

    # Email tracking (deprecated, use email_metadata relationship instead)
    email_id = Column(String(100))
    post_date = Column(String(200))

    # Cleaned email content for hover display
    cleaned_email_content = Column(Text)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    account = relationship("Account", back_populates="transactions")
    email_metadata = relationship("EmailMetadata", back_populates="transactions")
    category = relationship("Category")

    # Properties for backward compatibility
    @property
    def date_time(self):
        """Backward compatibility property for value_date."""
        return self.value_date

    @property
    def email_date(self):
        """Backward compatibility property for post_date."""
        return self.post_date

class CategoryRepository:
    """Repository class for category operations."""

    @staticmethod
    def create_category(session: Session, user_id: int, name: str, description: str = None) -> Optional[Category]:
        """
        Create a new category.

        Args:
            session (Session): Database session.
            user_id (int): User ID.
            name (str): Category name.
            description (str, optional): Category description.

        Returns:
            Optional[Category]: Created category or None if creation fails.
        """
        try:
            # Check if category already exists for this user
            existing_category = session.query(Category).filter(
                Category.user_id == user_id,
                Category.name == name
            ).first()

            if existing_category:
                logger.info(f"Category {name} already exists for user {user_id}")
                return existing_category

            category = Category(
                user_id=user_id,
                name=name,
                description=description
            )

            session.add(category)
            session.commit()
            logger.info(f"Created category: {category.name} for user {user_id}")
            return category

        except Exception as e:
            session.rollback()
            logger.error(f"Error creating category: {str(e)}")
            return None

    @staticmethod
    def get_categories(session: Session, user_id: int) -> List[Category]:
        """
        Get all categories for a user.

        Args:
            session (Session): Database session.
            user_id (int): User ID.

        Returns:
            List[Category]: List of user's categories.
        """
        try:
            categories = session.query(Category).filter(
                Category.user_id == user_id
            ).all()

            return categories

        except Exception as e:
            logger.error(f"Error getting categories: {str(e)}")
            return []

    @staticmethod
    def get_category(session: Session, category_id: int, user_id: int) -> Optional[Category]:
        """
        Get a category by ID.

        Args:
            session (Session): Database session.
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).

        Returns:
            Optional[Category]: Category or None if not found.
        """
        try:
            category = session.query(Category).filter(
                Category.id == category_id,
                Category.user_id == user_id
            ).first()

            return category

        except Exception as e:
            logger.error(f"Error getting category: {str(e)}")
            return None

    @staticmethod
    def update_category(session: Session, category_id: int, user_id: int, 
                        name: str = None, description: str = None) -> Optional[Category]:
        """
        Update a category.

        Args:
            session (Session): Database session.
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).
            name (str, optional): New category name.
            description (str, optional): New category description.

        Returns:
            Optional[Category]: Updated category or None if update fails.
        """
        try:
            category = session.query(Category).filter(
                Category.id == category_id,
                Category.user_id == user_id
            ).first()

            if not category:
                logger.error(f"Category {category_id} not found or user {user_id} does not have permission")
                return None

            if name is not None:
                category.name = name

            if description is not None:
                category.description = description

            session.commit()
            logger.info(f"Updated category: {category.id}")
            return category

        except Exception as e:
            session.rollback()
            logger.error(f"Error updating category: {str(e)}")
            return None

    @staticmethod
    def delete_category(session: Session, category_id: int, user_id: int) -> bool:
        """
        Delete a category.

        Args:
            session (Session): Database session.
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).

        Returns:
            bool: True if deletion is successful, False otherwise.
        """
        try:
            category = session.query(Category).filter(
                Category.id == category_id,
                Category.user_id == user_id
            ).first()

            if not category:
                logger.error(f"Category {category_id} not found or user {user_id} does not have permission")
                return False

            # Remove category from transactions
            # First, get transaction IDs to update
            transaction_ids = [row.id for row in session.query(Transaction.id).filter(
                Transaction.category_id == category_id
            ).all()]

            # Then update using a simple query
            if transaction_ids:
                session.query(Transaction).filter(
                    Transaction.id.in_(transaction_ids)
                ).update({Transaction.category_id: None}, synchronize_session=False)

            session.delete(category)
            session.commit()
            logger.info(f"Deleted category: {category_id}")
            return True

        except Exception as e:
            session.rollback()
            logger.error(f"Error deleting category: {str(e)}")
            return False

    @staticmethod
    def create_category_mapping(session: Session, category_id: int, user_id: int, 
                               mapping_type: CategoryType, pattern: str) -> Optional[CategoryMapping]:
        """
        Create a new category mapping.

        Args:
            session (Session): Database session.
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).
            mapping_type (CategoryType): Type of mapping (COUNTERPARTY or DESCRIPTION).
            pattern (str): Pattern to match (counterparty_name or description).

        Returns:
            Optional[CategoryMapping]: Created mapping or None if creation fails.
        """
        try:
            # Check if category exists and belongs to user
            category = session.query(Category).filter(
                Category.id == category_id,
                Category.user_id == user_id
            ).first()

            if not category:
                logger.error(f"Category {category_id} not found or user {user_id} does not have permission")
                return None

            # Check if mapping already exists
            existing_mapping = session.query(CategoryMapping).filter(
                CategoryMapping.category_id == category_id,
                CategoryMapping.mapping_type == mapping_type,
                CategoryMapping.pattern == pattern
            ).first()

            if existing_mapping:
                logger.info(f"Mapping for pattern '{pattern}' already exists for category {category_id}")
                return existing_mapping

            # Check if pattern is already mapped to another category
            existing_pattern_mapping = session.query(CategoryMapping).join(Category).filter(
                CategoryMapping.mapping_type == mapping_type,
                CategoryMapping.pattern == pattern,
                Category.user_id == user_id
            ).first()

            if existing_pattern_mapping:
                # Delete the existing mapping
                session.delete(existing_pattern_mapping)
                logger.info(f"Removed existing mapping for pattern '{pattern}' from category {existing_pattern_mapping.category_id}")

            mapping = CategoryMapping(
                category_id=category_id,
                mapping_type=mapping_type,
                pattern=pattern
            )

            session.add(mapping)
            session.commit()
            logger.info(f"Created category mapping: {mapping.id} for category {category_id}")

            # Update transactions that match this pattern
            if mapping_type == CategoryType.COUNTERPARTY:
                # Get transaction IDs that need to be updated
                transaction_ids = [t.id for t in session.query(Transaction.id).join(Account).filter(
                    Account.user_id == user_id,
                    Transaction.counterparty_name == pattern
                ).all()]

                # Update transactions without using join
                if transaction_ids:
                    session.query(Transaction).filter(
                        Transaction.id.in_(transaction_ids)
                    ).update({Transaction.category_id: category_id}, synchronize_session=False)
            else:  # DESCRIPTION
                # Get transaction IDs that need to be updated
                transaction_ids = [t.id for t in session.query(Transaction.id).join(Account).filter(
                    Account.user_id == user_id,
                    Transaction.description == pattern
                ).all()]

                # Update transactions without using join
                if transaction_ids:
                    session.query(Transaction).filter(
                        Transaction.id.in_(transaction_ids)
                    ).update({Transaction.category_id: category_id}, synchronize_session=False)

            session.commit()
            return mapping

        except Exception as e:
            session.rollback()
            logger.error(f"Error creating category mapping: {str(e)}")
            return None

    @staticmethod
    def delete_category_mapping(session: Session, mapping_id: int, user_id: int) -> bool:
        """
        Delete a category mapping.

        Args:
            session (Session): Database session.
            mapping_id (int): Mapping ID.
            user_id (int): User ID (for permission check).

        Returns:
            bool: True if deletion is successful, False otherwise.
        """
        try:
            mapping = session.query(CategoryMapping).join(Category).filter(
                CategoryMapping.id == mapping_id,
                Category.user_id == user_id
            ).first()

            if not mapping:
                logger.error(f"Mapping {mapping_id} not found or user {user_id} does not have permission")
                return False

            session.delete(mapping)
            session.commit()
            logger.info(f"Deleted category mapping: {mapping_id}")
            return True

        except Exception as e:
            session.rollback()
            logger.error(f"Error deleting category mapping: {str(e)}")
            return False

    @staticmethod
    def get_category_mappings(session: Session, category_id: int, user_id: int) -> List[CategoryMapping]:
        """
        Get all mappings for a category.

        Args:
            session (Session): Database session.
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).

        Returns:
            List[CategoryMapping]: List of category mappings.
        """
        try:
            mappings = session.query(CategoryMapping).join(Category).filter(
                CategoryMapping.category_id == category_id,
                Category.user_id == user_id
            ).all()

            return mappings

        except Exception as e:
            logger.error(f"Error getting category mappings: {str(e)}")
            return []

    @staticmethod
    def auto_categorize_transaction(session: Session, transaction_id: int, user_id: int) -> Optional[Transaction]:
        """
        Auto-categorize a transaction based on counterparty_name or description.

        Args:
            session (Session): Database session.
            transaction_id (int): Transaction ID.
            user_id (int): User ID (for permission check).

        Returns:
            Optional[Transaction]: Categorized transaction or None if categorization fails.
        """
        try:
            transaction = session.query(Transaction).join(Account).filter(
                Transaction.id == transaction_id,
                Account.user_id == user_id
            ).first()

            if not transaction:
                logger.error(f"Transaction {transaction_id} not found or user {user_id} does not have permission")
                return None

            # Try to categorize by exact counterparty_name match first
            if transaction.counterparty_name:
                mapping = session.query(CategoryMapping).join(Category).filter(
                    CategoryMapping.mapping_type == CategoryType.COUNTERPARTY,
                    CategoryMapping.pattern == transaction.counterparty_name,
                    Category.user_id == user_id
                ).first()

                if mapping:
                    transaction.category_id = mapping.category_id
                    session.commit()
                    logger.info(f"Auto-categorized transaction {transaction_id} by exact counterparty_name match")
                    return transaction

            # Try to categorize by exact description match
            if transaction.description:
                mapping = session.query(CategoryMapping).join(Category).filter(
                    CategoryMapping.mapping_type == CategoryType.DESCRIPTION,
                    CategoryMapping.pattern == transaction.description,
                    Category.user_id == user_id
                ).first()

                if mapping:
                    transaction.category_id = mapping.category_id
                    session.commit()
                    logger.info(f"Auto-categorized transaction {transaction_id} by exact description match")
                    return transaction

            # If no exact matches, try pattern matching for counterparty_name
            if transaction.counterparty_name:
                # Get all counterparty mappings for this user
                counterparty_mappings = session.query(CategoryMapping).join(Category).filter(
                    CategoryMapping.mapping_type == CategoryType.COUNTERPARTY,
                    Category.user_id == user_id
                ).all()

                # Check each pattern - use word boundaries for more accurate matching
                for mapping in counterparty_mappings:
                    # Skip empty patterns
                    if not mapping.pattern or not mapping.pattern.strip():
                        continue

                    # Check if pattern is a whole word or part of a word
                    pattern = mapping.pattern.lower()
                    counterparty = transaction.counterparty_name.lower()

                    # Check for word boundaries or exact match
                    if (f" {pattern} " in f" {counterparty} " or 
                        counterparty.startswith(f"{pattern} ") or 
                        counterparty.endswith(f" {pattern}") or 
                        counterparty == pattern):
                        transaction.category_id = mapping.category_id
                        session.commit()
                        logger.info(f"Auto-categorized transaction {transaction_id} by counterparty_name pattern match")
                        return transaction

            # Try pattern matching for description
            if transaction.description:
                # Get all description mappings for this user
                description_mappings = session.query(CategoryMapping).join(Category).filter(
                    CategoryMapping.mapping_type == CategoryType.DESCRIPTION,
                    Category.user_id == user_id
                ).all()

                # Check each pattern - use word boundaries for more accurate matching
                for mapping in description_mappings:
                    # Skip empty patterns
                    if not mapping.pattern or not mapping.pattern.strip():
                        continue

                    # Check if pattern is a whole word or part of a word
                    pattern = mapping.pattern.lower()
                    description = transaction.description.lower()

                    # Check for word boundaries or exact match
                    if (f" {pattern} " in f" {description} " or 
                        description.startswith(f"{pattern} ") or 
                        description.endswith(f" {pattern}") or 
                        description == pattern):
                        transaction.category_id = mapping.category_id
                        session.commit()
                        logger.info(f"Auto-categorized transaction {transaction_id} by description pattern match")
                        return transaction

            logger.info(f"Could not auto-categorize transaction {transaction_id}")
            return transaction

        except Exception as e:
            session.rollback()
            logger.error(f"Error auto-categorizing transaction: {str(e)}")
            return None

    @staticmethod
    def categorize_transaction(session: Session, transaction_id: int, category_id: int, user_id: int) -> Optional[Transaction]:
        """
        Manually categorize a transaction.

        Args:
            session (Session): Database session.
            transaction_id (int): Transaction ID.
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).

        Returns:
            Optional[Transaction]: Categorized transaction or None if categorization fails.
        """
        try:
            transaction = session.query(Transaction).join(Account).filter(
                Transaction.id == transaction_id,
                Account.user_id == user_id
            ).first()

            if not transaction:
                logger.error(f"Transaction {transaction_id} not found or user {user_id} does not have permission")
                return None

            category = session.query(Category).filter(
                Category.id == category_id,
                Category.user_id == user_id
            ).first()

            if not category:
                logger.error(f"Category {category_id} not found or user {user_id} does not have permission")
                return None

            transaction.category_id = category_id
            session.commit()
            logger.info(f"Categorized transaction {transaction_id} as {category.name}")

            # Create mapping if it doesn't exist
            if transaction.counterparty_name:
                CategoryRepository.create_category_mapping(
                    session, category_id, user_id, CategoryType.COUNTERPARTY, transaction.counterparty_name
                )

            if transaction.description:
                CategoryRepository.create_category_mapping(
                    session, category_id, user_id, CategoryType.DESCRIPTION, transaction.description
                )

            return transaction

        except Exception as e:
            session.rollback()
            logger.error(f"Error categorizing transaction: {str(e)}")
            return None

class TransactionRepository:
    """Repository class for transaction operations."""

    @staticmethod
    def create_user(session: Session, user_data: Dict[str, Any]) -> Optional[User]:
        """
        Create a new user.

        Args:
            session (Session): Database session.
            user_data (Dict[str, Any]): User data.

        Returns:
            Optional[User]: Created user or None if creation fails.
        """
        try:
            # Debug logging
            logger.info(f"TransactionRepository.create_user called with username: {user_data.get('username')}, email: {user_data.get('email')}")

            # Check if user already exists
            existing_user = session.query(User).filter(
                (User.username == user_data['username']) | (User.email == user_data['email'])
            ).first()

            if existing_user:
                logger.info(f"User {user_data['username']} or email {user_data['email']} already exists")
                return None

            # Create user object
            logger.info("Creating User object")
            user = User(
                username=user_data['username'],
                email=user_data['email']
            )

            # Set password
            logger.info("Setting password hash")
            try:
                user.set_password(user_data['password'])
            except Exception as pw_error:
                logger.error(f"Error setting password: {str(pw_error)}")
                raise

            # Add to session and commit
            logger.info("Adding user to session")
            session.add(user)

            logger.info("Committing session")
            session.commit()

            logger.info(f"Created user: {user.username} with ID: {user.id}")
            return user

        except Exception as e:
            session.rollback()
            logger.error(f"Error creating user: {str(e)}")
            # Print exception traceback for debugging
            import traceback
            logger.error(f"Traceback: {traceback.format_exc()}")
            return None

    @staticmethod
    def create_email_config(session: Session, config_data: Dict[str, Any]) -> Optional[EmailConfiguration]:
        """
        Create or update email configuration for a user.

        Args:
            session (Session): Database session.
            config_data (Dict[str, Any]): Email configuration data.

        Returns:
            Optional[EmailConfiguration]: Created/updated configuration or None if creation fails.
        """
        try:
            user_id = config_data['user_id']

            # Check if configuration already exists for this user
            existing_config = session.query(EmailConfiguration).filter(
                EmailConfiguration.user_id == user_id
            ).first()

            if existing_config:
                # Update existing configuration
                for key, value in config_data.items():
                    if key != 'user_id' and hasattr(existing_config, key):
                        setattr(existing_config, key, value)

                session.commit()
                logger.info(f"Updated email configuration for user ID: {user_id}")
                return existing_config

            # Create new configuration
            email_config = EmailConfiguration(
                user_id=user_id,
                email_host=config_data['email_host'],
                email_port=config_data['email_port'],
                email_username=config_data['email_username'],
                email_password=config_data['email_password'],
                email_use_ssl=config_data.get('email_use_ssl', True),
                bank_email_addresses=config_data.get('bank_email_addresses', ''),
                bank_email_subjects=config_data.get('bank_email_subjects', '')
            )

            session.add(email_config)
            session.commit()
            logger.info(f"Created email configuration for user ID: {user_id}")
            return email_config

        except Exception as e:
            session.rollback()
            logger.error(f"Error creating/updating email configuration: {str(e)}")
            return None

    @staticmethod
    def create_account(session: Session, account_data: Dict[str, Any]) -> Optional[Account]:
        """
        Create a new account.

        Args:
            session (Session): Database session.
            account_data (Dict[str, Any]): Account data.

        Returns:
            Optional[Account]: Created account or None if creation fails.
        """
        try:
            user_id = account_data.get('user_id')
            if not user_id:
                logger.error("No user_id provided for account creation")
                return None

            # Check if account already exists for this user
            existing_account = session.query(Account).filter(
                Account.user_id == user_id,
                Account.account_number == account_data['account_number']
            ).first()

            if existing_account:
                logger.info(f"Account {account_data['account_number']} already exists for user {user_id}")
                return existing_account

            account = Account(
                user_id=user_id,
                account_number=account_data['account_number'],
                bank_name=account_data.get('bank_name', 'Unknown'),
                account_holder=account_data.get('account_holder'),
                balance=account_data.get('balance', 0.0),
                currency=account_data.get('currency', 'OMR'),
                email_config_id=account_data.get('email_config_id')
            )

            session.add(account)
            session.commit()
            logger.info(f"Created account: {account.account_number} for user {user_id}")
            return account

        except Exception as e:
            session.rollback()
            logger.error(f"Error creating account: {str(e)}")
            return None

    @staticmethod
    def create_email_metadata(session: Session, email_data: Dict[str, Any]) -> Optional[EmailMetadata]:
        """
        Create email metadata.

        Args:
            session (Session): Database session.
            email_data (Dict[str, Any]): Email data.

        Returns:
            Optional[EmailMetadata]: Created email metadata or None if creation fails.
        """
        try:
            user_id = email_data.get('user_id')
            if not user_id:
                logger.error("No user_id provided for email metadata creation")
                return None

            email_metadata = EmailMetadata(
                user_id=user_id,
                email_id=email_data.get('id'),
                subject=email_data.get('subject', ''),
                sender=email_data.get('from', ''),
                recipient=email_data.get('to', ''),
                date=email_data.get('date', ''),
                body=email_data.get('body', ''),
                cleaned_body=email_data.get('cleaned_body', ''),
                processed=email_data.get('processed', False)
            )

            session.add(email_metadata)
            session.commit()
            logger.info(f"Created email metadata: {email_metadata.id}")
            return email_metadata

        except Exception as e:
            session.rollback()
            logger.error(f"Error creating email metadata: {str(e)}")
            return None

    @staticmethod
    def create_transaction(session: Session, transaction_data: Dict[str, Any]) -> Optional[Transaction]:
        """
        Create a new transaction.

        Args:
            session (Session): Database session.
            transaction_data (Dict[str, Any]): Transaction data.

        Returns:
            Optional[Transaction]: Created transaction or None if creation fails.
        """
        try:
            # Get or create account
            account_number = transaction_data.get('account_number')
            user_id = transaction_data.get('user_id')

            if not account_number:
                logger.error("No account number provided for transaction")
                return None

            if not user_id:
                logger.error("No user_id provided for transaction")
                return None

            account_data = {
                'user_id': user_id,
                'account_number': account_number,
                'bank_name': transaction_data.get('bank_name', 'Unknown'),
                'currency': transaction_data.get('currency', 'OMR'),
                'balance': transaction_data.get('balance', 0.0)
            }
            account = TransactionRepository.create_account(session, account_data)

            if not account:
                return None

            # Check if transaction already exists (by transaction_id and date)
            if transaction_data.get('transaction_id'):
                existing_transaction = session.query(Transaction).filter(
                    Transaction.account_id == account.id,
                    Transaction.transaction_id == transaction_data['transaction_id']
                ).first()

                if existing_transaction:
                    logger.info(f"Transaction {transaction_data['transaction_id']} already exists")
                    return existing_transaction

            # Convert transaction type
            transaction_type_str = transaction_data.get('transaction_type', 'unknown').lower()
            try:
                transaction_type = TransactionType(transaction_type_str)
            except ValueError:
                transaction_type = TransactionType.UNKNOWN

            # Handle email metadata if provided
            email_metadata_id = None
            if transaction_data.get('email_metadata_id'):
                email_metadata_id = transaction_data['email_metadata_id']
            elif transaction_data.get('email_data'):
                # Create email metadata from email data
                email_data = transaction_data['email_data']
                email_data['user_id'] = user_id
                email_metadata = TransactionRepository.create_email_metadata(session, email_data)
                if email_metadata:
                    email_metadata_id = email_metadata.id

            transaction = Transaction(
                account_id=account.id,
                email_metadata_id=email_metadata_id,
                transaction_type=transaction_type,
                amount=transaction_data.get('amount', 0.0),
                currency=transaction_data.get('currency', 'OMR'),
                value_date=transaction_data.get('date_time', None),  # Using date_time from input for backward compatibility
                description=transaction_data.get('description'),
                transaction_id=transaction_data.get('transaction_id'),
                bank_name=transaction_data.get('bank_name'),
                branch=transaction_data.get('branch'),
                transaction_sender=transaction_data.get('transaction_sender'),
                transaction_receiver=transaction_data.get('transaction_receiver'),
                counterparty_name=transaction_data.get('counterparty_name'),
                from_party=transaction_data.get('from_party'),
                to_party=transaction_data.get('to_party'),
                transaction_details=transaction_data.get('transaction_details'),
                country=transaction_data.get('country'),
                email_id=transaction_data.get('email_id'),
                post_date=transaction_data.get('email_date'),  # Using email_date from input for backward compatibility
                cleaned_email_content=transaction_data.get('cleaned_email_content')
            )

            session.add(transaction)
            session.commit()

            # Check if we should update the account balance
            preserve_balance = transaction_data.get('preserve_balance', False)

            # Only preserve balance if the flag is set and this is a first scrape
            # We determine if it's a first scrape by checking if there are existing transactions
            # Note: We need to check this before adding the current transaction
            is_first_scrape = False
            if preserve_balance:
                # We need to exclude the current transaction from the count
                # Since we just added it, we need to check if there were any transactions before
                existing_transactions_count = session.query(Transaction).filter(
                    Transaction.account_id == account.id,
                    Transaction.id != transaction.id  # Exclude the current transaction
                ).count()
                is_first_scrape = existing_transactions_count > 0

            # Update balance if we're not preserving balance or if this is not the first scrape
            # if not (preserve_balance and is_first_scrape): # This Only update balance if not preserving or not first scrape
            if is_first_scrape:
                if transaction_type == TransactionType.INCOME:
                    account.balance += transaction.amount
                elif transaction_type == TransactionType.EXPENSE:
                    account.balance -= transaction.amount
                elif transaction_type == TransactionType.TRANSFER:
                    # For transfers, we don't change the balance by default
                    # This would need to be handled differently if transfers between accounts are tracked
                    logger.info(f"Transfer transaction: {transaction.id} - not updating balance")
                elif transaction_type == TransactionType.UNKNOWN:
                    logger.warning(f"Unknown transaction type for transaction: {transaction.id} - not updating balance")
                session.commit()

            logger.info(f"Created transaction: {transaction.id}")
            return transaction

        except Exception as e:
            session.rollback()
            logger.error(f"Error creating transaction: {str(e)}")
            return None

    @staticmethod
    def get_account_summary(session: Session, user_id: int, account_number: str) -> Optional[Dict[str, Any]]:
        """
        Get account summary including balance and transaction counts.

        Args:
            session (Session): Database session.
            user_id (int): User ID.
            account_number (str): Account number.

        Returns:
            Optional[Dict[str, Any]]: Account summary or None if not found.
        """
        try:
            account = session.query(Account).filter(
                Account.user_id == user_id,
                Account.account_number == account_number
            ).first()

            if not account:
                return None

            # Use more efficient SQL aggregation instead of loading all transactions
            from sqlalchemy import func, case

            # Get transaction counts and sums by type
            transaction_stats = session.query(
                func.count(Transaction.id).label('total_count'),
                func.sum(case((Transaction.transaction_type == TransactionType.INCOME, Transaction.amount), else_=0)).label('total_income'),
                func.sum(case((Transaction.transaction_type == TransactionType.EXPENSE, Transaction.amount), else_=0)).label('total_expense'),
                func.sum(case((Transaction.transaction_type == TransactionType.TRANSFER, Transaction.amount), else_=0)).label('total_transfer'),
                func.count(case((Transaction.transaction_type == TransactionType.INCOME, 1), else_=None)).label('income_count'),
                func.count(case((Transaction.transaction_type == TransactionType.EXPENSE, 1), else_=None)).label('expense_count')
            ).filter(
                Transaction.account_id == account.id
            ).first()

            # Handle case where there are no transactions
            if not transaction_stats or transaction_stats.total_count == 0:
                total_income = 0
                total_expense = 0
                total_transfer = 0
                income_count = 0
                expense_count = 0
                transaction_count = 0
            else:
                total_income = transaction_stats.total_income or 0
                total_expense = transaction_stats.total_expense or 0
                total_transfer = transaction_stats.total_transfer or 0
                income_count = transaction_stats.income_count or 0
                expense_count = transaction_stats.expense_count or 0
                transaction_count = transaction_stats.total_count or 0

            # Get the most recent transactions for display
            recent_transactions = session.query(Transaction).filter(
                Transaction.account_id == account.id
            ).order_by(Transaction.value_date.desc()).limit(10).all()

            return {
                'account_number': account.account_number,
                'bank_name': account.bank_name,
                'account_holder': account.account_holder,
                'balance': account.balance,
                'currency': account.currency,
                'transaction_count': transaction_count,
                'total_income': total_income,
                'total_expense': total_expense,
                'total_transfer': total_transfer,
                'net_balance': total_income - total_expense,
                'transactions': recent_transactions,  # Only include recent transactions
                'income_count': income_count,
                'expense_count': expense_count,
            }

        except Exception as e:
            logger.error(f"Error getting account summary: {str(e)}")
            return None

    @staticmethod
    def get_user_accounts(session: Session, user_id: int) -> List[Account]:
        """
        Get all accounts for a user.

        Args:
            session (Session): Database session.
            user_id (int): User ID.

        Returns:
            List[Account]: List of user's accounts.
        """
        try:
            accounts = session.query(Account).filter(
                Account.user_id == user_id
            ).all()

            return accounts

        except Exception as e:
            logger.error(f"Error getting user accounts: {str(e)}")
            return []

    @staticmethod
    def update_transaction(session: Session, transaction_id: int, transaction_data: Dict[str, Any]) -> Optional[Transaction]:
        """
        Update an existing transaction.

        Args:
            session (Session): Database session.
            transaction_id (int): ID of the transaction to update.
            transaction_data (Dict[str, Any]): Updated transaction data.

        Returns:
            Optional[Transaction]: Updated transaction or None if update fails.
        """
        try:
            transaction = session.query(Transaction).filter(
                Transaction.id == transaction_id
            ).first()

            if not transaction:
                logger.error(f"Transaction {transaction_id} not found")
                return None

            # Get the old amount and transaction type for balance adjustment
            old_amount = transaction.amount
            old_type = transaction.transaction_type

            # Update transaction fields
            for key, value in transaction_data.items():
                if key == 'transaction_type':
                    try:
                        value = TransactionType(value.lower())
                    except ValueError:
                        value = TransactionType.UNKNOWN

                if hasattr(transaction, key):
                    setattr(transaction, key, value)

            # Update the account balance if amount or transaction type changed
            if 'amount' in transaction_data or 'transaction_type' in transaction_data:
                account = transaction.account

                # Revert the old transaction's effect on balance
                if old_type == TransactionType.INCOME:
                    account.balance -= old_amount
                elif old_type == TransactionType.EXPENSE:
                    account.balance += old_amount

                # Apply the new transaction's effect on balance
                if transaction.transaction_type == TransactionType.INCOME:
                    account.balance += transaction.amount
                elif transaction.transaction_type == TransactionType.EXPENSE:
                    account.balance -= transaction.amount

            session.commit()
            logger.info(f"Updated transaction: {transaction.id}")
            return transaction

        except Exception as e:
            session.rollback()
            logger.error(f"Error updating transaction: {str(e)}")
            return None

    @staticmethod
    def delete_transaction(session: Session, transaction_id: int) -> bool:
        """
        Delete a transaction.

        Args:
            session (Session): Database session.
            transaction_id (int): ID of the transaction to delete.

        Returns:
            bool: True if deletion is successful, False otherwise.
        """
        try:
            transaction = session.query(Transaction).filter(
                Transaction.id == transaction_id
            ).first()

            if not transaction:
                logger.error(f"Transaction {transaction_id} not found")
                return False

            # Update the account balance
            account = transaction.account
            if transaction.transaction_type == TransactionType.INCOME:
                account.balance -= transaction.amount
            elif transaction.transaction_type == TransactionType.EXPENSE:
                account.balance += transaction.amount

            session.delete(transaction)
            session.commit()
            logger.info(f"Deleted transaction: {transaction_id}")
            return True

        except Exception as e:
            session.rollback()
            logger.error(f"Error deleting transaction: {str(e)}")
            return False

    @staticmethod
    def get_transactions_by_date_range(session: Session, user_id: int, account_number: str,
                                       start_date: datetime, end_date: datetime) -> List[Transaction]:
        """
        Get transactions within a date range for an account.

        Args:
            session (Session): Database session.
            user_id (int): User ID.
            account_number (str): Account number.
            start_date (datetime): Start date.
            end_date (datetime): End date.

        Returns:
            List[Transaction]: List of transactions.
        """
        try:
            account = session.query(Account).filter(
                Account.user_id == user_id,
                Account.account_number == account_number
            ).first()

            if not account:
                return []

            transactions = session.query(Transaction).filter(
                Transaction.account_id == account.id,
                Transaction.value_date >= start_date,
                Transaction.value_date <= end_date
            ).order_by(Transaction.value_date.desc()).all()

            return transactions

        except Exception as e:
            logger.error(f"Error getting transactions by date range: {str(e)}")
            return []

    @staticmethod
    def get_account_transaction_history(session: Session, user_id: int, account_number: str,
                                        page: int = 1, per_page: int = 200) -> Dict[str, Any]:
        """
        Get paginated transaction history for an account with HTML-friendly formatting.

        Args:
            session (Session): Database session.
            user_id (int): User ID.
            account_number (str): Account number.
            page (int): Page number (1-based).
            per_page (int): Number of items per page.

        Returns:
            Dict[str, Any]: Dictionary containing transactions and pagination info.
        """
        try:
            account = session.query(Account).filter(
                Account.user_id == user_id,
                Account.account_number == account_number
            ).first()

            if not account:
                return {
                    'transactions': [],
                    'total': 0,
                    'pages': 0,
                    'current_page': page,
                    'per_page': per_page,
                    'account': None
                }

            query = session.query(Transaction).filter(
                Transaction.account_id == account.id
            )

            total = query.count()
            pages = (total + per_page - 1) // per_page

            transactions = query.order_by(Transaction.value_date.desc()) \
                .offset((page - 1) * per_page) \
                .limit(per_page) \
                .all()

            # Convert enum values to uppercase strings for template compatibility
            for transaction in transactions:
                transaction.transaction_type = transaction.transaction_type.value.upper()

            return {
                'transactions': transactions,
                'total': total,
                'pages': pages,
                'current_page': page,
                'per_page': per_page,
                'account': account
            }

        except Exception as e:
            logger.error(f"Error getting account transaction history: {str(e)}")
            return {
                'transactions': [],
                'total': 0,
                'pages': 0,
                'current_page': page,
                'per_page': per_page,
                'account': None
            }
