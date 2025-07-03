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
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Check password against hash."""
        return check_password_hash(self.password_hash, password)

class EmailConfiguration(Base):
    """Email configuration model for storing user's email settings."""
    __tablename__ = 'email_configurations'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    email_host = Column(String(100), nullable=False)
    email_port = Column(Integer, nullable=False)
    email_username = Column(String(100), nullable=False)
    email_password = Column(String(200), nullable=False)  # Should be encrypted in production
    email_use_ssl = Column(Boolean, default=True)
    bank_email_addresses = Column(Text)  # Comma-separated list
    bank_email_subjects = Column(Text)  # Comma-separated list
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship
    user = relationship("User", back_populates="email_configs")

class Account(Base):
    """Account model representing a bank account."""
    __tablename__ = 'accounts'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    account_number = Column(String(50), nullable=False)
    bank_name = Column(String(100), nullable=False)
    account_holder = Column(String(100))
    balance = Column(Float, default=0.0)
    currency = Column(String(10), default='OMR')
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="accounts")
    transactions = relationship("Transaction", back_populates="account")

    # Composite unique constraint for user_id and account_number
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
    processed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User")
    transactions = relationship("Transaction", back_populates="email_metadata")

class Transaction(Base):
    """Transaction model representing a financial transaction."""
    __tablename__ = 'transactions'

    id = Column(Integer, primary_key=True)
    account_id = Column(Integer, ForeignKey('accounts.id'), nullable=False)
    email_metadata_id = Column(Integer, ForeignKey('email_metadata.id'), nullable=True)
    transaction_type = Column(Enum(TransactionType), nullable=False)
    amount = Column(Float, nullable=False)
    currency = Column(String(10), default='OMR')
    date_time = Column(DateTime, nullable=False)
    description = Column(Text)
    transaction_id = Column(String(100))  # Bank's transaction reference

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
    email_date = Column(String(200))

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    account = relationship("Account", back_populates="transactions")
    email_metadata = relationship("EmailMetadata", back_populates="transactions")

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
            # Check if user already exists
            existing_user = session.query(User).filter(
                (User.username == user_data['username']) | (User.email == user_data['email'])
            ).first()

            if existing_user:
                logger.info(f"User {user_data['username']} or email {user_data['email']} already exists")
                return None

            user = User(
                username=user_data['username'],
                email=user_data['email']
            )
            user.set_password(user_data['password'])

            session.add(user)
            session.commit()
            logger.info(f"Created user: {user.username}")
            return user

        except Exception as e:
            session.rollback()
            logger.error(f"Error creating user: {str(e)}")
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
                currency=account_data.get('currency', 'OMR')
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

            account = session.query(Account).filter(
                Account.user_id == user_id,
                Account.account_number == account_number
            ).first()

            if not account:
                # Create account if it doesn't exist
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
                date_time=transaction_data.get('date_time', None),
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
                email_date=transaction_data.get('email_date')
            )

            session.add(transaction)
            session.commit()

            # Update account balance
            if transaction_type == TransactionType.INCOME:
                account.balance += transaction.amount
            elif transaction_type == TransactionType.EXPENSE:
                account.balance -= transaction.amount
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

            transactions = session.query(Transaction).filter(
                Transaction.account_id == account.id
            ).all()

            total_income = sum(t.amount for t in transactions if t.transaction_type == TransactionType.INCOME)
            total_expense = sum(t.amount for t in transactions if t.transaction_type == TransactionType.EXPENSE)
            total_transfer = sum(t.amount for t in transactions if t.transaction_type == TransactionType.TRANSFER)
            income_count = len([t for t in transactions if t.transaction_type == TransactionType.INCOME])
            expense_count = len([t for t in transactions if t.transaction_type == TransactionType.EXPENSE])

            return {
                'account_number': account.account_number,
                'bank_name': account.bank_name,
                'account_holder': account.account_holder,
                'balance': account.balance,
                'currency': account.currency,
                'transaction_count': len(transactions),
                'total_income': total_income,
                'total_expense': total_expense,
                'total_transfer': total_transfer,
                'net_balance': total_income - total_expense,
                'transactions': transactions,
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
                Transaction.date_time >= start_date,
                Transaction.date_time <= end_date
            ).order_by(Transaction.date_time.desc()).all()

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

            transactions = query.order_by(Transaction.date_time.desc()) \
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
