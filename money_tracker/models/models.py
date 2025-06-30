"""
Database models for the Bank Email Parser & Account Tracker.
"""

import enum
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Enum, Float, Text
from sqlalchemy.orm import relationship, Session
from money_tracker.models.database import Base

logger = logging.getLogger(__name__)

class TransactionType(enum.Enum):
    """Enum for transaction types."""
    INCOME = 'income'
    EXPENSE = 'expense'
    TRANSFER = 'transfer'
    UNKNOWN = 'unknown'

class Account(Base):
    """Account model representing a bank account."""
    __tablename__ = 'accounts'

    id = Column(Integer, primary_key=True)
    account_number = Column(String(50), unique=True, nullable=False)
    bank_name = Column(String(100), nullable=False)
    account_holder = Column(String(100))
    balance = Column(Float, default=0.0)
    currency = Column(String(10), default='OMR')
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship
    transactions = relationship("Transaction", back_populates="account")

class Transaction(Base):
    """Transaction model representing a financial transaction."""
    __tablename__ = 'transactions'

    id = Column(Integer, primary_key=True)
    account_id = Column(Integer, ForeignKey('accounts.id'), nullable=False)
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

    # Email tracking
    email_id = Column(String(100))
    email_date = Column(String(200))

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship
    account = relationship("Account", back_populates="transactions")

class TransactionRepository:
    """Repository class for transaction operations."""

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
            # Check if account already exists
            existing_account = session.query(Account).filter(
                Account.account_number == account_data['account_number']
            ).first()

            if existing_account:
                logger.info(f"Account {account_data['account_number']} already exists")
                return existing_account

            account = Account(
                account_number=account_data['account_number'],
                bank_name=account_data.get('bank_name', 'Unknown'),
                account_holder=account_data.get('account_holder'),
                currency=account_data.get('currency', 'OMR')
            )

            session.add(account)
            session.commit()
            logger.info(f"Created account: {account.account_number}")
            return account

        except Exception as e:
            session.rollback()
            logger.error(f"Error creating account: {str(e)}")
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
            if not account_number:
                logger.error("No account number provided for transaction")
                return None

            account = session.query(Account).filter(
                Account.account_number == account_number
            ).first()

            if not account:
                # Create account if it doesn't exist
                account_data = {
                    'account_number': account_number,
                    'bank_name': transaction_data.get('bank_name', 'Unknown'),
                    'currency': transaction_data.get('currency', 'OMR')
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

            transaction = Transaction(
                account_id=account.id,
                transaction_type=transaction_type,
                amount=transaction_data.get('amount', 0.0),
                currency=transaction_data.get('currency', 'OMR'),
                date_time=transaction_data.get('date_time', datetime.utcnow()),
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
            logger.info(f"Created transaction: {transaction.id}")
            return transaction

        except Exception as e:
            session.rollback()
            logger.error(f"Error creating transaction: {str(e)}")
            return None

    @staticmethod
    def get_account_summary(session: Session, account_number: str) -> Optional[Dict[str, Any]]:
        """
        Get account summary including balance and transaction counts.

        Args:
            session (Session): Database session.
            account_number (str): Account number.

        Returns:
            Optional[Dict[str, Any]]: Account summary or None if not found.
        """
        try:
            account = session.query(Account).filter(
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

            return {
                'account': account,
                'transaction_count': len(transactions),
                'total_income': total_income,
                'total_expense': total_expense,
                'total_transfer': total_transfer,
                'net_balance': total_income - total_expense,
                'transactions': transactions
            }

        except Exception as e:
            logger.error(f"Error getting account summary: {str(e)}")
            return None

    @staticmethod
    def get_transactions_by_date_range(session: Session, account_number: str,
                                       start_date: datetime, end_date: datetime) -> List[Transaction]:
        """
        Get transactions within a date range for an account.

        Args:
            session (Session): Database session.
            account_number (str): Account number.
            start_date (datetime): Start date.
            end_date (datetime): End date.

        Returns:
            List[Transaction]: List of transactions.
        """
        try:
            account = session.query(Account).filter(
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