"""
Database models for the Bank Email Parser & Account Tracker.
"""

import logging
from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, Text, Enum
from sqlalchemy.orm import relationship
import enum

from money_tracker.models.database import Base

logger = logging.getLogger(__name__)

class TransactionType(enum.Enum):
    """Enum for transaction types."""
    INCOME = 'income'
    EXPENSE = 'expense'
    TRANSFER = 'transfer'
    UNKNOWN = 'unknown'

class Account(Base):
    """Model for bank accounts."""
    __tablename__ = 'accounts'
    
    id = Column(Integer, primary_key=True)
    account_number = Column(String(50), unique=True, nullable=False)
    bank_name = Column(String(100), nullable=False)
    current_balance = Column(Float, default=0.0)
    currency = Column(String(10), default='OMR')
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    transactions = relationship('Transaction', back_populates='account')
    
    def __repr__(self):
        return f"<Account(id={self.id}, account_number={self.account_number}, bank_name={self.bank_name})>"
    
    def update_balance(self, session):
        """
        Update the account balance based on all transactions.
        
        Args:
            session: Database session.
            
        Returns:
            float: Updated balance.
        """
        try:
            # Get all transactions for this account
            transactions = session.query(Transaction).filter(
                Transaction.account_id == self.id
            ).all()
            
            # Calculate balance
            balance = 0.0
            for transaction in transactions:
                if transaction.transaction_type == TransactionType.INCOME.value:
                    balance += transaction.amount
                elif transaction.transaction_type == TransactionType.EXPENSE.value:
                    balance -= transaction.amount
                # For transfers, we need to check if it's incoming or outgoing
                elif transaction.transaction_type == TransactionType.TRANSFER.value:
                    # If this account is the receiver, add the amount
                    if transaction.transaction_receiver and self.account_number in transaction.transaction_receiver:
                        balance += transaction.amount
                    # If this account is the sender, subtract the amount
                    elif transaction.transaction_sender and self.account_number in transaction.transaction_sender:
                        balance -= transaction.amount
            
            # Update balance
            self.current_balance = balance
            self.updated_at = datetime.utcnow()
            session.commit()
            
            logger.info(f"Updated balance for account {self.account_number}: {self.current_balance} {self.currency}")
            return self.current_balance
        except Exception as e:
            logger.error(f"Error updating balance for account {self.account_number}: {str(e)}")
            session.rollback()
            return self.current_balance

class Transaction(Base):
    """Model for bank transactions."""
    __tablename__ = 'transactions'
    
    id = Column(Integer, primary_key=True)
    transaction_id = Column(String(100), unique=True, nullable=True)
    account_id = Column(Integer, ForeignKey('accounts.id'), nullable=False)
    transaction_type = Column(String(20), nullable=False)
    amount = Column(Float, nullable=False)
    currency = Column(String(10), default='OMR')
    date_time = Column(DateTime, nullable=True)
    transaction_sender = Column(String(255), nullable=True)
    transaction_receiver = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    country = Column(String(100), nullable=True)
    email_id = Column(String(100), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    account = relationship('Account', back_populates='transactions')
    
    def __repr__(self):
        return f"<Transaction(id={self.id}, type={self.transaction_type}, amount={self.amount})>"

class TransactionRepository:
    """Repository for transaction operations."""
    
    @staticmethod
    def get_or_create_account(session, account_number, bank_name, currency='OMR'):
        """
        Get an existing account or create a new one if it doesn't exist.
        
        Args:
            session: Database session.
            account_number (str): Account number.
            bank_name (str): Bank name.
            currency (str, optional): Currency. Defaults to 'OMR'.
            
        Returns:
            Account: Account object.
        """
        try:
            # Try to find existing account
            account = session.query(Account).filter(
                Account.account_number == account_number
            ).first()
            
            # Create new account if it doesn't exist
            if not account:
                account = Account(
                    account_number=account_number,
                    bank_name=bank_name,
                    currency=currency
                )
                session.add(account)
                session.commit()
                logger.info(f"Created new account: {account_number}")
            
            return account
        except Exception as e:
            logger.error(f"Error getting or creating account {account_number}: {str(e)}")
            session.rollback()
            return None
    
    @staticmethod
    def create_transaction(session, transaction_data):
        """
        Create a new transaction.
        
        Args:
            session: Database session.
            transaction_data (dict): Transaction data.
            
        Returns:
            Transaction: Created transaction object or None if error.
        """
        try:
            # Get or create account
            account = TransactionRepository.get_or_create_account(
                session,
                transaction_data.get('account_number'),
                transaction_data.get('bank_name', 'Bank Muscat'),
                transaction_data.get('currency', 'OMR')
            )
            
            if not account:
                logger.error("Failed to get or create account")
                return None
            
            # Check if transaction already exists
            if transaction_data.get('transaction_id'):
                existing_transaction = session.query(Transaction).filter(
                    Transaction.transaction_id == transaction_data.get('transaction_id')
                ).first()
                
                if existing_transaction:
                    logger.info(f"Transaction {transaction_data.get('transaction_id')} already exists")
                    return existing_transaction
            
            # Create new transaction
            transaction = Transaction(
                transaction_id=transaction_data.get('transaction_id'),
                account_id=account.id,
                transaction_type=transaction_data.get('transaction_type'),
                amount=transaction_data.get('amount'),
                currency=transaction_data.get('currency', 'OMR'),
                date_time=transaction_data.get('date_time'),
                transaction_sender=transaction_data.get('transaction_sender'),
                transaction_receiver=transaction_data.get('transaction_receiver'),
                description=transaction_data.get('description'),
                country=transaction_data.get('country'),
                email_id=transaction_data.get('email_id')
            )
            
            session.add(transaction)
            session.commit()
            
            # Update account balance
            account.update_balance(session)
            
            logger.info(f"Created new transaction: {transaction.id}")
            return transaction
        except Exception as e:
            logger.error(f"Error creating transaction: {str(e)}")
            session.rollback()
            return None
    
    @staticmethod
    def get_account_summary(session, account_number):
        """
        Get summary of an account including balance and transaction counts.
        
        Args:
            session: Database session.
            account_number (str): Account number.
            
        Returns:
            dict: Account summary.
        """
        try:
            # Get account
            account = session.query(Account).filter(
                Account.account_number == account_number
            ).first()
            
            if not account:
                logger.warning(f"Account {account_number} not found")
                return None
            
            # Get transaction counts
            income_count = session.query(Transaction).filter(
                Transaction.account_id == account.id,
                Transaction.transaction_type == TransactionType.INCOME.value
            ).count()
            
            expense_count = session.query(Transaction).filter(
                Transaction.account_id == account.id,
                Transaction.transaction_type == TransactionType.EXPENSE.value
            ).count()
            
            transfer_count = session.query(Transaction).filter(
                Transaction.account_id == account.id,
                Transaction.transaction_type == TransactionType.TRANSFER.value
            ).count()
            
            # Get total income and expense
            income_total = session.query(Transaction).filter(
                Transaction.account_id == account.id,
                Transaction.transaction_type == TransactionType.INCOME.value
            ).with_entities(
                Transaction.amount
            ).all()
            
            expense_total = session.query(Transaction).filter(
                Transaction.account_id == account.id,
                Transaction.transaction_type == TransactionType.EXPENSE.value
            ).with_entities(
                Transaction.amount
            ).all()
            
            # Calculate totals
            income_sum = sum(amount[0] for amount in income_total) if income_total else 0
            expense_sum = sum(amount[0] for amount in expense_total) if expense_total else 0
            
            return {
                'account_number': account.account_number,
                'bank_name': account.bank_name,
                'current_balance': account.current_balance,
                'currency': account.currency,
                'income_count': income_count,
                'expense_count': expense_count,
                'transfer_count': transfer_count,
                'income_total': income_sum,
                'expense_total': expense_sum,
                'last_updated': account.updated_at
            }
        except Exception as e:
            logger.error(f"Error getting account summary for {account_number}: {str(e)}")
            return None