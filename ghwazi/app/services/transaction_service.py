"""
Transaction service for processing emails and storing transaction data.
"""

import logging
from typing import Any, Dict, List, Optional

from app.models.database import Database
from app.models.transaction import TransactionRepository
from app.services.email_service import EmailService
from app.services.parser_service import TransactionParser

logger = logging.getLogger(__name__)


class TransactionService:
    """Service for processing emails and storing transaction data."""

    def __init__(self):
        """Initialize the transaction service."""
        self.email_service = EmailService()
        self.parser = TransactionParser()
        self.db = Database()
        self.db.connect()
        self.db.create_tables()

    def process_emails(self, folder: str = "INBOX", unread_only: bool = True) -> int:
        """
        Process emails from the specified folder, extract transaction data,
        and store it in the database.

        Args:
            folder (str): Email folder to process.
            unread_only (bool): If True, only process unread emails.

        Returns:
            int: Number of transactions processed.
        """
        try:
            # Get bank emails
            emails = self.email_service.get_bank_emails(folder, unread_only)
            if not emails:
                logger.info("No bank emails found")
                return 0

            logger.info(f"Processing {len(emails)} bank emails")

            # Process each email
            processed_count = 0
            session = self.db.get_session()

            try:
                for email_data in emails:
                    # Parse email
                    transaction_data = self.parser.parse_email(email_data)
                    if not transaction_data:
                        logger.warning(f"Failed to parse email {email_data.get('id')}")
                        continue

                    # Store transaction
                    transaction = TransactionRepository.create_transaction(
                        session, transaction_data
                    )
                    if transaction:
                        processed_count += 1

                logger.info(f"Processed {processed_count} transactions")
                return processed_count
            finally:
                self.db.close_session(session)
        except Exception as e:
            logger.error(f"Error processing emails: {str(e)}")
            return 0

    def get_account_summaries(self) -> List[Dict[str, Any]]:
        """
        Get summaries for all accounts.

        Returns:
            List[Dict[str, Any]]: List of account summaries.
        """
        try:
            session = self.db.get_session()

            try:
                from app.models.models import Account

                # Get all accounts
                accounts = session.query(Account).all()

                # Get summary for each account
                summaries = []
                for account in accounts:
                    summary = TransactionRepository.get_account_summary(
                        session, account.user_id, account.account_number
                    )
                    if summary:
                        summaries.append(summary)

                return summaries
            finally:
                self.db.close_session(session)
        except Exception as e:
            logger.error(f"Error getting account summaries: {str(e)}")
            return []

    def get_account_summary(
        self, account_number: str, user_id: int = 1
    ) -> Optional[Dict[str, Any]]:
        """
        Get summary for a specific account.

        Args:
            account_number (str): Account number.
            user_id (int, optional): User ID. Defaults to 1 for command-line usage.

        Returns:
            Optional[Dict[str, Any]]: Account summary or None if not found.
        """
        try:
            session = self.db.get_session()

            try:
                summary = TransactionRepository.get_account_summary(
                    session, user_id, account_number
                )
                return summary
            finally:
                self.db.close_session(session)
        except Exception as e:
            logger.error(
                f"Error getting account summary for {account_number}: {str(e)}"
            )
            return None

    def close(self):
        """Close connections."""
        try:
            self.email_service.disconnect()
            logger.info("Closed email connection")
        except Exception as e:
            logger.error(f"Error closing email connection: {str(e)}")
