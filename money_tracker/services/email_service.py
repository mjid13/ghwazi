"""
Email service for connecting to email accounts and retrieving bank emails.
"""

import imaplib
import email
from email.header import decode_header
import logging
from typing import List, Dict, Any, Optional
import re

from money_tracker.config import settings

logger = logging.getLogger(__name__)

class EmailService:
    """Service for connecting to email accounts and retrieving bank emails."""

    def __init__(self, host=None, port=None, username=None, password=None, use_ssl=None, 
                 bank_email_addresses=None, bank_email_subjects=None):
        """
        Initialize the email service with settings from config or custom parameters.

        Args:
            host (str, optional): Email server host. Defaults to settings.EMAIL_HOST.
            port (int, optional): Email server port. Defaults to settings.EMAIL_PORT.
            username (str, optional): Email username. Defaults to settings.EMAIL_USERNAME.
            password (str, optional): Email password. Defaults to settings.EMAIL_PASSWORD.
            use_ssl (bool, optional): Whether to use SSL. Defaults to settings.EMAIL_USE_SSL.
            bank_email_addresses (list, optional): List of bank email addresses. Defaults to settings.BANK_EMAIL_ADDRESSES.
            bank_email_subjects (list, optional): List of bank email subjects. Defaults to settings.BANK_EMAIL_SUBJECTS.
        """
        self.host = host if host is not None else settings.EMAIL_HOST
        self.port = port if port is not None else settings.EMAIL_PORT
        self.username = username if username is not None else settings.EMAIL_USERNAME
        self.password = password if password is not None else settings.EMAIL_PASSWORD
        self.use_ssl = use_ssl if use_ssl is not None else settings.EMAIL_USE_SSL
        self.bank_email_addresses = bank_email_addresses if bank_email_addresses is not None else settings.BANK_EMAIL_ADDRESSES
        self.bank_email_subjects = bank_email_subjects if bank_email_subjects is not None else settings.BANK_EMAIL_SUBJECTS
        self.connection = None

    def connect(self) -> bool:
        """
        Connect to the email server.

        Returns:
            bool: True if connection is successful, False otherwise.
        """
        try:
            if self.use_ssl:
                self.connection = imaplib.IMAP4_SSL(self.host, self.port)
            else:
                self.connection = imaplib.IMAP4(self.host, self.port)

            self.connection.login(self.username, self.password)
            logger.info(f"Successfully connected to {self.host}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to {self.host}: {str(e)}")
            return False

    def disconnect(self) -> None:
        """Disconnect from the email server."""
        if self.connection:
            try:
                self.connection.logout()
                logger.info(f"Disconnected from {self.host}")
            except Exception as e:
                logger.error(f"Error during disconnect: {str(e)}")
            finally:
                self.connection = None

    def get_bank_emails(self, folder: str = "INBOX", unread_only: bool = True) -> List[Dict[str, Any]]:
        """
        Retrieve bank emails from the specified folder.

        Args:
            folder (str): Email folder to search in.
            unread_only (bool): If True, only fetch unread emails.

        Returns:
            List[Dict[str, Any]]: List of email data dictionaries.
        """
        if not self.connection:
            if not self.connect():
                return []

        try:
            # Select the mailbox
            status, messages = self.connection.select(folder)
            if status != 'OK':
                logger.error(f"Failed to select folder {folder}")
                return []

            # Create search criteria
            search_criteria = []
            if unread_only:
                search_criteria.append('UNSEEN')

            # Add FROM criteria for bank email addresses
            from_criteria = []
            for address in self.bank_email_addresses:
                from_criteria.append(f'FROM "{address}"')

            if from_criteria:
                search_criteria.append(f"({' OR '.join(from_criteria)})")

            # Execute search
            search_query = ' '.join(search_criteria)
            status, data = self.connection.search(None, search_query)
            if status != 'OK':
                logger.error(f"Failed to search emails with criteria: {search_query}")
                return []

            email_ids = data[0].split()
            logger.info(f"Found {len(email_ids)} potential bank emails")

            # Fetch and process emails
            emails = []
            for email_id in email_ids:
                email_data = self._fetch_email(email_id)
                if email_data and self._is_bank_email(email_data):
                    emails.append(email_data)

            logger.info(f"Retrieved {len(emails)} bank emails")
            return emails
        except Exception as e:
            logger.error(f"Error retrieving bank emails: {str(e)}")
            return []

    def _fetch_email(self, email_id: bytes) -> Optional[Dict[str, Any]]:
        """
        Fetch and parse an email by ID.

        Args:
            email_id (bytes): Email ID to fetch.

        Returns:
            Optional[Dict[str, Any]]: Email data dictionary or None if error.
        """
        try:
            status, data = self.connection.fetch(email_id, '(RFC822)')
            if status != 'OK':
                logger.error(f"Failed to fetch email {email_id}")
                return None

            raw_email = data[0][1]
            msg = email.message_from_bytes(raw_email)

            # Extract basic email information
            subject = self._decode_header(msg['Subject'])
            from_addr = self._decode_header(msg['From'])
            date = msg['Date']

            # Extract email body
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))

                    # Skip attachments
                    if "attachment" in content_disposition:
                        continue

                    # Get text content
                    if content_type == "text/plain":
                        try:
                            body_part = part.get_payload(decode=True).decode()
                            body += body_part
                        except Exception as e:
                            logger.warning(f"Error decoding email part: {str(e)}")
            else:
                # Not multipart - get payload directly
                try:
                    body = msg.get_payload(decode=True).decode()
                except Exception as e:
                    logger.warning(f"Error decoding email body: {str(e)}")

            return {
                'id': email_id.decode(),
                'subject': subject,
                'from': from_addr,
                'date': date,
                'body': body,
                'raw_message': msg
            }
        except Exception as e:
            logger.error(f"Error processing email {email_id}: {str(e)}")
            return None

    def _is_bank_email(self, email_data: Dict[str, Any]) -> bool:
        """
        Check if an email is from the bank based on sender and subject.

        Args:
            email_data (Dict[str, Any]): Email data dictionary.

        Returns:
            bool: True if it's a bank email, False otherwise.
        """
        # Check sender
        from_addr = email_data.get('from', '').lower()
        for bank_email in self.bank_email_addresses:
            if bank_email.lower() in from_addr:
                return True

        # Check subject for keywords
        subject = email_data.get('subject', '').lower()
        for keyword in self.bank_email_subjects:
            if keyword.lower() in subject:
                return True

        # Check body for bank-specific patterns
        body = email_data.get('body', '').lower()
        bank_patterns = [
            r'bank\s*muscat',
            r'transaction',
            r'account\s*number',
            r'amount\s*:',
            r'omr\s*\d+',
            r'debit\s*card',
            r'credit\s*card',
            r'balance'
        ]

        for pattern in bank_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return True

        return False

    def _decode_header(self, header: Optional[str]) -> str:
        """
        Decode email header.

        Args:
            header (Optional[str]): Email header to decode.

        Returns:
            str: Decoded header.
        """
        if not header:
            return ""

        decoded_header = ""
        try:
            decoded_parts = decode_header(header)
            for part, encoding in decoded_parts:
                if isinstance(part, bytes):
                    if encoding:
                        decoded_header += part.decode(encoding)
                    else:
                        decoded_header += part.decode()
                else:
                    decoded_header += part
            return decoded_header
        except Exception as e:
            logger.warning(f"Error decoding header: {str(e)}")
            return header
