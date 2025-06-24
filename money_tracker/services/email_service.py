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
        self.host = host if host is not None else settings.EMAIL_HOST
        self.port = port if port is not None else settings.EMAIL_PORT
        self.username = username if username is not None else settings.EMAIL_USERNAME
        self.password = password if password is not None else settings.EMAIL_PASSWORD
        self.use_ssl = use_ssl if use_ssl is not None else settings.EMAIL_USE_SSL
        self.bank_email_addresses = bank_email_addresses if bank_email_addresses is not None else settings.BANK_EMAIL_ADDRESSES
        self.bank_email_subjects = bank_email_subjects if bank_email_subjects is not None else settings.BANK_EMAIL_SUBJECTS
        self.connection = None
        logger.debug("Initialized EmailService with host=%s, port=%s, username=%s, use_ssl=%s", 
                     self.host, self.port, self.username, self.use_ssl)

    def connect(self) -> bool:
        """
        Connect to the email server.

        Returns:
            bool: True if connection is successful, False otherwise.
        """
        try:
            logger.debug("Attempting to connect to server %s:%s with SSL=%s", self.host, self.port, self.use_ssl)
            if self.use_ssl:
                self.connection = imaplib.IMAP4_SSL(self.host, self.port)
            else:
                self.connection = imaplib.IMAP4(self.host, self.port)

            self.connection.login(self.username, self.password)
            logger.info(f"Successfully connected to {self.host}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to {self.host}: {str(e)}")
            logger.debug("Exception in connect: ", exc_info=True)
            return False

    def disconnect(self) -> None:
        """Disconnect from the email server."""
        if self.connection:
            try:
                logger.debug("Logging out from server %s", self.host)
                self.connection.logout()
                logger.info(f"Disconnected from {self.host}")
            except Exception as e:
                logger.error(f"Error during disconnect: {str(e)}")
                logger.debug("Exception in disconnect: ", exc_info=True)
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
            logger.debug("No existing email connection. Attempting to connect.")
            if not self.connect():
                logger.debug("Connection attempt failed, returning empty email list.")
                return []

        try:
            logger.debug("Selecting folder '%s'", folder)
            status, messages = self.connection.select(folder)
            logger.debug("Select status: %s, messages: %s", status, messages)
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
                logger.debug("Adding FROM criteria: %s", address)
                from_criteria.append(f'FROM "{address}"')

            if from_criteria:
                logger.debug("Combining search criteria with bank addresses")
                search_criteria.append(f"({' OR '.join(from_criteria)})")

            # Execute search
            search_query = ' '.join(search_criteria)
            logger.debug("Executing search with query: %s", search_query)
            status, data = self.connection.search(None, search_query)
            logger.debug("Search status: %s, data: %s", status, data)
            if status != 'OK':
                logger.error(f"Failed to search emails with criteria: {search_query}")
                return []

            email_ids = data[0].split()
            logger.info(f"Found {len(email_ids)} potential bank emails")

            # Fetch and process emails
            emails = []
            for email_id in email_ids:
                logger.debug("Fetching email ID: %s", email_id)
                email_data = self._fetch_email(email_id)
                if email_data and self._is_bank_email(email_data):
                    logger.debug("Fetched email data for: %s", email_id)
                    emails.append(email_data)

            logger.info(f"Retrieved {len(emails)} bank emails")
            return emails
        except Exception as e:
            logger.error(f"Error retrieving bank emails: {str(e)}")
            logger.debug("Exception in get_bank_emails: ", exc_info=True)
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
            logger.debug("Fetching email using ID: %s", email_id)
            status, data = self.connection.fetch(email_id, '(RFC822)')
            logger.debug("Fetch status: %s, data length: %d", status, len(data) if data else 0)
            if status != 'OK':
                logger.error(f"Failed to fetch email {email_id}")
                return None

            raw_email = data[0][1]
            msg = email.message_from_bytes(raw_email)

            subject = self._decode_header(msg['Subject'])
            from_addr = self._decode_header(msg['From'])
            date = msg['Date']

            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))
                    logger.debug("Email part content_type: %s, content_disposition: %s", content_type, content_disposition)
                    if "attachment" in content_disposition:
                        logger.debug("Skipping attachment part")
                        continue

                    # Get text content
                    if content_type == "text/plain":
                        try:
                            body_part = part.get_payload(decode=True).decode()
                            body += body_part
                        except Exception as e:
                            logger.warning(f"Error decoding email part: {str(e)}")
                            logger.debug("Exception in decoding multipart: ", exc_info=True)
            else:
                # Not multipart - get payload directly
                try:
                    body = msg.get_payload(decode=True).decode()
                except Exception as e:
                    logger.warning(f"Error decoding email body: {str(e)}")
                    logger.debug("Exception in non-multipart decoding: ", exc_info=True)

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
            logger.debug("Exception in _fetch_email: ", exc_info=True)
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
        logger.debug("Checking if email is bank email, from: %s", from_addr)
        for bank_email in self.bank_email_addresses:
            if bank_email.lower() in from_addr:
                logger.debug("Email matched by bank address: %s", bank_email)
                return True

        # Check subject for keywords
        subject = email_data.get('subject', '').lower()
        logger.debug("Checking for keywords in subject: %s", subject)
        for keyword in self.bank_email_subjects:
            if keyword.lower() in subject:
                logger.debug("Email matched by subject keyword: %s", keyword)
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
                logger.debug("Email matched by body pattern: %s", pattern)
                return True

        logger.debug("Email did not match bank criteria")
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
            logger.debug("Decoded header parts: %s", decoded_parts)
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
            logger.debug("Exception in _decode_header: ", exc_info=True)
            return header