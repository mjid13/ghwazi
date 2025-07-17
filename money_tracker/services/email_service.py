"""
Email service for connecting to email accounts and retrieving bank emails.
"""

import imaplib
import email
from email.header import decode_header
import logging
from typing import List, Dict, Any, Optional
import re
import socket
import ssl
import time

from money_tracker.config import settings

from money_tracker.models.models import Account, EmailConfiguration

logger = logging.getLogger(__name__)

class EmailService:
    """Service for connecting to email accounts and retrieving bank emails."""

    def __init__(self, host=None, port=None, username=None, password=None, use_ssl=None,
                 bank_email_addresses=None, bank_email_subjects=None, user_id=None, user_accounts=None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.use_ssl = use_ssl
        self.bank_email_addresses = bank_email_addresses
        self.bank_email_subjects = bank_email_subjects
        self.user_id = user_id
        self.user_accounts = user_accounts or []  # List of user's bank accounts
        self.connection = None
        self.max_retries = 3
        self.retry_delay = 2  # seconds
        logger.debug("Initialized EmailService with host=%s, port=%s, username=%s, use_ssl=%s",
                     self.host, self.port, self.username, self.use_ssl)

    def connect(self) -> bool:
        """
        Connect to the email server with retry logic.

        Returns:
            bool: True if connection is successful, False otherwise.
        """
        for attempt in range(self.max_retries):
            try:
                logger.debug("Attempting to connect to server %s:%s with SSL=%s (attempt %d/%d)",
                             self.host, self.port, self.use_ssl, attempt + 1, self.max_retries)

                if self.use_ssl:
                    # Create SSL context with more flexible settings
                    context = ssl.create_default_context()
                    # Allow older TLS versions if needed
                    context.minimum_version = ssl.TLSVersion.TLSv1_2
                    # Set timeout for socket operations
                    self.connection = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=context)
                    # Set socket timeout
                    self.connection.sock.settimeout(60)
                else:
                    self.connection = imaplib.IMAP4(self.host, self.port)
                    # Set socket timeout
                    self.connection.sock.settimeout(60)

                self.connection.login(self.username, self.password)
                logger.info(f"Successfully connected to {self.host}")
                return True

            except (socket.error, ssl.SSLError, imaplib.IMAP4.error) as e:
                logger.warning(f"Connection attempt {attempt + 1} failed: {str(e)}")
                if attempt < self.max_retries - 1:
                    logger.info(f"Retrying in {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)
                    # Increase delay for next retry
                    self.retry_delay *= 2
                else:
                    logger.error(f"All connection attempts failed for {self.host}")

            except Exception as e:
                logger.error(f"Unexpected error during connection: {str(e)}")
                logger.debug("Exception in connect: ", exc_info=True)
                break

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

    def _reconnect_if_needed(self) -> bool:
        """
        Check if connection is still alive and reconnect if necessary.

        Returns:
            bool: True if connection is available, False otherwise.
        """
        if not self.connection:
            return self.connect()

        try:
            # Try a simple NOOP command to check if connection is alive
            self.connection.noop()
            return True
        except Exception as e:
            logger.warning(f"Connection seems to be dead: {str(e)}")
            self.connection = None
            return self.connect()

    def get_bank_emails(self, folder: str = "INBOX", unread_only: bool = True) -> List[Dict[str, Any]]:
        """
        Retrieve bank emails from the specified folder.

        Args:
            folder (str): Email folder to search in.
            unread_only (bool): If True, only fetch unread emails.

        Returns:
            List[Dict[str, Any]]: List of email data dictionaries.
        """
        if not self._reconnect_if_needed():
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
                if email_data:
                    emails.append(email_data)

            logger.info(f"Retrieved {len(emails)} bank emails")
            return emails
        except Exception as e:
            logger.error(f"Error retrieving bank emails: {str(e)}")
            logger.debug("Exception in get_bank_emails: ", exc_info=True)
            return []

def _fetch_email(self, email_id: bytes) -> Optional[Dict[str, Any]]:
    """
    Fetch and parse an email by ID with retry logic.

    Args:
        email_id (bytes): Email ID to fetch.

    Returns:
        Optional[Dict[str, Any]]: Email data dictionary or None if error.
    """
    for attempt in range(self.max_retries):
        try:
            logger.debug("Fetching email using ID: %s (attempt %d/%d)",
                         email_id, attempt + 1, self.max_retries)

            # Check connection before fetching
            if not self._reconnect_if_needed():
                logger.error("Cannot establish connection for email fetch")
                return None

            status, data = self.connection.fetch(email_id, '(RFC822)')
            logger.debug("Fetch status: %s, data length: %d", status, len(data) if data else 0)

            if status != 'OK':
                logger.error(f"Failed to fetch email {email_id}")
                # Try with different fetch parameters on next attempt
                if attempt < self.max_retries - 1:
                    logger.info("Retrying with different fetch parameters...")
                    time.sleep(self.retry_delay)
                    continue
                return None

            # Validate the response structure
            if not data or len(data) == 0:
                logger.error(f"Empty response for email {email_id}")
                if attempt < self.max_retries - 1:
                    logger.info("Retrying due to empty response...")
                    time.sleep(self.retry_delay)
                    continue
                return None

            # Check if we have the expected tuple structure
            if not isinstance(data[0], tuple) or len(data[0]) < 2:
                logger.error(f"Unexpected response structure for email {email_id}: {type(data[0])}")
                if attempt < self.max_retries - 1:
                    logger.info("Retrying due to unexpected response structure...")
                    time.sleep(self.retry_delay)
                    continue
                return None

            raw_email = data[0][1]

            # Validate that raw_email is bytes
            if not isinstance(raw_email, bytes):
                logger.error(f"Expected bytes for raw email data, got {type(raw_email)} for email {email_id}")

                # Try alternative fetch methods on retry
                if attempt < self.max_retries - 1:
                    logger.info("Retrying with alternative fetch method...")
                    time.sleep(self.retry_delay)

                    # Try different fetch approaches
                    try:
                        # Method 1: Try fetching with BODY[] instead of RFC822
                        logger.debug("Attempting fetch with BODY[] method")
                        status, alt_data = self.connection.fetch(email_id, '(BODY[])')
                        if status == 'OK' and alt_data and len(alt_data) > 0:
                            if isinstance(alt_data[0], tuple) and len(alt_data[0]) >= 2:
                                alt_raw_email = alt_data[0][1]
                                if isinstance(alt_raw_email, bytes):
                                    raw_email = alt_raw_email
                                    logger.debug("Successfully fetched with BODY[] method")
                                    # Continue with processing
                                else:
                                    logger.debug("BODY[] method also returned non-bytes data")
                                    continue

                    except Exception as e:
                        logger.warning(f"Alternative fetch method failed: {str(e)}")
                        continue
                else:
                    return None

            # Try to parse the email
            try:
                msg = email.message_from_bytes(raw_email)
            except Exception as e:
                logger.error(f"Failed to parse email message: {str(e)}")
                if attempt < self.max_retries - 1:
                    logger.info("Retrying email parsing...")
                    time.sleep(self.retry_delay)
                    continue
                return None

            # Extract email components with error handling
            try:
                subject = self._decode_header(msg['Subject'])
                from_addr = self._decode_header(msg['From'])
                date = msg['Date']
            except Exception as e:
                logger.error(f"Failed to extract email headers: {str(e)}")
                if attempt < self.max_retries - 1:
                    logger.info("Retrying header extraction...")
                    time.sleep(self.retry_delay)
                    continue
                return None

            # Extract body with error handling
            body = ""
            try:
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
                                body_part = part.get_payload(decode=True)
                                if body_part:
                                    if isinstance(body_part, bytes):
                                        body += body_part.decode('utf-8', errors='ignore')
                                    else:
                                        body += str(body_part)
                            except Exception as e:
                                logger.warning(f"Error decoding email part: {str(e)}")
                                logger.debug("Exception in decoding multipart: ", exc_info=True)
                else:
                    # Not multipart - get payload directly
                    try:
                        payload = msg.get_payload(decode=True)
                        if payload:
                            if isinstance(payload, bytes):
                                body = payload.decode('utf-8', errors='ignore')
                            else:
                                body = str(payload)
                    except Exception as e:
                        logger.warning(f"Error decoding email body: {str(e)}")
                        logger.debug("Exception in non-multipart decoding: ", exc_info=True)
            except Exception as e:
                logger.error(f"Failed to extract email body: {str(e)}")
                if attempt < self.max_retries - 1:
                    logger.info("Retrying body extraction...")
                    time.sleep(self.retry_delay)
                    continue
                # Return partial data if body extraction fails but headers are available
                body = ""

            # Successfully parsed email
            email_data = {
                'id': email_id.decode(),
                'subject': subject,
                'from': from_addr,
                'date': date,
                'body': body,
                'raw_message': msg
            }

            logger.debug("Successfully parsed email %s", email_id)
            return email_data

        except (socket.error, ssl.SSLError, imaplib.IMAP4.abort) as e:
            logger.warning(f"Network error fetching email {email_id} (attempt {attempt + 1}): {str(e)}")
            if attempt < self.max_retries - 1:
                logger.info(f"Retrying email fetch in {self.retry_delay} seconds...")
                time.sleep(self.retry_delay)
                # Reset connection on network errors
                self.connection = None
            else:
                logger.error(f"All fetch attempts failed for email {email_id}")

        except Exception as e:
            logger.error(f"Unexpected error processing email {email_id}: {str(e)}")
            logger.debug("Exception in _fetch_email: ", exc_info=True)
            if attempt < self.max_retries - 1:
                logger.info(f"Retrying due to unexpected error in {self.retry_delay} seconds...")
                time.sleep(self.retry_delay)
            else:
                logger.error(f"All retry attempts exhausted for email {email_id}")
                break

    return None

    def _is_bank_email(self, email_data: Dict[str, Any]) -> bool:
        """
        Check if an email is from the bank based on sender and subject.
        If user_accounts are provided, also check if the email is related to one of the user's accounts.

        Args:
            email_data (Dict[str, Any]): Email data dictionary.

        Returns:
            bool: True if it's a bank email related to user's accounts, False otherwise.
        """
        is_from_bank = False

        # ** no need to check check sender ***

        # from_addr = email_data.get('from', '').lower()
        # logger.debug("Checking if email is bank email, from: %s", from_addr)
        # for bank_email in self.bank_email_addresses:
        #     if bank_email.lower() in from_addr:
        #         logger.debug("Email matched by bank address: %s", bank_email)
        #         is_from_bank = True
        #         break

        if not is_from_bank:
            # Check subject for keywords
            subject = email_data.get('subject', '').lower()
            logger.debug("Checking for keywords in subject: %s", subject)
            for keyword in self.bank_email_subjects:
                if keyword.lower() in subject:
                    logger.debug("Email matched by subject keyword: %s", keyword)
                    is_from_bank = True
                    break

        if not is_from_bank:
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
                    is_from_bank = True
                    break

        # If not from a bank or no user accounts to filter by, return the result
        if not is_from_bank or not self.user_accounts:
            if not is_from_bank:
                logger.debug("Email did not match bank criteria")
            return is_from_bank

        # If we have user accounts, check if the email is related to one of them
        body = email_data.get('body', '').lower()
        for account in self.user_accounts:
            # Check for account number in the email body
            account_number = account.account_number.lower()
            if account_number in body:
                logger.debug(f"Email matched user account: {account_number}")
                return True

            # Check for bank name in the email body
            bank_name = account.bank_name.lower()
            if bank_name in body:
                logger.debug(f"Email matched user bank: {bank_name}")
                return True

        logger.debug("Email is from a bank but not related to user's accounts")
        return False

    @classmethod
    def from_user_config(cls, session, user_id: int) -> Optional['EmailService']:
        """
        Create an EmailService instance from a user's email configuration.

        Args:
            session: Database session.
            user_id (int): User ID.

        Returns:
            Optional[EmailService]: EmailService instance or None if configuration not found.
        """
        try:
            from money_tracker.models.models import EmailConfiguration, Account, TransactionRepository

            # Get user's email configuration
            email_config = session.query(EmailConfiguration).filter(
                EmailConfiguration.user_id == user_id
            ).first()

            if not email_config:
                logger.error(f"No email configuration found for user {user_id}")
                return None

            # Get user's accounts
            user_accounts = TransactionRepository.get_user_accounts(session, user_id)

            # Create bank email addresses and subjects lists from comma-separated strings
            bank_email_addresses = []
            if email_config.bank_email_addresses:
                bank_email_addresses = [addr.strip() for addr in email_config.bank_email_addresses.split(',')]

            bank_email_subjects = []
            if email_config.bank_email_subjects:
                bank_email_subjects = [subj.strip() for subj in email_config.bank_email_subjects.split(',')]

            # Create EmailService instance
            email_service = cls(
                host=email_config.email_host,
                port=email_config.email_port,
                username=email_config.email_username,
                password=email_config.email_password,
                use_ssl=email_config.email_use_ssl,
                bank_email_addresses=bank_email_addresses,
                bank_email_subjects=bank_email_subjects,
                user_id=user_id,
                user_accounts=user_accounts
            )

            return email_service

        except Exception as e:
            logger.error(f"Error creating EmailService from user config: {str(e)}")
            return None

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