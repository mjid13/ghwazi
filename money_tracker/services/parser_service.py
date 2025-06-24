"""
Parser service for extracting transaction data from bank emails.
"""

import re
import logging
import html
from typing import Dict, Any, Optional, List
from datetime import datetime
import dateutil.parser

logger = logging.getLogger(__name__)

class TransactionParser:
    """Parser for extracting transaction data from bank emails."""

    def __init__(self):
        """Initialize the transaction parser."""
        # Define regex patterns for different transaction types
        self.patterns = {
            # Account number pattern - updated to handle "Your account xxxx0027"
            'account_number': r'(?:account\s+(?:number|no|#)\s*[:]\s*|a/c\s+|your\s+account\s+)([a-z0-9]+)',

            # Amount pattern - updated to handle "credited by OMR"
            'amount': r'(?:amount\s*[:]\s*|you\s+have\s+received\s+|you\s+have\s+sent\s+|credited\s+by\s+|debited\s+by\s+)(?:omr|OMR)\s*([0-9,]+(?:\.[0-9]+)?)',

            # Date patterns
            'date': [
                r'(?:date/time|date)\s*[:]\s*([0-9]{1,2}\s+[a-zA-Z]{3}\s+[0-9]{2}\s+[0-9]{1,2}:[0-9]{1,2})',  # 13 MAY 25 17:20
                r'(?:date/time|date)\s*[:]\s*([0-9]{1,2}/[0-9]{1,2}/[0-9]{2,4})',  # 05/02/25
                r'value\s+date\s+([0-9]{1,2}/[0-9]{1,2}/[0-9]{2,4})'  # value date 05/02/25
            ],

            # Transaction ID pattern
            'transaction_id': r'(?:txn\s+id|transaction\s+id|reference)\s+([a-zA-Z0-9]+)',

            # Sender/receiver patterns - updated for transfer emails
            'sender': r'(?:from\s+([a-zA-Z0-9\s]+)\s+in\s+your|(?:transfer.*?\n.*?\n)(.*?)(?:\n|$))',
            'receiver': r'(?:to|received by)\s+([a-zA-Z0-9\s]+)(?:\s+from|\s+using)',

            # Description pattern
            'description': r'description\s*[:]\s*([^\n]+)',

            # Transaction country
            'country': r'transaction\s+country\s*[:]\s*([^\n]+)',
        }

        # Define patterns for identifying transaction types - updated transfer patterns
        self.transaction_type_patterns = {
            'expense': [
                r'debit\s+card.*has\s+been\s+utilised',
                r'you\s+have\s+sent',
                r'has\s+been\s+debited'
            ],
            'income': [
                r'you\s+have\s+received',
            ],
            'transfer': [
                r'transfer',
                r'contribution',
                r'has\s+been\s+credited.*value\s+date',  # For transfer emails with "credited"
                r'has\s+been\s+credited\s+by.*value\s+date'
            ]
        }

        # Bank Muscat specific patterns
        self.bank_muscat_patterns = {
            # Account number patterns - multiple formats
            'account_number': [
                r'your\s+account\s+(xxxx\d+)',
                r'a/c\s+(xxxx\d+)',
                r'account\s+number\s*:\s*(xxxx\d+)'
            ],

            # Amount patterns
            'debit_amount': r'has\s+been\s+debited\s+by\s+OMR\s+([0-9,.]+)',
            'credit_amount': r'has\s+been\s+credited\s+by\s+OMR\s+([0-9,.]+)',
            'received_amount': r'you\s+have\s+received\s+OMR\s+([0-9,.]+)',
            'sent_amount': r'you\s+have\s+sent\s+OMR\s+([0-9,.]+)',
            'card_amount': r'amount\s*:\s*OMR\s+([0-9,.]+)',

            # Date patterns
            'value_date': r'value\s+date\s+(\d{2}/\d{2}/\d{2})',
            'card_date': r'date/time\s*:\s*(\d{1,2}\s+[A-Z]{3}\s+\d{2}\s+\d{1,2}:\d{1,2})',

            # Transaction details
            'transaction_type': r'details.*?reference.*?([A-Z]+)',
            'transaction_id': r'txn\s+id\s+([A-Z0-9]+)',
            'card_description': r'description\s*:\s*([^<\n]+)',

            # Sender/receiver
            'sender': r'from\s+([A-Z][A-Z\s]+[A-Z])\s+in\s+your',
            'receiver': r'to\s+([A-Z][A-Z\s]+[A-Z])\s+from',

            # Branch
            'branch': r'with\s+([\d-]+\s+-\s+[^\s]+)',

            # Transaction details after reference line
            'details_line': r'reference.*?\n([^\n]+)',

            # Name in capital letters (usually sender or receiver)
            'name': r'\n([A-Z][A-Z\s]+[A-Z])\s*\n',
        }

    def parse_email(self, email_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse an email and extract transaction data.

        Args:
            email_data (Dict[str, Any]): Email data dictionary.

        Returns:
            Optional[Dict[str, Any]]: Extracted transaction data or None if parsing fails.
        """
        try:
            body = email_data.get('body', '')
            if not body:
                logger.warning("Email body is empty, cannot parse transaction")
                return None

            # Check if this is a Bank Muscat email with the specific format
            if '=3D' in body and 'bank muscat' in body.lower():
                # Use the specialized Bank Muscat parser
                return self.parse_bank_muscat_email(email_data)

            # For other emails, use the original parsing logic
            return self._parse_generic_email(email_data)

        except Exception as e:
            logger.error(f"Error parsing email: {str(e)}")
            return None

    def _parse_generic_email(self, email_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse a generic email and extract transaction data.

        Args:
            email_data (Dict[str, Any]): Email data dictionary.

        Returns:
            Optional[Dict[str, Any]]: Extracted transaction data or None if parsing fails.
        """
        try:
            body = email_data.get('body', '')

            # Determine transaction type
            transaction_type = self._determine_transaction_type(body)

            # Extract transaction data
            transaction_data = {
                'transaction_type': transaction_type,
                'bank_name': 'Bank Muscat',  # Default based on examples
                'email_id': email_data.get('id'),
                'email_date': email_data.get('date')
            }

            # Extract account number
            account_number = self._extract_pattern(body, self.patterns['account_number'])
            if account_number:
                transaction_data['account_number'] = account_number

            # Extract amount
            amount_str = self._extract_pattern(body, self.patterns['amount'])
            if amount_str:
                # Remove commas and convert to float
                amount = float(amount_str.replace(',', ''))
                transaction_data['amount'] = amount
                transaction_data['currency'] = 'OMR'  # Default based on examples

            # Extract date
            date_str = None
            for date_pattern in self.patterns['date']:
                date_str = self._extract_pattern(body, date_pattern)
                if date_str:
                    break

            if date_str:
                try:
                    # Parse date string to datetime object
                    transaction_date = self._parse_date(date_str)
                    if transaction_date:
                        transaction_data['date_time'] = transaction_date
                except Exception as e:
                    logger.warning(f"Failed to parse date '{date_str}': {str(e)}")

            # Extract transaction ID
            transaction_id = self._extract_pattern(body, self.patterns['transaction_id'])
            if transaction_id:
                transaction_data['transaction_id'] = transaction_id

            # Extract sender/receiver based on transaction type
            if transaction_type == 'income':
                sender = self._extract_pattern(body, self.patterns['sender'])
                if sender:
                    transaction_data['transaction_sender'] = sender.strip()
            elif transaction_type == 'expense':
                receiver = self._extract_pattern(body, self.patterns['receiver'])
                if receiver:
                    transaction_data['transaction_receiver'] = receiver.strip()

                # For expenses, also try to get description
                description = self._extract_pattern(body, self.patterns['description'])
                if description:
                    transaction_data['description'] = description.strip()

                # Get transaction country if available
                country = self._extract_pattern(body, self.patterns['country'])
                if country:
                    transaction_data['country'] = country.strip()

            # For transfers, try to extract both sender and receiver
            if transaction_type == 'transfer':
                # For transfers, extract sender from the end of the email
                lines = body.strip().split('\n')
                # Look for the sender name (usually the last non-empty line)
                for line in reversed(lines):
                    line = line.strip()
                    if line and not line.lower().startswith('kind regards') and not line.lower().startswith('bank'):
                        # This is likely the sender name
                        transaction_data['transaction_sender'] = line
                        break

                # For transfers, also look for description
                # Look for lines after "Transfer" keyword
                for i, line in enumerate(lines):
                    if 'transfer' in line.lower() and i + 1 < len(lines):
                        next_line = lines[i + 1].strip()
                        if next_line and not next_line.upper().isupper():  # Not all caps (likely not name)
                            transaction_data['description'] = next_line
                            break

            # Validate extracted data
            if not self._validate_transaction_data(transaction_data):
                logger.warning("Extracted transaction data is incomplete")
                return None

            return transaction_data
        except Exception as e:
            logger.error(f"Error parsing generic email: {str(e)}")
            return None

    def parse_bank_muscat_email(self, email_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse a Bank Muscat email with the specific format and extract transaction data.

        Args:
            email_data (Dict[str, Any]): Email data dictionary.

        Returns:
            Optional[Dict[str, Any]]: Extracted transaction data or None if parsing fails.
        """
        try:
            body = email_data.get('body', '')

            # Clean up the email body - replace =3D with = and handle line breaks
            body = body.replace('=3D', '=').replace('=\n', '')

            # Convert HTML entities
            body = html.unescape(body)

            # Initialize transaction data
            transaction_data = {
                'bank_name': 'Bank Muscat',
                'email_id': email_data.get('id'),
                'email_date': email_data.get('date'),
                'currency': 'OMR'
            }

            # Extract account number - try each pattern
            account_number = None
            for pattern in self.bank_muscat_patterns['account_number']:
                account_number = self._extract_pattern(body, pattern)
                if account_number:
                    transaction_data['account_number'] = account_number
                    break

            # Determine transaction type and extract amount
            if 'been debited' in body.lower():
                transaction_data['transaction_type'] = 'expense'
                amount_str = self._extract_pattern(body, self.bank_muscat_patterns['debit_amount'])
            elif 'have sent' in body.lower():
                transaction_data['transaction_type'] = 'expense'
                amount_str = self._extract_pattern(body, self.bank_muscat_patterns['sent_amount'])
            elif 'debit card' in body.lower() or 'card number' in body.lower():
                transaction_data['transaction_type'] = 'expense'
                amount_str = self._extract_pattern(body, self.bank_muscat_patterns['card_amount'])
            elif 'been credited' in body.lower():
                transaction_data['transaction_type'] = 'income'
                amount_str = self._extract_pattern(body, self.bank_muscat_patterns['credit_amount'])
            elif 'have received' in body.lower():
                transaction_data['transaction_type'] = 'income'
                amount_str = self._extract_pattern(body, self.bank_muscat_patterns['received_amount'])
            else:
                # Default to transfer if we can't determine the type
                transaction_data['transaction_type'] = 'transfer'
                # Try to find any amount pattern
                for pattern_name in ['credit_amount', 'debit_amount', 'received_amount', 'sent_amount', 'card_amount']:
                    amount_str = self._extract_pattern(body, self.bank_muscat_patterns[pattern_name])
                    if amount_str:
                        break

            # Process amount
            if amount_str:
                # Remove commas and convert to float
                amount = float(amount_str.replace(',', ''))
                transaction_data['amount'] = amount

            # Extract date
            date_str = self._extract_pattern(body, self.bank_muscat_patterns['value_date'])
            if not date_str:
                date_str = self._extract_pattern(body, self.bank_muscat_patterns['card_date'])

            if date_str:
                try:
                    # Parse date string to datetime object
                    transaction_date = self._parse_date(date_str)
                    if transaction_date:
                        transaction_data['date_time'] = transaction_date
                except Exception as e:
                    logger.warning(f"Failed to parse date '{date_str}': {str(e)}")

            # Extract transaction ID
            transaction_id = self._extract_pattern(body, self.bank_muscat_patterns['transaction_id'])
            if transaction_id:
                transaction_data['transaction_id'] = transaction_id

            # Extract description
            description = self._extract_pattern(body, self.bank_muscat_patterns['card_description'])
            if description:
                transaction_data['description'] = description.strip()
            else:
                # Look for transaction details after "reference" line
                details = self._extract_pattern(body, self.bank_muscat_patterns['details_line'])
                if details:
                    transaction_data['description'] = details.strip()

            # Extract sender/receiver
            if transaction_data['transaction_type'] == 'income':
                sender = self._extract_pattern(body, self.bank_muscat_patterns['sender'])
                if sender:
                    transaction_data['transaction_sender'] = sender.strip()
            elif transaction_data['transaction_type'] == 'expense':
                receiver = self._extract_pattern(body, self.bank_muscat_patterns['receiver'])
                if receiver:
                    transaction_data['transaction_receiver'] = receiver.strip()

            # If we couldn't find sender/receiver, look for names in capital letters
            if ('transaction_sender' not in transaction_data and 
                'transaction_receiver' not in transaction_data):
                names = re.findall(self.bank_muscat_patterns['name'], body)
                if names:
                    # Use the first name as sender or receiver based on transaction type
                    if transaction_data['transaction_type'] == 'income':
                        transaction_data['transaction_sender'] = names[0].strip()
                    elif transaction_data['transaction_type'] == 'expense':
                        transaction_data['transaction_receiver'] = names[0].strip()

            # Extract country if available (usually for card transactions)
            country_match = re.search(r'transaction\s+country\s*[:]\s*([^<\n]+)', body, re.IGNORECASE)
            if country_match:
                transaction_data['country'] = country_match.group(1).strip()

            # Validate extracted data
            if not self._validate_transaction_data(transaction_data):
                logger.warning("Extracted transaction data is incomplete")
                return None

            return transaction_data
        except Exception as e:
            logger.error(f"Error parsing Bank Muscat email: {str(e)}")
            return None

    def _determine_transaction_type(self, body: str) -> str:
        """
        Determine the transaction type based on email body content.

        Args:
            body (str): Email body text.

        Returns:
            str: Transaction type ('income', 'expense', 'transfer', or 'unknown').
        """
        body_lower = body.lower()

        # Check transfer patterns first (more specific)
        for pattern in self.transaction_type_patterns['transfer']:
            if re.search(pattern, body_lower, re.IGNORECASE):
                return 'transfer'

        # Check other patterns
        for transaction_type in ['expense', 'income']:
            patterns = self.transaction_type_patterns[transaction_type]
            for pattern in patterns:
                if re.search(pattern, body_lower, re.IGNORECASE):
                    return transaction_type

        return 'unknown'

    def _extract_pattern(self, text: str, pattern: str) -> Optional[str]:
        """
        Extract data using a regex pattern.

        Args:
            text (str): Text to search in.
            pattern (str): Regex pattern to use.

        Returns:
            Optional[str]: Extracted data or None if not found.
        """
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1)
        return None

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """
        Parse date string to datetime object.

        Args:
            date_str (str): Date string to parse.

        Returns:
            Optional[datetime]: Parsed datetime or None if parsing fails.
        """
        try:
            # First try custom parsing for specific formats to ensure DD/MM/YY interpretation

            # Format: 13 MAY 25 17:20
            match = re.match(r'(\d{1,2})\s+([A-Za-z]{3})\s+(\d{2})\s+(\d{1,2}):(\d{1,2})', date_str)
            if match:
                day, month_str, year, hour, minute = match.groups()
                month_map = {
                    'JAN': 1, 'FEB': 2, 'MAR': 3, 'APR': 4, 'MAY': 5, 'JUN': 6,
                    'JUL': 7, 'AUG': 8, 'SEP': 9, 'OCT': 10, 'NOV': 11, 'DEC': 12
                }
                month = month_map.get(month_str.upper(), 1)
                year = 2000 + int(year)  # Assume 20xx
                return datetime(year, month, int(day), int(hour), int(minute))

            # Format: DD/MM/YY - Force DD/MM/YY interpretation for Bank Muscat
            match = re.match(r'(\d{1,2})/(\d{1,2})/(\d{2,4})', date_str)
            if match:
                day, month, year = match.groups()
                if len(year) == 2:
                    year = 2000 + int(year)  # Assume 20xx
                else:
                    year = int(year)
                # Explicitly use DD/MM/YY format (day first, then month)
                return datetime(year, int(month), int(day))

        except Exception as e:
            logger.warning(f"Failed to parse date with custom parser: {str(e)}")

        try:
            # Only try dateutil as fallback, and force DD/MM/YY interpretation
            # Use dayfirst=True to prioritize DD/MM/YY format over MM/DD/YY
            dt = dateutil.parser.parse(date_str, dayfirst=True)

            # Handle two-digit years
            if dt.year < 100:
                # Assume 20xx for years less than 100
                dt = dt.replace(year=2000 + dt.year)

            return dt
        except Exception as e:
            logger.warning(f"Failed to parse date with dateutil: {str(e)}")

        return None

    def _validate_transaction_data(self, data: Dict[str, Any]) -> bool:
        """
        Validate that the extracted transaction data has the minimum required fields.

        Args:
            data (Dict[str, Any]): Transaction data to validate.

        Returns:
            bool: True if data is valid, False otherwise.
        """
        required_fields = ['transaction_type', 'account_number', 'amount']

        for field in required_fields:
            if field not in data or data[field] is None:
                logger.warning(f"Missing required field: {field}")
                return False

        return True
