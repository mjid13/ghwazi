"""
Parser service for extracting transaction data from bank emails.
"""

import re
import logging
import html
from typing import Dict, Any, Optional, List
from datetime import datetime
import dateutil.parser
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class TransactionParser:
    """Parser for extracting transaction data from bank emails."""

    def __init__(self):
        """Initialize the transaction parser."""
        pass

    def clean_text(self, raw_html: str) -> str:
        """
        Clean HTML text that may be in quoted-printable format.
        Handles Bank Muscat email format with proper quoted-printable decoding.
        """
        # Step 1: Handle quoted-printable encoding
        # Remove soft line breaks (= at end of line followed by newline)
        text = re.sub(r'=\r?\n', '', raw_html)

        # Decode quoted-printable sequences
        # =3D -> =, =20 -> space, =0D -> \r, =0A -> \n, etc.
        quoted_printable_patterns = {
            '=3D': '=',
            '=20': ' ',
            '=0D': '\r',
            '=0A': '\n',
            '=09': '\t',
            '=22': '"',
            '=27': "'",
            '=3C': '<',
            '=3E': '>',
            '=26': '&',
        }

        for encoded, decoded in quoted_printable_patterns.items():
            text = text.replace(encoded, decoded)

        # Handle any remaining =XX patterns (hexadecimal encoded characters)
        def decode_hex(match):
            try:
                hex_value = match.group(1)
                return chr(int(hex_value, 16))
            except (ValueError, OverflowError):
                return match.group(0)  # Return original if can't decode

        text = re.sub(r'=([0-9A-F]{2})', decode_hex, text)

        # Step 2: Decode HTML entities
        text = html.unescape(text)

        # Step 3: Parse HTML with BeautifulSoup
        soup = BeautifulSoup(text, 'html.parser')

        # Remove images and non-essential elements for cleaner text
        for tag in soup.find_all(['img', 'style', 'script']):
            tag.decompose()

        # Step 4: Extract text with proper formatting
        # Handle BR tags as line breaks
        for br in soup.find_all('br'):
            br.replace_with('\n')

        # Extract text with newlines as separators for block elements
        text = soup.get_text(separator='\n')

        # Step 5: Clean up whitespace and empty lines
        lines = []
        for line in text.split('\n'):
            # Normalize whitespace within each line - this fixes "Dear cus    tomer" issue
            line = re.sub(r'\s+', ' ', line.strip())
            if line:  # Only keep non-empty lines
                lines.append(line)

        if len(lines) > 2:
            lines = lines[:-2]  # Remove last 2 lines

        # Join lines with single newlines
        clean_text = '\n'.join(lines)

        # Remove multiple consecutive newlines
        clean_text = re.sub(r'\n{3,}', '\n\n', clean_text)

        return clean_text.strip()

    def _get_name(self, email_text: str) -> Optional[str]:
        """Extract counterparty name from email text."""
        counterparty_re1 = re.compile(
            r'(?:from|to)\s+([A-Z](?:[A-Z\s]+[A-Z]))', re.IGNORECASE
        )
        counterparty_match = counterparty_re1.search(email_text)
        if counterparty_match:
            # Clean up spaces, remove extra whitespace
            name = ' '.join(counterparty_match.group(1).split())
            if name.upper().startswith('TRANSFER'):
                name = name[8:].strip()  # Remove 'TRANSFER' (8 characters) and any leading whitespace
            if name.endswith('from your a') or name.endswith('in your a'):
                name = ' '.join(name.split()[:-3]).strip()  # Remove 'from your account' or 'in your account'
            return name
        else:
            # fallback: try to find uppercase name lines near transaction details (like Email #1)
            # This will match 2+ uppercase words together
            counterparty_re2 = re.compile(r'\n([A-Z][A-Z\s]{4,})\n', re.MULTILINE)
            names = counterparty_re2.findall(email_text)
            if names:  # Check if names list is not empty
                name = ' '.join(names[0].split())
                if name.upper().startswith('TRANSFER'):
                    name = name[8:].strip()  # Remove 'TRANSFER' (8 characters) and any leading whitespace
                if name.endswith('from your a') or name.endswith('in your a'):
                    name = ' '.join(name.split()[:-3]).strip()  # Remove 'from your account' or 'in your account'
                return name
            else:
                return None

    def determine_transaction_type(self, email_text: str) -> str:
        """
        Determine transaction type based on bank email content.
        Returns one of: 'income', 'expense', 'transfer', 'unknown'.
        """
        text = email_text.lower()

        # Typical wording for type detection (customize these as needed)
        income_patterns = [
            r'credited',
            r'received',
            r'deposited',
        ]

        expense_patterns = [
            r'debit',
            r'utilised',
            r'sent',
            r'payment',
            r'purchase',
            r'withdrawal',
            r'spent',
        ]

        for pattern in income_patterns:
            if re.search(pattern, text):
                return 'income'

        for pattern in expense_patterns:
            if re.search(pattern, text):
                return 'expense'

        return 'unknown'

    def extract_bank_email_data(self, email_text: str) -> Dict[str, Optional[str]]:
        """Extract structured data from bank email text."""
        data = {
            "account_number": None,
            "branch": None,
            "transaction_type": None,
            "amount": None,
            "date": None,
            "transaction_details": None,
            "counterparty_name": None,
            "transaction_id": None,
            "description": None,
            "type": None,
            "from": None,
            "to": None,
            "currency": None,
        }

        # Account number (xxxx + digits)
        account_re = re.compile(
            r'account\s+(xxxx\d{4})|Account number\s*:\s*(xxxx\d{4})|a/c\s+(xxxx\d{4})',
            re.IGNORECASE
        )
        acc_match = account_re.search(email_text)
        if acc_match:
            data['account_number'] = acc_match.group(1) or acc_match.group(2) or acc_match.group(3)

        # Branch/location (digits + 'Br' + text)
        branch_re = re.compile(r'with\s+([\d\- ]*Br [A-Za-z ]+)', re.IGNORECASE)
        branch_match = branch_re.search(email_text)
        if branch_match:
            data['branch'] = branch_match.group(1).strip()

        # Transaction type: debited, credited, received, sent
        type_re = re.compile(r'\b(debited|credited|received|sent)\b', re.IGNORECASE)
        type_match = type_re.search(email_text)
        if type_match:
            data['transaction_type'] = type_match.group(1).lower()


            # Amount and currency: Currency code with decimal or integer (with optional commas)
        currency_re = re.compile(r'\s([A-Z]{3})\s*([\d,]+\.\d+|[\d,]+)', re.IGNORECASE)
        currency_match = currency_re.search(email_text)
        if currency_match:
            data['currency'] = currency_match.group(1).upper()


        amount_re = re.compile(rf'{currency_match.group(1).upper()}\s*([\d,]+\.\d+|[\d,]+)', re.IGNORECASE)

        amount_match = amount_re.search(email_text)
        if amount_match:
            data['amount'] = amount_match.group(1).replace(',', '')

        # Date (two formats): "value date dd/mm/yy" or "Date/Time : 22 JUN 25 20:29"
        date_re1 = re.compile(r'value date\s+(\d{2}/\d{2}/\d{2})', re.IGNORECASE)
        date_re2 = re.compile(r'Date/Time\s*:\s*([\d]{1,2}\s+[A-Z]{3}\s+\d{2}\s+[\d:]+)', re.IGNORECASE)
        date_match = date_re1.search(email_text) or date_re2.search(email_text)
        if date_match:
            data['date'] = date_match.group(1).strip()

        # Transaction details keywords: e.g., TRANSFER, Cash Dep, SALARY, Mobile Payment
        # We'll pick the first occurrence from a known list, case-insensitive
        txn_details_list = ['TRANSFER', 'Cash Dep', 'SALARY', 'Mobile Payment', 'Salary']
        for detail in txn_details_list:
            if re.search(r'\b' + re.escape(detail) + r'\b', email_text, re.IGNORECASE):
                data['transaction_details'] = detail
                break

        # Description: "Description : <text>"
        desc_re = re.compile(r'Description\s*:\s*(.+)', re.IGNORECASE)
        desc_match = desc_re.search(email_text)
        if desc_match:
            description= desc_match.group(1).strip()
            data['description'] = description

        # Counterparty (Sender/Receiver) name
        counterparty_name = self._get_name(email_text)
        if counterparty_name:
            data['counterparty_name'] = counterparty_name
        else:
            data['counterparty_name'] = '-'.join(description.split('-')[1:]).strip() if description else None
        txn_id_re = re.compile(r'Txn Id\s+(\w+)', re.IGNORECASE)
        txn_id_match = txn_id_re.search(email_text)
        if txn_id_match:
            data['transaction_id'] = txn_id_match.group(1)

        # Determine transaction type using the helper function
        txn_type = self.determine_transaction_type(email_text)
        data['type'] = txn_type

        # Determine "from" and "to" according to type
        if txn_type == 'expense':
            # "Me" is sender, Recipient is 'to'
            data['from'] = 'me'
            data['to'] = self._get_name(email_text)
        elif txn_type == 'income':
            # Extract sender as 'from', "Me" is receiving
            data['from'] = self._get_name(email_text)
            data['to'] = 'me'
        else:
            data['from'] = None
            data['to'] = None

        return data

    def parse_email(self, email_data: Dict[str, Any], bank_name: str = 'Bank Muscat') -> Optional[Dict[str, Any]]:
        """
        Parse an email and extract transaction data using the new approach.

        Args:
            email_data (Dict[str, Any]): Email data dictionary.
            bank_name (str, optional): Name of the bank. Defaults to 'Bank Muscat'.

        Returns:
            Optional[Dict[str, Any]]: Extracted transaction data or None if parsing fails.
        """
        try:
            body = email_data.get('body', '')
            if not body:
                logger.warning("Email body is empty, cannot parse transaction")
                return None

            # Clean the email text first
            clean_text = self.clean_text(body)

            # Extract bank email data using the new function
            extracted_data = self.extract_bank_email_data(clean_text)

            # Convert to the format expected by the rest of the system
            transaction_data = {
                'bank_name': bank_name,
                'email_id': email_data.get('id'),
                'email_date': email_data.get('date'),
                'currency': extracted_data.get('currency', 'OMR'),
                'cleaned_email_content': clean_text  # Include the cleaned email content
            }

            # Map the extracted data to transaction_data
            if extracted_data.get('account_number'):
                transaction_data['account_number'] = extracted_data['account_number']

            if extracted_data.get('amount'):
                try:
                    transaction_data['amount'] = float(extracted_data['amount'])
                except (ValueError, TypeError):
                    logger.warning(f"Could not convert amount to float: {extracted_data['amount']}")

            if extracted_data.get('type'):
                transaction_data['transaction_type'] = extracted_data['type']
            elif extracted_data.get('transaction_type'):
                transaction_data['transaction_type'] = extracted_data['transaction_type']
            else:
                transaction_data['transaction_type'] = 'unknown'

            if extracted_data.get('date'):
                try:
                    transaction_date = self._parse_date(extracted_data['date'])
                    if transaction_date:
                        transaction_data['date_time'] = transaction_date
                except Exception as e:
                    logger.warning(f"Failed to parse date '{extracted_data['date']}': {str(e)}")

            if extracted_data.get('transaction_id'):
                transaction_data['transaction_id'] = extracted_data['transaction_id']

            if extracted_data.get('description'):
                transaction_data['description'] = extracted_data['description']

            if extracted_data.get('branch'):
                transaction_data['branch'] = extracted_data['branch']

            # Handle sender/receiver based on transaction type
            if extracted_data.get('from') and extracted_data.get('from') != 'me':
                transaction_data['transaction_sender'] = extracted_data['from']

            if extracted_data.get('to') and extracted_data.get('to') != 'me':
                transaction_data['transaction_receiver'] = extracted_data['to']

            # Add the new fields
            transaction_data['from_party'] = extracted_data.get('from')
            transaction_data['to_party'] = extracted_data.get('to')
            transaction_data['counterparty_name'] = extracted_data.get('counterparty_name')
            transaction_data['transaction_details'] = extracted_data.get('transaction_details')

            # Validate that we have minimum required data
            if not self._validate_transaction_data(transaction_data):
                logger.warning("Extracted transaction data is incomplete")
                return None

            return transaction_data

        except Exception as e:
            logger.error(f"Error parsing email: {str(e)}")
            return None

    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """
        Parse date string to datetime object.

        Args:
            date_str (str): Date string to parse.

        Returns:
            Optional[datetime]: Parsed datetime or None if parsing fails.
        """
        if not date_str:
            logger.warning("Empty date string provided")
            return None

        # Clean the date string
        date_str = date_str.strip()

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

                # Handle two-digit years properly
                current_year = datetime.now().year
                year_prefix = str(current_year)[0:2]  # Get first 2 digits of current year
                full_year = int(year_prefix + year)

                # If the resulting year is more than 10 years in the future, assume previous century
                if full_year > current_year + 10:
                    full_year -= 100

                return datetime(full_year, month, int(day), int(hour), int(minute))

            # Format: DD/MM/YY HH:MM - Handle time component
            match = re.match(r'(\d{1,2})/(\d{1,2})/(\d{2,4})(?:\s+(\d{1,2}):(\d{1,2}))?', date_str)
            if match:
                groups = match.groups()
                day, month, year = groups[0:3]

                # Handle two-digit years properly
                if len(year) == 2:
                    current_year = datetime.now().year
                    year_prefix = str(current_year)[0:2]  # Get first 2 digits of current year
                    full_year = int(year_prefix + year)

                    # If the resulting year is more than 10 years in the future, assume previous century
                    if full_year > current_year + 10:
                        full_year -= 100
                else:
                    full_year = int(year)

                # Handle time component if present
                hour, minute = 0, 0
                if len(groups) > 3 and groups[3] is not None and groups[4] is not None:
                    hour, minute = int(groups[3]), int(groups[4])

                # Explicitly use DD/MM/YY format (day first, then month)
                return datetime(full_year, int(month), int(day), hour, minute)

        except Exception as e:
            logger.warning(f"Failed to parse date with custom parser: {str(e)}")

        try:
            # Only try dateutil as fallback, and force DD/MM/YY interpretation
            # Use dayfirst=True to prioritize DD/MM/YY format over MM/DD/YY
            dt = dateutil.parser.parse(date_str, dayfirst=True)

            # Handle two-digit years properly
            if dt.year < 100:
                current_year = datetime.now().year
                year_prefix = str(current_year)[0:2]  # Get first 2 digits of current year
                full_year = int(year_prefix + str(dt.year).zfill(2))

                # If the resulting year is more than 10 years in the future, assume previous century
                if full_year > current_year + 10:
                    full_year -= 100

                dt = dt.replace(year=full_year)

            return dt
        except Exception as e:
            logger.warning(f"Failed to parse date with dateutil: {str(e)}")

        return None

    def _validate_transaction_data(self, data: Dict[str, Any]) -> bool:
        """
        Validate that the extracted transaction data has the minimum required fields
        and that the values are of the correct type and within valid ranges.

        Args:
            data (Dict[str, Any]): Transaction data to validate.

        Returns:
            bool: True if data is valid, False otherwise.
        """

        logger.info(f"Validating transaction data: {data}")
        # Check required fields exist
        required_fields = ['transaction_type', 'account_number', 'amount']
        for field in required_fields:
            if field not in data or data[field] is None:
                logger.warning(f"Missing required field: {field}")
                return False

        # Validate transaction_type
        valid_types = ['income', 'expense', 'transfer', 'unknown']
        if data['transaction_type'] not in valid_types:
            logger.warning(f"Invalid transaction_type: {data['transaction_type']}")
            data['transaction_type'] = 'unknown'  # Set to default if invalid

        # Validate account_number
        if not isinstance(data['account_number'], str) or not data['account_number'].strip():
            logger.warning(f"Invalid account_number: {data['account_number']}")
            return False

        # Validate amount
        try:
            # Ensure amount is a float
            if not isinstance(data['amount'], float):
                data['amount'] = float(data['amount'])

            # Check for unreasonable amounts (e.g., negative or extremely large)
            if data['amount'] < 0:
                logger.warning(f"Negative amount: {data['amount']}")
                # Don't return False, just log the warning
            elif data['amount'] > 1000000:  # Arbitrary large amount threshold
                logger.warning(f"Unusually large amount: {data['amount']}")
                # Don't return False, just log the warning
        except (ValueError, TypeError):
            logger.warning(f"Invalid amount: {data['amount']}")
            return False

        # Validate date_time if present
        if 'date_time' in data and data['date_time'] is not None:
            if not isinstance(data['date_time'], datetime):
                logger.warning(f"Invalid date_time: {data['date_time']}")
                return False

        return True
