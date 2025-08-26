"""
Parser service for extracting transaction data from bank emails.
"""

import html
import logging
import re
from datetime import datetime
from typing import Any, Dict, Optional

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
        text = re.sub(r"=\r?\n", "", raw_html)

        # Decode quoted-printable sequences
        # =3D -> =, =20 -> space, =0D -> \r, =0A -> \n, etc.
        quoted_printable_patterns = {
            "=3D": "=",
            "=20": " ",
            "=0D": "\r",
            "=0A": "\n",
            "=09": "\t",
            "=22": '"',
            "=27": "'",
            "=3C": "<",
            "=3E": ">",
            "=26": "&",
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

        text = re.sub(r"=([0-9A-F]{2})", decode_hex, text)

        # Step 2: Decode HTML entities
        text = html.unescape(text)

        # Step 3: Parse HTML with BeautifulSoup
        soup = BeautifulSoup(text, "html.parser")

        # Remove images and non-essential elements for cleaner text
        for tag in soup.find_all(["img", "style", "script"]):
            tag.decompose()

        # Step 4: Extract text with proper formatting
        # Handle BR tags as line breaks
        for br in soup.find_all("br"):
            br.replace_with("\n")

        # Extract text with newlines as separators for block elements
        text = soup.get_text(separator="\n")

        # Step 5: Clean up whitespace and empty lines
        lines = []
        for line in text.split("\n"):
            # Normalize whitespace within each line - this fixes "Dear cus    tomer" issue
            line = re.sub(r"\s+", " ", line.strip())
            if line:  # Only keep non-empty lines
                lines.append(line)

        if len(lines) > 2:
            lines = lines[:-2]  # Remove last 2 lines

        # Join lines with single newlines
        clean_text = "\n".join(lines)

        # Remove multiple consecutive newlines
        clean_text = re.sub(r"\n{3,}", "\n\n", clean_text)

        return clean_text.strip()

    def _get_name(self, email_text: str) -> Optional[str]:
        """Extract counterparty/merchant name from email text."""
        # 1) Prefer extracting from the 'Description :' field. Stop before Amount/Date/Time/etc.
        desc_match = re.search(
            r"Description\s*:\s*(.+?)(?:\s+(?:Amount|Date/Time|Transaction Country|Txn Id)\b|[\r\n]|$)",
            email_text,
            re.IGNORECASE,
        )
        if desc_match:
            raw = desc_match.group(1).strip()

            # Remove leading numeric reference like "911792-" or "911792 :"
            raw = re.sub(r"^[#\s]*\d{2,}\s*[-:]\s*", "", raw)
            # If there are multiple separators, pick the most name-like (usually the last text part)
            parts = [p.strip() for p in re.split(r"[-:]", raw) if p.strip()]
            candidate = None
            for p in reversed(parts):
                if re.search(r"[A-Za-z]{2}", p):
                    candidate = p
                    break
            name = candidate or raw

            # Guard against any leaked currency/amount tokens
            name = re.split(r"\s+(?:OMR|USD|EUR|GBP|AED|SAR|QAR|KWD|BHD|JPY)\b", name)[0]

            # Normalize whitespace
            name = re.sub(r"\s{2,}", " ", name).strip()
            if name:
                return name

        # 2) Fallback: try explicit "from/to NAME" pattern
        counterparty_re1 = re.compile(r"(?:from|to)\s+([A-Z](?:[A-Z\s]+[A-Z]))", re.IGNORECASE)
        counterparty_match = counterparty_re1.search(email_text)
        if counterparty_match:
            name = " ".join(counterparty_match.group(1).split())
            if name.upper().startswith("TRANSFER"):
                name = name[8:].strip()  # Remove 'TRANSFER'
            if name.endswith("from your a") or name.endswith("in your a"):
                name = " ".join(name.split()[:-3]).strip()
            return name

        # 3) Last resort: uppercase block between newlines
        counterparty_re2 = re.compile(r"\n([A-Z][A-Z\s]{4,})\n", re.MULTILINE)
        names = counterparty_re2.findall(email_text)
        if names:
            name = " ".join(names[0].split())
            if name.upper().startswith("TRANSFER"):
                name = name[8:].strip()
            if name.endswith("from your a") or name.endswith("in your a"):
                name = " ".join(name.split()[:-3]).strip()
            return name
        # 4) NEW: Look for counterparty name at the end of the email after transaction details
        # This handles cases like the Bank Muscat format where name appears as the last line
        lines = email_text.split('\n')
        lines = [line.strip() for line in lines if line.strip()]  # Remove empty lines

        if lines:
            # Look at the last few lines for potential counterparty names
            for line in reversed(lines[-3:]):  # Check last 3 lines
                # Skip common footer/signature patterns
                if any(skip_word in line.lower() for skip_word in [
                    'dear customer', 'thank you', 'regards', 'sincerely',
                    'bank muscat', 'customer service', 'email', 'phone',
                    'visit', 'website', 'disclaimer', 'confidential',
                    'value date', 'transaction', 'account', 'amount', 'omr'
                ]):
                    continue

                # if re.match(r'^[A-Z][A-Z\s]{2,50}$', line):
                if re.match(r'^[A-Z][A-Z\s]', line):
                    # Additional validation: should contain mostly letters
                    # if re.search(r'[A-Za-z]', line) and len(re.findall(r'[A-Za-z]', line)) >= len(line) * 0.7:
                    name = ' '.join(line.split())
                    return name

        return None

    def determine_transaction_type(self, email_text: str) -> str:
        """
        Determine transaction type based on the first matching keyword
        found in the email content.
        Returns one of: 'income', 'expense', 'transfer', 'unknown'.
        """
        text = email_text.lower()

        pattern_types = {
            "income": [
                r"credited",
                r"received",
                r"deposited",
            ],
            "expense": [
                r"debit",
                r"utilised",
                r"sent",
                r"payment",
                r"purchase",
                r"withdrawal",
                r"spent",
            ],
        }

        earliest_type = "unknown"
        earliest_index = len(text) + 1

        for type_name, patterns in pattern_types.items():
            for pattern in patterns:
                match = re.search(pattern, text)
                if match:
                    pos = match.start()
                    if pos < earliest_index:
                        earliest_index = pos
                        earliest_type = type_name

        return earliest_type

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
            "country": None,
        }

        # Account number (xxxx + digits)
        account_re = re.compile(
            r"(?:\baccount\s+(xxxx\d{4})\b|Account number\s*:\s*(xxxx\d{4})\b|a/c\s+(xxxx\d{4})\b|\(?\s*a/?c\s+([0-9\*\s]{6,})\s*\)?)",
            re.IGNORECASE,
        )
        acc_match = account_re.search(email_text)
        if acc_match:
            acc_val = acc_match.group(1) or acc_match.group(2) or acc_match.group(3)
            if not acc_val:
                masked = acc_match.group(4)
                if masked:
                    masked = re.sub(r"\s+", "", masked)
                    if "*" in masked:
                        acc_val = masked
            data["account_number"] = acc_val


        # Branch/location (digits + 'Br' + text)
        branch_re = re.compile(r"with\s+([\d\- ]*Br [A-Za-z ]+)", re.IGNORECASE)
        branch_match = branch_re.search(email_text)
        if branch_match:
            data["branch"] = branch_match.group(1).strip()

        # Transaction type: debited, credited, received, sent
        # type_re = re.compile(r"\b(debited|credited|received|sent)\b", re.IGNORECASE)
        # type_match = type_re.search(email_text)
        # if type_match:
        #     data["transaction_type"] = type_match.group(1).lower()

        # Amount and currency: Currency code with decimal or integer (with optional commas)
        # Valid currency codes (ISO 4217)
        # TODO: This list shuld be dynamic or configurable by the user or admin
        valid_currencies = [
            "OMR",
            "USD",
            "EUR",
            "GBP",
            "AED",
            "SAR",
            "QAR",
            "KWD",
            "BHD",
            "JPY",
        ]

        # Create pattern that matches valid currency codes
        currency_pattern = (
            r"\s(" + "|".join(valid_currencies) + r")\s*([\d,]+\.\d+|[\d,]+)"
        )
        currency_re = re.compile(currency_pattern, re.IGNORECASE)
        currency_match = currency_re.search(email_text)
        if currency_match:
            data["currency"] = currency_match.group(1).upper()
            # Extract the first amount associated with the first currency occurrence
            data["amount"] = currency_match.group(2).replace(",", "")



        # Date (two formats): "value date dd/mm/yy" or "Date/Time : 22 JUN 25 20:29"
        date_re1 = re.compile(r"value date\s+(\d{2}/\d{2}/\d{2})", re.IGNORECASE)
        date_re2 = re.compile(
            r"Date/Time\s*:\s*([\d]{1,2}\s+[A-Z]{3}\s+\d{2}\s+[\d:]+)", re.IGNORECASE
        )
        date_match = date_re1.search(email_text) or date_re2.search(email_text)
        if date_match:
            data["date"] = date_match.group(1).strip()


        # Transaction details keywords: e.g., TRANSFER, Cash Dep, SALARY, Mobile Payment
        # We'll pick the first occurrence from a known list, case-insensitive
        txn_details_list = [
            "TRANSFER",
            "Cash Dep",
            "SALARY",
            "Mobile Payment",
            "Salary",
        ]
        for detail in txn_details_list:
            if re.search(r"\b" + re.escape(detail) + r"\b", email_text, re.IGNORECASE):
                data["transaction_details"] = detail
                break

        # Country: "Transaction Country : <text>"
        country_re = re.compile(r"Transaction Country\s*:\s*(.+)", re.IGNORECASE)
        country_match = country_re.search(email_text)
        if country_match:
            data["country"] = country_match.group(1).strip()

        # Description: "Description : <text>"
        desc_re = re.compile(r"Description\s*:\s*(.+?)(?=[:/]|$)", re.IGNORECASE)
        desc_match = desc_re.search(email_text)
        description = None
        if desc_match:
            description = desc_match.group(1).strip()
            data["description"] = description

        # Counterparty (Sender/Receiver) name
        counterparty_name = self._get_name(email_text)
        if counterparty_name:
            data["counterparty_name"] = counterparty_name
        elif description:
            data["counterparty_name"] = "-".join(description.split("-")[1:]).strip()

        txn_id_re = re.compile(r"Txn Id\s+(\w+)", re.IGNORECASE)
        txn_id_match = txn_id_re.search(email_text)
        if txn_id_match:
            data["transaction_id"] = txn_id_match.group(1)

        # Determine transaction type using the helper function
        txn_type = self.determine_transaction_type(email_text)
        data["type"] = txn_type
        data["transaction_type"] = txn_type

        # Determine "from" and "to" according to type
        if txn_type == "expense":
            # "Me" is sender, Recipient is 'to'
            data["from"] = "me"
            data["to"] = data["counterparty_name"]
        elif txn_type == "income":
            # Extract sender as 'from', "Me" is receiving
            data["from"] = data["counterparty_name"]
            data["to"] = "me"
        else:
            data["from"] = None
            data["to"] = None

        return data

    def parse_email(
        self, email_data: Dict[str, Any], bank_name: str = "Bank Muscat"
    ) -> Optional[Dict[str, Any]]:
        """
        Parse an email and extract transaction data using the new approach.

        Args:
            email_data (Dict[str, Any]): Email data dictionary.
            bank_name (str, optional): Name of the bank. Defaults to 'Bank Muscat'.

        Returns:
            Optional[Dict[str, Any]]: Extracted transaction data or None if parsing fails.
        """
        try:
            body = email_data.get("body") or email_data.get("body_text", "")
            if not body:
                logger.warning("Email body is empty, cannot parse transaction")
                return None

            # Clean the email text first
            clean_text = self.clean_text(body)
            # Extract bank email data using the new function
            extracted_data = self.extract_bank_email_data(clean_text)

            # Convert to the format expected by the rest of the system
            transaction_data = {
                "bank_name": bank_name,
                "email_id": email_data.get("id"),
                "currency": extracted_data.get("currency", "OMR"),
                "transaction_content": clean_text,
                "account_number": extracted_data.get("account_number"),
                "transaction_type": extracted_data.get("transaction_type"),
                "date": extracted_data.get("date"),
                "transaction_details": extracted_data.get("transaction_details"),
                "counterparty_name": extracted_data.get("counterparty_name"),
                "transaction_id": extracted_data.get("transaction_id"),
                "description": extracted_data.get("description"),
                "type": extracted_data.get("type"),
            }

            if extracted_data.get("amount"):
                try:
                    transaction_data["amount"] = float(extracted_data["amount"])
                except (ValueError, TypeError):
                    logger.warning(
                        f"Could not convert amount to float: {extracted_data['amount']}"
                    )
            if extracted_data.get("country"):
                transaction_data["country"] = extracted_data["country"].split()[0]
            if extracted_data.get("type"):
                transaction_data["transaction_type"] = extracted_data["type"]
            elif extracted_data.get("transaction_type"):
                transaction_data["transaction_type"] = extracted_data["transaction_type"]
            else:
                transaction_data["transaction_type"] = "unknown"

            if extracted_data.get("date"):
                try:
                    transaction_date = self._parse_date(extracted_data["date"])
                    if transaction_date:
                        transaction_data["value_date"] = transaction_date
                    else:
                        # Use email date as fallback for Gmail transactions
                        email_date = email_data.get("date")
                        if email_date:
                            if isinstance(email_date, datetime):
                                transaction_data["value_date"] = email_date
                            elif isinstance(email_date, str):
                                try:
                                    transaction_data["value_date"] = datetime.fromisoformat(email_date.replace('Z', '+00:00'))
                                except ValueError:
                                    # Try parsing with dateutil as fallback
                                    import dateutil.parser
                                    transaction_data["value_date"] = dateutil.parser.parse(email_date)
                except Exception as e:
                    logger.warning(
                        f"Failed to parse date '{extracted_data['date']}': {str(e)}"
                    )
            else:
                # If no transaction date found in email body, use email date for Gmail
                email_date = email_data.get("date")
                if email_date:
                    try:
                        if isinstance(email_date, datetime):
                            transaction_data["value_date"] = email_date
                        elif isinstance(email_date, str):
                            try:
                                transaction_data["value_date"] = datetime.fromisoformat(email_date.replace('Z', '+00:00'))
                            except ValueError:
                                # Try parsing with dateutil as fallback
                                import dateutil.parser
                                transaction_data["value_date"] = dateutil.parser.parse(email_date)
                    except Exception as e:
                        logger.warning(f"Failed to parse email date '{email_date}': {str(e)}")


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
            match = re.match(
                r"(\d{1,2})\s+([A-Za-z]{3})\s+(\d{2})\s+(\d{1,2}):(\d{1,2})", date_str
            )
            if match:
                day, month_str, year, hour, minute = match.groups()
                month_map = {
                    "JAN": 1,
                    "FEB": 2,
                    "MAR": 3,
                    "APR": 4,
                    "MAY": 5,
                    "JUN": 6,
                    "JUL": 7,
                    "AUG": 8,
                    "SEP": 9,
                    "OCT": 10,
                    "NOV": 11,
                    "DEC": 12,
                }
                month = month_map.get(month_str.upper(), 1)

                # Handle two-digit years properly
                current_year = datetime.now().year
                year_prefix = str(current_year)[
                    0:2
                ]  # Get first 2 digits of current year
                full_year = int(year_prefix + year)

                # If the resulting year is more than 10 years in the future, assume previous century
                if full_year > current_year + 10:
                    full_year -= 100

                return datetime(full_year, month, int(day), int(hour), int(minute))

            # Format: DD/MM/YY HH:MM - Handle time component
            match = re.match(
                r"(\d{1,2})/(\d{1,2})/(\d{2,4})(?:\s+(\d{1,2}):(\d{1,2}))?", date_str
            )
            if match:
                groups = match.groups()
                month, day, year = groups[0:3]

                # Handle two-digit years properly
                if len(year) == 2:
                    current_year = datetime.now().year
                    year_prefix = str(current_year)[
                        0:2
                    ]  # Get first 2 digits of current year
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
                year_prefix = str(current_year)[
                    0:2
                ]  # Get first 2 digits of current year
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
        required_fields = ["transaction_type", "account_number", "amount"]
        for field in required_fields:
            if field not in data or data[field] is None:
                logger.warning(f"Missing required field: {field}")
                return False

        # Validate transaction_type
        valid_types = ["income", "expense", "transfer", "unknown"]
        if data["transaction_type"] not in valid_types:
            logger.warning(f"Invalid transaction_type: {data['transaction_type']}")
            data["transaction_type"] = "unknown"  # Set to default if invalid

        # Validate account_number
        if (
            not isinstance(data["account_number"], str)
            or not data["account_number"].strip()
        ):
            logger.warning(f"Invalid account_number: {data['account_number']}")
            return False

        # Validate amount
        try:
            # Ensure amount is a float
            if not isinstance(data["amount"], float):
                data["amount"] = float(data["amount"])

            # Check for unreasonable amounts (e.g., negative or extremely large)
            if data["amount"] < 0:
                logger.warning(f"Negative amount: {data['amount']}")
                # Don't return False, just log the warning
            elif data["amount"] > 1000000:  # Arbitrary large amount threshold
                logger.warning(f"Unusually large amount: {data['amount']}")
                # Don't return False, just log the warning
        except (ValueError, TypeError):
            logger.warning(f"Invalid amount: {data['amount']}")
            return False

        # Validate value_date if present
        if "value_date" in data and data["value_date"] is not None:
            if not isinstance(data["value_date"], datetime):
                logger.warning(f"Invalid value_date: {data['value_date']}")
                return False

        return True

# def parse_bank_email(email_text: str) -> Optional[Dict[str, Any]]:
#     parser = TransactionParser()
#     email_data = {
#     "id": "1980c623880ae87a",
#     "thread_id": "1980768ef1a82533",
#     "label_ids": ["IMPORTANT", "CATEGORY_UPDATES", "INBOX"],
#     "snippet": "Dear Customer, Your Debit card number 4837**** ****1518 has been utilised as follows: Account number : xxxx0019 Description : 911792-JENAN TEA AIRP Amount : OMR 0.2 Date/Time : 15 JUL 25 08:39",
#     "history_id": "1965802",
#     "internal_date": "1752554415000",
#     "size_estimate": 6445,
#     "subject": "Account Transaction",
#     "sender": "NOREPLY@bankmuscat.com",
#     "recipient": "Abdulmajeed.alhadhrami@gmail.com",
#     "date": "2025-07-15T08:40:15+04:00",
#     "date_string": "Tue, 15 Jul 2025 08:40:15 +0400",
#     "body_text": """Dear customer,
#     Your account xxxx0019 with 0442 - Br Maabela Ind has been credited by OMR 13.000 with value date 07/29/25.
#     Details of this transaction are provided below for your reference.
#     Trnsfer
#     SULAIMAN MOHD Ka
#     """,
#     "headers": {
#       "delivered-to": "abdulmajeed.alhadhrami@gmail.com",
#       "received": "from dc1t24brchapp2.bmoman.bankmuscat.com ( [10.6.233.161]) by DC1MG3-OM-SMG.bmoman.bankmuscat.com (Symantec Messaging Gateway) with SMTP id 38.31.10146.EABD5786; Tue, 15 Jul 2025 08:40:14 +0400 (+04)",
#       "x-google-smtp-source": "AGHT+IHXcWPbbOeS4oJm5QGsY9a5ZLtv9dYIJD0hBz/vNyUGEoDd9WdRZtMh3DsfV1xS9Jaud1Jk",
#       "x-received": "by 2002:a05:600c:46c3:b0:439:86fb:7340 with SMTP id 5b1f17b1804b1-454f425a04bmr144764235e9.30.1752554420721; Mon, 14 Jul 2025 21:40:20 -0700 (PDT)",
#       "arc-seal": "i=1; a=rsa-sha256; t=1752554420; cv=none; d=google.com; s=arc-20240605; b=S//jkMF6Ogv8lJRNG+uqsXp3XbvHM1Ab6/NqTGvCO9k4ewP1gC4ZaMfTPilR5VmvgD7iYN70Ix+e7Wxl9d4+2Vuo6cz8FfQmKubXDW2n9kyXoTIwC7izetSq77ANWXXjaLK8AEFct0rR15fjh57ov6HIbCz5+HtO+vqu8L5dvdKJW6V5S+dwRItHiqRF6/16P5dCIZO+o5waRltnaCT9EDhnwmcVBQWPOmRAeh3LkCHzL9A9dCwPdk5+XLAPyudweXbH/kCi9rAZ3IrjlQJK4p0wyf9JuXISzXamnv92sj2njCS9yUTFQ0PpGrqkbRKP6MVzM6iH2pNTXzK2xguC5A==",
#       "arc-message-signature": "i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605; h=content-transfer-encoding:mime-version:subject:message-id:to:from:date:dkim-signature; bh=/jOT/FZ5YZtbAuBtTBeLf4O9KKx8BVUuN0HTzBJdzho=; fh=+/2bNCdLvIlW6mSN/DUx3u4RCdSMbFYBnTvHujmKYbU=; b=QskmJOVacsU7KCdszQvO+KP+YcfpRthQnZd/ROby0o6+EKJZP5GSIxBrrh7I2MQa0CYl/bAI4EbM62+a0Q0dtNsRKdt3zBcwH9UnsKmg3NMYn1FMgSseztU2ezRIFkqcTmPe2+M0A+vLtFzLzvVq0Ag3rmhsTSaToGJ/cl4kmns3GSH8nBmbG/6TBYRC5NWfIseF7EPRVk9GIMz6q/lECRHA2zMTo9NuoDqVhyS/IxVc6dhsKaYkMLJOJsYbZHnb8gk5H9AyR4XnItr1TWYCjYx4aHhfMfe/7jmdxY8Cr2XoDYmStHYVAzw04N3YAW4d4Yib4uhZAZm3y2R5AV2O7A==",
#       "arc-authentication-results": "i=1; mx.google.com; dkim=pass header.i=@bankmuscat.com header.s=selector3 header.b=ZtJlhV0b; spf=pass (google.com: domain of noreply@bankmuscat.com designates 85.154.45.22 as permitted sender) smtp.mailfrom=NOREPLY@bankmuscat.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=bankmuscat.com",
#       "return-path": "<NOREPLY@bankmuscat.com>",
#       "received-spf": "pass (google.com: domain of noreply@bankmuscat.com designates 85.154.45.22 as permitted sender) client-ip=85.154.45.22;",
#       "authentication-results": "mx.google.com; dkim=pass header.i=@bankmuscat.com header.s=selector3 header.b=ZtJlhV0b; spf=pass (google.com: domain of noreply@bankmuscat.com designates 85.154.45.22 as permitted sender) smtp.mailfrom=NOREPLY@bankmuscat.com; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=bankmuscat.com",
#       "dkim-signature": "v=1; a=rsa-sha256; d=bankmuscat.com; s=selector3; c=relaxed/simple; q=dns/txt; i=@bankmuscat.com; t=1752554415; x=1838868015; h=From:Sender:Reply-To:Subject:Date:Message-ID:To:Cc:MIME-Version:Content-Type:Content-Transfer-Encoding:Content-ID:Content-Description:Resent-Date:Resent-From:Resent-Sender:Resent-To:Resent-Cc:Resent-Message-ID:In-Reply-To:References:List-Id:List-Help:List-Unsubscribe:List-Subscribe:List-Post:List-Owner:List-Archive; bh=++OdcubP69THstLU32IDOGMHwAnJvDSAZLic1YvsQtw=; b=ZtJlhV0bAjb659F10oApQQEUXyEBb7wKe6+Mj9Hblk3P65+WUBjgZQuFhfX+2oze5H4jX4ohyUw3FtLjY2yYRrVYOUWXAjMNvuValxUNiUNcT6OEG1s32nPYU7yfUVp8YNn/lBnv3cS/DauO1UELMyEkZ6ewDYA6aA42zQEVb+8=;",
#       "date": "Tue, 15 Jul 2025 08:40:15 +0400",
#       "x-auditid": "0a061957-da6ca700000027a2-3e-6875dbaea517",
#       "from": "NOREPLY@bankmuscat.com",
#       "to": "Abdulmajeed.alhadhrami@gmail.com",
#       "message-id": "<-96706420.3599217.1752554414970@dc1t24brchapp2.bmoman.bankmuscat.com>",
#       "subject": "Account Transaction",
#       "mime-version": "1.0",
#       "content-type": "text/html; charset=UTF-8",
#       "content-transfer-encoding": "quoted-printable",
#       "x-brightmail-tracker": "H4sIAAAAAAAAA+NgFtrMJMWRmVeSWpSXmKPExsXCxfZyoe6626UZBpOW2VhcubWGyYHRY+es u+wBjFFcNimpOZllqUX6dglcGZNOJxS85ap42nCFtYGxh7OLkZNDQsBEYs/mXjYQW0jgCqPE jAsCIDabgIzEmp6NTCC2iICKxJUNX1hAbF6BIIk1j3exg9jCQDUP7lyFigtKnJz5BMxmFlCT uL3tKjuErS2xbOFr5gmMnLOQlM1CUjYLSdkCRuZVjDIuzoa+7sa6/r66wb7uek6Oft6+ocHO jiF6zv6+mxjBXpYM38G45VGT/iFGJg7GQ4zSHCxK4rxW67QyhATSE0tSs1NTC1KL4otKc1KL QUo4pRqY9BZvu7ghUHbywicf/jEfk3/CEnTOaF9IzDr9b/dfm75L/HM7b3vOtLBrBvyu5Qfc rBpjf058LsCble7OmlESVfJhW0P+tnU3NqYXxiSn7r/x6OuN2LV2x6JjA+9MPD5z8YTH52a0 28vXNX963N3tvDTb4e/NJy0H+/+/965if38o3vTa7AizxSV/4u3lvR2MktVKf+YbnFTcnuus XvbkaOaps4ZiCqv807cIrvldeN1oRqj5z/1Z+/Je63fHSkxx7GYodNG6ydnAuN0tp/KGncuX V8s2nNmowcI6o2bDW3lZ0z9sOx1mNDjkPlym1bBpx40WwY8bPN0eSS2fYv3Q1bVDd/2sbJe/ Yje02BR/KbEUZyQaajEXFScCAA9QtmRGAgAA"
#     }
#   }
#     return parser.parse_email(email_data)

# text = """Dear Customer, Your Debit card number 4837**** ****1518 has been utilised as follows: Account number : xxxx0019 Description : 998232-JENAN TEA MUTT Amount : OMR 0.2 Date/Time : 14 JUL 25 11:01 Transaction Country : Oman Kind Regards, Bank Muscat To unsubscribe / modify the email alert service please contact your nearest Branch / ARM or contact bank muscat Call Center at 24795555. This e-mail is confidential and may also be legally privileged. If you are not the intended recipient, please notify us immediately. You should not copy, forward, disclose or use it for any purpose either partly or completely. If you have received this message by error, please delete all its copies from your system and notify us by e-mail to care@bankmuscat.com. Internet communications cannot be guaranteed to be timely, secure, error or virus-free. Also, the Web/ IT/ Email administrator might not allow emails with attachments, thus the sender does not accept liability for any errors or omissions.
# """

# output = parse_bank_email(text)
# for i,j in output.items():
#
#     print(f"{i}: {j}")
        # Account number (xxxx + digits)
