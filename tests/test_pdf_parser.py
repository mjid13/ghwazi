# !/usr/bin/env python3
"""
Tests for the PDF bank statement parser.
"""

import unittest
import os
from datetime import datetime
from money_tracker.services.pdf_parser_service import PDFParser


class TestPDFBankStatementParser(unittest.TestCase):
    """Test cases for the PDFBankStatementParser class."""

    def setUp(self):
        """Set up test fixtures."""
        self.parser = PDFParser()
        self.sample_pdf_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'bmcT.pdf')

    def test_parse_date(self):
        """Test parsing date strings."""
        # Test various date formats
        test_cases = [
            ('01/05/2023', datetime(2023, 5, 1)),  # DD/MM/YYYY
            ('01/05/23', datetime(2023, 5, 1)),    # DD/MM/YY
            ('1 May 2023', datetime(2023, 5, 1)),  # D Month YYYY
            ('01 MAY 23', datetime(2023, 5, 1)),   # DD MMM YY
            ('2023-05-01', datetime(2023, 5, 1)),  # YYYY-MM-DD
            ('', None),                            # Empty string
            (None, None),                          # None
        ]

        for date_str, expected in test_cases:
            with self.subTest(date_str=date_str):
                result = self.parser._parse_date(date_str)
                if expected is None:
                    self.assertIsNone(result)
                else:
                    self.assertEqual(result.year, expected.year)
                    self.assertEqual(result.month, expected.month)
                    self.assertEqual(result.day, expected.day)

    def test_parse_amount(self):
        """Test parsing amount strings."""
        # Test various amount formats
        test_cases = [
            ('100.00', 100.0),           # Simple decimal
            ('1,000.00', 1000.0),        # With comma separator
            ('OMR 100.00', 100.0),       # With currency symbol
            ('OMR1,000.00', 1000.0),     # With currency symbol and no space
            ('-100.00', -100.0),         # Negative amount
            ('', None),                  # Empty string
            (None, None),                # None
        ]

        for amount_str, expected in test_cases:
            with self.subTest(amount_str=amount_str):
                result = self.parser._parse_amount(amount_str)
                self.assertEqual(result, expected)

    def test_extract_counterparty_name(self):
        """Test extracting counterparty names from narration field."""
        # Test various narration patterns
        test_cases = [
            # POS transaction
            ('POS 685694-SHARARAH MART AL M POS251610D175XM3X', 'SHARARAH MART AL M'),

            # Wallet transaction
            ('Wallet Trx BMCT010484967766 AHMED NASSER KHALF AL MUFARGI FT25161622715487', 'AHMED NASSER KHALF AL MUFARGI'),
            
            # Easy Deposit
            ('Easy Deposit CDM12478415 13:38:31 ABDULMAJEED CDM251660294YXKKS', 'ABDULMAJEED'),
            
            # Salary
            ('SALARY Salary for 6 202 SALARY 209948320732336.050001', 'Salary for 6 202'),
            
            # Transfer
            ('Transfer Lunch for new couples and light fix IMAN MOHAMMED KHASIB AL HADHRAMI LF', 'IMAN MOHAMMED KHASIB AL HADHRAMI LF'),
            
            # Empty or None
            ('', None),
            (None, None),
        ]

        for narration, expected in test_cases:
            with self.subTest(narration=narration):
                result = self.parser._parse_narration(narration)
                self.assertEqual(result, expected)

    def test_format_transaction_data(self):
        """Test formatting transaction data."""
        # Test formatting transaction data
        raw_transaction = {
            'account_number': '1234567890',
            'currency': 'OMR',
            'post_date': datetime(2023, 5, 1),
            'value_date': datetime(2023, 5, 2),
            'description': 'POS 685694-SHARARAH MART AL M POS251610D175XM3X',
            'transaction_type': 'EXPENSE',
            'amount': 100.0,
            'counterparty_name': 'SHARARAH MART AL M',
        }

        expected = {
            'account_number': '1234567890',
            'transaction_type': 'EXPENSE',
            'amount': 100.0,
            'currency': 'OMR',
            'value_date': datetime(2023, 5, 2),
            'post_date': datetime(2023, 5, 1),
            'description': 'POS 685694-SHARARAH MART AL M POS251610D175XM3X',
            'counterparty_name': 'SHARARAH MART AL M',
            'bank_name': 'Bank Muscat',
        }

        result = self.parser.format_transaction_data(raw_transaction)
        self.assertEqual(result, expected)

    def test_pdf_exists(self):
        """Test that the sample PDF file exists."""
        self.assertTrue(os.path.exists(self.sample_pdf_path), f"Sample PDF file not found: {self.sample_pdf_path}")


if __name__ == '__main__':
    unittest.main()