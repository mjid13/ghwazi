# !/usr/bin/env python3
"""
Tests for the transaction parser.
"""

import unittest
from datetime import datetime
from money_tracker.services.parser_service import TransactionParser


class TestTransactionParser(unittest.TestCase):
    """Test cases for the TransactionParser class."""

    def setUp(self):
        """Set up test fixtures."""
        self.parser = TransactionParser()

    def test_expense_email_parsing(self):
        """Test parsing an expense email."""
        # Create a mock expense email
        email_data = {
            'id': '123',
            'subject': 'Transaction Alert',
            'from': 'Bank Muscat <bankmuscat@bankmuscat.com>',
            'date': 'Wed, 13 May 2025 17:20:00 +0400',
            'body': """
            Dear Customer,
            Your Debit card number 4837**** ****1518 has been utilised as follows:

            Account number : xxxx0019
            Description : 448311-JENAN TEA AIRP
            Amount : OMR 0.1
            Date/Time : 13 MAY 25 17:20
            Transaction Country : Oman

            Kind Regards,
            Bank Muscat
            """
        }

        # Parse the email
        transaction_data = self.parser.parse_email(email_data)

        # Verify the parsed data
        self.assertIsNotNone(transaction_data)
        self.assertEqual(transaction_data['transaction_type'], 'expense')
        self.assertEqual(transaction_data['account_number'], 'xxxx0019')
        self.assertEqual(transaction_data['amount'], 0.1)
        self.assertEqual(transaction_data['currency'], 'OMR')
        self.assertEqual(transaction_data['description'], '448311-JENAN TEA AIRP')
        self.assertEqual(transaction_data['country'], 'Oman')

        # Check that the date was parsed correctly
        self.assertIsInstance(transaction_data['value_date'], datetime)
        self.assertEqual(transaction_data['value_date'].year, 2025)
        self.assertEqual(transaction_data['value_date'].month, 5)
        self.assertEqual(transaction_data['value_date'].day, 13)
        self.assertEqual(transaction_data['value_date'].hour, 17)
        self.assertEqual(transaction_data['value_date'].minute, 20)

    def test_income_email_parsing(self):
        """Test parsing an income email."""
        # Create a mock income email
        email_data = {
            'id': '456',
            'subject': 'Transaction Alert',
            'from': 'Bank Muscat <bankmuscat@bankmuscat.com>',
            'date': 'Wed, 13 May 2025 10:30:00 +0400',
            'body': """
            Dear customer,
            You have received OMR 65.000 from ABDUL HAMID MOHAMED AL HADHRAMI in your a/c xxxx0019 using Mobile Payment services/mobile wallet.
            Txn Id BMCT009962940757.
            Kind regards,
            Bank muscat
            """
        }

        # Parse the email
        transaction_data = self.parser.parse_email(email_data)

        # Verify the parsed data
        self.assertIsNotNone(transaction_data)
        self.assertEqual(transaction_data['transaction_type'], 'income')
        self.assertEqual(transaction_data['account_number'], 'xxxx0019')
        self.assertEqual(transaction_data['amount'], 65.0)
        self.assertEqual(transaction_data['currency'], 'OMR')
        self.assertEqual(transaction_data['transaction_sender'], 'ABDUL HAMID MOHAMED AL HADHRAMI')
        self.assertEqual(transaction_data['transaction_id'], 'BMCT009962940757')

    def test_transfer_email_parsing(self):
        """Test parsing a transfer email."""
        # Create a mock transfer email
        email_data = {
            'id': '789',
            'subject': 'Transaction Alert',
            'from': 'Bank Muscat <bankmuscat@bankmuscat.com>',
            'date': 'Wed, 05 Feb 2025 14:45:00 +0400',
            'body': """
            Dear customer,
            Your account xxxx0027 with 0442 - Br Maabela Ind has been credited by OMR 60.000 with value date 05/02/25.
            Details of this transaction are provided below for your reference.
            Transfer
            Mazin contribution
            MOOSA MOHAMMED KHASIB ALHADHRAMI
            """
        }

        # Parse the email
        transaction_data = self.parser.parse_email(email_data)

        # Verify the parsed data
        self.assertIsNotNone(transaction_data)
        self.assertEqual(transaction_data['transaction_type'], 'transfer')
        self.assertEqual(transaction_data['account_number'], 'xxxx0027')
        self.assertEqual(transaction_data['amount'], 60.0)
        self.assertEqual(transaction_data['currency'], 'OMR')

        # Check that the date was parsed correctly - DD/MM/YY format
        # 05/02/25 should be interpreted as 5th February 2025, not 2nd May 2025
        self.assertIsInstance(transaction_data['value_date'], datetime)
        self.assertEqual(transaction_data['value_date'].year, 2025)
        self.assertEqual(transaction_data['value_date'].month, 2)  # February
        self.assertEqual(transaction_data['value_date'].day, 5)  # 5th day


if __name__ == '__main__':
    unittest.main()
