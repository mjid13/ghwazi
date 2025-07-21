import unittest
from money_tracker.services.parser_service import TransactionParser

class TestBankMuscatParser(unittest.TestCase):
    """Test cases for the Bank Muscat email parser."""

    def setUp(self):
        """Set up test fixtures."""
        self.parser = TransactionParser()

    def test_debit_transaction_parsing(self):
        """Test parsing a debit transaction email."""
        # Create a mock debit transaction email
        email_data = {
            'id': '123',
            'subject': 'Transaction Alert',
            'from': 'Bank Muscat <bankmuscat@bankmuscat.com>',
            'date': 'Wed, 06 Jan 2025 10:30:00 +0400',
            'body': """<img src=3D"https://www.bankmuscat.com/en/PublishingImages/Account Transact=
ion/Advertisment-header.jpg"><BR> <p style=3D"font-size:Medium;">Dear custo=
mer, <BR> Your account xxxx0027 with 0442 - Br Maabela Ind has been debited=
 by OMR 115 with value date 06/01/25. <BR> Details of this transaction are =
provided below for your reference.<BR> TRANSFER <BR>  <BR> KHASEEB DAWOOD K=
HASEEB AL HADHRAMI <BR> <BR> Kind regards, <BR> bank muscat </P>"""
        }

        # Parse the email
        transaction_data = self.parser.parse_email(email_data)

        # Verify the parsed data
        self.assertIsNotNone(transaction_data)
        self.assertEqual(transaction_data['transaction_type'], 'expense')
        self.assertEqual(transaction_data['account_number'], 'xxxx0027')
        self.assertEqual(transaction_data['amount'], 115)
        self.assertEqual(transaction_data['currency'], 'OMR')

        # Check that the date was parsed correctly
        self.assertIsNotNone(transaction_data.get('value_date'))
        self.assertEqual(transaction_data['value_date'].year, 2025)
        self.assertEqual(transaction_data['value_date'].month, 1)
        self.assertEqual(transaction_data['value_date'].day, 6)

    def test_credit_transaction_parsing(self):
        """Test parsing a credit transaction email."""
        # Create a mock credit transaction email
        email_data = {
            'id': '456',
            'subject': 'Transaction Alert',
            'from': 'Bank Muscat <bankmuscat@bankmuscat.com>',
            'date': 'Wed, 06 Jan 2025 10:30:00 +0400',
            'body': """<img src=3D"https://www.bankmuscat.com/en/PublishingImages/Account Transact=
ion/Advertisment-header.jpg"><BR> <p style=3D"font-size:Medium;">Dear custo=
mer, <BR> Your account xxxx0019 with 0442 - Br Maabela Ind has been credite=
d by OMR 120.000 with value date 06/01/25. <BR> Details of this transaction=
 are provided below for your reference.<BR> Cash Dep <BR> CDM13720247 19:56=
:11 <BR> ABDULMAJEED <BR> <BR> Kind regards, <BR> bank muscat </P>"""
        }

        # Parse the email
        transaction_data = self.parser.parse_email(email_data)

        # Verify the parsed data
        self.assertIsNotNone(transaction_data)
        self.assertEqual(transaction_data['transaction_type'], 'income')
        self.assertEqual(transaction_data['account_number'], 'xxxx0019')
        self.assertEqual(transaction_data['amount'], 120.0)
        self.assertEqual(transaction_data['currency'], 'OMR')

        # Check that the date was parsed correctly
        self.assertIsNotNone(transaction_data.get('value_date'))
        self.assertEqual(transaction_data['value_date'].year, 2025)
        self.assertEqual(transaction_data['value_date'].month, 1)
        self.assertEqual(transaction_data['value_date'].day, 6)

    def test_salary_transaction_parsing(self):
        """Test parsing a salary transaction email."""
        # Create a mock salary transaction email
        email_data = {
            'id': '789',
            'subject': 'Transaction Alert',
            'from': 'Bank Muscat <bankmuscat@bankmuscat.com>',
            'date': 'Wed, 23 Jun 2025 10:30:00 +0400',
            'body': """<img src=3D"https://www.bankmuscat.com/en/PublishingImages/Account Transact=
ion/Advertisment-header.jpg"><BR> <p style=3D"font-size:Medium;">Dear custo=
mer, <BR> Your account xxxx0019 with 0442 - Br Maabela Ind has been credite=
d by OMR 722.200 with value date 06/23/25. <BR> Details of this transaction=
 are provided below for your reference.<BR> SALARY <BR> Salary for 6 202 <B=
R> SALARY <BR> <BR> Kind regards, <BR> bank muscat </P>"""
        }

        # Parse the email
        transaction_data = self.parser.parse_email(email_data)

        # Verify the parsed data
        self.assertIsNotNone(transaction_data)
        self.assertEqual(transaction_data['transaction_type'], 'income')
        self.assertEqual(transaction_data['account_number'], 'xxxx0019')
        self.assertEqual(transaction_data['amount'], 722.2)
        self.assertEqual(transaction_data['currency'], 'OMR')

        # Check that the date was parsed correctly
        self.assertIsNotNone(transaction_data.get('value_date'))
        self.assertEqual(transaction_data['value_date'].year, 2025)
        self.assertEqual(transaction_data['value_date'].month, 6)
        self.assertEqual(transaction_data['value_date'].day, 23)

    def test_mobile_payment_received_parsing(self):
        """Test parsing a mobile payment received email."""
        # Create a mock mobile payment received email
        email_data = {
            'id': '101112',
            'subject': 'Transaction Alert',
            'from': 'Bank Muscat <bankmuscat@bankmuscat.com>',
            'date': 'Wed, 06 Jan 2025 10:30:00 +0400',
            'body': """<img src=3D"https://www.bankmuscat.com/en/PublishingImages/Account%20Transa=
ction/Advertisment-header.jpg"><BR> <p style=3D"font-size:Medium;">Dear cus=
tomer, <BR> You have received OMR 300.000 from MOHAMMED MOOSA SALIM AL AZRI=
 in your a/c xxxx0019  using Mobile Payment services/mobile wallet.<BR> Txn=
 Id BMCT010568450267. <BR> Kind regards, <BR> Bank muscat </P>"""
        }

        # Parse the email
        transaction_data = self.parser.parse_email(email_data)

        # Verify the parsed data
        self.assertIsNotNone(transaction_data)
        self.assertEqual(transaction_data['transaction_type'], 'income')
        self.assertEqual(transaction_data['account_number'], 'xxxx0019')
        self.assertEqual(transaction_data['amount'], 300.0)
        self.assertEqual(transaction_data['currency'], 'OMR')
        self.assertEqual(transaction_data['transaction_id'], 'BMCT010568450267')
        self.assertEqual(transaction_data['transaction_sender'], 'MOHAMMED MOOSA SALIM AL AZRI')

    def test_mobile_payment_sent_parsing(self):
        """Test parsing a mobile payment sent email."""
        # Create a mock mobile payment sent email
        email_data = {
            'id': '131415',
            'subject': 'Transaction Alert',
            'from': 'Bank Muscat <bankmuscat@bankmuscat.com>',
            'date': 'Wed, 06 Jan 2025 10:30:00 +0400',
            'body': """<img src=3D"https://www.bankmuscat.com/en/PublishingImages/Account%20Transa=
ction/Advertisment-header.jpg"><BR> <p style=3D"font-size:Medium;">Dear cus=
tomer, <BR> You have sent OMR 240.000 to TARIXXXXXXXXXXXXXXXXXUK from your =
a/c xxxx0019 using Mobile Payment services/mobile wallet.<BR> Txn Id BMCT01=
0568736731. <BR> <BR> Kind regards, <BR> Bank muscat </P>"""
        }

        # Parse the email
        transaction_data = self.parser.parse_email(email_data)

        # Verify the parsed data
        self.assertIsNotNone(transaction_data)
        self.assertEqual(transaction_data['transaction_type'], 'expense')
        self.assertEqual(transaction_data['account_number'], 'xxxx0019')
        self.assertEqual(transaction_data['amount'], 240.0)
        self.assertEqual(transaction_data['currency'], 'OMR')
        self.assertEqual(transaction_data['transaction_id'], 'BMCT010568736731')
        self.assertEqual(transaction_data['transaction_receiver'], 'TARIXXXXXXXXXXXXXXXXXUK')

    def test_card_transaction_parsing(self):
        """Test parsing a card transaction email."""
        # Create a mock card transaction email
        email_data = {
            'id': '161718',
            'subject': 'Transaction Alert',
            'from': 'Bank Muscat <bankmuscat@bankmuscat.com>',
            'date': 'Wed, 22 Jun 2025 20:29:00 +0400',
            'body': """<img src=3D"https://www.bankmuscat.com/en/PublishingImages/Account Transact=
ion/Advertisment-header.jpg"><BR> <p style=3D"font-size:Medium;">Dear Custo=
mer, <BR> Your Debit card number 4837**** ****1518 has been utilised as fol=
lows:<BR> <BR> Account number : xxxx0019 <BR> Description : 883315-Quality =
Saving - Al AraMUSC <BR> Amount : OMR 10.561 <BR> Date/Time : 22 JUN 25 20:=
29 <BR> Transaction Country : Oman <BR> <BR> Kind Regards, <BR>Bank Muscat =
</P>"""
        }

        # Parse the email
        transaction_data = self.parser.parse_email(email_data)

        # Verify the parsed data
        self.assertIsNotNone(transaction_data)
        self.assertEqual(transaction_data['transaction_type'], 'expense')
        self.assertEqual(transaction_data['account_number'], 'xxxx0019')
        self.assertEqual(transaction_data['amount'], 10.561)
        self.assertEqual(transaction_data['currency'], 'OMR')
        self.assertEqual(transaction_data['description'], '883315-Quality Saving - Al AraMUSC')
        self.assertEqual(transaction_data['country'], 'Oman')

        # Check that the date was parsed correctly
        self.assertIsNotNone(transaction_data.get('value_date'))
        self.assertEqual(transaction_data['value_date'].year, 2025)
        self.assertEqual(transaction_data['value_date'].month, 6)
        self.assertEqual(transaction_data['value_date'].day, 22)
        self.assertEqual(transaction_data['value_date'].hour, 20)
        self.assertEqual(transaction_data['value_date'].minute, 29)

if __name__ == '__main__':
    unittest.main()
