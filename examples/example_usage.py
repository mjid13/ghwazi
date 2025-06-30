#!/usr/bin/env python3
"""
Example script demonstrating how to use the Bank Email Parser & Account Tracker programmatically.
"""

import sys
import os
import logging
from datetime import datetime, timedelta

# Add the parent directory to the path so we can import the money_tracker package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from money_tracker.services.transaction_service import TransactionService
from money_tracker.models.database import Database
from money_tracker.models.models import TransactionRepository

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def example_process_emails():
    """Example of processing emails and storing transactions."""
    logger.info("Example: Processing emails")
    
    service = TransactionService()
    try:
        # Process unread emails from the INBOX folder
        count = service.process_emails(folder="INBOX", unread_only=True)
        logger.info(f"Processed {count} transactions")
    finally:
        service.close()

def example_get_account_summaries():
    """Example of getting account summaries."""
    logger.info("Example: Getting account summaries")
    
    service = TransactionService()
    try:
        # Get summaries for all accounts
        summaries = service.get_account_summaries()
        
        if not summaries:
            logger.info("No accounts found")
            return
        
        for summary in summaries:
            logger.info(f"Account: {summary['account_number']}")
            logger.info(f"Balance: {summary['current_balance']} {summary['currency']}")
            logger.info(f"Income transactions: {summary['income_count']} (Total: {summary['income_total']})")
            logger.info(f"Expense transactions: {summary['expense_count']} (Total: {summary['expense_total']})")
            logger.info(f"Transfer transactions: {summary['transfer_count']}")
            logger.info(f"Last updated: {summary['last_updated']}")
            logger.info("---")
    finally:
        service.close()

def example_add_manual_transaction():
    """Example of adding a manual transaction."""
    logger.info("Example: Adding a manual transaction")
    
    # Connect to the database
    db = Database()
    db.connect()
    db.create_tables()
    
    session = db.get_session()
    try:
        # Create a manual transaction
        transaction_data = {
            'transaction_id': f"MANUAL-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'account_number': 'xxxx0019',  # Replace with your account number
            'bank_name': 'Bank Muscat',
            'transaction_type': 'expense',
            'amount': 25.50,
            'currency': 'OMR',
            'date_time': datetime.now(),
            'transaction_receiver': 'Coffee Shop',
            'description': 'Coffee and snacks',
            'country': 'Oman'
        }
        
        # Store the transaction
        transaction = TransactionRepository.create_transaction(session, transaction_data)
        
        if transaction:
            logger.info(f"Created manual transaction: {transaction.id}")
            
            # Get the account
            account = transaction.account
            logger.info(f"Updated balance for account {account.account_number}: {account.current_balance} {account.currency}")
        else:
            logger.error("Failed to create manual transaction")
    finally:
        db.close_session(session)

def main():
    """Run the examples."""
    logger.info("Starting examples")
    
    # Uncomment the examples you want to run
    example_process_emails()
    example_get_account_summaries()
    example_add_manual_transaction()
    
    logger.info("Examples completed")

if __name__ == "__main__":
    # main()
    from bs4 import BeautifulSoup
    import html

    email_html_list = [
        '''<img src=3D"https://www.bankmuscat.com/en/PublishingImages/Account Transact=
    ion/Advertisment-header.jpg"><BR> <p style=3D"font-size:Medium;">Dear custo=
    mer, <BR> Your account xxxx0027 with 0442 - Br Maabela Ind has been debited=
     by OMR 115 with value date 06/01/25. <BR> Details of this transaction are =
    provided below for your reference.<BR> TRANSFER <BR>  <BR> KHASEEB DAWOOD K=
    HASEEB AL HADHRAMI <BR> <BR> Kind regards, <BR> bank muscat </P> To unsubsc=
    ribe / modify the email alert service please contact  your nearest Branch /=
     ARM or contact bank muscat Call Center  at 24795555.  <p style=3D"font-siz=
    e:small;"> This e-mail is confidential and may also be legally privileged. =
     If you are not the intended recipient, please notify us  immediately. You =
    should not copy, forward, disclose or use it for  any purpose either partly=
     or completely. If you have received this  message by error, please delete =
    all its copies from your system and  notify us by e-mail to care@bankmuscat=
    .com. Internet communications cannot be guaranteed to be timely, secure, er=
    ror  or virus-free. Also, the Web/ IT/ Email administrator might not  allow=
     emails with attachments, thus the sender does not accept  liability for an=
    y errors or omissions. </P>  <BR><img src=3D"https://www.bankmuscat.com/en/=
    PublishingImages/Account Transaction/Advertisment-footer.jpg">''',

        '''<img src=3D"https://www.bankmuscat.com/en/PublishingImages/Account Transact=
    ion/Advertisment-header.jpg"><BR> <p style=3D"font-size:Medium;">Dear custo=
    mer, <BR> Your account xxxx0019 with 0442 - Br Maabela Ind has been credite=
    d by OMR 120.000 with value date 06/01/25. <BR> Details of this transaction=
     are provided below for your reference.<BR> Cash Dep <BR> CDM13720247 19:56=
    :11 <BR> ABDULMAJEED <BR> <BR> Kind regards, <BR> bank muscat </P> To unsub=
    scribe / modify the email alert service please contact  your nearest Branch=
     / ARM or contact bank muscat Call Center  at 24795555.  <p style=3D"font-s=
    ize:small;"> This e-mail is confidential and may also be legally privileged=
    .  If you are not the intended recipient, please notify us  immediately. Yo=
    u should not copy, forward, disclose or use it for  any purpose either part=
    ly or completely. If you have received this  message by error, please delet=
    e all its copies from your system and  notify us by e-mail to care@bankmusc=
    at.com. Internet communications cannot be guaranteed to be timely, secure, =
    error  or virus-free. Also, the Web/ IT/ Email administrator might not  all=
    ow emails with attachments, thus the sender does not accept  liability for =
    any errors or omissions. </P>  <BR><img src=3D"https://www.bankmuscat.com/e=
    n/PublishingImages/Account Transaction/Advertisment-footer.jpg">''',

        '''<img src=3D"https://www.bankmuscat.com/en/PublishingImages/Account Transact=
    ion/Advertisment-header.jpg"><BR> <p style=3D"font-size:Medium;">Dear custo=
    mer, <BR> Your account xxxx0019 with 0442 - Br Maabela Ind has been credite=
    d by OMR 722.200 with value date 06/23/25. <BR> Details of this transaction=
     are provided below for your reference.<BR> SALARY <BR> Salary for 6 202 <B=
    R> SALARY <BR> <BR> Kind regards, <BR> bank muscat </P> To unsubscribe / mo=
    dify the email alert service please contact  your nearest Branch / ARM or c=
    ontact bank muscat Call Center  at 24795555.  <p style=3D"font-size:small;"=
    > This e-mail is confidential and may also be legally privileged.  If you a=
    re not the intended recipient, please notify us  immediately. You should no=
    t copy, forward, disclose or use it for  any purpose either partly or compl=
    etely. If you have received this  message by error, please delete all its c=
    opies from your system and  notify us by e-mail to care@bankmuscat.com. Int=
    ernet communications cannot be guaranteed to be timely, secure, error  or v=
    irus-free. Also, the Web/ IT/ Email administrator might not  allow emails w=
    ith attachments, thus the sender does not accept  liability for any errors =
    or omissions. </P>  <BR><img src=3D"https://www.bankmuscat.com/en/Publishin=
    gImages/Account Transaction/Advertisment-footer.jpg">''',

        '''<img src=3D"https://www.bankmuscat.com/en/PublishingImages/Account%20Transa=
    ction/Advertisment-header.jpg"><BR> <p style=3D"font-size:Medium;">Dear cus=
    tomer, <BR> You have received OMR 300.000 from MOHAMMED MOOSA SALIM AL AZRI=
     in your a/c xxxx0019  using Mobile Payment services/mobile wallet.<BR> Txn=
     Id BMCT010568450267. <BR> Kind regards, <BR> Bank muscat </P> To unsubscri=
    be / modify the email alert service please contact your nearest Branch / AR=
    M or contact bank muscat Call Center at 24795555. <p style=3D"font-size:sma=
    ll;">This e-mail is confidential and may also be legally privileged. If you=
     are not the intended recipient , please notify us immediately; you should =
    not copy, forward, disclose or use it for any purpose either partly or comp=
    letely. If you have received this message in error, please delete it and al=
    l copies from your system and notify us by e-mail to support@bankmuscat.com=
    . Internet communications cannot be guaranteed to be timely, secure, error =
    or virus-free. Also, the Web/ IT/ Email administrator might not allow email=
    s with attachment. Thus the sender does not accept liability for any errors=
     or omissions. </P> <BR><img src=3D"https://www.bankmuscat.com/en/Publishin=
    gImages/Account%20Transaction/Advertisment-footer.jpg">''',

        '''<img src=3D"https://www.bankmuscat.com/en/PublishingImages/Account%20Transa=
    ction/Advertisment-header.jpg"><BR> <p style=3D"font-size:Medium;">Dear cus=
    tomer, <BR> You have sent OMR 240.000 to TARIXXXXXXXXXXXXXXXXXUK from your =
    a/c xxxx0019 using Mobile Payment services/mobile wallet.<BR> Txn Id BMCT01=
    0568736731. <BR> <BR> Kind regards, <BR> Bank muscat </P> To unsubscribe / =
    modify the email alert service please contact your nearest Branch / ARM or =
    contact bank muscat Call Center at 24795555. <p style=3D"font-size:small;">=
    This e-mail is confidential and may also be legally privileged. If you are =
    not the intended recipient , please notify us immediately; you should not c=
    opy, forward, disclose or use it for any purpose either partly or completel=
    y. If you have received this message in error, please delete it and all cop=
    ies from your system and notify us by e-mail to support@bankmuscat.com. Int=
    ernet communications cannot be guaranteed to be timely, secure, error or vi=
    rus-free. Also, the Web/ IT/ Email administrator might not allow emails wit=
    h attachment. Thus the sender does not accept liability for any errors or o=
    missions. </P> <BR><img src=3D"https://www.bankmuscat.com/en/PublishingImag=
    es/Account%20Transaction/Advertisment-footer.jpg">''',

        '''<img src=3D"https://www.bankmuscat.com/en/PublishingImages/Account Transact=
    ion/Advertisment-header.jpg"><BR> <p style=3D"font-size:Medium;">Dear Custo=
    mer, <BR> Your Debit card number 4837**** ****1518 has been utilised as fol=
    lows:<BR> <BR> Account number : xxxx0019 <BR> Description : 883315-Quality =
    Saving - Al AraMUSC <BR> Amount : OMR 10.561 <BR> Date/Time : 22 JUN 25 20:=
    29 <BR> Transaction Country : Oman <BR> <BR> Kind Regards, <BR>Bank Muscat =
    </P> To unsubscribe / modify the email alert service please contact  your n=
    earest Branch / ARM or contact bank muscat Call Center  at 24795555.  <p st=
    yle=3D"font-size:small;"> This e-mail is confidential and may also be legal=
    ly privileged.  If you are not the intended recipient, please notify us  im=
    mediately. You should not copy, forward, disclose or use it for  any purpos=
    e either partly or completely. If you have received this  message by error,=
     please delete all its copies from your system and  notify us by e-mail to =
    care@bankmuscat.com. Internet communications cannot be guaranteed to be tim=
    ely, secure, error  or virus-free. Also, the Web/ IT/ Email administrator m=
    ight not  allow emails with attachments, thus the sender does not accept  l=
    iability for any errors or omissions. </P>  <BR><img src=3D"https://www.ban=
    kmuscat.com/en/PublishingImages/Account Transaction/Advertisment-footer.jpg=
    ">'''
    ]


    def clean_text(raw_html: str) -> str:
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
    import re
    from typing import Optional, Dict

    def _get_name(email_text):
        counterparty_re1 = re.compile(
            r'(?:from|to)\s+([A-Z][A-Z\sX]+[A-Z])(?=\s|$)', re.IGNORECASE

        )
        counterparty_match = counterparty_re1.search(email_text)
        if counterparty_match:
            # Clean up spaces, remove extra whitespace
            name = ' '.join(counterparty_match.group(1).split())
        else:
            # fallback: try to find uppercase name lines near transaction details (like Email #1)
            # This will match 2+ uppercase words together
            counterparty_re2 = re.compile(r'\n([A-Z][A-Z\s]{4,})\n', re.MULTILINE)
            names = counterparty_re2.findall(email_text)
            if names:  # Check if names list is not empty
                name = ' '.join(names[0].split())
                return name
            else:
                return None

        return name if name else None


    import re


    def determine_transaction_type(email_text: str) -> str:
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
    def extract_bank_email_data(email_text: str) -> Dict[str, Optional[str]]:
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

        # Amount: OMR with decimal or integer (with optional commas)
        amount_re = re.compile(r'OMR\s*([\d,]+\.\d+|[\d,]+)', re.IGNORECASE)
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
            data['description'] = desc_match.group(1).strip()
        # Counterparty (Sender/Receiver) name
        # Patterns:
        # - "from NAME" or "to NAME" (for mobile payments)
        # - or lines with all uppercase words (names)
        # I want it to stop capturing any space or lowercase latter after the last uppercase letter, like iti like this (MOHAMMED MOOSA SALIM AL AZRI in your a) the regx should give only this (MOHAMMED MOOSA SALIM AL AZRI)
        counterparty_re1 = re.compile(
r'(?:from|to)\s+([A-Z](?:[A-Z\s]+[A-Z]))', re.IGNORECASE
        )
        counterparty_match = counterparty_re1.search(email_text)
        if counterparty_match:
            # Clean up spaces, remove extra whitespace
            name = ' '.join(counterparty_match.group(1).split())
            data['counterparty_name'] = name
        else:
            # fallback: try to find uppercase name lines near transaction details (like Email #1)
            # This will match 2+ uppercase words together
            counterparty_re2 = re.compile(r'\n([A-Z][A-Z\s]{4,})\n', re.MULTILINE)
            names = counterparty_re2.findall(email_text)
            if names:
                # Pick first candidate, clean spaces
                data['counterparty_name'] = ' '.join(names[0].split())

        # Transaction ID: "Txn Id <id>"
        txn_id_re = re.compile(r'Txn Id\s+(\w+)', re.IGNORECASE)
        txn_id_match = txn_id_re.search(email_text)
        if txn_id_match:
            data['transaction_id'] = txn_id_match.group(1)

        txn_type = determine_transaction_type(email_text)  # You may have this as a method or external call
        data['type'] = txn_type

        # Determine "from" and "to" according to type
        if txn_type == 'expense':
            # "Me" is sender, Recipient (e.g., description or extract from body) is 'to'
            data['from'] = 'me'
            data['to'] = _get_name(email_text)  # Implement logic to extract recipient name or description
        elif txn_type == 'income':
            # Extract sender as 'from', "Me" is receiving
            data['from'] = _get_name(email_text)  # Implement logic to extract sender name
            data['to'] = 'me'
        # elif txn_type == 'transfer':
        #     # Implement your logic for transfer
        #     data['from'] = _get_name(email_text)
        #     data['to'] = _get_name(email_text)
        else:
            data['from'] = None
            data['to'] = None

        return data




    # Process and print cleaned text of all emails
    for idx, raw_html in enumerate(email_html_list, 1):
        print(f"--- Cleaned Email #{idx} ---")
        clean_txt = clean_text(raw_html)
        print(clean_text(raw_html))
        extracted = extract_bank_email_data(clean_txt)
        print(extracted)
        print("\n")
