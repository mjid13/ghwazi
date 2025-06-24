#!/usr/bin/env python3
"""
Script to run all tests for the Bank Email Parser & Account Tracker.
"""

import unittest
import sys
import os

def run_tests():
    """Run all tests in the tests directory."""
    # Add the current directory to the path so we can import the money_tracker package
    sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
    
    # Discover and run all tests
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover('tests')
    
    test_runner = unittest.TextTestRunner(verbosity=2)
    result = test_runner.run(test_suite)
    
    # Return non-zero exit code if tests failed
    return 0 if result.wasSuccessful() else 1
# clear_db.py
from webapp import db
from money_tracker.models.models import Base
def clear_db():
    """Delete all data from all tables."""
    meta = Base.metadata
    with db.engine.begin() as connection:
        for table in reversed(meta.sorted_tables):
            connection.execute(table.delete())

# if __name__ == "__main__":
#     clear_db()
#     print("Database cleared.")
# if __name__ == '__main__':
#     sys.exit(run_tests())

# fetch_bankmuscat_emails.py
import imaplib
import email

IMAP_HOST = "imap.gmail.com"
IMAP_PORT = 993
EMAIL_USER = "abdulmajeed.alhadhrami@gmail.com"
EMAIL_PASS = "ftlm ddld ahdv ylan"
MAILBOX = "INBOX"
BANK_SENDER = "noreply@bankmuscat.com"

def main():
    # Connect to the email server
    mail = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT)
    mail.login(EMAIL_USER, EMAIL_PASS)
    mail.select(MAILBOX)

    # Search for all emails from the specific sender
    status, data = mail.search(None, f'FROM "{BANK_SENDER}"')
    if status != "OK":
        print("Failed to search for emails.")
        return

    # List of email IDs
    email_ids = data[0].split()
    print(f"Found {len(email_ids)} emails from {BANK_SENDER}")

    for eid in email_ids:
        status, msg_data = mail.fetch(eid, "(RFC822)")
        if status != "OK":
            continue

        msg = email.message_from_bytes(msg_data[0][1])
        subject = email.header.decode_header(msg["Subject"])[0][0]
        if isinstance(subject, bytes):
            subject = subject.decode(errors="ignore")
        print(f"Subject: {subject}")

        # (Optional) Print plain text body
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    print(part.get_payload(decode=True).decode(errors="ignore"))
        else:
            print(msg.get_payload(decode=True).decode(errors="ignore"))

    mail.logout()

if __name__ == "__main__":
    main()