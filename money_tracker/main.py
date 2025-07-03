#!/usr/bin/env python3
"""
Bank Email Parser & Account Tracker

This script connects to an email inbox, parses transaction emails from a bank,
extracts structured data, and saves it to a database.
"""

import logging
import sys
import os
import argparse
from datetime import datetime
from tabulate import tabulate

from money_tracker.services.transaction_service import TransactionService
from money_tracker.config import settings

# Setup logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def process_emails(args):
    """Process emails and store transactions."""
    service = TransactionService()
    try:
        count = service.process_emails(args.folder, not args.all)
        print(f"Processed {count} transactions")
    finally:
        service.close()

def show_accounts(args):
    """Show account summaries."""
    service = TransactionService()
    try:
        if args.account:
            # Show specific account
            summary = service.get_account_summary(args.account)
            if summary:
                print_account_summary(summary)
            else:
                print(f"Account {args.account} not found")
        else:
            # Show all accounts
            summaries = service.get_account_summaries()
            if summaries:
                for summary in summaries:
                    print_account_summary(summary)
                    print()
            else:
                print("No accounts found")
    finally:
        service.close()

def print_account_summary(summary):
    """Print account summary in a formatted way."""
    print(f"Account: {summary['account_number']} ({summary['bank_name']})")
    print(f"Balance: {summary['current_balance']} {summary['currency']}")
    # print(f"Last Updated: {summary['last_updated']}")

    # Create a table for transaction counts
    counts_table = [
        ["Income", summary['income_count'], summary['income_total']],
        ["Expense", summary['expense_count'], summary['expense_total']],
        ["Transfer", summary['transfer_count'], "N/A"]
    ]

    print("\nTransaction Summary:")
    print(tabulate(counts_table, headers=["Type", "Count", "Total"]))

def main():
    """Main entry point for the application."""
    parser = argparse.ArgumentParser(description="Bank Email Parser & Account Tracker")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Process emails command
    process_parser = subparsers.add_parser("process", help="Process emails and store transactions")
    process_parser.add_argument("--folder", default="INBOX", help="Email folder to process")
    process_parser.add_argument("--all", action="store_true", help="Process all emails, not just unread")

    # Show accounts command
    accounts_parser = subparsers.add_parser("accounts", help="Show account summaries")
    accounts_parser.add_argument("--account", help="Show specific account")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    logger.info(f"Starting Bank Email Parser & Account Tracker - Command: {args.command}")

    try:
        if args.command == "process":
            process_emails(args)
        elif args.command == "accounts":
            show_accounts(args)

        logger.info("Command completed successfully")
    except Exception as e:
        logger.error(f"An error occurred: {str(e)}")
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
