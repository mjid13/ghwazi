#!/usr/bin/env python3
"""
Test script to verify that the specific queries mentioned in the error messages now work correctly.
"""

import logging
import sys
from money_tracker.models.database import Database
from money_tracker.models.models import Account, EmailConfiguration

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def test_account_query():
    """Test the account query that was failing."""
    logger.info("Testing account query")
    
    # Initialize database
    db = Database()
    if not db.connect():
        logger.error("Failed to connect to database")
        return False
    
    # Get a session
    session = db.get_session()
    
    try:
        # This is the query that was failing according to the error message
        # Create a test user
        test_user = Account(bank_id="test_bank", bank_name="Test Bank")
        session.add(test_user)
        session.commit()
        
        # Use the test user's ID in the query
        accounts = session.query(Account).filter(
            Account.user_id == test_user.id
        ).all()
        
        logger.info(f"Successfully queried accounts table. Found {len(accounts)} accounts.")
        
        # Print some details about the accounts to verify the data
        for account in accounts:
            logger.info(f"Account ID: {account.id}, Bank ID: {account.bank_id}, Bank Name: {account.bank_name}")
        
        # Clean up the test user
        session.delete(test_user)
        session.commit()
        
        return True
    except Exception as e:
        logger.error(f"Error querying accounts: {str(e)}")
        return False
    finally:
        db.close_session(session)

def test_email_config_query():
    """Test the email configuration query that was failing."""
    logger.info("Testing email configuration query")
    
    # Initialize database
    db = Database()
    if not db.connect():
        logger.error("Failed to connect to database")
        return False
    
    # Get a session
    session = db.get_session()
    
    try:
        # This is the query that was failing according to the error message
        # Create a test user
        test_user = User(name="Test User")
        session.add(test_user)
        session.commit()
        
        # Use the dynamically created user's ID
        email_configs = session.query(EmailConfiguration).filter(
            EmailConfiguration.user_id == test_user.id
        ).all()
        
        logger.info(f"Successfully queried email_configurations table. Found {len(email_configs)} configurations.")
        
        # Print some details about the email configurations to verify the data
        for config in email_configs:
            logger.info(f"Config ID: {config.id}, Bank ID: {config.bank_id}, Email: {config.email_username}")
        
        return True
    except Exception as e:
        logger.error(f"Error querying email configurations: {str(e)}")
        return False
    finally:
        db.close_session(session)

def main():
    """Run the test queries."""
    logger.info("Starting test queries")
    
    # Test account query
    account_success = test_account_query()
    
    # Test email configuration query
    email_config_success = test_email_config_query()
    
    # Check if both tests passed
    if account_success and email_config_success:
        logger.info("All test queries completed successfully")
        return True
    else:
        logger.error("Some test queries failed")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)