#!/usr/bin/env python3
"""
Test script to run database migrations.
This script initializes the database and runs the create_tables method to trigger migrations.
"""

import logging
import sys
from money_tracker.models.database import Database
from money_tracker.config import settings

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def main():
    """Run database migrations."""
    logger.info("Starting database migration test")
    
    # Initialize database
    db = Database()
    if not db.connect():
        logger.error("Failed to connect to database")
        return False
    
    # Run create_tables to trigger migrations
    if not db.create_tables():
        logger.error("Failed to create tables")
        return False
    
    logger.info("Database migration test completed successfully")
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)