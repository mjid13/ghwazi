"""
Database connection and session management for the Bank Email Parser & Account Tracker.
"""

import logging
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session

from money_tracker.config import settings

logger = logging.getLogger(__name__)

# Create SQLAlchemy base class for models
Base = declarative_base()

class Database:
    """Database connection and session management."""
    
    def __init__(self, database_url=None):
        """
        Initialize database connection.
        
        Args:
            database_url (str, optional): Database connection URL. If not provided,
                                         uses the URL from settings.
        """
        self.database_url = database_url or settings.DATABASE_URL
        self.engine = None
        self.session_factory = None
        self.Session = None
    
    def connect(self):
        """
        Connect to the database and create session factory.
        
        Returns:
            bool: True if connection is successful, False otherwise.
        """
        try:
            # Create engine
            self.engine = create_engine(self.database_url)
            
            # Create session factory
            self.session_factory = sessionmaker(bind=self.engine)
            self.Session = scoped_session(self.session_factory)
            
            logger.info(f"Connected to database: {self.database_url}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to database: {str(e)}")
            return False
    
    def create_tables(self):
        """
        Create all tables defined in the models.
        
        Returns:
            bool: True if tables are created successfully, False otherwise.
        """
        try:
            Base.metadata.create_all(self.engine)
            logger.info("Database tables created")
            return True
        except Exception as e:
            logger.error(f"Failed to create database tables: {str(e)}")
            return False
    
    def get_session(self):
        """
        Get a database session.
        
        Returns:
            Session: Database session.
        """
        if not self.Session:
            self.connect()
        return self.Session()
    
    def close_session(self, session):
        """
        Close a database session.
        
        Args:
            session: Database session to close.
        """
        try:
            session.close()
        except Exception as e:
            logger.error(f"Error closing database session: {str(e)}")