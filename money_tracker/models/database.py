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
            # Check if tables exist and have user_id column
            from sqlalchemy import inspect, Column, Integer, ForeignKey
            inspector = inspect(self.engine)

            # Create all tables that don't exist
            Base.metadata.create_all(self.engine)

            # Tables that need user_id column
            tables_to_check = ['accounts', 'email_configurations', 'email_metadata']

            # Check if tables exist and have user_id column
            for table_name in tables_to_check:
                if table_name in inspector.get_table_names():
                    # Check if user_id column exists in table
                    columns = [column['name'] for column in inspector.get_columns(table_name)]
                    if 'user_id' not in columns:
                        # Add user_id column to table
                        from sqlalchemy.sql import text
                        with self.engine.connect() as connection:
                            # Create a default user if none exists
                            connection.execute(text("""
                                INSERT OR IGNORE INTO users (id, username, email, password_hash, created_at, updated_at)
                                VALUES (1, 'default_user', 'default@example.com', 'pbkdf2:sha256:150000$abc123', 
                                       CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                            """))

                            # Add user_id column with default value
                            connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN user_id INTEGER REFERENCES users(id) DEFAULT 1"))

                            # Commit the transaction
                            connection.commit()

                        logger.info(f"Added user_id column to {table_name} table")

            # Check if transactions table exists and has email_metadata_id column
            if 'transactions' in inspector.get_table_names():
                columns = [column['name'] for column in inspector.get_columns('transactions')]
                if 'email_metadata_id' not in columns:
                    try:
                        # Add email_metadata_id column to transactions table
                        from sqlalchemy.sql import text
                        with self.engine.connect() as connection:
                            # Add email_metadata_id column with NULL default value
                            connection.execute(text("ALTER TABLE transactions ADD COLUMN email_metadata_id INTEGER REFERENCES email_metadata(id)"))

                            # Commit the transaction
                            connection.commit()

                        logger.info("Added email_metadata_id column to transactions table")
                    except Exception as e:
                        logger.error(f"Error adding email_metadata_id column to transactions table: {str(e)}")
                        # If ALTER TABLE fails, try recreating the table with the new column
                        try:
                            # Get all transactions data
                            with self.engine.connect() as connection:
                                result = connection.execute(text("SELECT * FROM transactions"))
                                transactions_data = [dict(row) for row in result]

                            # Create a new table with the correct schema
                            with self.engine.connect() as connection:
                                # Drop the old table
                                connection.execute(text("DROP TABLE IF EXISTS transactions_old"))
                                connection.execute(text("ALTER TABLE transactions RENAME TO transactions_old"))

                                # Commit the transaction
                                connection.commit()

                            # Create the new table with Base.metadata.create_all
                            from money_tracker.models.models import Transaction
                            Base.metadata.create_all(self.engine, tables=[Transaction.__table__])

                            # Copy data from old table to new table
                            if transactions_data:
                                with self.engine.connect() as connection:
                                    for row in transactions_data:
                                        # Remove id from the row data (it will be auto-generated)
                                        if 'id' in row:
                                            del row['id']

                                        # Build column names and placeholders for the INSERT statement
                                        columns = ', '.join(row.keys())
                                        placeholders = ', '.join([':' + k for k in row.keys()])

                                        # Execute the INSERT statement
                                        connection.execute(
                                            text(f"INSERT INTO transactions ({columns}) VALUES ({placeholders})"),
                                            row
                                        )

                                    # Commit the transaction
                                    connection.commit()

                                logger.info(f"Recreated transactions table with email_metadata_id column and copied {len(transactions_data)} rows")
                            else:
                                logger.info("Recreated transactions table with email_metadata_id column (no data to copy)")

                            # Drop the old table
                            with self.engine.connect() as connection:
                                connection.execute(text("DROP TABLE IF EXISTS transactions_old"))
                                connection.commit()

                        except Exception as e2:
                            logger.error(f"Error recreating transactions table: {str(e2)}")
                            # If recreation fails, try a simpler approach - just create the column without foreign key constraint
                            try:
                                with self.engine.connect() as connection:
                                    connection.execute(text("ALTER TABLE transactions ADD COLUMN email_metadata_id INTEGER"))
                                    connection.commit()
                                logger.info("Added email_metadata_id column to transactions table (without foreign key constraint)")
                            except Exception as e3:
                                logger.error(f"All attempts to add email_metadata_id column failed: {str(e3)}")
                                # At this point, we've tried everything and failed
                                # The application will likely encounter errors when trying to use this column

            # Check if transactions table has counterparty_id column
            if 'transactions' in inspector.get_table_names():
                columns = [column['name'] for column in inspector.get_columns('transactions')]
                if 'counterparty_id' not in columns:
                    try:
                        # Add counterparty_id column to transactions table
                        from sqlalchemy.sql import text
                        with self.engine.connect() as connection:
                            # Add counterparty_id column with NULL default value
                            connection.execute(text("ALTER TABLE transactions ADD COLUMN counterparty_id INTEGER REFERENCES counterparties(id)"))
                            connection.commit()
                        logger.info("Added counterparty_id column to transactions table")
                    except Exception as e:
                        logger.error(f"Error adding counterparty_id column to transactions table: {str(e)}")
                        # This might fail if counterparties table doesn't exist yet, which is fine
            
            # Migrate existing counterparty data
            # try:
            #     self.migrate_counterparty_data()
            # except Exception as e:
            #     logger.error(f"Error migrating counterparty data: {str(e)}")
            #     # Continue even if migration fails
            
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

    def migrate_counterparty_data(self):
        """
        Migrate existing counterparty data from transactions to the new counterparty table.
        This creates counterparty records and updates transaction.counterparty_id references.
        """
        try:
            logger.info("Starting migration of counterparty data")
            from sqlalchemy.sql import text
            from sqlalchemy.orm import Session
            
            # Get a session
            session = self.get_session()
            
            try:
                # Get all unique counterparty names from transactions
                result = session.execute(text("""
                    SELECT DISTINCT counterparty_name 
                    FROM transactions 
                    WHERE counterparty_name IS NOT NULL AND counterparty_name != ''
                """))
                
                counterparty_names = [row[0] for row in result]
                logger.info(f"Found {len(counterparty_names)} unique counterparties to migrate")
                
                # Create counterparty records for each unique name
                counterparty_id_map = {}  # Map of counterparty_name to id
                
                for name in counterparty_names:
                    # Check if counterparty already exists
                    existing = session.execute(
                        text("SELECT id FROM counterparties WHERE name = :name"),
                        {"name": name}
                    ).fetchone()
                    
                    if existing:
                        counterparty_id = existing[0]
                        logger.info(f"Counterparty '{name}' already exists with ID {counterparty_id}")
                    else:
                        # Insert new counterparty
                        result = session.execute(
                            text("""
                                INSERT INTO counterparties (name, created_at, updated_at) 
                                VALUES (:name, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                                RETURNING id
                            """),
                            {"name": name}
                        )
                        counterparty_id = result.fetchone()[0]
                        logger.info(f"Created new counterparty '{name}' with ID {counterparty_id}")
                    
                    counterparty_id_map[name] = counterparty_id
                
                # Update transactions to reference counterparties
                for name, counterparty_id in counterparty_id_map.items():
                    session.execute(
                        text("""
                            UPDATE transactions 
                            SET counterparty_id = :counterparty_id 
                            WHERE counterparty_name = :name
                        """),
                        {"counterparty_id": counterparty_id, "name": name}
                    )
                    logger.info(f"Updated transactions for counterparty '{name}' to reference ID {counterparty_id}")
                
                # Commit all changes
                session.commit()
                logger.info("Counterparty data migration completed successfully")
                
            except Exception as e:
                session.rollback()
                logger.error(f"Error during counterparty data migration: {str(e)}")
                raise
            finally:
                self.close_session(session)
                
        except Exception as e:
            logger.error(f"Failed to migrate counterparty data: {str(e)}")

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
