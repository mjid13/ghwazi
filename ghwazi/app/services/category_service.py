"""
Category service for managing transaction categories.
"""

import logging
from typing import List, Optional

from app.models.category import CategoryRepository
from app.models.database import Database
from app.models.models import (Category, CategoryMapping, CategoryType,
                               Transaction)

logger = logging.getLogger(__name__)


class CategoryService:
    """Service for managing transaction categories."""

    def __init__(self):
        """Initialize the category service."""
        self.db = Database()
        self.db.connect()
        self.db.create_tables()

    def create_category(
        self, user_id: int, name: str, description: str = None, color: str = None
    ) -> Optional[Category]:
        """
        Create a new category.

        Args:
            user_id (int): User ID.
            name (str): Category name.
            description (str, optional): Category description.
            color (str, optional): Category color as hex code (e.g., #FF5733). If not provided, a unique random color will be generated.

        Returns:
            Optional[Category]: Created category or None if creation fails.
        """
        try:
            session = self.db.get_session()

            try:
                category = CategoryRepository.create_category(
                    session, user_id, name, description, color
                )
                return category
            finally:
                self.db.close_session(session)
        except Exception as e:
            logger.error(f"Error creating category: {str(e)}")
            return None

    def get_categories(self, user_id: int) -> List[Category]:
        """
        Get all categories for a user.

        Args:
            user_id (int): User ID.

        Returns:
            List[Category]: List of user's categories.
        """
        try:
            session = self.db.get_session()

            try:
                categories = CategoryRepository.get_categories(session, user_id)
                return categories
            finally:
                self.db.close_session(session)
        except Exception as e:
            logger.error(f"Error getting categories: {str(e)}")
            return []

    def get_category(self, category_id: int, user_id: int) -> Optional[Category]:
        """
        Get a category by ID.

        Args:
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).

        Returns:
            Optional[Category]: Category or None if not found.
        """
        try:
            session = self.db.get_session()

            try:
                category = CategoryRepository.get_category(
                    session, category_id, user_id
                )
                return category
            finally:
                self.db.close_session(session)
        except Exception as e:
            logger.error(f"Error getting category: {str(e)}")
            return None

    def update_category(
        self,
        category_id: int,
        user_id: int,
        name: str = None,
        description: str = None,
        color: str = None,
    ) -> Optional[Category]:
        """
        Update a category.

        Args:
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).
            name (str, optional): New category name.
            description (str, optional): New category description.
            color (str, optional): New category color as hex code (e.g., #FF5733).

        Returns:
            Optional[Category]: Updated category or None if update fails.
        """
        try:
            session = self.db.get_session()

            try:
                category = CategoryRepository.update_category(
                    session, category_id, user_id, name, description, color
                )
                return category
            finally:
                self.db.close_session(session)
        except Exception as e:
            logger.error(f"Error updating category: {str(e)}")
            return None

    def delete_category(self, category_id: int, user_id: int) -> bool:
        """
        Delete a category.

        Args:
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).

        Returns:
            bool: True if deletion is successful, False otherwise.
        """
        try:
            session = self.db.get_session()

            try:
                result = CategoryRepository.delete_category(
                    session, category_id, user_id
                )
                return result
            finally:
                self.db.close_session(session)
        except Exception as e:
            logger.error(f"Error deleting category: {str(e)}")
            return False

    def create_category_mapping(
        self, category_id: int, user_id: int, mapping_type: CategoryType, pattern: str
    ) -> Optional[CategoryMapping]:
        """
        Create a new category mapping.

        Args:
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).
            mapping_type (CategoryType): Type of mapping (COUNTERPARTY or DESCRIPTION).
            pattern (str): Pattern to match (counterparty_name or description).

        Returns:
            Optional[CategoryMapping]: Created mapping or None if creation fails.
        """
        try:
            session = self.db.get_session()

            try:
                mapping = CategoryRepository.create_category_mapping(
                    session, category_id, user_id, mapping_type, pattern
                )
                return mapping
            finally:
                self.db.close_session(session)
        except Exception as e:
            logger.error(f"Error creating category mapping: {str(e)}")
            return None

    def delete_category_mapping(self, mapping_id: int, user_id: int) -> bool:
        """
        Delete a category mapping.

        Args:
            mapping_id (int): Mapping ID.
            user_id (int): User ID (for permission check).

        Returns:
            bool: True if deletion is successful, False otherwise.
        """
        try:
            session = self.db.get_session()

            try:
                result = CategoryRepository.delete_category_mapping(
                    session, mapping_id, user_id
                )
                return result
            finally:
                self.db.close_session(session)
        except Exception as e:
            logger.error(f"Error deleting category mapping: {str(e)}")
            return False

    def get_category_mappings(
        self, category_id: int, user_id: int
    ) -> List[CategoryMapping]:
        """
        Get all mappings for a category.

        Args:
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).

        Returns:
            List[CategoryMapping]: List of category mappings.
        """
        try:
            session = self.db.get_session()

            try:
                mappings = CategoryRepository.get_category_mappings(
                    session, category_id, user_id
                )
                return mappings
            finally:
                self.db.close_session(session)
        except Exception as e:
            logger.error(f"Error getting category mappings: {str(e)}")
            return []

    def auto_categorize_transaction(
        self, transaction_id: int, user_id: int
    ) -> Optional[Transaction]:
        """
        Auto-categorize a transaction based on counterparty_name or description.

        Args:
            transaction_id (int): Transaction ID.
            user_id (int): User ID (for permission check).

        Returns:
            Optional[Transaction]: Categorized transaction or None if categorization fails.
        """
        try:
            session = self.db.get_session()

            try:
                transaction = CategoryRepository.auto_categorize_transaction(
                    session, transaction_id, user_id
                )
                return transaction
            finally:
                self.db.close_session(session)
        except Exception as e:
            logger.error(f"Error auto-categorizing transaction: {str(e)}")
            return None

    def categorize_transaction(
        self, transaction_id: int, category_id: int, user_id: int
    ) -> Optional[Transaction]:
        """
        Manually categorize a transaction.

        Args:
            transaction_id (int): Transaction ID.
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).

        Returns:
            Optional[Transaction]: Categorized transaction or None if categorization fails.
        """
        try:
            session = self.db.get_session()

            try:
                transaction = CategoryRepository.categorize_transaction(
                    session, transaction_id, category_id, user_id
                )
                return transaction
            finally:
                self.db.close_session(session)
        except Exception as e:
            logger.error(f"Error categorizing transaction: {str(e)}")
            return None

    def auto_categorize_all_transactions(self, user_id: int) -> int:
        """
        Auto-categorize all uncategorized transactions for a user.

        Args:
            user_id (int): User ID.

        Returns:
            int: Number of transactions categorized.
        """
        try:
            session = self.db.get_session()

            try:
                # Get all uncategorized transactions for this user
                from sqlalchemy import and_

                from app.models.models import Account

                transactions = (
                    session.query(Transaction)
                    .join(Account)
                    .filter(Account.user_id == user_id, Transaction.category_id == None)
                    .all()
                )

                categorized_count = 0
                for transaction in transactions:
                    result = CategoryRepository.auto_categorize_transaction(
                        session, transaction.id, user_id
                    )
                    if result and result.category_id is not None:
                        categorized_count += 1

                return categorized_count
            finally:
                self.db.close_session(session)
        except Exception as e:
            logger.error(f"Error auto-categorizing all transactions: {str(e)}")
            return 0

    def close(self):
        """Close database connection."""
        try:
            self.db.close()
            logger.info("Closed database connection")
        except Exception as e:
            logger.error(f"Error closing database connection: {str(e)}")
