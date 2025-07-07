"""
Counterparty service for managing unique counterparty transactions.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple

from money_tracker.models.database import Database
from money_tracker.models.models import CategoryRepository, Category, CategoryMapping, CategoryType, Transaction

logger = logging.getLogger(__name__)

# Import CategoryService for reusing category CRUD operations
from money_tracker.services.category_service import CategoryService

class CounterpartyService:
    """Service for managing unique counterparty transactions with dynamic categorization."""

    def __init__(self):
        """Initialize the counterparty service."""
        self.db = Database()
        self.db.connect()
        self.db.create_tables()
        self.category_service = CategoryService()

    def get_unique_counterparties(self, user_id: int) -> List[Dict[str, Any]]:
        """
        Get all unique counterparties for a user.

        Args:
            user_id (int): User ID.

        Returns:
            List[Dict[str, Any]]: List of unique counterparties with their categories.
        """
        try:
            session = self.db.get_session()

            try:
                # Get all unique counterparty_name values from transactions
                from sqlalchemy import distinct, func
                from money_tracker.models.models import Account

                # Query for unique counterparty_name values
                counterparty_query = session.query(
                    Transaction.counterparty_name,
                    Transaction.description,
                    Transaction.transaction_details,
                    Category.name.label('category_name'),
                    Category.id.label('category_id')
                ).join(
                    Account, Account.id == Transaction.account_id
                ).outerjoin(
                    Category, Category.id == Transaction.category_id
                ).filter(
                    Account.user_id == user_id,
                    Transaction.counterparty_name != None
                ).distinct(
                    Transaction.counterparty_name,
                    Transaction.description
                ).all()

                # Convert to list of dictionaries
                result = []
                for cp in counterparty_query:
                    result.append({
                        'counterparty_name': cp.counterparty_name,
                        'description': cp.description,
                        'transaction_details': cp.transaction_details,
                        'category_name': cp.category_name,
                        'category_id': cp.category_id
                    })

                return result
            finally:
                self.db.close_session(session)
        except Exception as e:
            logger.error(f"Error getting unique counterparties: {str(e)}")
            return []

    def categorize_counterparty(self, user_id: int, counterparty_name: str, description: str, 
                               category_id: int) -> bool:
        """
        Categorize a counterparty with a specific description.

        Args:
            user_id (int): User ID.
            counterparty_name (str): Counterparty name.
            description (str): Transaction description.
            category_id (int): Category ID.

        Returns:
            bool: True if categorization was successful, False otherwise.
        """
        try:
            session = self.db.get_session()

            try:
                # Verify the category exists and belongs to the user
                category = session.query(Category).filter(
                    Category.id == category_id,
                    Category.user_id == user_id
                ).first()

                if not category:
                    logger.error(f"Category {category_id} not found or user {user_id} does not have permission")
                    return False

                # Create mappings for both counterparty_name and description if they exist
                if counterparty_name:
                    CategoryRepository.create_category_mapping(
                        session, category_id, user_id, CategoryType.COUNTERPARTY, counterparty_name
                    )

                if description:
                    CategoryRepository.create_category_mapping(
                        session, category_id, user_id, CategoryType.DESCRIPTION, description
                    )

                # Update all matching transactions with this category
                from sqlalchemy import and_
                from money_tracker.models.models import Account

                # Find all transactions with this counterparty_name or description
                from sqlalchemy import or_

                # Build the filter conditions based on what was provided
                filter_conditions = [Account.user_id == user_id]

                if counterparty_name and description:
                    # If both are provided, find transactions with either match
                    filter_conditions.append(
                        or_(
                            Transaction.counterparty_name == counterparty_name,
                            Transaction.description == description
                        )
                    )
                elif counterparty_name:
                    # Only counterparty_name provided
                    filter_conditions.append(Transaction.counterparty_name == counterparty_name)
                elif description:
                    # Only description provided
                    filter_conditions.append(Transaction.description == description)

                transactions = session.query(Transaction).join(Account).filter(
                    *filter_conditions
                ).all()

                # Update each transaction with the new category
                for transaction in transactions:
                    transaction.category_id = category_id

                session.commit()
                logger.info(f"Categorized counterparty {counterparty_name} with description {description} as {category.name}")
                return True
            except Exception as e:
                session.rollback()
                logger.error(f"Error categorizing counterparty: {str(e)}")
                return False
            finally:
                self.db.close_session(session)
        except Exception as e:
            logger.error(f"Error categorizing counterparty: {str(e)}")
            return False

    def auto_categorize_transaction(self, transaction_id: int, user_id: int) -> Optional[Transaction]:
        """
        Auto-categorize a transaction based on counterparty_name or description.

        Args:
            transaction_id (int): Transaction ID.
            user_id (int): User ID.

        Returns:
            Optional[Transaction]: Categorized transaction or None if categorization fails.
        """
        try:
            session = self.db.get_session()

            try:
                # Use the existing repository method
                transaction = CategoryRepository.auto_categorize_transaction(session, transaction_id, user_id)
                return transaction
            finally:
                self.db.close_session(session)
        except Exception as e:
            logger.error(f"Error auto-categorizing transaction: {str(e)}")
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
                from money_tracker.models.models import Account

                transactions = session.query(Transaction).join(Account).filter(
                    Account.user_id == user_id,
                    Transaction.category_id == None
                ).all()

                categorized_count = 0
                for transaction in transactions:
                    result = CategoryRepository.auto_categorize_transaction(session, transaction.id, user_id)
                    if result and result.category_id is not None:
                        categorized_count += 1

                return categorized_count
            finally:
                self.db.close_session(session)
        except Exception as e:
            logger.error(f"Error auto-categorizing all transactions: {str(e)}")
            return 0

    # Category CRUD operations

    def create_category(self, user_id: int, name: str, description: str = None) -> Optional[Category]:
        """
        Create a new category.

        Args:
            user_id (int): User ID.
            name (str): Category name.
            description (str, optional): Category description.

        Returns:
            Optional[Category]: Created category or None if creation fails.
        """
        return self.category_service.create_category(user_id, name, description)

    def get_categories(self, user_id: int) -> List[Category]:
        """
        Get all categories for a user.

        Args:
            user_id (int): User ID.

        Returns:
            List[Category]: List of categories.
        """
        return self.category_service.get_categories(user_id)

    def get_category(self, category_id: int, user_id: int) -> Optional[Category]:
        """
        Get a category by ID.

        Args:
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).

        Returns:
            Optional[Category]: Category or None if not found.
        """
        return self.category_service.get_category(category_id, user_id)

    def update_category(self, category_id: int, user_id: int, name: str = None, description: str = None) -> bool:
        """
        Update a category.

        Args:
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).
            name (str, optional): New category name.
            description (str, optional): New category description.

        Returns:
            bool: True if update was successful, False otherwise.
        """
        return self.category_service.update_category(category_id, user_id, name, description)

    def delete_category(self, category_id: int, user_id: int) -> bool:
        """
        Delete a category.

        Args:
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).

        Returns:
            bool: True if deletion was successful, False otherwise.
        """
        return self.category_service.delete_category(category_id, user_id)

    def create_category_mapping(self, category_id: int, user_id: int, mapping_type: CategoryType, pattern: str) -> Optional[CategoryMapping]:
        """
        Create a category mapping.

        Args:
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).
            mapping_type (CategoryType): Type of mapping (COUNTERPARTY or DESCRIPTION).
            pattern (str): Pattern to match.

        Returns:
            Optional[CategoryMapping]: Created mapping or None if creation fails.
        """
        return self.category_service.create_category_mapping(category_id, user_id, mapping_type, pattern)

    def delete_category_mapping(self, mapping_id: int, user_id: int) -> bool:
        """
        Delete a category mapping.

        Args:
            mapping_id (int): Mapping ID.
            user_id (int): User ID (for permission check).

        Returns:
            bool: True if deletion was successful, False otherwise.
        """
        return self.category_service.delete_category_mapping(mapping_id, user_id)

    def get_category_mappings(self, category_id: int, user_id: int) -> List[CategoryMapping]:
        """
        Get all mappings for a category.

        Args:
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).

        Returns:
            List[CategoryMapping]: List of category mappings.
        """
        return self.category_service.get_category_mappings(category_id, user_id)

    def close(self):
        """Close database connection."""
        try:
            self.category_service.close()
            self.db.close()
            logger.info("Closed database connection")
        except Exception as e:
            logger.error(f"Error closing database connection: {str(e)}")
