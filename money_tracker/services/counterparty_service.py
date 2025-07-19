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
                from sqlalchemy import distinct, func, case
                from money_tracker.models.models import Account

                # First get all unique counterparty names
                counterparty_names = session.query(
                    distinct(Transaction.counterparty_name)
                ).join(
                    Account, Account.id == Transaction.account_id
                ).filter(
                    Account.user_id == user_id,
                    Transaction.counterparty_name != None,
                    Transaction.counterparty_name != ''
                ).all()

                # For each unique counterparty name, get the most recent transaction
                result = []
                for cp_name in counterparty_names:
                    counterparty_name = cp_name[0]

                    # Get the most recent transaction for this counterparty
                    latest_transaction = session.query(
                        Transaction,
                        Category.name.label('category_name'),
                        Category.id.label('category_id')
                    ).join(
                        Account, Account.id == Transaction.account_id
                    ).outerjoin(
                        Category, Category.id == Transaction.category_id
                    ).filter(
                        Account.user_id == user_id,
                        Transaction.counterparty_name == counterparty_name
                    ).order_by(
                        Transaction.value_date.desc()
                    ).first()

                    if latest_transaction:
                        transaction = latest_transaction[0]
                        result.append({
                            'counterparty_name': counterparty_name,
                            'transaction_details': transaction.transaction_details,
                            'category_name': latest_transaction.category_name,
                            'category_id': latest_transaction.category_id,
                            'last_transaction_date': transaction.value_date
                        })

                # Sort by counterparty name
                result.sort(key=lambda x: x['counterparty_name'].lower() if x['counterparty_name'] else '')

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
            # Validate inputs
            if not category_id:
                logger.error("Category ID is required")
                return False

            # Clean inputs
            counterparty_name = counterparty_name.strip() if counterparty_name else None
            description = description.strip() if description else None

            # At least one of counterparty_name or description must be provided
            if not counterparty_name and not description:
                logger.error("Either counterparty_name or description must be provided")
                return False

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
                    mapping = CategoryRepository.create_category_mapping(
                        session, category_id, user_id, CategoryType.COUNTERPARTY, counterparty_name
                    )
                    if not mapping:
                        logger.warning(f"Failed to create mapping for counterparty: {counterparty_name}")

                if description:
                    mapping = CategoryRepository.create_category_mapping(
                        session, category_id, user_id, CategoryType.DESCRIPTION, description
                    )
                    if not mapping:
                        logger.warning(f"Failed to create mapping for description: {description}")

                # Update all matching transactions with this category
                from sqlalchemy import and_, or_
                from money_tracker.models.models import Account

                # Build the filter conditions based on what was provided
                filter_conditions = [Account.user_id == user_id]

                if counterparty_name and description:
                    # If both are provided, find transactions with either match
                    filter_conditions.append(
                        or_(
                            Transaction.counterparty_name == counterparty_name,
                            Transaction.transaction_details == description
                        )
                    )
                elif counterparty_name:
                    # Only counterparty_name provided
                    filter_conditions.append(Transaction.counterparty_name == counterparty_name)
                elif description:
                    # Only description provided
                    filter_conditions.append(Transaction.transaction_details == description)

                # Count transactions before update
                transaction_count = session.query(Transaction).join(Account).filter(
                    *filter_conditions
                ).count()

                if transaction_count == 0:
                    logger.info(f"No transactions found matching counterparty {counterparty_name} or description {description}")
                    # Still return True because we created the mappings successfully
                    return True

                # Get transaction IDs that need to be updated
                transaction_ids = [t.id for t in session.query(Transaction.id).join(Account).filter(
                    *filter_conditions
                ).all()]

                # Update transactions without using join
                if transaction_ids:
                    session.query(Transaction).filter(
                        Transaction.id.in_(transaction_ids)
                    ).update({Transaction.category_id: category_id}, synchronize_session=False)

                session.commit()
                logger.info(f"Categorized {transaction_count} transactions with counterparty {counterparty_name} or description {description} as {category.name}")
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

    def create_category(self, user_id: int, name: str, description: str = None, color: str = None) -> Optional[Category]:
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
        return self.category_service.create_category(user_id, name, description, color)

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

    def update_category(self, category_id: int, user_id: int, name: str = None, description: str = None, color: str = None) -> bool:
        """
        Update a category.

        Args:
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).
            name (str, optional): New category name.
            description (str, optional): New category description.
            color (str, optional): New category color as hex code (e.g., #FF5733).

        Returns:
            bool: True if update was successful, False otherwise.
        """
        return self.category_service.update_category(category_id, user_id, name, description, color)

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
