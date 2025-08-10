import logging
import random
from typing import List, Optional

from sqlalchemy.orm import Session

from .models import (Account, Category, CategoryMapping, CategoryType,
                     Counterparty, CounterpartyCategory, Transaction)
from ..services.default_categories import suggest_category, normalize_text

logger = logging.getLogger(__name__)


class CategoryRepository:
    """Repository class for category operations."""

    @staticmethod
    def generate_unique_color(session: Session, user_id: int) -> str:
        """
        Generate a unique random color that is not used by any other category for this user.

        Args:
            session (Session): Database session.
            user_id (int): User ID.

        Returns:
            str: A unique hex color code (e.g., #FF5733).
        """
        # Get all existing colors for this user's categories
        existing_colors = [
            category.color
            for category in session.query(Category)
            .filter(Category.user_id == user_id)
            .all()
            if category.color is not None
        ]

        # Generate a random color that's not in existing_colors
        while True:
            # Generate a random hex color
            r = random.randint(0, 255)
            g = random.randint(0, 255)
            b = random.randint(0, 255)
            color = f"#{r:02x}{g:02x}{b:02x}"

            # Make sure it's not too light (close to white) or too dark
            # Convert to RGB values for calculation
            r_val = int(color[1:3], 16)
            g_val = int(color[3:5], 16)
            b_val = int(color[5:7], 16)

            # Calculate luminance (simplified formula)
            luminance = (0.299 * r_val + 0.587 * g_val + 0.114 * b_val) / 255

            # Skip colors that are too light or too dark
            if luminance < 0.2 or luminance > 0.8:
                continue

            # If color is unique, return it
            if color.upper() not in [c.upper() for c in existing_colors]:
                return color.upper()

    @staticmethod
    def create_category(
        session: Session,
        user_id: int,
        name: str,
        description: str = None,
        color: str = None,
    ) -> Optional[Category]:
        """
        Create a new category.

        Args:
            session (Session): Database session.
            user_id (int): User ID.
            name (str): Category name.
            description (str, optional): Category description.
            color (str, optional): Category color as hex code (e.g., #FF5733). If not provided, a unique random color will be generated.

        Returns:
            Optional[Category]: Created category or None if creation fails.
        """
        try:
            # Check if category already exists for this user
            existing_category = (
                session.query(Category)
                .filter(Category.user_id == user_id, Category.name == name)
                .first()
            )

            if existing_category:
                logger.info(f"Category {name} already exists for user {user_id}")
                return existing_category

            # Generate a unique random color if none is provided
            if not color:
                color = CategoryRepository.generate_unique_color(session, user_id)

            category = Category(
                user_id=user_id, name=name, description=description, color=color
            )

            session.add(category)
            session.commit()
            logger.info(f"Created category: {category.name} for user {user_id}")
            return category

        except Exception as e:
            session.rollback()
            logger.error(f"Error creating category: {str(e)}")
            return None

    @staticmethod
    def get_categories(session: Session, user_id: int) -> List[Category]:
        """
        Get all categories for a user.

        Args:
            session (Session): Database session.
            user_id (int): User ID.

        Returns:
            List[Category]: List of user's categories.
        """
        try:
            categories = (
                session.query(Category).filter(Category.user_id == user_id).all()
            )

            return categories

        except Exception as e:
            logger.error(f"Error getting categories: {str(e)}")
            return []

    @staticmethod
    def get_category(
        session: Session, category_id: int, user_id: int
    ) -> Optional[Category]:
        """
        Get a category by ID.

        Args:
            session (Session): Database session.
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).

        Returns:
            Optional[Category]: Category or None if not found.
        """
        try:
            category = (
                session.query(Category)
                .filter(Category.id == category_id, Category.user_id == user_id)
                .first()
            )

            return category

        except Exception as e:
            logger.error(f"Error getting category: {str(e)}")
            return None

    @staticmethod
    def update_category(
        session: Session,
        category_id: int,
        user_id: int,
        name: str = None,
        description: str = None,
        color: str = None,
    ) -> Optional[Category]:
        """
        Update a category.

        Args:
            session (Session): Database session.
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).
            name (str, optional): New category name.
            description (str, optional): New category description.
            color (str, optional): New category color as hex code (e.g., #FF5733).

        Returns:
            Optional[Category]: Updated category or None if update fails.
        """
        try:
            category = (
                session.query(Category)
                .filter(Category.id == category_id, Category.user_id == user_id)
                .first()
            )

            if not category:
                logger.error(
                    f"Category {category_id} not found or user {user_id} does not have permission"
                )
                return None

            if name is not None:
                category.name = name

            if description is not None:
                category.description = description

            if color is not None:
                category.color = color
            # If color is None but the category doesn't have a color yet, generate one
            elif category.color is None:
                category.color = CategoryRepository.generate_unique_color(
                    session, user_id
                )

            session.commit()
            logger.info(f"Updated category: {category.id}")
            return category

        except Exception as e:
            session.rollback()
            logger.error(f"Error updating category: {str(e)}")
            return None

    @staticmethod
    def delete_category(session: Session, category_id: int, user_id: int) -> bool:
        """
        Delete a category.

        Args:
            session (Session): Database session.
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).

        Returns:
            bool: True if deletion is successful, False otherwise.
        """
        try:
            category = (
                session.query(Category)
                .filter(Category.id == category_id, Category.user_id == user_id)
                .first()
            )

            if not category:
                logger.error(
                    f"Category {category_id} not found or user {user_id} does not have permission"
                )
                return False

            # Remove category from transactions
            # First, get transaction IDs to update
            transaction_ids = [
                row.id
                for row in session.query(Transaction.id)
                .filter(Transaction.category_id == category_id)
                .all()
            ]

            # Then update using a simple query
            if transaction_ids:
                session.query(Transaction).filter(
                    Transaction.id.in_(transaction_ids)
                ).update({Transaction.category_id: None}, synchronize_session=False)

            session.delete(category)
            session.commit()
            logger.info(f"Deleted category: {category_id}")
            return True

        except Exception as e:
            session.rollback()
            logger.error(f"Error deleting category: {str(e)}")
            return False

    @staticmethod
    def create_category_mapping(
        session: Session,
        category_id: int,
        user_id: int,
        mapping_type: CategoryType,
        pattern: str,
    ) -> Optional[CategoryMapping]:
        """
        Create a new category mapping.

        Args:
            session (Session): Database session.
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).
            mapping_type (CategoryType): Type of mapping (COUNTERPARTY or DESCRIPTION).
            pattern (str): Pattern to match (counterparty_name or description).

        Returns:
            Optional[CategoryMapping]: Created mapping or None if creation fails.
        """
        try:
            # Check if category exists and belongs to user
            category = (
                session.query(Category)
                .filter(Category.id == category_id, Category.user_id == user_id)
                .first()
            )

            if not category:
                logger.error(
                    f"Category {category_id} not found or user {user_id} does not have permission"
                )
                return None

            # Check if mapping already exists
            existing_mapping = (
                session.query(CategoryMapping)
                .filter(
                    CategoryMapping.category_id == category_id,
                    CategoryMapping.mapping_type == mapping_type,
                    CategoryMapping.pattern == pattern,
                )
                .first()
            )

            if existing_mapping:
                logger.info(
                    f"Mapping for pattern '{pattern}' already exists for category {category_id}"
                )
                return existing_mapping

            # Check if pattern is already mapped to another category
            existing_pattern_mapping = (
                session.query(CategoryMapping)
                .join(Category)
                .filter(
                    CategoryMapping.mapping_type == mapping_type,
                    CategoryMapping.pattern == pattern,
                    Category.user_id == user_id,
                )
                .first()
            )

            if existing_pattern_mapping:
                # Delete the existing mapping
                session.delete(existing_pattern_mapping)
                logger.info(
                    f"Removed existing mapping for pattern '{pattern}' from category {existing_pattern_mapping.category_id}"
                )

            mapping = CategoryMapping(
                category_id=category_id, mapping_type=mapping_type, pattern=pattern
            )

            session.add(mapping)
            session.commit()
            logger.info(
                f"Created category mapping: {mapping.id} for category {category_id}"
            )

            # Update transactions that match this pattern
            if mapping_type == CategoryType.COUNTERPARTY:
                # Get transaction IDs that need to be updated
                transaction_ids = [
                    t.id
                    for t in session.query(Transaction.id)
                    .join(Account, Transaction.account)
                    .join(Counterparty, Transaction.counterparty)
                    .filter(
                        Account.user_id == user_id,
                        Counterparty.name == pattern,
                    )
                    .all()
                ]

                # Update transactions without using join
                if transaction_ids:
                    session.query(Transaction).filter(
                        Transaction.id.in_(transaction_ids)
                    ).update(
                        {Transaction.category_id: category_id},
                        synchronize_session=False,
                    )
            else:  # DESCRIPTION
                # Get transaction IDs that need to be updated
                transaction_ids = [
                    t.id
                    for t in session.query(Transaction.id)
                    .join(Account)
                    .filter(
                        Account.user_id == user_id,
                        Transaction.transaction_details == pattern,
                    )
                    .all()
                ]

                # Update transactions without using join
                if transaction_ids:
                    session.query(Transaction).filter(
                        Transaction.id.in_(transaction_ids)
                    ).update(
                        {Transaction.category_id: category_id},
                        synchronize_session=False,
                    )

            session.commit()
            return mapping

        except Exception as e:
            session.rollback()
            logger.error(f"Error creating category mapping: {str(e)}")
            return None

    @staticmethod
    def delete_category_mapping(
        session: Session, mapping_id: int, user_id: int
    ) -> bool:
        """
        Delete a category mapping.

        Args:
            session (Session): Database session.
            mapping_id (int): Mapping ID.
            user_id (int): User ID (for permission check).

        Returns:
            bool: True if deletion is successful, False otherwise.
        """
        try:
            mapping = (
                session.query(CategoryMapping)
                .join(Category)
                .filter(CategoryMapping.id == mapping_id, Category.user_id == user_id)
                .first()
            )

            if not mapping:
                logger.error(
                    f"Mapping {mapping_id} not found or user {user_id} does not have permission"
                )
                return False

            session.delete(mapping)
            session.commit()
            logger.info(f"Deleted category mapping: {mapping_id}")
            return True

        except Exception as e:
            session.rollback()
            logger.error(f"Error deleting category mapping: {str(e)}")
            return False

    @staticmethod
    def get_category_mappings(
        session: Session, category_id: int, user_id: int
    ) -> List[CategoryMapping]:
        """
        Get all mappings for a category.

        Args:
            session (Session): Database session.
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).

        Returns:
            List[CategoryMapping]: List of category mappings.
        """
        try:
            mappings = (
                session.query(CategoryMapping)
                .join(Category)
                .filter(
                    CategoryMapping.category_id == category_id,
                    Category.user_id == user_id,
                )
                .all()
            )

            return mappings

        except Exception as e:
            logger.error(f"Error getting category mappings: {str(e)}")
            return []

    @staticmethod
    def auto_categorize_transaction(
        session: Session, transaction_id: int, user_id: int
    ) -> Optional[Transaction]:
        """
        Auto-categorize a transaction based on counterparty or description.

        Args:
            session (Session): Database session.
            transaction_id (int): Transaction ID.
            user_id (int): User ID (for permission check).

        Returns:
            Optional[Transaction]: Categorized transaction or None if categorization fails.
        """
        try:
            transaction = (
                session.query(Transaction)
                .join(Account)
                .filter(Transaction.id == transaction_id, Account.user_id == user_id)
                .first()
            )

            if not transaction:
                logger.error(
                    f"Transaction {transaction_id} not found or user {user_id} does not have permission"
                )
                return None

            # Try to categorize by counterparty_id first (new relationship)
            if transaction.counterparty_id:
                # Check for a user-specific category mapping for this counterparty
                counterparty_category = (
                    session.query(CounterpartyCategory)
                    .filter(
                        CounterpartyCategory.counterparty_id
                        == transaction.counterparty_id,
                        CounterpartyCategory.user_id == user_id,
                    )
                    .first()
                )

                if counterparty_category:
                    transaction.category_id = counterparty_category.category_id
                    session.commit()
                    logger.info(
                        f"Auto-categorized transaction {transaction_id} by counterparty_id match"
                    )
                    return transaction

            # Try to categorize by exact counterparty_name match (legacy approach)
            if transaction.counterparty_id and transaction.counterparty and transaction.counterparty.name:
                cp_name = transaction.counterparty.name
                mapping = (
                    session.query(CategoryMapping)
                    .join(Category)
                    .filter(
                        CategoryMapping.mapping_type == CategoryType.COUNTERPARTY,
                        CategoryMapping.pattern == cp_name,
                        Category.user_id == user_id,
                    )
                    .first()
                )

                if mapping:
                    transaction.category_id = mapping.category_id
                    session.commit()
                    logger.info(
                        f"Auto-categorized transaction {transaction_id} by exact counterparty_name match"
                    )
                    return transaction

            # Try to categorize by exact description match
            if transaction.transaction_details:
                mapping = (
                    session.query(CategoryMapping)
                    .join(Category)
                    .filter(
                        CategoryMapping.mapping_type == CategoryType.DESCRIPTION,
                        CategoryMapping.pattern == transaction.transaction_details,
                        Category.user_id == user_id,
                    )
                    .first()
                )

                if mapping:
                    transaction.category_id = mapping.category_id
                    session.commit()
                    logger.info(
                        f"Auto-categorized transaction {transaction_id} by exact description match"
                    )
                    return transaction

            # If no exact matches, try pattern matching for counterparty_name
            if transaction.counterparty_id:
                # Get all counterparty mappings for this user
                counterparty_mappings = (
                    session.query(CategoryMapping)
                    .join(Category)
                    .filter(
                        CategoryMapping.mapping_type == CategoryType.COUNTERPARTY,
                        Category.user_id == user_id,
                    )
                    .all()
                )

                # Check each pattern - use word boundaries for more accurate matching
                for mapping in counterparty_mappings:
                    # Skip empty patterns
                    if not mapping.pattern or not mapping.pattern.strip():
                        continue

                    # Normalize both sides for robust matching (case-insensitive, accent-insensitive)
                    pattern = normalize_text(mapping.pattern)
                    counterparty = normalize_text(
                        transaction.counterparty.name if (transaction.counterparty and transaction.counterparty.name) else ""
                    )

                    # Check for word boundaries or exact match
                    if (
                        f" {pattern} " in f" {counterparty} "
                        or counterparty.startswith(f"{pattern} ")
                        or counterparty.endswith(f" {pattern}")
                        or counterparty == pattern
                    ):
                        transaction.category_id = mapping.category_id
                        session.commit()
                        logger.info(
                            f"Auto-categorized transaction {transaction_id} by counterparty_name pattern match"
                        )
                        return transaction

            # Try pattern matching for description
            if transaction.transaction_details:
                # Get all description mappings for this user
                description_mappings = (
                    session.query(CategoryMapping)
                    .join(Category)
                    .filter(
                        CategoryMapping.mapping_type == CategoryType.DESCRIPTION,
                        Category.user_id == user_id,
                    )
                    .all()
                )

                # Check each pattern - use word boundaries for more accurate matching
                for mapping in description_mappings:
                    # Skip empty patterns
                    if not mapping.pattern or not mapping.pattern.strip():
                        continue

                    # Normalize both sides for robust matching (case-insensitive, accent-insensitive)
                    pattern = normalize_text(mapping.pattern)
                    description = normalize_text(transaction.transaction_details)

                    # Check for word boundaries or exact match
                    if (
                        f" {pattern} " in f" {description} "
                        or description.startswith(f"{pattern} ")
                        or description.endswith(f" {pattern}")
                        or description == pattern
                    ):
                        transaction.category_id = mapping.category_id
                        session.commit()
                        logger.info(
                            f"Auto-categorized transaction {transaction_id} by description pattern match"
                        )
                        return transaction

            # Fallback: progressive seeding from default categories without overriding user mappings
            try:
                cp_name = (
                    transaction.counterparty.name
                    if (transaction.counterparty and transaction.counterparty.name)
                    else None
                )
                desc = transaction.transaction_details if transaction.transaction_details else None

                suggestion = suggest_category(cp_name, desc)
                if suggestion:
                    # Determine mapping type and the textual field used
                    mapping_type = (
                        CategoryType.COUNTERPARTY
                        if suggestion.get("mapping_type") == "COUNTERPARTY"
                        else CategoryType.DESCRIPTION
                    )
                    raw_token = suggestion.get("matched_substring") or suggestion.get("matched_pattern") or ""
                    pattern_token = normalize_text(raw_token)
                    # Respect user priority: if user already mapped this token (any type), reuse that category and do NOT change mappings
                    existing_user_mappings = (
                        session.query(CategoryMapping)
                        .join(Category)
                        .filter(Category.user_id == user_id)
                        .all()
                    )
                    normalized_pattern = pattern_token
                    for m in existing_user_mappings:
                        try:
                            if normalize_text(m.pattern) == normalized_pattern:
                                transaction.category_id = m.category_id
                                session.commit()
                                logger.info(
                                    f"Auto-categorized transaction {transaction_id} by default pattern using existing user mapping"
                                )
                                return transaction
                        except Exception:
                            continue

                    # No existing mapping found for this token; create category on-demand (minimal clutter)
                    category = (
                        session.query(Category)
                        .filter(Category.user_id == user_id, Category.name == suggestion.get("name"))
                        .first()
                    )
                    if not category:
                        category = CategoryRepository.create_category(
                            session,
                            user_id,
                            suggestion.get("name"),
                            suggestion.get("description"),
                        )
                    if category:
                        # Create a user mapping for the specific matched token
                        # Ensure we don't duplicate a same-type mapping for safety
                        existing_same_type = (
                            session.query(CategoryMapping)
                            .join(Category)
                            .filter(
                                Category.user_id == user_id,
                                CategoryMapping.mapping_type == mapping_type,
                                CategoryMapping.pattern == pattern_token,
                            )
                            .first()
                        )
                        if not existing_same_type:
                            CategoryRepository.create_category_mapping(
                                session,
                                category.id,
                                user_id,
                                mapping_type,
                                pattern_token,
                            )
                        # Categorize this transaction now
                        transaction.category_id = category.id
                        session.commit()
                        logger.info(
                            f"Auto-categorized transaction {transaction_id} by default pattern '{pattern_token}' into '{category.name}'"
                        )
                        return transaction
            except Exception as e:
                session.rollback()
                logger.error(f"Default pattern fallback failed: {str(e)}")

            logger.info(f"Could not auto-categorize transaction {transaction_id}")
            return transaction

        except Exception as e:
            session.rollback()
            logger.error(f"Error auto-categorizing transaction: {str(e)}")
            return None

    @staticmethod
    def categorize_transaction(
        session: Session, transaction_id: int, category_id: int, user_id: int
    ) -> Optional[Transaction]:
        """
        Manually categorize a transaction.

        Args:
            session (Session): Database session.
            transaction_id (int): Transaction ID.
            category_id (int): Category ID.
            user_id (int): User ID (for permission check).

        Returns:
            Optional[Transaction]: Categorized transaction or None if categorization fails.
        """
        try:
            transaction = (
                session.query(Transaction)
                .join(Account)
                .filter(Transaction.id == transaction_id, Account.user_id == user_id)
                .first()
            )

            if not transaction:
                logger.error(
                    f"Transaction {transaction_id} not found or user {user_id} does not have permission"
                )
                return None

            category = (
                session.query(Category)
                .filter(Category.id == category_id, Category.user_id == user_id)
                .first()
            )

            if not category:
                logger.error(
                    f"Category {category_id} not found or user {user_id} does not have permission"
                )
                return None

            transaction.category_id = category_id
            session.commit()
            logger.info(f"Categorized transaction {transaction_id} as {category.name}")

            # Create mapping if it doesn't exist
            if transaction.counterparty and transaction.counterparty.name:
                CategoryRepository.create_category_mapping(
                    session,
                    category_id,
                    user_id,
                    CategoryType.COUNTERPARTY,
                    transaction.counterparty.name,
                )

            if transaction.transaction_details:
                CategoryRepository.create_category_mapping(
                    session,
                    category_id,
                    user_id,
                    CategoryType.DESCRIPTION,
                    transaction.transaction_details,
                )

            return transaction

        except Exception as e:
            session.rollback()
            logger.error(f"Error categorizing transaction: {str(e)}")
            return None
