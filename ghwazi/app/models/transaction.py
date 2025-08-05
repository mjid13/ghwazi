from .user import User
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy import String
from sqlalchemy.orm import Session
from .models import (
    Account,
    Transaction,
    TransactionType,
    Counterparty,
    EmailConfiguration,
    EmailMetadata,
)

logger = logging.getLogger(__name__)


class TransactionRepository:
    """Repository class for transaction operations."""

    @staticmethod
    def create_user(session: Session, user_data: Dict[str, Any]) -> Optional[User]:
        """
        Create a new user.

        Args:
            session (Session): Database session.
            user_data (Dict[str, Any]): User data.

        Returns:
            Optional[User]: Created user or None if creation fails.
        """
        try:
            # Debug logging
            logger.info(
                f"TransactionRepository.create_user called with username: {user_data.get('username')}, email: {user_data.get('email')}"
            )

            # Check if user already exists
            existing_user = (
                session.query(User)
                .filter(
                    (User.username == user_data["username"])
                    | (User.email == user_data["email"])
                )
                .first()
            )

            if existing_user:
                logger.info(
                    f"User {user_data['username']} or email {user_data['email']} already exists"
                )
                return None

            # Create user object
            logger.info("Creating User object")
            user = User(username=user_data["username"], email=user_data["email"])

            # Set password
            logger.info("Setting password hash")
            try:
                user.set_password(user_data["password"])
            except Exception as pw_error:
                logger.error(f"Error setting password: {str(pw_error)}")
                raise

            # Add to session and commit
            logger.info("Adding user to session")
            session.add(user)

            logger.info("Committing session")
            session.commit()

            logger.info(f"Created user: {user.username} with ID: {user.id}")
            return user

        except Exception as e:
            session.rollback()
            logger.error(f"Error creating user: {str(e)}")
            # Print exception traceback for debugging
            import traceback

            logger.error(f"Traceback: {traceback.format_exc()}")
            return None

    @staticmethod
    def create_email_config(
        session: Session, config_data: Dict[str, Any]
    ) -> Optional[EmailConfiguration]:
        """
        Create or update email configuration for a user.

        Args:
            session (Session): Database session.
            config_data (Dict[str, Any]): Email configuration data.

        Returns:
            Optional[EmailConfiguration]: Created/updated configuration or None if creation fails.
        """
        try:
            user_id = config_data["user_id"]

            # Check if configuration already exists for this user
            existing_config = (
                session.query(EmailConfiguration)
                .filter(EmailConfiguration.user_id == user_id)
                .first()
            )

            if existing_config:
                # Update existing configuration
                for key, value in config_data.items():
                    if key != "user_id" and hasattr(existing_config, key):
                        setattr(existing_config, key, value)

                session.commit()
                logger.info(f"Updated email configuration for user ID: {user_id}")
                return existing_config

            # Create new configuration
            email_config = EmailConfiguration(
                user_id=user_id,
                email_host=config_data["email_host"],
                email_port=config_data["email_port"],
                email_username=config_data["email_username"],
                email_password=config_data["email_password"],
                email_use_ssl=config_data.get("email_use_ssl", True),
                bank_email_addresses=config_data.get("bank_email_addresses", ""),
                bank_email_subjects=config_data.get("bank_email_subjects", ""),
            )

            session.add(email_config)
            session.commit()
            logger.info(f"Created email configuration for user ID: {user_id}")
            return email_config

        except Exception as e:
            session.rollback()
            logger.error(f"Error creating/updating email configuration: {str(e)}")
            return None

    @staticmethod
    def create_account(
        session: Session, account_data: Dict[str, Any]
    ) -> Optional[Account]:
        """
        Create a new account if not exist.

        Args:
            session (Session): Database session.
            account_data (Dict[str, Any]): Account data.

        Returns:
            Optional[Account]: Created account or None if creation fails.
        """
        try:
            user_id = account_data.get("user_id")
            if not user_id:
                logger.error("No user_id provided for account creation")
                return None

            # Check if account already exists for this user
            existing_account = (
                session.query(Account)
                .filter(
                    Account.user_id == user_id,
                    Account.account_number == account_data["account_number"],
                )
                .first()
            )

            if existing_account:
                logger.info(
                    f"Account {account_data['account_number']} already exists for user {user_id}"
                )
                return existing_account

            account = Account(
                user_id=user_id,
                account_number=account_data["account_number"],
                bank_name=account_data.get("bank_name", "Unknown"),
                account_holder=account_data.get("account_holder"),
                branch=account_data.get("branch"),
                balance=account_data.get("balance", 0.0),
                currency=account_data.get("currency", "OMR"),
                email_config_id=account_data.get("email_config_id"),
            )

            session.add(account)
            session.commit()
            logger.info(f"Created account: {account.account_number} for user {user_id}")
            return account

        except Exception as e:
            session.rollback()
            logger.error(f"Error creating account: {str(e)}")
            return None

    @staticmethod
    def create_email_metadata(
        session: Session, email_data: Dict[str, Any]
    ) -> Optional[EmailMetadata]:
        """
        Create email metadata.

        Args:
            session (Session): Database session.
            email_data (Dict[str, Any]): Email data.

        Returns:
            Optional[EmailMetadata]: Created email metadata or None if creation fails.
        """
        try:
            user_id = email_data.get("user_id")
            if not user_id:
                logger.error("No user_id provided for email metadata creation")
                return None

            email_metadata = EmailMetadata(
                user_id=user_id,
                email_id=email_data.get("id"),
                subject=email_data.get("subject", ""),
                sender=email_data.get("from", ""),
                recipient=email_data.get("to", ""),
                date=email_data.get("date", ""),
                body=email_data.get("body", ""),
                cleaned_body=email_data.get("cleaned_body", ""),
                processed=email_data.get("processed", False),
            )

            session.add(email_metadata)
            session.commit()
            logger.info(f"Created email metadata: {email_metadata.id}")
            return email_metadata

        except Exception as e:
            session.rollback()
            logger.error(f"Error creating email metadata: {str(e)}")
            return None

    @staticmethod
    def create_transaction(
        session: Session, transaction_data: Dict[str, Any]
    ) -> Optional[Transaction]:
        """
        Create a new transaction.

        Args:
            session (Session): Database session.
            transaction_data (Dict[str, Any]): Transaction data.

        Returns:
            Optional[Transaction]: Created transaction or None if creation fails.
        """
        try:
            # Get or create account
            account_number = transaction_data.get("account_number")
            user_id = transaction_data.get("user_id")

            if not account_number:
                logger.error("No account number provided for transaction")
                return None

            if not user_id:
                logger.error("No user_id provided for transaction")
                return None

            account_data = {
                "user_id": user_id,
                "account_number": account_number,
                "bank_name": transaction_data.get("bank_name", "Unknown"),
                "currency": transaction_data.get("currency", "OMR"),
                "balance": transaction_data.get("balance", 0.0),
            }
            account = TransactionRepository.create_account(session, account_data)

            # Update account branch only if it's null and branch is provided in transaction data
            if account and account.branch is None and transaction_data.get("branch"):
                account.branch = transaction_data.get("branch")
                session.commit()

            if not account:
                return None

            # Check if transaction already exists (by transaction_id and date)
            if transaction_data.get("transaction_id"):
                existing_transaction = (
                    session.query(Transaction)
                    .filter(
                        Transaction.account_id == account.id,
                        Transaction.transaction_id
                        == transaction_data["transaction_id"],
                    )
                    .first()
                )

                if existing_transaction:
                    logger.info(
                        f"Transaction {transaction_data['transaction_id']} already exists"
                    )
                    return existing_transaction

            # Convert transaction type
            transaction_type_str = transaction_data.get(
                "transaction_type", "unknown"
            ).lower()
            try:
                transaction_type = TransactionType(transaction_type_str)
            except ValueError:
                transaction_type = TransactionType.UNKNOWN

            # Handle email metadata if provided
            email_metadata_id = None
            if transaction_data.get("email_metadata_id"):
                email_metadata_id = transaction_data["email_metadata_id"]
            elif transaction_data.get("email_data"):
                # Create email metadata from email data
                email_data = transaction_data["email_data"]
                email_data["user_id"] = user_id
                email_metadata = TransactionRepository.create_email_metadata(
                    session, email_data
                )
                if email_metadata:
                    email_metadata_id = email_metadata.id

            # Create a copy of transaction_data without the removed fields
            fields_to_exclude = ["branch", "description", "email_id", "bank_name"]
            transaction_data_copy = {
                k: v for k, v in transaction_data.items() if k not in fields_to_exclude
            }

            # If description is provided but transaction_details is not, use description for transaction_details
            if (
                "description" in transaction_data
                and "transaction_details" not in transaction_data_copy
            ):
                transaction_data_copy["transaction_details"] = transaction_data.get(
                    "description"
                )

            # Handle counterparty
            counterparty_id = None
            counterparty_name = transaction_data_copy.get("counterparty_name")

            if counterparty_name:
                # Check if counterparty already exists
                counterparty = (
                    session.query(Counterparty)
                    .filter(Counterparty.name == counterparty_name)
                    .first()
                )

                if not counterparty:
                    # Create new counterparty
                    counterparty = Counterparty(name=counterparty_name)
                    session.add(counterparty)
                    session.flush()  # Get ID without committing
                    logger.info(
                        f"Created new counterparty: {counterparty.name} with ID {counterparty.id}"
                    )

                counterparty_id = counterparty.id

            transaction = Transaction(
                account_id=account.id,
                email_metadata_id=email_metadata_id,
                transaction_type=transaction_type,
                amount=transaction_data_copy.get("amount", 0.0),
                currency=transaction_data_copy.get("currency", "OMR"),
                value_date=transaction_data_copy.get("value_date", None),
                # Using date_time from input for backward compatibility
                transaction_id=transaction_data_copy.get("transaction_id"),
                transaction_sender=transaction_data_copy.get("transaction_sender"),
                transaction_receiver=transaction_data_copy.get("transaction_receiver"),
                counterparty_name=counterparty_name,  # Keep for backward compatibility
                counterparty_id=counterparty_id,  # Set the new counterparty relationship
                transaction_details=transaction_data_copy.get("transaction_details"),
                country=transaction_data_copy.get("country"),
                post_date=transaction_data_copy.get("post_date"),
                # Using email_date from input for backward compatibility
                transaction_content=transaction_data_copy.get("transaction_content"),
            )

            session.add(transaction)
            session.commit()

            # Check if we should update the account balance
            preserve_balance = transaction_data.get("preserve_balance", False)

            # Only preserve balance if the flag is set and this is a first scrape
            # We determine if it's a first scrape by checking if there are existing transactions
            # Note: We need to check this before adding the current transaction
            is_first_scrape = False
            if preserve_balance:
                # We need to exclude the current transaction from the count
                # Since we just added it, we need to check if there were any transactions before
                existing_transactions_count = (
                    session.query(Transaction)
                    .filter(
                        Transaction.account_id == account.id,
                        Transaction.id
                        != transaction.id,  # Exclude the current transaction
                    )
                    .count()
                )
                is_first_scrape = existing_transactions_count > 0

            # Update balance if we're not preserving balance or if this is not the first scrape
            # if not (preserve_balance and is_first_scrape): # This Only update balance if not preserving or not first scrape
            if is_first_scrape:
                if transaction_type == TransactionType.INCOME:
                    account.balance += transaction.amount
                elif transaction_type == TransactionType.EXPENSE:
                    account.balance -= transaction.amount
                elif transaction_type == TransactionType.TRANSFER:
                    # For transfers, we don't change the balance by default
                    # This would need to be handled differently if transfers between accounts are tracked
                    logger.info(
                        f"Transfer transaction: {transaction.id} - not updating balance"
                    )
                elif transaction_type == TransactionType.UNKNOWN:
                    logger.warning(
                        f"Unknown transaction type for transaction: {transaction.id} - not updating balance"
                    )
                session.commit()

            logger.info(f"Created transaction: {transaction.id}")
            return transaction

        except Exception as e:
            session.rollback()
            logger.error(f"Error creating transaction: {str(e)}")
            return None

    @staticmethod
    def get_account_summary(
        session: Session, user_id: int, account_number: str
    ) -> Optional[Dict[str, Any]]:
        """
        Get account summary including balance and transaction counts.

        Args:
            session (Session): Database session.
            user_id (int): User ID.
            account_number (str): Account number.

        Returns:
            Optional[Dict[str, Any]]: Account summary or None if not found.
        """
        try:
            account = (
                session.query(Account)
                .filter(
                    Account.user_id == user_id, Account.account_number == account_number
                )
                .first()
            )

            if not account:
                return None

            # Use more efficient SQL aggregation instead of loading all transactions
            from sqlalchemy import func, case

            # Get transaction counts and sums by type
            transaction_stats = (
                session.query(
                    func.count(Transaction.id).label("total_count"),
                    func.sum(
                        case(
                            (
                                Transaction.transaction_type == TransactionType.INCOME,
                                Transaction.amount,
                            ),
                            else_=0,
                        )
                    ).label("total_income"),
                    func.sum(
                        case(
                            (
                                Transaction.transaction_type == TransactionType.EXPENSE,
                                Transaction.amount,
                            ),
                            else_=0,
                        )
                    ).label("total_expense"),
                    func.sum(
                        case(
                            (
                                Transaction.transaction_type
                                == TransactionType.TRANSFER,
                                Transaction.amount,
                            ),
                            else_=0,
                        )
                    ).label("total_transfer"),
                    func.count(
                        case(
                            (Transaction.transaction_type == TransactionType.INCOME, 1),
                            else_=None,
                        )
                    ).label("income_count"),
                    func.count(
                        case(
                            (
                                Transaction.transaction_type == TransactionType.EXPENSE,
                                1,
                            ),
                            else_=None,
                        )
                    ).label("expense_count"),
                )
                .filter(Transaction.account_id == account.id)
                .first()
            )

            # Handle case where there are no transactions
            if not transaction_stats or transaction_stats.total_count == 0:
                total_income = 0
                total_expense = 0
                total_transfer = 0
                income_count = 0
                expense_count = 0
                transaction_count = 0
            else:
                total_income = transaction_stats.total_income or 0
                total_expense = transaction_stats.total_expense or 0
                total_transfer = transaction_stats.total_transfer or 0
                income_count = transaction_stats.income_count or 0
                expense_count = transaction_stats.expense_count or 0
                transaction_count = transaction_stats.total_count or 0

            # Get the most recent transactions for display
            recent_transactions = (
                session.query(Transaction)
                .filter(Transaction.account_id == account.id)
                .order_by(Transaction.value_date.desc())
                .limit(10)
                .all()
            )

            return {
                "account_number": account.account_number,
                "bank_name": account.bank_name,
                "account_holder": account.account_holder,
                "balance": account.balance,
                "currency": account.currency,
                "transaction_count": transaction_count,
                "total_income": total_income,
                "total_expense": total_expense,
                "total_transfer": total_transfer,
                "net_balance": total_income - total_expense,
                "transactions": recent_transactions,  # Only include recent transactions
                "income_count": income_count,
                "expense_count": expense_count,
            }

        except Exception as e:
            logger.error(f"Error getting account summary: {str(e)}")
            return None

    @staticmethod
    def get_user_accounts(session: Session, user_id: int) -> List[Account]:
        """
        Get all accounts for a user.

        Args:
            session (Session): Database session.
            user_id (int): User ID.

        Returns:
            List[Account]: List of user's accounts.
        """
        try:
            accounts = session.query(Account).filter(Account.user_id == user_id).all()

            return accounts

        except Exception as e:
            logger.error(f"Error getting user accounts: {str(e)}")
            return []

    @staticmethod
    def update_transaction(
        session: Session, transaction_id: int, transaction_data: Dict[str, Any]
    ) -> Optional[Transaction]:
        """
        Update an existing transaction.

        Args:
            session (Session): Database session.
            transaction_id (int): ID of the transaction to update.
            transaction_data (Dict[str, Any]): Updated transaction data.

        Returns:
            Optional[Transaction]: Updated transaction or None if update fails.
        """
        try:
            transaction = (
                session.query(Transaction)
                .filter(Transaction.id == transaction_id)
                .first()
            )

            if not transaction:
                logger.error(f"Transaction {transaction_id} not found")
                return None

            # Get the old amount and transaction type for balance adjustment
            old_amount = transaction.amount
            old_type = transaction.transaction_type

            # Handle counterparty if counterparty_name is being updated
            if (
                "counterparty_name" in transaction_data
                and transaction_data["counterparty_name"]
                != transaction.counterparty_name
            ):
                counterparty_name = transaction_data["counterparty_name"]

                if counterparty_name:
                    # Check if counterparty already exists
                    counterparty = (
                        session.query(Counterparty)
                        .filter(Counterparty.name == counterparty_name)
                        .first()
                    )

                    if not counterparty:
                        # Create new counterparty
                        counterparty = Counterparty(name=counterparty_name)
                        session.add(counterparty)
                        session.flush()  # Get ID without committing
                        logger.info(
                            f"Created new counterparty: {counterparty.name} with ID {counterparty.id}"
                        )

                    # Update transaction's counterparty_id
                    transaction.counterparty_id = counterparty.id
                else:
                    # If counterparty_name is empty, set counterparty_id to None
                    transaction.counterparty_id = None

            # Update transaction fields
            for key, value in transaction_data.items():
                if key == "transaction_type":
                    try:
                        value = TransactionType(value.lower())
                    except ValueError:
                        value = TransactionType.UNKNOWN

                # Skip fields that have been moved or removed
                if key in [
                    "branch",
                    "description",
                    "email_id",
                    "bank_name",
                    "counterparty_id",
                ]:
                    continue

                # If description is provided, use it for transaction_details if not already set
                if key == "description" and not transaction.transaction_details:
                    setattr(transaction, "transaction_details", value)
                    continue

                if hasattr(transaction, key):
                    setattr(transaction, key, value)

            # Update account branch only if it's null and branch is provided in transaction data
            if (
                transaction.account
                and transaction.account.branch is None
                and transaction_data.get("branch")
            ):
                transaction.account.branch = transaction_data.get("branch")

            # Update the account balance if amount or transaction type changed
            if "amount" in transaction_data or "transaction_type" in transaction_data:
                account = transaction.account

                # Revert the old transaction's effect on balance
                if old_type == TransactionType.INCOME:
                    account.balance -= old_amount
                elif old_type == TransactionType.EXPENSE:
                    account.balance += old_amount

                # Apply the new transaction's effect on balance
                if transaction.transaction_type == TransactionType.INCOME:
                    account.balance += transaction.amount
                elif transaction.transaction_type == TransactionType.EXPENSE:
                    account.balance -= transaction.amount

            session.commit()
            logger.info(f"Updated transaction: {transaction.id}")
            return transaction

        except Exception as e:
            session.rollback()
            logger.error(f"Error updating transaction: {str(e)}")
            return None

    @staticmethod
    def delete_transaction(session: Session, transaction_id: int) -> bool:
        """
        Delete a transaction.

        Args:
            session (Session): Database session.
            transaction_id (int): ID of the transaction to delete.

        Returns:
            bool: True if deletion is successful, False otherwise.
        """
        try:
            transaction = (
                session.query(Transaction)
                .filter(Transaction.id == transaction_id)
                .first()
            )

            if not transaction:
                logger.error(f"Transaction {transaction_id} not found")
                return False

            # Update the account balance
            account = transaction.account
            if transaction.transaction_type == TransactionType.INCOME:
                account.balance -= transaction.amount
            elif transaction.transaction_type == TransactionType.EXPENSE:
                account.balance += transaction.amount

            session.delete(transaction)
            session.commit()
            logger.info(f"Deleted transaction: {transaction_id}")
            return True

        except Exception as e:
            session.rollback()
            logger.error(f"Error deleting transaction: {str(e)}")
            return False

    @staticmethod
    def get_transactions_by_date_range(
        session: Session,
        user_id: int,
        account_number: str,
        start_date: datetime,
        end_date: datetime,
    ) -> List[Transaction]:
        """
        Get transactions within a date range for an account.

        Args:
            session (Session): Database session.
            user_id (int): User ID.
            account_number (str): Account number.
            start_date (datetime): Start date.
            end_date (datetime): End date.

        Returns:
            List[Transaction]: List of transactions.
        """
        try:
            account = (
                session.query(Account)
                .filter(
                    Account.user_id == user_id, Account.account_number == account_number
                )
                .first()
            )

            if not account:
                return []

            transactions = (
                session.query(Transaction)
                .filter(
                    Transaction.account_id == account.id,
                    Transaction.value_date >= start_date,
                    Transaction.value_date <= end_date,
                )
                .order_by(Transaction.value_date.desc())
                .all()
            )

            return transactions

        except Exception as e:
            logger.error(f"Error getting transactions by date range: {str(e)}")
            return []

    @staticmethod
    def get_account_transaction_history(
        session: Session,
        user_id: int,
        account_number: str,
        page: int = 1,
        per_page: int = 200,
        date_from: datetime = None,
        date_to: datetime = None,
        transaction_type: str = None,
        search_text: str = None,
    ) -> Dict[str, Any]:
        """
        Get paginated transaction history for an account with HTML-friendly formatting.

        Args:
            session (Session): Database session.
            user_id (int): User ID.
            account_number (str): Account number.
            page (int): Page number (1-based).
            per_page (int): Number of items per page.
            date_from (datetime, optional): Filter transactions from this date.
            date_to (datetime, optional): Filter transactions to this date.
            transaction_type (str, optional): Filter by transaction type (INCOME, EXPENSE, TRANSFER).
            search_text (str, optional): Search text to filter by counterparty, amount, or description.

        Returns:
            Dict[str, Any]: Dictionary containing transactions and pagination info.
        """
        try:
            account = (
                session.query(Account)
                .filter(
                    Account.user_id == user_id, Account.account_number == account_number
                )
                .first()
            )

            if not account:
                return {
                    "transactions": [],
                    "total": 0,
                    "pages": 0,
                    "current_page": page,
                    "per_page": per_page,
                    "account": None,
                }

            query = session.query(Transaction).filter(
                Transaction.account_id == account.id
            )

            # Apply date range filters if provided
            if date_from:
                query = query.filter(Transaction.value_date >= date_from)

            if date_to:
                query = query.filter(Transaction.value_date <= date_to)

            # Apply transaction type filter if provided
            if transaction_type:
                # Handle case difference between string values and enum values
                if transaction_type == "INCOME":
                    query = query.filter(
                        Transaction.transaction_type == TransactionType.INCOME
                    )
                elif transaction_type == "EXPENSE":
                    query = query.filter(
                        Transaction.transaction_type == TransactionType.EXPENSE
                    )
                elif transaction_type == "TRANSFER":
                    query = query.filter(
                        Transaction.transaction_type == TransactionType.TRANSFER
                    )
                else:
                    logger.warning(f"Unknown transaction type: {transaction_type}")

            # Apply search text filter if provided
            if search_text and search_text.strip():
                search_pattern = f"%{search_text.strip()}%"
                query = query.filter(
                    # Search in counterparty name
                    (Transaction.counterparty_name.ilike(search_pattern))
                    |
                    # Search in transaction details (description)
                    (Transaction.transaction_details.ilike(search_pattern))
                    |
                    # Search in amount (convert to string for comparison)
                    (Transaction.amount.cast(String).ilike(search_pattern))
                )

            total = query.count()
            pages = (total + per_page - 1) // per_page

            transactions = (
                query.order_by(Transaction.value_date.desc())
                .offset((page - 1) * per_page)
                .limit(per_page)
                .all()
            )

            # Convert enum values to uppercase strings for template compatibility
            for transaction in transactions:
                transaction.transaction_type = (
                    transaction.transaction_type.value.upper()
                )

            return {
                "transactions": transactions,
                "total": total,
                "pages": pages,
                "current_page": page,
                "per_page": per_page,
                "account": account,
            }

        except Exception as e:
            logger.error(f"Error getting account transaction history: {str(e)}")
            return {
                "transactions": [],
                "total": 0,
                "pages": 0,
                "current_page": page,
                "per_page": per_page,
                "account": None,
            }
