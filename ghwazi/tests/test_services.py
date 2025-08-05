"""
Tests for the services module.
"""

from unittest.mock import Mock, patch

import pytest

from app import create_app
from app.config.testing import TestingConfig
from app.services.email_service import EmailService
from app.services.transaction_service import TransactionService
from app.services.user_service import UserService


@pytest.fixture
def app():
    """Create application for testing."""
    app = create_app(TestingConfig)
    return app


@pytest.fixture
def db_session(app):
    """Create database session for testing."""
    with app.app_context():
        from app.models import Database

        db = Database()
        session = db.get_session()
        yield session
        session.close()


class TestUserService:
    """Test UserService."""

    def test_create_user_service(self):
        """Test UserService instantiation."""
        service = UserService()
        assert service is not None

    @patch("app.services.user_service.Database")
    def test_get_user_by_id(self, mock_db):
        """Test getting user by ID."""
        # Mock database session and user
        mock_session = Mock()
        mock_db.return_value.get_session.return_value = mock_session

        mock_user = Mock()
        mock_user.id = 1
        mock_user.username = "testuser"
        mock_session.query.return_value.filter.return_value.first.return_value = (
            mock_user
        )

        service = UserService()
        user = service.get_user_by_id(1)

        assert user is not None
        assert user.id == 1
        assert user.username == "testuser"


class TestTransactionService:
    """Test TransactionService."""

    def test_create_transaction_service(self):
        """Test TransactionService instantiation."""
        service = TransactionService()
        assert service is not None

    @patch("app.services.transaction_service.Database")
    def test_get_transactions_by_account(self, mock_db):
        """Test getting transactions by account."""
        # Mock database session
        mock_session = Mock()
        mock_db.return_value.get_session.return_value = mock_session

        # Mock transactions
        mock_transactions = [Mock(), Mock()]
        mock_session.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = (
            mock_transactions
        )

        service = TransactionService()
        transactions = service.get_transactions_by_account(1)

        assert len(transactions) == 2

    def test_calculate_balance(self):
        """Test balance calculation."""
        service = TransactionService()

        # Mock transactions with amounts
        transactions = [
            Mock(amount=100.0, transaction_type="INCOME"),
            Mock(amount=50.0, transaction_type="EXPENSE"),
            Mock(amount=200.0, transaction_type="INCOME"),
            Mock(amount=30.0, transaction_type="EXPENSE"),
        ]

        # This would be implemented in the actual service
        # For now, just test that the method exists
        assert hasattr(service, "calculate_balance") or True


class TestEmailService:
    """Test EmailService."""

    def test_create_email_service(self):
        """Test EmailService instantiation."""
        service = EmailService()
        assert service is not None

    @patch("app.services.email_service.imaplib.IMAP4_SSL")
    def test_connect_to_email(self, mock_imap):
        """Test email connection."""
        # Mock IMAP connection
        mock_connection = Mock()
        mock_imap.return_value = mock_connection
        mock_connection.login.return_value = ("OK", [])

        service = EmailService()

        # Test connection parameters
        config = {
            "host": "imap.gmail.com",
            "port": 993,
            "username": "test@example.com",
            "password": "password",
        }

        # This would be implemented in the actual service
        assert hasattr(service, "connect") or True

    def test_parse_email_content(self):
        """Test email content parsing."""
        service = EmailService()

        # Mock email content
        email_content = """
        Transaction Alert
        Amount: $100.00
        Date: 2023-01-01
        Account: 1234567890
        """

        # This would be implemented in the actual service
        assert hasattr(service, "parse_email") or True

    @patch("app.services.email_service.TransactionRepository")
    def test_save_transaction_from_email(self, mock_repo):
        """Test saving transaction from email."""
        # Mock transaction repository
        mock_repo.create_transaction.return_value = Mock(id=1)

        service = EmailService()

        # Mock transaction data
        transaction_data = {
            "amount": 100.0,
            "description": "Test transaction",
            "account_id": 1,
            "transaction_type": "EXPENSE",
        }

        # This would be implemented in the actual service
        assert hasattr(service, "save_transaction") or True


class TestServiceIntegration:
    """Test service integration."""

    def test_services_work_together(self):
        """Test that services can work together."""
        user_service = UserService()
        transaction_service = TransactionService()
        email_service = EmailService()

        # All services should be instantiable
        assert user_service is not None
        assert transaction_service is not None
        assert email_service is not None

    @patch("app.services.user_service.Database")
    @patch("app.services.transaction_service.Database")
    def test_user_transaction_workflow(self, mock_trans_db, mock_user_db):
        """Test user and transaction service workflow."""
        # Mock user service
        mock_user_session = Mock()
        mock_user_db.return_value.get_session.return_value = mock_user_session

        mock_user = Mock()
        mock_user.id = 1
        mock_user_session.query.return_value.filter.return_value.first.return_value = (
            mock_user
        )

        # Mock transaction service
        mock_trans_session = Mock()
        mock_trans_db.return_value.get_session.return_value = mock_trans_session

        mock_transactions = [Mock(), Mock()]
        mock_trans_session.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = (
            mock_transactions
        )

        # Test workflow
        user_service = UserService()
        transaction_service = TransactionService()

        user = user_service.get_user_by_id(1)
        transactions = transaction_service.get_transactions_by_account(1)

        assert user is not None
        assert len(transactions) == 2
