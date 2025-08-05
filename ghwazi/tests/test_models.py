"""
Tests for the models module.
"""

import pytest

from app import create_app
from .app.config.testing import TestingConfig
from .app.models import Account, Category, Database, Transaction, User


@pytest.fixture
def app():
    """Create application for testing."""
    app = create_app(TestingConfig)
    return app


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


@pytest.fixture
def db_session(app):
    """Create database session for testing."""
    with app.app_context():
        db = Database()
        session = db.get_session()
        yield session
        session.close()


class TestUser:
    """Test User model."""

    def test_create_user(self, db_session):
        """Test user creation."""
        user_data = {
            "username": "testuser",
            "email": "test@example.com",
            "password": "testpassword123",
        }

        user = User(**user_data)
        db_session.add(user)
        db_session.commit()

        assert user.id is not None
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.check_password("testpassword123")

    def test_user_password_hashing(self, db_session):
        """Test password hashing."""
        user = User(username="test", email="test@example.com")
        user.set_password("secret")

        assert user.password_hash != "secret"
        assert user.check_password("secret")
        assert not user.check_password("wrong")


class TestAccount:
    """Test Account model."""

    def test_create_account(self, db_session):
        """Test account creation."""
        # First create a user
        user = User(username="testuser", email="test@example.com")
        user.set_password("password")
        db_session.add(user)
        db_session.commit()

        # Create account
        account = Account(
            account_number="1234567890",
            account_name="Test Account",
            bank_name="Test Bank",
            user_id=user.id,
        )
        db_session.add(account)
        db_session.commit()

        assert account.id is not None
        assert account.account_number == "1234567890"
        assert account.user_id == user.id


class TestCategory:
    """Test Category model."""

    def test_create_category(self, db_session):
        """Test category creation."""
        # First create a user
        user = User(username="testuser", email="test@example.com")
        user.set_password("password")
        db_session.add(user)
        db_session.commit()

        # Create category
        category = Category(name="Food", color="#FF0000", user_id=user.id)
        db_session.add(category)
        db_session.commit()

        assert category.id is not None
        assert category.name == "Food"
        assert category.color == "#FF0000"
        assert category.user_id == user.id
