"""
Tests for the views module.
"""

import pytest

from app import create_app
from app.config.testing import TestingConfig


@pytest.fixture
def app():
    """Create application for testing."""
    app = create_app(TestingConfig)
    return app


@pytest.fixture
def client(app):
    """Create test client."""
    return app.test_client()


class TestMainViews:
    """Test main views."""

    def test_index_page(self, client):
        """Test index page."""
        response = client.get("/")
        assert response.status_code == 200
        assert b"Money Tracker" in response.data or b"Welcome" in response.data

    def test_dashboard_requires_login(self, client):
        """Test dashboard requires authentication."""
        response = client.get("/dashboard")
        assert response.status_code == 302  # Redirect to login

    def test_accounts_requires_login(self, client):
        """Test accounts page requires authentication."""
        response = client.get("/accounts")
        assert response.status_code == 302  # Redirect to login


class TestAuthViews:
    """Test authentication views."""

    def test_register_page(self, client):
        """Test register page loads."""
        response = client.get("/auth/register")
        assert response.status_code == 200
        assert b"register" in response.data.lower()

    def test_login_page(self, client):
        """Test login page loads."""
        response = client.get("/auth/login")
        assert response.status_code == 200
        assert b"login" in response.data.lower()

    def test_register_user(self, client):
        """Test user registration."""
        response = client.post(
            "/auth/register",
            data={
                "username": "testuser",
                "email": "test@example.com",
                "password": "testpassword123",
                "confirm_password": "testpassword123",
            },
        )
        # Should redirect to login page on success
        assert response.status_code == 302

    def test_register_password_mismatch(self, client):
        """Test registration with password mismatch."""
        response = client.post(
            "/auth/register",
            data={
                "username": "testuser",
                "email": "test@example.com",
                "password": "testpassword123",
                "confirm_password": "differentpassword",
            },
        )
        assert response.status_code == 200
        assert b"password" in response.data.lower()


class TestAPIViews:
    """Test API views."""

    def test_api_requires_login(self, client):
        """Test API endpoints require authentication."""
        response = client.delete("/api/transaction/1")
        assert response.status_code == 302  # Redirect to login

    def test_chart_data_requires_login(self, client):
        """Test chart data endpoint requires authentication."""
        response = client.get("/api/chart/data")
        assert response.status_code == 302  # Redirect to login


class TestAdminViews:
    """Test admin views."""

    def test_categories_requires_login(self, client):
        """Test categories page requires authentication."""
        response = client.get("/admin/categories")
        assert response.status_code == 302  # Redirect to login

    def test_email_configs_requires_login(self, client):
        """Test email configs page requires authentication."""
        response = client.get("/admin/email-configs")
        assert response.status_code == 302  # Redirect to login
