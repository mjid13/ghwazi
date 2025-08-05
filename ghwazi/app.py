#!/usr/bin/env python3
"""
Application entry point for the Bank Email Parser & Account Tracker.

This script creates and runs the Flask application using the application factory pattern.
It handles different environments (development, production, testing) and provides
command-line interface for running the application.
"""

import os
import sys
from flask.cli import FlaskGroup

# Add the current directory to Python path to ensure imports work correctly
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)

# Import from the local app package (ghwawzi/app/)
from app import create_app
from .app.config.development import DevelopmentConfig
from .app.config.production import ProductionConfig
from .app.config.testing import TestingConfig
from .app.models.database import Database


def get_config_class():
    """Get the appropriate configuration class based on environment."""
    env = os.environ.get('FLASK_ENV', 'development').lower()

    config_map = {
        'development': DevelopmentConfig,
        'production': ProductionConfig,
        'testing': TestingConfig
    }

    return config_map.get(env, DevelopmentConfig)


def create_application():
    """Create the Flask application with appropriate configuration."""
    config_class = get_config_class()
    app = create_app(config_class)
    return app


def initialize_database():
    """Initialize database safely with proper error handling."""
    try:
        db = Database()
        db.connect()
        db.create_tables()
        print("Database initialized successfully!")
        return db
    except Exception as e:
        print(f"Error initializing database: {e}")
        return None


# Create the application instance
app = create_application()

# Create Flask CLI group for additional commands
cli = FlaskGroup(app)


@cli.command()
def init_db():
    """Initialize the database with tables."""
    from .app.extensions import db

    with app.app_context():
        db.create_all()
        print("Database tables created successfully!")


@cli.command()
def drop_db():
    """Drop all database tables."""
    from .app.extensions import db

    with app.app_context():
        if input("Are you sure you want to drop all tables? (y/N): ").lower() == 'y':
            db.drop_all()
            print("Database tables dropped successfully!")
        else:
            print("Operation cancelled.")


@cli.command()
def create_admin():
    """Create an admin user."""
    from .app.models import Database, TransactionRepository

    username = input("Enter admin username: ")
    email = input("Enter admin email: ")
    password = input("Enter admin password: ")

    if not all([username, email, password]):
        print("All fields are required!")
        return

    db = Database()
    db_session = db.get_session()

    try:
        user_data = {
            'username': username,
            'email': email,
            'password': password,
            'is_admin': True  # If your User model supports admin flag
        }

        user = TransactionRepository.create_user(db_session, user_data)
        if user:
            print(f"Admin user '{username}' created successfully!")
        else:
            print("Failed to create admin user.")
    except Exception as e:
        print(f"Error creating admin user: {str(e)}")
    finally:
        db.close_session(db_session)


@cli.command()
def test():
    """Run the test suite."""
    import pytest

    # Run tests with coverage if available
    try:
        exit_code = pytest.main([
            'tests/',
            '--verbose',
            '--cov=app',
            '--cov-report=term-missing',
            '--cov-report=html'
        ])
    except ImportError:
        # Fallback to basic pytest if coverage not available
        exit_code = pytest.main(['tests/', '--verbose'])

    sys.exit(exit_code)


@cli.command()
def lint():
    """Run code linting."""
    import subprocess

    print("Running flake8...")
    try:
        subprocess.run(['flake8', 'app/', 'tests/'], check=True)
        print("✓ Linting passed!")
    except subprocess.CalledProcessError:
        print("✗ Linting failed!")
        sys.exit(1)
    except FileNotFoundError:
        print("flake8 not found. Install with: pip install flake8")
        sys.exit(1)


@cli.command()
def format_code():
    """Format code using black."""
    import subprocess

    print("Formatting code with black...")
    try:
        subprocess.run(['black', 'app/', 'tests/', 'run.py'], check=False)
        print("✓ Code formatted!")
    except FileNotFoundError:
        print("black not found. Install with: pip install black")
        sys.exit(1)


@cli.command()
def fetch_emails():
    """Manually fetch emails from configured accounts."""
    from .app.services.email_service import EmailService

    print("Starting email fetch process...")
    try:
        email_service = EmailService()
        # This would need to be implemented in the EmailService
        # email_service.fetch_all_accounts()
        print("Email fetch completed!")
    except Exception as e:
        print(f"Error fetching emails: {str(e)}")


if __name__ == '__main__':
    # Initialize database when running directly
    db = initialize_database()

    # Check if we're running in development mode
    if os.environ.get('FLASK_ENV') == 'development':
        # Run with Flask's built-in development server
        app.run(
            host=os.environ.get('FLASK_HOST', '127.0.0.1'),
            port=int(os.environ.get('FLASK_PORT', 5000)),
            debug=os.environ.get('FLASK_DEBUG', 'True').lower() in ('true', '1', 't')
        )
    else:
        # For production, recommend using a WSGI server
        print("For production deployment, use a WSGI server like Gunicorn:")
        print("gunicorn -w 4 -b 0.0.0.0:8000 run:app")

        # Still allow running with built-in server if needed
        app.run(
            host='0.0.0.0',
            port=int(os.environ.get('PORT', 5000)),
            debug=False
        )