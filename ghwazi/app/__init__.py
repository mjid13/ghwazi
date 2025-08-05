"""
Application factory for the Flask app.
"""

import logging
import os
import time
from datetime import timedelta

from flask import Flask, session

from app.views.email import email_tasks, email_tasks_lock, scraping_accounts

from .config.base import Config
from .extensions import db, migrate


def create_app(config_class=Config):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)

    # Register blueprints
    from app.views.account import account_bp
    from app.views.admin import admin_bp
    from app.views.api import api_bp
    from app.views.auth import auth_bp
    from app.views.category import category_bp
    from app.views.email import email_bp
    from app.views.main import main_bp
    from app.views.transaction import transaction_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(account_bp, url_prefix="/account")
    app.register_blueprint(category_bp, url_prefix="/category")
    app.register_blueprint(email_bp, url_prefix="/email")
    app.register_blueprint(transaction_bp, url_prefix="/transaction")

    # Configure logging
    if not app.debug and not app.testing:
        if not os.path.exists("logs"):
            os.mkdir("logs")
        file_handler = logging.FileHandler("logs/app.log")
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"
            )
        )
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info("Application startup")

    # Register error handlers
    @app.errorhandler(404)
    def not_found_error(error):
        from flask import render_template

        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def internal_error(error):
        from flask import render_template

        db.session.rollback()
        return render_template("errors/500.html"), 500

    # Add template globals
    @app.template_global()
    def generate_csrf_token():
        import secrets

        return secrets.token_hex(16)

    @app.context_processor
    def inject_csrf_token():
        return {"csrf_token": generate_csrf_token}

    # Or alternatively, register it as a global function:
    app.jinja_env.globals["csrf_token"] = generate_csrf_token

    # Add session configuration
    app.permanent_session_lifetime = timedelta(days=30)

    @app.before_request
    def before_request():
        """Ensure user session is handled properly."""
        # Make session permanent
        session.permanent = True

        # Check if user is logged in and update session timestamp
        if "user_id" in session:
            session["last_activity"] = time.time()

        # Clear old tasks from email_tasks dict
        current_time = time.time()
        tasks_to_remove = []
        accounts_to_remove = []

        with email_tasks_lock:
            # Clean up old tasks
            for task_id, task in email_tasks.items():
                # Remove tasks older than 1 hour
                if "end_time" in task and (current_time - task["end_time"]) > 3600:
                    tasks_to_remove.append(task_id)

            for task_id in tasks_to_remove:
                email_tasks.pop(task_id, None)

            # Clean up stale scraping_accounts entries (older than 30 minutes)
            for account_number, account_info in scraping_accounts.items():
                if (current_time - account_info["start_time"]) > 1800:  # 30 minutes
                    accounts_to_remove.append(account_number)

            for account_number in accounts_to_remove:
                scraping_accounts.pop(account_number, None)

    @app.after_request
    def after_request(response):
        """Add security headers to response."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        return response

    return app
