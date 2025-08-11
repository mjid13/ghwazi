"""
Application factory for the Flask app.
"""

import logging
import os
import time
from datetime import timedelta

from flask import Flask, session, redirect, url_for, flash, request, jsonify

from .views.email import email_tasks, email_tasks_lock, scraping_accounts

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
    from .views.account import account_bp
    from .views.admin import admin_bp
    from .views.api import api_bp
    from .views.auth import auth_bp
    from .views.category import category_bp
    from .views.email import email_bp
    from .views.main import main_bp
    from .views.oauth import oauth_bp
    from .views.transaction import transaction_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(account_bp, url_prefix="/account")
    app.register_blueprint(category_bp, url_prefix="/category")
    app.register_blueprint(email_bp, url_prefix="/email")
    app.register_blueprint(oauth_bp, url_prefix="/oauth")
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
        file_handler.setLevel(logging.DEBUG)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.DEBUG)
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

    # Session configuration based on Config
    app.permanent_session_lifetime = timedelta(seconds=app.config.get("PERMANENT_SESSION_LIFETIME", 3600))

    @app.before_request
    def before_request():
        """Ensure user session is handled properly and proactively cleanup DB sessions.
        Also enforce idle-timeout and basic session security.
        """
        # Make session permanent so PERMANENT_SESSION_LIFETIME applies
        session.permanent = True

        # Proactively cleanup any lingering sessions at the start of the request
        try:
            db.session.remove()
        except Exception as e:
            app.logger.debug(f"Flask-SQLAlchemy session pre-clean error: {e}")
        try:
            from .models.database import Database
            Database.remove_scoped_session()
        except Exception as e:
            app.logger.debug(f"Custom Database scoped session pre-clean error: {e}")

        # Enforce idle timeout for authenticated users
        idle_timeout = app.config.get("SESSION_IDLE_TIMEOUT", 1800)
        is_api_request = request.path.startswith("/api") or (
            request.accept_mimetypes and request.accept_mimetypes.best == "application/json"
        )

        if "user_id" in session:
            last = session.get("last_activity")
            now = time.time()
            if last and (now - float(last)) > idle_timeout:
                # Session expired due to inactivity
                session.clear()
                if is_api_request:
                    return jsonify({"error": "session_expired", "message": "Session expired due to inactivity."}), 401
                else:
                    flash("Your session has expired due to inactivity. Please log in again.", "warning")
                    return redirect(url_for("auth.login"))
            # Update last activity timestamp (sliding window)
            session["last_activity"] = now

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
        """Add security headers to response and cleanup DB sessions."""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Request-level DB session cleanup
        try:
            # Flask-SQLAlchemy session
            db.session.remove()
        except Exception as e:
            app.logger.debug(f"Flask-SQLAlchemy session remove error: {e}")
        try:
            # Custom SQLAlchemy scoped session used by services
            from .models.database import Database
            Database.remove_scoped_session()
        except Exception as e:
            app.logger.debug(f"Custom Database scoped session remove error: {e}")

        return response

    @app.teardown_appcontext
    def shutdown_session(exception=None):
        """Ensure sessions are removed at the end of the app context."""
        try:
            db.session.remove()
        except Exception as e:
            app.logger.debug(f"Flask-SQLAlchemy teardown remove error: {e}")
        try:
            from .models.database import Database
            Database.remove_scoped_session()
        except Exception as e:
            app.logger.debug(f"Custom Database teardown remove error: {e}")

    return app
