"""
Application factory for the Flask app.
"""

import logging
import os
import time
import traceback
from datetime import timedelta

from flask import Flask, session, redirect, url_for, flash, request, jsonify

from .views.email import email_tasks, email_tasks_lock, scraping_accounts

from .config.base import Config
from .extensions import db, migrate, limiter, csrf
from flask_wtf.csrf import CSRFError, generate_csrf

# Optional Redis session support
try:
    import redis
    from flask_session import Session as FlaskSession
except Exception:  # pragma: no cover
    redis = None
    FlaskSession = None


def create_app(config_class=Config):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize session management
    _initialize_session_management(app)

    # Set application start time for uptime tracking
    app.config['START_TIME'] = time.time()

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)
    csrf.init_app(app)

    # Register blueprints
    _register_blueprints(app)

    # Configure CSRF exemptions
    _configure_csrf_exemptions(app)

    # Configure logging
    _configure_logging(app)

    # Register error handlers
    _register_error_handlers(app)

    # Add template globals and filters
    _configure_template_globals(app)
    _register_template_filters(app)

    # Configure security headers middleware
    _configure_security_middleware(app)

    # Session configuration
    app.permanent_session_lifetime = timedelta(
        seconds=app.config.get("PERMANENT_SESSION_LIFETIME", 3600)
    )

    # Register request handlers
    _register_request_handlers(app)

    return app


def _initialize_session_management(app):
    """Initialize session management with Redis or filesystem fallback."""
    try:
        redis_url = app.config.get('REDIS_URL') or os.environ.get('REDISCLOUD_URL')

        if redis_url and FlaskSession and redis:
            # Production: Use Redis for sessions
            app.config['SESSION_TYPE'] = 'redis'
            app.config['SESSION_REDIS'] = redis.from_url(redis_url)
            app.config['SESSION_PERMANENT'] = True
            app.config['SESSION_USE_SIGNER'] = True
            app.config['SESSION_KEY_PREFIX'] = 'session:'
            app.config['SESSION_COOKIE_SECURE'] = app.config.get('SESSION_COOKIE_SECURE', False)
            app.config['SESSION_COOKIE_HTTPONLY'] = True
            app.config['SESSION_COOKIE_SAMESITE'] = app.config.get('SESSION_COOKIE_SAMESITE', 'Lax')
            FlaskSession(app)
            app.logger.info('Flask-Session initialized with Redis backend')

        elif FlaskSession:
            # Development: Use filesystem sessions
            app.config['SESSION_TYPE'] = 'filesystem'
            session_dir = '/tmp/flask_sessions' if os.environ.get('DYNO') else './instance/sessions'

            # Ensure session directory exists
            try:
                os.makedirs(session_dir, exist_ok=True)
                app.config['SESSION_FILE_DIR'] = session_dir
            except Exception as e:
                app.logger.warning(f"Could not create session directory {session_dir}: {e}")
                app.config['SESSION_FILE_DIR'] = '/tmp/flask_sessions'
                os.makedirs('/tmp/flask_sessions', exist_ok=True)

            app.config['SESSION_PERMANENT'] = True
            app.config['SESSION_USE_SIGNER'] = True
            FlaskSession(app)
            app.logger.info(f'Flask-Session initialized with filesystem backend at {app.config["SESSION_FILE_DIR"]}')

        else:
            # Fallback to default Flask sessions (signed cookies)
            app.logger.warning('Flask-Session not available, using default cookie sessions')

    except Exception as e:
        app.logger.error(f'Failed to initialize session management: {e}')
        # Continue with default Flask sessions
        pass


def _register_blueprints(app):
    """Register all application blueprints."""
    from .views.account import account_bp
    from .views.admin import admin_bp
    from .views.api import api_bp
    from .views.auth import auth_bp
    from .views.category import category_bp
    from .views.email import email_bp
    from .views.health import health_bp
    from .views.main import main_bp
    from .views.oauth import oauth_bp
    from .views.session import session_bp
    from .views.transaction import transaction_bp

    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(api_bp, url_prefix="/api")
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(account_bp, url_prefix="/account")
    app.register_blueprint(category_bp, url_prefix="/category")
    app.register_blueprint(email_bp, url_prefix="/email")
    app.register_blueprint(health_bp, url_prefix="/health")
    app.register_blueprint(oauth_bp, url_prefix="/oauth")
    app.register_blueprint(session_bp, url_prefix="/session")
    app.register_blueprint(transaction_bp, url_prefix="/transaction")


def _configure_csrf_exemptions(app):
    """Configure CSRF exemptions for API and health endpoints."""
    try:
        from .views.api import api_bp
        from .views.health import health_bp
        csrf.exempt(api_bp)
        csrf.exempt(health_bp)
    except Exception as e:
        app.logger.warning(f"Could not configure CSRF exemptions: {e}")


def _configure_logging(app):
    """Configure application logging."""
    if not app.debug and not app.testing:
        try:
            import sys

            # Use stdout for Heroku/containerized environments
            if os.environ.get('DYNO') or os.environ.get('HEROKU'):
                handler = logging.StreamHandler(sys.stdout)
                handler.setFormatter(
                    logging.Formatter(
                        "%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"
                    )
                )
                handler.setLevel(getattr(logging, app.config.get('LOG_LEVEL', 'INFO')))
                app.logger.addHandler(handler)
                app.logger.setLevel(getattr(logging, app.config.get('LOG_LEVEL', 'INFO')))
                app.logger.info("Logging configured for production (stdout)")
            else:
                # Local development - use file logging
                if not os.path.exists("logs"):
                    os.mkdir("logs")
                handler = logging.FileHandler("logs/app.log")
                handler.setFormatter(
                    logging.Formatter(
                        "%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"
                    )
                )
                handler.setLevel(getattr(logging, app.config.get('LOG_LEVEL', 'INFO')))
                app.logger.addHandler(handler)
                app.logger.setLevel(getattr(logging, app.config.get('LOG_LEVEL', 'INFO')))
                app.logger.info("Logging configured for development (file)")

        except Exception as e:
            # Logging setup failure shouldn't crash the app
            print(f"Warning: Could not configure logging: {e}")


def _register_error_handlers(app):
    """Register comprehensive error handlers."""
    from .utils.error_handlers import (
        SecureErrorHandler, handle_database_error,
        handle_validation_error, handle_permission_error, handle_rate_limit_error
    )
    from sqlalchemy.exc import SQLAlchemyError
    from werkzeug.exceptions import HTTPException

    @app.errorhandler(400)
    def bad_request_error(error):
        return SecureErrorHandler.create_safe_error_response(error, 400)

    @app.errorhandler(401)
    def unauthorized_error(error):
        return SecureErrorHandler.create_safe_error_response(error, 401)

    @app.errorhandler(403)
    def forbidden_error(error):
        return SecureErrorHandler.create_safe_error_response(error, 403)

    @app.errorhandler(404)
    def not_found_error(error):
        return SecureErrorHandler.create_safe_error_response(error, 404)

    @app.errorhandler(422)
    def unprocessable_entity_error(error):
        return SecureErrorHandler.create_safe_error_response(error, 422)

    @app.errorhandler(429)
    def too_many_requests_error(error):
        return SecureErrorHandler.create_safe_error_response(error, 429)

    @app.errorhandler(500)
    def internal_error(error):
        try:
            db.session.rollback()
        except Exception as rollback_error:
            app.logger.error(f"Database rollback failed: {rollback_error}")
        return SecureErrorHandler.create_safe_error_response(error, 500)

    @app.errorhandler(503)
    def service_unavailable_error(error):
        return SecureErrorHandler.create_safe_error_response(error, 503)

    @app.errorhandler(SQLAlchemyError)
    def database_error(error):
        try:
            db.session.rollback()
        except Exception as rollback_error:
            app.logger.error(f"Database rollback failed during error handling: {rollback_error}")
        return handle_database_error(error)

    @app.errorhandler(HTTPException)
    def http_error(error):
        return SecureErrorHandler.create_safe_error_response(error, error.code or 500)

    @app.errorhandler(Exception)
    def generic_error(error):
        app.logger.critical(
            f"Unexpected error: {type(error).__name__} - {str(error)}",
            extra={'stack_trace': traceback.format_exc()}
        )
        try:
            db.session.rollback()
        except Exception as rollback_error:
            app.logger.error(f"Database rollback failed during generic error handling: {rollback_error}")
        return SecureErrorHandler.create_safe_error_response(error, 500)

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        is_api_request = request.path.startswith("/api") or (
                request.accept_mimetypes and request.accept_mimetypes.best == "application/json"
        )
        message = getattr(e, 'description', 'The form you submitted is invalid or has expired. Please try again.')
        if is_api_request:
            return jsonify({"error": "csrf_failed", "message": message}), 400
        flash(message, "error")
        return redirect(request.referrer or url_for('main.index'))


def _configure_template_globals(app):
    """Configure template globals and context processors."""
    @app.template_global()
    def generate_csrf_token():
        return generate_csrf()

    @app.context_processor
    def inject_csrf_token():
        return {"csrf_token": generate_csrf_token}

    app.jinja_env.globals["csrf_token"] = generate_csrf_token


def _register_template_filters(app):
    """Register custom template filters."""
    try:
        from .utils.template_filters import register_template_filters, register_template_globals
        register_template_filters(app)
        register_template_globals(app)
    except ImportError:
        app.logger.warning("Template filters not found, skipping registration")


def _configure_security_middleware(app):
    """Configure security headers middleware."""
    try:
        from .middleware import configure_security_headers
        security_middleware, csp_reporter = configure_security_headers(
            app, app.config.get('ENV', 'production')
        )
    except ImportError:
        app.logger.warning("Security middleware not found, skipping configuration")


def _register_request_handlers(app):
    """Register before/after request handlers."""

    @app.before_request
    def before_request():
        """Enhanced session management with security features and DB cleanup."""
        # Make session permanent so PERMANENT_SESSION_LIFETIME applies
        session.permanent = True

        # Proactive database cleanup
        try:
            db.session.remove()
        except Exception as e:
            app.logger.debug(f"Flask-SQLAlchemy session pre-clean error: {e}")

        try:
            from .models.database import Database
            Database.remove_scoped_session()
        except Exception as e:
            app.logger.debug(f"Custom Database scoped session pre-clean error: {e}")

        # Basic session validation for authenticated users
        is_api_request = request.path.startswith("/api") or (
                request.accept_mimetypes and request.accept_mimetypes.best == "application/json"
        )

        if "user_id" in session:
            # Simple session timeout check
            last_activity = session.get("last_activity")
            now = time.time()
            idle_timeout = app.config.get("SESSION_IDLE_TIMEOUT", 1800)  # 30 minutes default

            if last_activity and (now - float(last_activity)) > idle_timeout:
                # Session expired due to inactivity
                session.clear()
                if is_api_request:
                    return jsonify({
                        "error": "session_expired",
                        "message": "Session expired due to inactivity."
                    }), 401
                else:
                    flash("Your session has expired due to inactivity. Please log in again.", "warning")
                    return redirect(url_for("auth.login"))

            # Update last activity timestamp
            session["last_activity"] = now

        # Clean up old email tasks
        _cleanup_email_tasks()

    @app.after_request
    def after_request(response):
        """Cleanup DB sessions after each request."""
        try:
            db.session.remove()
        except Exception as e:
            app.logger.debug(f"Flask-SQLAlchemy session remove error: {e}")

        try:
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


def _cleanup_email_tasks():
    """Clean up old email tasks and scraping accounts."""
    try:
        current_time = time.time()
        tasks_to_remove = []
        accounts_to_remove = []

        with email_tasks_lock:
            # Clean up old tasks (older than 1 hour)
            for task_id, task in email_tasks.items():
                if "end_time" in task and (current_time - task["end_time"]) > 3600:
                    tasks_to_remove.append(task_id)

            for task_id in tasks_to_remove:
                email_tasks.pop(task_id, None)

            # Clean up stale scraping_accounts entries (older than 30 minutes)
            for account_number, account_info in scraping_accounts.items():
                if (current_time - account_info["start_time"]) > 1800:
                    accounts_to_remove.append(account_number)

            for account_number in accounts_to_remove:
                scraping_accounts.pop(account_number, None)

    except Exception as e:
        # Don't let cleanup errors affect the request
        pass