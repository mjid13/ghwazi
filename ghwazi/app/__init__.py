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
    
    # Initialize Redis-backed sessions in production if REDIS_URL is set
    try:
        redis_url = app.config.get('REDIS_URL') or os.environ.get('REDISCLOUD_URL')
        if redis_url and FlaskSession and redis:
            app.config['SESSION_TYPE'] = 'redis'
            app.config['SESSION_REDIS'] = redis.from_url(redis_url)
            app.config['SESSION_PERMANENT'] = True
            FlaskSession(app)
            app.logger.info('Flask-Session initialized with Redis')
    except Exception as e:
        app.logger.error(f'Failed to initialize Redis-backed sessions: {e}')
    
    # Set application start time for uptime tracking
    app.config['START_TIME'] = time.time()

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)
    limiter.init_app(app)
    # Enable CSRF protection
    csrf.init_app(app)
    
    # Initialize comprehensive session management
    from .services.session_persistence import initialize_session_persistence
    from .services.session_monitor import initialize_session_monitoring
    from .services.session_migration import initialize_session_migrations
    
    try:
        initialize_session_persistence(app)
        initialize_session_monitoring(app)
        initialize_session_migrations(app)
        app.logger.info("Advanced session management systems initialized")
    except Exception as e:
        app.logger.error(f"Failed to initialize session management: {e}")
        # Continue with basic functionality

    # Register blueprints
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

    # Exempt API and health blueprints from CSRF (use token/headers if added later)
    try:
        csrf.exempt(api_bp)
        csrf.exempt(health_bp)  # Health checks should be accessible without CSRF
    except Exception:
        pass

    # Configure logging: use stdout in production/Heroku, file in local dev if desired
    if not app.debug and not app.testing:
        try:
            import sys
            # If running on Heroku (DYNO env), prefer stdout
            if os.environ.get('DYNO') or os.environ.get('HEROKU', '').lower() in ('1', 'true', 'yes'):
                stream_handler = logging.StreamHandler(sys.stdout)
                stream_handler.setFormatter(
                    logging.Formatter(
                        "%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"
                    )
                )
                stream_handler.setLevel(getattr(logging, app.config.get('LOG_LEVEL', 'INFO')))
                app.logger.addHandler(stream_handler)
            else:
                if not os.path.exists("logs"):
                    os.mkdir("logs")
                file_handler = logging.FileHandler("logs/app.log")
                file_handler.setFormatter(
                    logging.Formatter(
                        "%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"
                    )
                )
                file_handler.setLevel(getattr(logging, app.config.get('LOG_LEVEL', 'INFO')))
                app.logger.addHandler(file_handler)
            app.logger.setLevel(getattr(logging, app.config.get('LOG_LEVEL', 'INFO')))
            app.logger.info("Application startup")
        except Exception as e:
            pass

    # Register comprehensive error handlers
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
        # Rollback database session to prevent corrupted state
        try:
            db.session.rollback()
        except Exception as rollback_error:
            app.logger.error(f"Database rollback failed: {rollback_error}")
        
        return SecureErrorHandler.create_safe_error_response(error, 500)
    
    @app.errorhandler(503)
    def service_unavailable_error(error):
        return SecureErrorHandler.create_safe_error_response(error, 503)
    
    # Handle database errors specifically
    @app.errorhandler(SQLAlchemyError)
    def database_error(error):
        # Ensure database session is clean
        try:
            db.session.rollback()
        except Exception as rollback_error:
            app.logger.error(f"Database rollback failed during error handling: {rollback_error}")
        
        return handle_database_error(error)
    
    # Generic HTTPException handler (fallback)
    @app.errorhandler(HTTPException)
    def http_error(error):
        return SecureErrorHandler.create_safe_error_response(error, error.code or 500)
    
    # Generic Exception handler (catch-all for unexpected errors)
    @app.errorhandler(Exception)
    def generic_error(error):
        # Log unexpected errors with high priority
        app.logger.critical(
            f"Unexpected error: {type(error).__name__} - {str(error)}",
            extra={'stack_trace': traceback.format_exc()}
        )
        
        # Rollback any pending database transactions
        try:
            db.session.rollback()
        except Exception as rollback_error:
            app.logger.error(f"Database rollback failed during generic error handling: {rollback_error}")
        
        return SecureErrorHandler.create_safe_error_response(error, 500)

    # Add template globals - use Flask-WTF's CSRF token generator
    @app.template_global()
    def generate_csrf_token():
        # Use Flask-WTF's generate_csrf so tokens match CSRFProtect validation
        return generate_csrf()

    @app.context_processor
    def inject_csrf_token():
        return {"csrf_token": generate_csrf_token}

    # Or alternatively, register it as a global function:
    app.jinja_env.globals["csrf_token"] = generate_csrf_token
    
    # Register template filters for safe output encoding
    from .utils.template_filters import register_template_filters, register_template_globals
    register_template_filters(app)
    register_template_globals(app)
    
    # Initialize comprehensive security headers middleware
    from .middleware import configure_security_headers
    security_middleware, csp_reporter = configure_security_headers(app, app.config.get('ENV', 'production'))

    # Session configuration based on Config
    app.permanent_session_lifetime = timedelta(seconds=app.config.get("PERMANENT_SESSION_LIFETIME", 3600))

    @app.before_request
    def before_request():
        """Enhanced session management with security features and DB cleanup."""
        from .services.session_service import SessionService
        
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

        # Periodic session cleanup
        try:
            SessionService.cleanup_expired_sessions()
        except Exception as e:
            app.logger.debug(f"Session cleanup error: {e}")

        # Enhanced session validation for authenticated users
        is_api_request = request.path.startswith("/api") or (
            request.accept_mimetypes and request.accept_mimetypes.best == "application/json"
        )

        if "user_id" in session:
            session_id = session.get("session_id")
            
            if session_id:
                # Use enhanced session validation
                is_valid, session_data = SessionService.validate_session(session_id)
                
                if not is_valid:
                    # Session invalid or expired
                    session.clear()
                    if is_api_request:
                        return jsonify({"error": "session_expired", "message": "Session expired or invalid."}), 401
                    else:
                        flash("Your session has expired. Please log in again.", "warning")
                        return redirect(url_for("auth.login"))
                
                # Update Flask session with fresh data
                if session_data:
                    session["session_id"] = session_data["session_id"]
                    session["last_activity"] = session_data["last_activity"]
            else:
                # Legacy session without session_id - validate using old method
                last = session.get("last_activity")
                now = time.time()
                idle_timeout = app.config.get("SESSION_IDLE_TIMEOUT", 1800)
                
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

    # CSRF error handling
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

    @app.after_request
    def after_request(response):
        """Cleanup DB sessions. Security headers are handled by middleware."""
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
