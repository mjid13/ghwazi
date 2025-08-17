"""
Enhanced decorators for the Flask application with secure error handling.
"""

import functools
import logging
from flask import request, session, redirect, url_for, flash, current_app
from werkzeug.exceptions import Forbidden, Unauthorized

from .error_handlers import (
    SecureErrorHandler, handle_validation_error, 
    handle_permission_error, handle_rate_limit_error
)


def login_required(f):
    """Original login required decorator - kept for backward compatibility."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page", "error")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)
    return decorated_function


def handle_view_errors(f):
    """
    Decorator to handle errors in view functions securely.
    Catches exceptions and returns appropriate error responses.
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except (Forbidden, PermissionError) as e:
            return handle_permission_error(e)
        except Unauthorized as e:
            # For unauthorized access, redirect to login for web requests
            if not (request.path.startswith('/api') or request.accept_mimetypes.accept_json):
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('auth.login'))
            return SecureErrorHandler.create_safe_error_response(e, 401)
        except ValueError as e:
            # Handle validation-type errors
            return handle_validation_error(e)
        except Exception as e:
            # Log the error and return a generic error response
            error_id = SecureErrorHandler.log_error(
                e, 
                additional_context={
                    'view_function': f.__name__,
                    'view_args': args,
                    'view_kwargs': kwargs
                }
            )
            return SecureErrorHandler.create_safe_error_response(e, 500)
    
    return decorated_function


def require_login(f):
    """
    Enhanced login required decorator with better error handling.
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api') or request.accept_mimetypes.accept_json:
                return SecureErrorHandler.create_safe_error_response(
                    Unauthorized("Authentication required"), 401
                )
            else:
                flash('Please log in to access this page.', 'info')
                return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    
    return decorated_function


def require_admin(f):
    """
    Admin required decorator with secure error handling.
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api') or request.accept_mimetypes.accept_json:
                return SecureErrorHandler.create_safe_error_response(
                    Unauthorized("Authentication required"), 401
                )
            else:
                flash('Please log in to access this page.', 'info')
                return redirect(url_for('auth.login'))
        
        # Check if user is admin (you'll need to implement this check based on your user model)
        # This is a placeholder - replace with your actual admin check logic
        user_is_admin = session.get('is_admin', False)
        
        if not user_is_admin:
            return handle_permission_error(
                Forbidden("Administrator privileges required"),
                required_permission="admin_access"
            )
        
        return f(*args, **kwargs)
    
    return decorated_function


def validate_input(schema_name=None, validation_schema=None):
    """
    Decorator for input validation with secure error handling.
    
    Args:
        schema_name: Name of the validation schema to use from validation_schemas.py
        validation_schema: Optional validation schema instance (alternative to schema_name)
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Get validation schema
            schema = None
            if schema_name:
                try:
                    from .validation_schemas import get_validation_schema
                    schema = get_validation_schema(schema_name)
                except Exception as e:
                    current_app.logger.error(f"Failed to load validation schema '{schema_name}': {e}")
                    return handle_validation_error(
                        ValueError("Validation configuration error"),
                        field_errors={'_general': ['Validation error occurred']}
                    )
            elif validation_schema:
                schema = validation_schema
            
            if schema:
                try:
                    # Get form data based on request method
                    if request.method in ['POST', 'PUT', 'PATCH']:
                        if request.is_json:
                            data = request.get_json() or {}
                        else:
                            data = request.form.to_dict()
                    else:
                        data = request.args.to_dict()
                    
                    # Validate the data
                    is_valid, errors, cleaned_data = schema.validate(data)
                    
                    if not is_valid:
                        return handle_validation_error(
                            ValueError("Validation failed"),
                            field_errors=errors
                        )
                    
                    # Add cleaned data to request context for the view function
                    request.validated_data = cleaned_data
                    
                except Exception as e:
                    current_app.logger.error(f"Validation error: {e}")
                    return handle_validation_error(e)
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def rate_limit(requests_per_minute=60, requests_per_hour=1000):
    """
    Simple rate limiting decorator.
    In production, use Redis or similar for distributed rate limiting.
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # This is a simplified rate limiting implementation
            # In production, implement proper distributed rate limiting
            
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            if client_ip:
                client_ip = client_ip.split(',')[0].strip()
            
            # Log rate limit check (for monitoring)
            current_app.logger.debug(f"Rate limit check for {client_ip} on {request.endpoint}")
            
            # For now, just continue (implement actual rate limiting logic here)
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def log_user_action(action_type="unknown"):
    """
    Decorator to log user actions for audit trails.
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            if client_ip:
                client_ip = client_ip.split(',')[0].strip()
            
            # Log the user action
            current_app.logger.info(
                f"User action: {action_type}",
                extra={
                    'user_id': user_id,
                    'client_ip': client_ip,
                    'endpoint': request.endpoint,
                    'method': request.method,
                    'user_agent': request.headers.get('User-Agent'),
                    'action_type': action_type
                }
            )
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def csrf_protect(f):
    """
    Simple CSRF protection decorator.
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            # Skip CSRF for API endpoints (assuming they use other auth methods)
            if request.path.startswith('/api'):
                return f(*args, **kwargs)
            
            token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
            expected_token = session.get('csrf_token')
            
            if not token or not expected_token or token != expected_token:
                return handle_validation_error(
                    ValueError("CSRF validation failed"),
                    field_errors={'csrf_token': ['Invalid or missing CSRF token']}
                )
        
        return f(*args, **kwargs)
    
    return decorated_function
