"""
Secure error handling utilities for the Flask application.
Provides proper error handling that doesn't expose internal details
and includes secure logging functionality.
"""

import logging
import traceback
import uuid
from datetime import datetime
from flask import request, jsonify, render_template, current_app, session
from werkzeug.exceptions import HTTPException


class SecureErrorHandler:
    """Handles errors securely without exposing internal details."""
    
    @staticmethod
    def log_error(error, error_id=None, user_id=None, additional_context=None):
        """
        Log errors securely with contextual information.
        
        Args:
            error: The exception that occurred
            error_id: Unique identifier for the error
            user_id: ID of the user who encountered the error
            additional_context: Additional context for debugging
        """
        if error_id is None:
            error_id = str(uuid.uuid4())[:8]
        
        # Build secure log entry
        log_data = {
            'error_id': error_id,
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': user_id or session.get('user_id'),
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'ip_address': SecureErrorHandler._get_client_ip(),
            'method': request.method,
            'url': request.url,
            'endpoint': request.endpoint,
            'error_type': type(error).__name__,
            'error_message': str(error),
        }
        
        # Add additional context if provided
        if additional_context:
            log_data['context'] = additional_context
        
        # Log the error with stack trace for debugging
        current_app.logger.error(
            f"Error {error_id}: {type(error).__name__} - {str(error)}",
            extra={
                'error_data': log_data,
                'stack_trace': traceback.format_exc()
            }
        )
        
        return error_id
    
    @staticmethod
    def _get_client_ip():
        """Get client IP address safely."""
        # Check for forwarded IP headers (common in production with reverse proxies)
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        else:
            return request.remote_addr or 'Unknown'
    
    @staticmethod
    def create_safe_error_response(error, status_code=500):
        """
        Create a safe error response that doesn't expose internal details.
        
        Args:
            error: The exception that occurred
            status_code: HTTP status code to return
            
        Returns:
            Appropriate response based on request type (JSON/HTML)
        """
        error_id = SecureErrorHandler.log_error(error)
        
        # Determine if this is an API request
        is_api_request = (
            request.path.startswith('/api') or 
            request.accept_mimetypes.accept_json and 
            not request.accept_mimetypes.accept_html
        )
        
        if is_api_request:
            return SecureErrorHandler._create_json_error_response(error_id, status_code)
        else:
            return SecureErrorHandler._create_html_error_response(error_id, status_code)
    
    @staticmethod
    def _create_json_error_response(error_id, status_code):
        """Create JSON error response for API endpoints."""
        error_messages = {
            400: "Bad Request - The request could not be understood",
            401: "Unauthorized - Authentication required",
            403: "Forbidden - You don't have permission to access this resource",
            404: "Not Found - The requested resource could not be found",
            422: "Unprocessable Entity - The request was well-formed but contains invalid data",
            429: "Too Many Requests - Rate limit exceeded",
            500: "Internal Server Error - Something went wrong on our end",
            503: "Service Unavailable - The service is temporarily unavailable"
        }
        
        return jsonify({
            'error': True,
            'error_id': error_id,
            'message': error_messages.get(status_code, "An unexpected error occurred"),
            'status_code': status_code,
            'timestamp': datetime.utcnow().isoformat()
        }), status_code
    
    @staticmethod
    def _create_html_error_response(error_id, status_code):
        """Create HTML error response for web pages."""
        template_map = {
            400: 'errors/400.html',
            401: 'errors/401.html',
            403: 'errors/403.html',
            404: 'errors/404.html',
            422: 'errors/422.html',
            429: 'errors/429.html',
            500: 'errors/500.html',
            503: 'errors/503.html'
        }
        
        template = template_map.get(status_code, 'errors/500.html')
        
        try:
            return render_template(template, error_id=error_id), status_code
        except Exception:
            # Fallback if error template doesn't exist
            return render_template('errors/500.html', error_id=error_id), status_code


def handle_database_error(error):
    """Handle database-specific errors securely."""
    from sqlalchemy.exc import (
        IntegrityError, DataError, OperationalError, 
        InvalidRequestError, TimeoutError
    )
    
    # Map database errors to appropriate HTTP status codes
    if isinstance(error, IntegrityError):
        status_code = 422  # Unprocessable Entity
        additional_context = {"error_category": "integrity_constraint"}
    elif isinstance(error, DataError):
        status_code = 400  # Bad Request
        additional_context = {"error_category": "data_validation"}
    elif isinstance(error, (OperationalError, TimeoutError)):
        status_code = 503  # Service Unavailable
        additional_context = {"error_category": "database_unavailable"}
    elif isinstance(error, InvalidRequestError):
        status_code = 400  # Bad Request
        additional_context = {"error_category": "invalid_request"}
    else:
        status_code = 500
        additional_context = {"error_category": "unknown_database_error"}
    
    error_id = SecureErrorHandler.log_error(
        error, 
        additional_context=additional_context
    )
    
    return SecureErrorHandler.create_safe_error_response(error, status_code)


def handle_validation_error(error, field_errors=None):
    """Handle validation errors with field-specific details."""
    error_id = SecureErrorHandler.log_error(
        error,
        additional_context={
            "error_category": "validation",
            "field_errors": field_errors or {}
        }
    )
    
    is_api_request = (
        request.path.startswith('/api') or 
        request.accept_mimetypes.accept_json and 
        not request.accept_mimetypes.accept_html
    )
    
    if is_api_request:
        response_data = {
            'error': True,
            'error_id': error_id,
            'message': "Validation failed",
            'status_code': 422,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        if field_errors:
            response_data['field_errors'] = field_errors
        
        return jsonify(response_data), 422
    else:
        return render_template('errors/422.html', 
                             error_id=error_id, 
                             field_errors=field_errors), 422


def handle_permission_error(error, required_permission=None):
    """Handle permission/authorization errors."""
    error_id = SecureErrorHandler.log_error(
        error,
        additional_context={
            "error_category": "authorization",
            "required_permission": required_permission
        }
    )
    
    # Don't expose the specific permission requirement in the response
    return SecureErrorHandler.create_safe_error_response(error, 403)


def handle_rate_limit_error(error, retry_after=None):
    """Handle rate limiting errors."""
    error_id = SecureErrorHandler.log_error(
        error,
        additional_context={
            "error_category": "rate_limit",
            "retry_after": retry_after
        }
    )
    
    is_api_request = (
        request.path.startswith('/api') or 
        request.accept_mimetypes.accept_json and 
        not request.accept_mimetypes.accept_html
    )
    
    response = SecureErrorHandler.create_safe_error_response(error, 429)
    
    # Add Retry-After header if provided
    if retry_after and hasattr(response, 'headers'):
        response.headers['Retry-After'] = str(retry_after)
    
    return response