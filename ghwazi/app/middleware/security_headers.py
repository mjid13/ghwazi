"""
Security Headers Middleware for Flask Application.

This middleware sets comprehensive security headers to protect against various attacks
including XSS, clickjacking, MIME sniffing, and other security vulnerabilities.

Features:
- Content Security Policy (CSP) with nonce support
- HTTP Strict Transport Security (HSTS)
- X-Frame-Options, X-Content-Type-Options
- Referrer Policy, Permissions Policy
- Configurable security levels
- Environment-aware settings
"""

import secrets
import time
from flask import request, g, current_app
from typing import Dict, List, Optional, Union


class SecurityHeadersConfig:
    """Configuration class for security headers."""
    
    def __init__(self):
        # Default security headers configuration
        self.headers = {
            # Prevent MIME type sniffing
            'X-Content-Type-Options': 'nosniff',
            
            # Control framing of the page
            'X-Frame-Options': 'SAMEORIGIN',  # or 'DENY' for stricter security
            
            # XSS Protection (legacy but still useful)
            'X-XSS-Protection': '1; mode=block',
            
            # Control referrer information
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            
            # Prevent browsers from guessing content types
            'X-Download-Options': 'noopen',
            
            # Control how much information user agents include in cross-origin requests
            'Cross-Origin-Embedder-Policy': 'require-corp',
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Resource-Policy': 'same-origin',
            
            # Feature Policy (replaced by Permissions Policy)
            'Permissions-Policy': (
                'camera=(), microphone=(), geolocation=(), '
                'payment=(), usb=(), magnetometer=(), '
                'accelerometer=(), gyroscope=(), '
                'fullscreen=(self), display-capture=()'
            ),
        }
        
        # HSTS Configuration
        self.hsts_config = {
            'max_age': 31536000,  # 1 year
            'include_subdomains': True,
            'preload': False,  # Set to True only if registered with HSTS preload list
        }
        
        # CSP Configuration
        self.csp_config = {
            'default_src': ["'self'"],
            'script_src': [
                "'self'",
                "'unsafe-inline'",  # Required for inline scripts - use nonces in production
                'https://cdn.jsdelivr.net',
                'https://code.jquery.com',
                'https://cdn.datatables.net',
                'https://cdn.jsdelivr.net/npm/bootstrap@5.3.2',
            ],
            'style_src': [
                "'self'",
                "'unsafe-inline'",  # Required for inline styles
                'https://cdn.jsdelivr.net',
                'https://cdn.datatables.net',
                'https://fonts.googleapis.com',
            ],
            'font_src': [
                "'self'",
                'https://fonts.gstatic.com',
                'https://cdn.jsdelivr.net',
            ],
            'img_src': [
                "'self'",
                'data:',
                'https:',  # Allow HTTPS images
                'blob:',   # Allow blob URLs for dynamic images
            ],
            'connect_src': [
                "'self'",
                # Add API endpoints or external services as needed
            ],
            'frame_ancestors': ["'none'"],  # Prevent framing
            'base_uri': ["'self'"],
            'form_action': ["'self'"],
            'object_src': ["'none'"],
            'media_src': ["'self'"],
            'worker_src': ["'self'"],
            'child_src': ["'self'"],
        }
        
        # Environment-specific overrides
        self.development_overrides = {
            # More permissive CSP for development
            'script_src': [
                "'self'",
                "'unsafe-inline'",
                "'unsafe-eval'",  # For development tools
                'https://cdn.jsdelivr.net',
                'https://code.jquery.com',
                'https://cdn.datatables.net',
                'https://cdn.jsdelivr.net/npm/bootstrap@5.3.2',
                'http://localhost:*',
                'ws://localhost:*',  # For hot reload
            ],
            'connect_src': [
                "'self'",
                'http://localhost:*',
                'ws://localhost:*',
            ],
        }
    
    def get_hsts_header(self) -> str:
        """Generate HSTS header string."""
        hsts_parts = [f"max-age={self.hsts_config['max_age']}"]
        
        if self.hsts_config['include_subdomains']:
            hsts_parts.append('includeSubDomains')
        
        if self.hsts_config['preload']:
            hsts_parts.append('preload')
        
        return '; '.join(hsts_parts)
    
    def get_csp_header(self, nonce: str = None, environment: str = 'production') -> str:
        """Generate Content Security Policy header string."""
        csp_config = self.csp_config.copy()
        
        # Apply development overrides if in development
        if environment == 'development':
            for directive, sources in self.development_overrides.items():
                csp_config[directive] = sources
        
        # Add nonce to script-src if provided
        if nonce:
            script_src = csp_config.get('script_src', [])
            if f"'nonce-{nonce}'" not in script_src:
                script_src.insert(0, f"'nonce-{nonce}'")
                csp_config['script_src'] = script_src
        
        # Build CSP string
        csp_parts = []
        for directive, sources in csp_config.items():
            if sources:
                directive_name = directive.replace('_', '-')
                sources_str = ' '.join(sources)
                csp_parts.append(f"{directive_name} {sources_str}")
        
        return '; '.join(csp_parts)


class SecurityHeadersMiddleware:
    """
    Middleware class to add security headers to Flask responses.
    """
    
    def __init__(self, app=None, config: SecurityHeadersConfig = None):
        self.config = config or SecurityHeadersConfig()
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize the middleware with Flask app."""
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        
        # Add template global for CSP nonce
        @app.template_global()
        def csp_nonce():
            """Get the CSP nonce for the current request."""
            return getattr(g, 'csp_nonce', '')
    
    def before_request(self):
        """Generate CSP nonce before processing request."""
        # Generate a unique nonce for this request
        g.csp_nonce = secrets.token_urlsafe(16)
        
        # Store request start time for performance monitoring
        g.request_start_time = time.time()
    
    def after_request(self, response):
        """Add security headers to response."""
        # Skip security headers for certain endpoints
        if self._should_skip_headers():
            return response
        
        # Get environment
        environment = current_app.config.get('ENV', 'production')
        is_https = request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https'
        
        # Add basic security headers
        self._add_basic_headers(response)
        
        # Add HSTS header for HTTPS requests
        if is_https:
            self._add_hsts_header(response)
        
        # Add Content Security Policy
        self._add_csp_header(response, environment)
        
        # Add additional security headers based on content type
        self._add_content_type_headers(response)
        
        # Add performance and monitoring headers
        self._add_monitoring_headers(response)
        
        return response
    
    def _should_skip_headers(self) -> bool:
        """Determine if security headers should be skipped for this request."""
        # Skip for certain file types or endpoints
        skip_patterns = [
            '/static/',
            '/favicon.ico',
            '/robots.txt',
            '/sitemap.xml',
        ]
        
        path = request.path.lower()
        return any(pattern in path for pattern in skip_patterns)
    
    def _add_basic_headers(self, response):
        """Add basic security headers."""
        for header, value in self.config.headers.items():
            response.headers[header] = value
        
        # Add cache control for sensitive pages
        if self._is_authenticated_request():
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
    
    def _add_hsts_header(self, response):
        """Add HTTP Strict Transport Security header."""
        response.headers['Strict-Transport-Security'] = self.config.get_hsts_header()
    
    def _add_csp_header(self, response, environment: str):
        """Add Content Security Policy header."""
        nonce = getattr(g, 'csp_nonce', None)
        csp_header = self.config.get_csp_header(nonce, environment)
        response.headers['Content-Security-Policy'] = csp_header
        
        # Also add CSP as report-only for monitoring (optional)
        if current_app.config.get('CSP_REPORT_ONLY', False):
            response.headers['Content-Security-Policy-Report-Only'] = csp_header
    
    def _add_content_type_headers(self, response):
        """Add headers based on content type."""
        content_type = response.content_type or ''
        
        if 'application/json' in content_type:
            # Additional headers for JSON responses
            response.headers['X-Content-Type-Options'] = 'nosniff'
        
        elif 'text/html' in content_type:
            # Additional headers for HTML responses
            response.headers['X-UA-Compatible'] = 'IE=edge'
    
    def _add_monitoring_headers(self, response):
        """Add performance and monitoring headers."""
        # Add request processing time
        if hasattr(g, 'request_start_time'):
            processing_time = time.time() - g.request_start_time
            response.headers['X-Response-Time'] = f"{processing_time:.3f}s"
        
        # Add server identification (but don't reveal too much)
        response.headers['X-Powered-By'] = 'GHWAZI Financial Tracker'
        
        # Remove default Flask server header for security
        response.headers.pop('Server', None)
    
    def _is_authenticated_request(self) -> bool:
        """Check if the current request is from an authenticated user."""
        from flask import session
        return 'user_id' in session
    
    def update_csp_sources(self, directive: str, sources: List[str], replace: bool = False):
        """
        Update CSP sources for a specific directive.
        
        Args:
            directive: CSP directive (e.g., 'script_src')
            sources: List of sources to add
            replace: If True, replace existing sources; if False, append
        """
        if replace:
            self.config.csp_config[directive] = sources
        else:
            existing = self.config.csp_config.get(directive, [])
            self.config.csp_config[directive] = existing + sources
    
    def set_header(self, header: str, value: str):
        """Set a custom security header."""
        self.config.headers[header] = value
    
    def remove_header(self, header: str):
        """Remove a security header."""
        self.config.headers.pop(header, None)


class CSPViolationReporter:
    """Handles CSP violation reports."""
    
    def __init__(self, app=None):
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize CSP violation reporting."""
        @app.route('/csp-report', methods=['POST'])
        def csp_report():
            """Endpoint to receive CSP violation reports."""
            try:
                if request.is_json:
                    report = request.get_json()
                    self.log_violation(report)
                    return '', 204
                else:
                    return 'Invalid content type', 400
            except Exception as e:
                current_app.logger.error(f"CSP violation report error: {e}")
                return 'Error processing report', 500
    
    def log_violation(self, report: Dict):
        """Log CSP violation."""
        violation = report.get('csp-report', {})
        
        # Extract key information
        blocked_uri = violation.get('blocked-uri', 'unknown')
        violated_directive = violation.get('violated-directive', 'unknown')
        original_policy = violation.get('original-policy', 'unknown')
        document_uri = violation.get('document-uri', 'unknown')
        referrer = violation.get('referrer', 'unknown')
        
        # Log the violation
        current_app.logger.warning(
            f"CSP Violation: {violated_directive} blocked {blocked_uri} "
            f"on {document_uri} (referrer: {referrer})"
        )
        
        # You could also send this to an external monitoring service
        # or store in database for analysis


def configure_security_headers(app, environment: str = None):
    """
    Configure security headers for the Flask application.
    
    Args:
        app: Flask application instance
        environment: Environment name (development, production, testing)
    """
    if environment is None:
        environment = app.config.get('ENV', 'production')
    
    # Create configuration
    config = SecurityHeadersConfig()
    
    # Apply configuration from Flask config
    security_config = app.config.get('SECURITY_HEADERS', {})
    csp_domains = app.config.get('CSP_DOMAINS', {})
    
    # Update HSTS configuration
    if 'HSTS_MAX_AGE' in security_config:
        config.hsts_config['max_age'] = security_config['HSTS_MAX_AGE']
    if 'HSTS_INCLUDE_SUBDOMAINS' in security_config:
        config.hsts_config['include_subdomains'] = security_config['HSTS_INCLUDE_SUBDOMAINS']
    if 'HSTS_PRELOAD' in security_config:
        config.hsts_config['preload'] = security_config['HSTS_PRELOAD']
    
    # Update frame options
    if 'FRAME_OPTIONS' in security_config:
        config.headers['X-Frame-Options'] = security_config['FRAME_OPTIONS']
    
    # Update CSP domains from configuration
    for directive, domains in csp_domains.items():
        if domains:  # Only update if domains are provided
            csp_directive = directive.lower()
            if csp_directive in config.csp_config:
                # Extend existing domains with configured ones
                existing_domains = config.csp_config[csp_directive]
                config.csp_config[csp_directive] = existing_domains + [d.strip() for d in domains if d.strip()]
    
    # Customize configuration based on environment
    if environment == 'development':
        # More permissive settings for development
        if config.hsts_config['max_age'] > 3600:  # Only reduce if currently high
            config.hsts_config['max_age'] = 300  # 5 minutes
        config.headers['X-Frame-Options'] = 'SAMEORIGIN'  # Allow framing for debugging
    
    elif environment == 'production':
        # Ensure strict settings for production
        if config.hsts_config['max_age'] < 86400:  # Ensure at least 1 day
            config.hsts_config['max_age'] = 31536000  # 1 year
    
    # Initialize middleware
    security_middleware = SecurityHeadersMiddleware(app, config)
    
    # Initialize CSP violation reporter if not in report-only mode
    csp_reporter = CSPViolationReporter(app)
    
    return security_middleware, csp_reporter


# Utility functions for templates
def create_inline_script_with_nonce(script_content: str) -> str:
    """
    Create an inline script tag with CSP nonce.
    
    Args:
        script_content: JavaScript code to include
        
    Returns:
        HTML script tag with nonce attribute
    """
    from flask import g
    nonce = getattr(g, 'csp_nonce', '')
    return f'<script nonce="{nonce}">{script_content}</script>'


def create_inline_style_with_nonce(style_content: str) -> str:
    """
    Create an inline style tag with CSP nonce.
    
    Args:
        style_content: CSS code to include
        
    Returns:
        HTML style tag with nonce attribute
    """
    from flask import g
    nonce = getattr(g, 'csp_nonce', '')
    return f'<style nonce="{nonce}">{style_content}</style>'