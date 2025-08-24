# Security Headers Implementation Guide

This document covers the comprehensive security headers middleware implemented for the GHWAZI Money Tracker application to protect against various web security vulnerabilities.

## Table of Contents

1. [Overview](#overview)
2. [Security Headers Reference](#security-headers-reference)
3. [Content Security Policy (CSP)](#content-security-policy-csp)
4. [Configuration](#configuration)
5. [Usage Examples](#usage-examples)
6. [Testing Security Headers](#testing-security-headers)
7. [Best Practices](#best-practices)
8. [Troubleshooting](#troubleshooting)

## Overview

The security headers middleware automatically adds comprehensive HTTP security headers to all responses, providing protection against:

- **Cross-Site Scripting (XSS)** attacks
- **Clickjacking** attacks
- **MIME-type sniffing** vulnerabilities
- **Man-in-the-Middle** attacks
- **Content injection** attacks
- **Information leakage** through referrer headers

### Key Features

- ✅ **Content Security Policy (CSP)** with nonce support
- ✅ **HTTP Strict Transport Security (HSTS)**
- ✅ **X-Frame-Options** protection
- ✅ **Referrer Policy** control
- ✅ **Permissions Policy** for browser features
- ✅ **Environment-aware** configuration
- ✅ **CSP violation reporting**
- ✅ **Performance monitoring** headers

## Security Headers Reference

### Core Security Headers

| Header | Purpose | Default Value |
|--------|---------|---------------|
| `X-Content-Type-Options` | Prevent MIME-type sniffing | `nosniff` |
| `X-Frame-Options` | Prevent clickjacking | `SAMEORIGIN` |
| `X-XSS-Protection` | Legacy XSS protection | `1; mode=block` |
| `Referrer-Policy` | Control referrer information | `strict-origin-when-cross-origin` |
| `Strict-Transport-Security` | Enforce HTTPS | `max-age=31536000; includeSubDomains` |
| `Content-Security-Policy` | Control resource loading | [See CSP section](#content-security-policy-csp) |

### Additional Security Headers

| Header | Purpose | Default Value |
|--------|---------|---------------|
| `X-Download-Options` | Prevent file execution | `noopen` |
| `Cross-Origin-Embedder-Policy` | Control cross-origin embedding | `require-corp` |
| `Cross-Origin-Opener-Policy` | Control cross-origin window access | `same-origin` |
| `Cross-Origin-Resource-Policy` | Control resource sharing | `same-origin` |
| `Permissions-Policy` | Control browser features | [Restrictive policy](#permissions-policy) |

### Performance Headers

| Header | Purpose | Example Value |
|--------|---------|---------------|
| `X-Response-Time` | Request processing time | `0.123s` |
| `X-Powered-By` | Application identification | `GHWAZI Financial Tracker` |

## Content Security Policy (CSP)

CSP is the most important security header, controlling which resources can be loaded by the browser.

### Default CSP Configuration

```
default-src 'self'; 
script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://code.jquery.com https://cdn.datatables.net; 
style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdn.datatables.net https://fonts.googleapis.com; 
font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; 
img-src 'self' data: https: blob:; 
connect-src 'self'; 
frame-ancestors 'none'; 
base-uri 'self'; 
form-action 'self'; 
object-src 'none'; 
media-src 'self'
```

### CSP Nonce Support

The middleware generates unique nonces for each request to allow inline scripts and styles:

```html
<!-- In templates -->
<script nonce="{{ csp_nonce() }}">
    // Your inline JavaScript
</script>

<style nonce="{{ csp_nonce() }}">
    /* Your inline CSS */
</style>
```

### CSP Violation Reporting

CSP violations are automatically logged and can be sent to an endpoint:

```
Content-Security-Policy: ...; report-uri /csp-report
```

## Configuration

### Environment Variables

Configure security headers through environment variables:

```bash
# HSTS Configuration
HSTS_MAX_AGE=31536000                    # 1 year in seconds
HSTS_INCLUDE_SUBDOMAINS=True             # Include subdomains
HSTS_PRELOAD=False                       # HSTS preload (only if registered)

# Frame Options
X_FRAME_OPTIONS=SAMEORIGIN               # DENY, SAMEORIGIN, or ALLOW-FROM

# CSP Reporting
CSP_REPORT_ONLY=False                    # Enable CSP report-only mode

# Additional CSP Sources
CSP_SCRIPT_SRC=https://example.com,https://another.com
CSP_STYLE_SRC=https://fonts.example.com
CSP_IMG_SRC=https://images.example.com
CSP_CONNECT_SRC=https://api.example.com
```

### Flask Configuration

Configure in your Flask config class:

```python
class Config:
    SECURITY_HEADERS = {
        'HSTS_MAX_AGE': 31536000,        # 1 year
        'HSTS_INCLUDE_SUBDOMAINS': True,
        'HSTS_PRELOAD': False,
        'CSP_REPORT_ONLY': False,
        'FRAME_OPTIONS': 'SAMEORIGIN',   # DENY, SAMEORIGIN
    }
    
    CSP_DOMAINS = {
        'SCRIPT_SRC': ['https://trusted-scripts.com'],
        'STYLE_SRC': ['https://trusted-styles.com'],
        'IMG_SRC': ['https://trusted-images.com'],
        'CONNECT_SRC': ['https://api.example.com'],
    }
```

### Programmatic Configuration

Modify headers programmatically:

```python
from app.middleware import configure_security_headers

# Configure during app initialization
security_middleware, csp_reporter = configure_security_headers(app)

# Add additional CSP sources
security_middleware.update_csp_sources(
    'script_src', 
    ['https://new-trusted-domain.com']
)

# Set custom header
security_middleware.set_header('X-Custom-Security', 'custom-value')

# Remove a header
security_middleware.remove_header('X-XSS-Protection')
```

## Usage Examples

### Basic Usage

The middleware is automatically initialized in the Flask app:

```python
from app import create_app

app = create_app()
# Security headers are automatically applied to all responses
```

### Template Integration

Use CSP nonces in templates:

```html
<!DOCTYPE html>
<html>
<head>
    <!-- Inline style with nonce -->
    <style nonce="{{ csp_nonce() }}">
        .custom-style { color: red; }
    </style>
</head>
<body>
    <!-- Inline script with nonce -->
    <script nonce="{{ csp_nonce() }}">
        console.log('This script is allowed by CSP');
    </script>
    
    <!-- External scripts (must be whitelisted in CSP) -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

### API Endpoints

API endpoints automatically receive appropriate headers:

```python
@app.route('/api/data')
def api_data():
    return jsonify({'data': 'value'})
# Response includes security headers appropriate for JSON
```

### Custom CSP for Specific Routes

For routes requiring special CSP handling:

```python
from flask import g

@app.route('/special-page')
def special_page():
    # This would require custom middleware extension
    return render_template('special.html')
```

## Testing Security Headers

### Automated Testing Script

```python
#!/usr/bin/env python3
"""Test script for security headers."""

import requests
import sys

def test_security_headers(base_url):
    """Test security headers on the application."""
    
    # Test endpoints
    endpoints = ['/', '/login', '/api/test']
    
    # Expected headers
    expected_headers = [
        'X-Content-Type-Options',
        'X-Frame-Options', 
        'X-XSS-Protection',
        'Referrer-Policy',
        'Content-Security-Policy',
        'Strict-Transport-Security',  # Only on HTTPS
    ]
    
    for endpoint in endpoints:
        print(f"\nTesting {base_url}{endpoint}")
        
        try:
            response = requests.get(f"{base_url}{endpoint}")
            
            # Check each expected header
            for header in expected_headers:
                if header in response.headers:
                    print(f"✅ {header}: {response.headers[header]}")
                else:
                    print(f"❌ {header}: Missing")
            
            # Check CSP nonce (if HTML response)
            if 'text/html' in response.headers.get('content-type', ''):
                if 'nonce-' in response.text:
                    print("✅ CSP nonce found in HTML")
                else:
                    print("⚠️  CSP nonce not found in HTML")
        
        except Exception as e:
            print(f"❌ Error testing {endpoint}: {e}")

if __name__ == '__main__':
    base_url = sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:5000'
    test_security_headers(base_url)
```

### Manual Testing

Test headers using curl:

```bash
# Test security headers
curl -I http://localhost:5000/

# Test with HTTPS (for HSTS)
curl -I https://yourdomain.com/

# Test CSP violation reporting
curl -X POST http://localhost:5000/csp-report \
  -H "Content-Type: application/json" \
  -d '{"csp-report": {"blocked-uri": "https://evil.com"}}'
```

### Browser Testing

1. Open Developer Tools → Security tab
2. Check for security warnings
3. Test CSP by trying to execute blocked content
4. Monitor Console for CSP violations

## Best Practices

### Development Environment

```python
# More permissive settings for development
SECURITY_HEADERS = {
    'HSTS_MAX_AGE': 300,           # 5 minutes
    'FRAME_OPTIONS': 'SAMEORIGIN', # Allow framing for debugging
}
```

### Production Environment

```python
# Strict settings for production
SECURITY_HEADERS = {
    'HSTS_MAX_AGE': 31536000,      # 1 year
    'HSTS_PRELOAD': True,          # Only if registered
    'FRAME_OPTIONS': 'DENY',       # Prevent all framing
}
```

### CSP Best Practices

1. **Avoid `unsafe-inline`**: Use nonces or hashes instead
2. **Use `strict-dynamic`**: For modern browsers
3. **Monitor violations**: Set up CSP reporting
4. **Test thoroughly**: CSP can break functionality
5. **Gradual deployment**: Use `Content-Security-Policy-Report-Only` first

### HSTS Best Practices

1. **Start small**: Begin with short `max-age`
2. **Test thoroughly**: HSTS can't be easily undone
3. **Consider preload**: Only for permanent HTTPS sites
4. **Include subdomains**: Use `includeSubDomains` carefully

## Troubleshooting

### Common Issues

**CSP Blocking Resources**
```
Content Security Policy: The page's settings blocked the loading of a resource
```
*Solution*: Add the domain to appropriate CSP directive

**HSTS Errors**
```
NET::ERR_CERT_AUTHORITY_INVALID
```
*Solution*: Ensure valid SSL certificate before enabling HSTS

**Mixed Content Warnings**
```
Mixed Content: The page was loaded over HTTPS, but requested an insecure resource
```
*Solution*: Use HTTPS URLs or add to CSP with appropriate protocol

### Debugging CSP

1. **Use report-only mode**:
   ```python
   CSP_REPORT_ONLY = True
   ```

2. **Check browser console** for CSP violations

3. **Use CSP evaluator tools**:
   - https://csp-evaluator.withgoogle.com/
   - Browser DevTools Security tab

### Performance Considerations

1. **CSP nonce generation**: Minimal overhead
2. **Header size**: Keep CSP concise
3. **Caching**: Headers don't affect caching significantly

## Advanced Configuration

### Custom CSP Directives

```python
# Add custom CSP directive
config.csp_config['worker_src'] = ["'self'", "blob:"]
```

### Conditional Headers

```python
def conditional_headers(response):
    # Add headers based on request context
    if request.path.startswith('/admin'):
        response.headers['X-Frame-Options'] = 'DENY'
    return response
```

### Integration with External Services

```python
# Add monitoring service domains
CSP_DOMAINS = {
    'CONNECT_SRC': [
        'https://api.sentry.io',        # Error tracking
        'https://www.google-analytics.com'  # Analytics
    ]
}
```

## Security Headers Checklist

- ✅ CSP implemented with nonces
- ✅ HSTS configured appropriately
- ✅ Frame options set correctly
- ✅ Referrer policy configured
- ✅ Content type options enabled
- ✅ XSS protection enabled
- ✅ Permissions policy restrictive
- ✅ CSP violation reporting set up
- ✅ Headers tested in all environments
- ✅ Performance impact measured

## Resources

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN HTTP Security Headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#security)
- [CSP Reference](https://content-security-policy.com/)
- [HSTS Specification](https://tools.ietf.org/html/rfc6797)
- [SecurityHeaders.com](https://securityheaders.com/) - Test your headers

The security headers middleware provides comprehensive protection while maintaining flexibility for different deployment scenarios. Regular testing and monitoring ensure optimal security posture.