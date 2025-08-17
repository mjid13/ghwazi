"""
Template filters for safe output encoding and data formatting.
These filters ensure that all output is properly encoded to prevent XSS attacks.
"""

import html
import json
import urllib.parse
from datetime import datetime
from decimal import Decimal
from markupsafe import escape, Markup

from .validators import OutputEncoder


def register_template_filters(app):
    """Register all template filters with the Flask app."""
    
    @app.template_filter('safe_html')
    def safe_html_filter(value, allowed_tags=None):
        """
        Filter to safely render HTML content.
        
        Usage in template: {{ content|safe_html }}
        With custom tags: {{ content|safe_html(['b', 'i', 'p']) }}
        """
        if allowed_tags is None:
            allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'p', 'br']
        
        return OutputEncoder.safe_html(value, allowed_tags)
    
    @app.template_filter('html_escape')
    def html_escape_filter(value):
        """
        Filter to HTML-escape content for safe display.
        
        Usage in template: {{ user_input|html_escape }}
        """
        return OutputEncoder.html_escape(value)
    
    @app.template_filter('html_attr')
    def html_attr_filter(value):
        """
        Filter to safely encode content for HTML attributes.
        
        Usage in template: <div title="{{ user_title|html_attr }}">
        """
        return OutputEncoder.html_attribute(value)
    
    @app.template_filter('js_escape')
    def js_escape_filter(value):
        """
        Filter to safely encode content for JavaScript.
        
        Usage in template: <script>var data = {{ data|js_escape|safe }};</script>
        """
        return OutputEncoder.javascript_escape(value)
    
    @app.template_filter('url_encode')
    def url_encode_filter(value):
        """
        Filter to URL-encode content.
        
        Usage in template: <a href="/search?q={{ query|url_encode }}">
        """
        return OutputEncoder.url_encode(value)
    
    @app.template_filter('css_escape')
    def css_escape_filter(value):
        """
        Filter to safely encode content for CSS.
        
        Usage in template: <style>.class-{{ name|css_escape }} { }</style>
        """
        return OutputEncoder.css_escape(value)
    
    @app.template_filter('currency')
    def currency_filter(value, currency_symbol='$'):
        """
        Filter to format monetary values safely.
        
        Usage in template: {{ amount|currency }}
        Usage with symbol: {{ amount|currency('€') }}
        """
        if value is None or value == '':
            return ''
        
        try:
            if isinstance(value, str):
                value = Decimal(value)
            elif isinstance(value, float):
                value = Decimal(str(value))
            elif not isinstance(value, Decimal):
                value = Decimal(str(value))
            
            # Format to 2 decimal places
            formatted = f"{value:.2f}"
            
            # Add currency symbol (safely escaped)
            safe_symbol = html.escape(currency_symbol)
            return f"{safe_symbol}{formatted}"
            
        except (ValueError, TypeError, ArithmeticError):
            return html.escape(str(value))
    
    @app.template_filter('date_format')
    def date_format_filter(value, format_string='%Y-%m-%d'):
        """
        Filter to safely format dates.
        
        Usage in template: {{ date|date_format }}
        Usage with format: {{ date|date_format('%B %d, %Y') }}
        """
        if not value:
            return ''
        
        try:
            if isinstance(value, str):
                # Try to parse string as datetime
                try:
                    value = datetime.strptime(value, '%Y-%m-%d')
                except ValueError:
                    try:
                        value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        return html.escape(str(value))
            
            if isinstance(value, datetime):
                return value.strftime(format_string)
            else:
                return html.escape(str(value))
                
        except (ValueError, AttributeError):
            return html.escape(str(value))
    
    @app.template_filter('truncate_safe')
    def truncate_safe_filter(value, length=50, suffix='...'):
        """
        Filter to safely truncate text with HTML escaping.
        
        Usage in template: {{ long_text|truncate_safe(100) }}
        """
        if not value:
            return ''
        
        # Convert to string and escape HTML
        safe_value = html.escape(str(value))
        
        if len(safe_value) <= length:
            return safe_value
        
        # Truncate and add suffix
        truncated = safe_value[:length].rsplit(' ', 1)[0]  # Don't cut words
        safe_suffix = html.escape(suffix)
        
        return f"{truncated}{safe_suffix}"
    
    @app.template_filter('nl2br')
    def nl2br_filter(value):
        """
        Filter to convert newlines to <br> tags safely.
        
        Usage in template: {{ text_with_newlines|nl2br|safe }}
        """
        if not value:
            return ''
        
        # First escape HTML
        safe_value = html.escape(str(value))
        
        # Then convert newlines to <br> tags
        return Markup(safe_value.replace('\n', '<br>\n'))
    
    @app.template_filter('json_safe')
    def json_safe_filter(value):
        """
        Filter to safely convert values to JSON for use in JavaScript.
        
        Usage in template: <script>var config = {{ config|json_safe|safe }};</script>
        """
        try:
            return json.dumps(value, default=str, ensure_ascii=True)
        except (TypeError, ValueError):
            return 'null'
    
    @app.template_filter('strip_tags')
    def strip_tags_filter(value):
        """
        Filter to safely remove all HTML tags.
        
        Usage in template: {{ html_content|strip_tags }}
        """
        if not value:
            return ''
        
        import re
        # Remove HTML tags and decode HTML entities
        clean = re.sub(r'<[^>]+>', '', str(value))
        clean = html.unescape(clean)
        
        # Re-escape for safe output
        return html.escape(clean)
    
    @app.template_filter('slugify')
    def slugify_filter(value):
        """
        Filter to create URL-safe slugs from text.
        
        Usage in template: <a href="/category/{{ category.name|slugify }}">
        """
        if not value:
            return ''
        
        import re
        # Convert to string and lowercase
        slug = str(value).lower()
        
        # Replace spaces and special characters with hyphens
        slug = re.sub(r'[^\w\s-]', '', slug)
        slug = re.sub(r'[-\s]+', '-', slug)
        
        # Remove leading/trailing hyphens
        slug = slug.strip('-')
        
        return slug
    
    @app.template_filter('boolean_icon')
    def boolean_icon_filter(value, true_icon='bi-check-circle-fill text-success', 
                           false_icon='bi-x-circle-fill text-danger'):
        """
        Filter to display boolean values as Bootstrap icons.
        
        Usage in template: {{ is_active|boolean_icon|safe }}
        """
        if value:
            icon_class = html.escape(true_icon)
            return Markup(f'<i class="{icon_class}"></i>')
        else:
            icon_class = html.escape(false_icon)
            return Markup(f'<i class="{icon_class}"></i>')
    
    @app.template_filter('file_size')
    def file_size_filter(value):
        """
        Filter to format file sizes in human-readable format.
        
        Usage in template: {{ file.size|file_size }}
        """
        if not value:
            return '0 B'
        
        try:
            size = float(value)
        except (ValueError, TypeError):
            return html.escape(str(value))
        
        # Define size units
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        
        unit_index = 0
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        
        if unit_index == 0:
            return f"{int(size)} {units[unit_index]}"
        else:
            return f"{size:.1f} {units[unit_index]}"
    
    @app.template_filter('percentage')
    def percentage_filter(value, decimal_places=1):
        """
        Filter to format values as percentages.
        
        Usage in template: {{ ratio|percentage }}
        Usage with decimals: {{ ratio|percentage(2) }}
        """
        if value is None or value == '':
            return ''
        
        try:
            percentage = float(value) * 100
            return f"{percentage:.{decimal_places}f}%"
        except (ValueError, TypeError):
            return html.escape(str(value))
    
    @app.template_filter('default_if_empty')
    def default_if_empty_filter(value, default='N/A'):
        """
        Filter to provide default values for empty content.
        
        Usage in template: {{ description|default_if_empty('No description') }}
        """
        if not value or (isinstance(value, str) and not value.strip()):
            return html.escape(str(default))
        return html.escape(str(value))


def register_template_globals(app):
    """Register global template functions."""
    
    @app.template_global()
    def csrf_token():
        """Generate CSRF token for forms."""
        try:
            from flask_wtf.csrf import generate_csrf
            return generate_csrf()
        except ImportError:
            # Fallback if Flask-WTF is not available
            import secrets
            return secrets.token_hex(16)
    
    @app.template_global()
    def current_year():
        """Get current year for copyright notices."""
        return datetime.now().year
    
    @app.template_global()
    def encode_for_js(value):
        """Safely encode a value for JavaScript context."""
        return OutputEncoder.javascript_escape(value)
    
    @app.template_global()
    def safe_json(value):
        """Safely convert value to JSON string."""
        try:
            return json.dumps(value, default=str, ensure_ascii=True)
        except (TypeError, ValueError):
            return 'null'