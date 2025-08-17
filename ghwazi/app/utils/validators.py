"""
Comprehensive validation and sanitization functions for the application.
Provides input validation and output encoding to prevent security vulnerabilities.
"""

import re
import html
import json
import urllib.parse
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any, Dict, List, Optional, Tuple, Union
import bleach
from markupsafe import Markup, escape


def validate_email(email):
    """Validate email address format."""
    if not email:
        return False

    # Basic email validation
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(email_pattern, email) is not None


def validate_password(password):
    """Validate password strength."""
    if not password:
        return False, "Password is required"

    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"

    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"

    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit"

    return True, "Password is valid"


def validate_account_number(account_number):
    """Validate account number format."""
    if not account_number:
        return False, "Account number is required"

    # Remove spaces and hyphens
    clean_number = re.sub(r"[\s-]", "", account_number)

    # Check if it contains only digits and is of reasonable length
    if not clean_number.isdigit():
        return False, "Account number must contain only digits"

    if len(clean_number) < 8 or len(clean_number) > 20:
        return False, "Account number must be between 8 and 20 digits"

    return True, "Account number is valid"


def validate_amount(amount):
    """Validate monetary amount."""
    try:
        amount_float = float(amount)
        if amount_float < 0:
            return False, "Amount cannot be negative"
        return True, "Amount is valid"
    except (ValueError, TypeError):
        return False, "Amount must be a valid number"


def validate_required_field(value, field_name):
    """Validate that a required field is not empty."""
    if not value or (isinstance(value, str) and not value.strip()):
        return False, f"{field_name} is required"
    return True, f"{field_name} is valid"


def validate_phone_number(phone):
    """Validate phone number format."""
    if not phone:
        return True, "Phone number is optional"  # Phone is optional

    # Remove all non-digit characters
    clean_phone = re.sub(r"\D", "", phone)

    # Check if it's a valid length (10-15 digits)
    if len(clean_phone) < 10 or len(clean_phone) > 15:
        return False, "Phone number must be between 10 and 15 digits"

    return True, "Phone number is valid"


# =============================================================================
# ENHANCED INPUT VALIDATION
# =============================================================================

class ValidationError(Exception):
    """Custom exception for validation errors."""
    def __init__(self, message: str, field: str = None, code: str = None):
        self.message = message
        self.field = field
        self.code = code
        super().__init__(message)


class InputValidator:
    """Comprehensive input validator with sanitization capabilities."""
    
    # Common regex patterns
    PATTERNS = {
        'username': r'^[a-zA-Z0-9_.-]{3,30}$',
        'slug': r'^[a-z0-9-]+$',
        'hex_color': r'^#[0-9A-Fa-f]{6}$',
        'uuid': r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$',
        'ip_address': r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$',
        'alpha_numeric': r'^[a-zA-Z0-9]+$',
        'alpha_space': r'^[a-zA-Z\s]+$',
        'numeric': r'^[0-9]+$',
    }
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 1000, allow_html: bool = False) -> str:
        """
        Sanitize string input to prevent XSS and other attacks.
        
        Args:
            value: Input string to sanitize
            max_length: Maximum allowed length
            allow_html: Whether to allow safe HTML tags
            
        Returns:
            Sanitized string
        """
        if not isinstance(value, str):
            return str(value)
        
        # Trim whitespace
        value = value.strip()
        
        # Truncate to max length
        if len(value) > max_length:
            value = value[:max_length]
        
        if allow_html:
            # Allow only safe HTML tags
            allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li']
            allowed_attributes = {}
            value = bleach.clean(value, tags=allowed_tags, attributes=allowed_attributes, strip=True)
        else:
            # Escape all HTML
            value = html.escape(value)
        
        return value
    
    @staticmethod
    def validate_string(value: str, field_name: str, min_length: int = 0, 
                       max_length: int = 1000, pattern: str = None, 
                       required: bool = True, allow_empty: bool = False) -> Tuple[bool, str]:
        """
        Comprehensive string validation.
        
        Args:
            value: String to validate
            field_name: Name of the field for error messages
            min_length: Minimum required length
            max_length: Maximum allowed length
            pattern: Regex pattern to match (optional)
            required: Whether the field is required
            allow_empty: Whether to allow empty strings when not required
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not value:
            if required:
                return False, f"{field_name} is required"
            elif not allow_empty:
                return False, f"{field_name} cannot be empty"
            else:
                return True, "Valid"
        
        if not isinstance(value, str):
            return False, f"{field_name} must be a string"
        
        # Check length constraints
        if len(value) < min_length:
            return False, f"{field_name} must be at least {min_length} characters long"
        
        if len(value) > max_length:
            return False, f"{field_name} must be no more than {max_length} characters long"
        
        # Check pattern if provided
        if pattern:
            if pattern in InputValidator.PATTERNS:
                pattern = InputValidator.PATTERNS[pattern]
            
            if not re.match(pattern, value):
                return False, f"{field_name} format is invalid"
        
        return True, "Valid"
    
    @staticmethod
    def validate_integer(value: Union[int, str], field_name: str, min_value: int = None,
                        max_value: int = None, required: bool = True) -> Tuple[bool, str, Optional[int]]:
        """
        Validate integer input.
        
        Returns:
            Tuple of (is_valid, error_message, converted_value)
        """
        if not value and value != 0:
            if required:
                return False, f"{field_name} is required", None
            else:
                return True, "Valid", None
        
        try:
            int_value = int(value)
        except (ValueError, TypeError):
            return False, f"{field_name} must be a valid integer", None
        
        if min_value is not None and int_value < min_value:
            return False, f"{field_name} must be at least {min_value}", None
        
        if max_value is not None and int_value > max_value:
            return False, f"{field_name} must be no more than {max_value}", None
        
        return True, "Valid", int_value
    
    @staticmethod
    def validate_decimal(value: Union[float, str, Decimal], field_name: str, 
                        min_value: Decimal = None, max_value: Decimal = None,
                        decimal_places: int = 2, required: bool = True) -> Tuple[bool, str, Optional[Decimal]]:
        """
        Validate decimal/monetary values.
        
        Returns:
            Tuple of (is_valid, error_message, converted_value)
        """
        if not value and value != 0:
            if required:
                return False, f"{field_name} is required", None
            else:
                return True, "Valid", None
        
        try:
            decimal_value = Decimal(str(value))
        except (InvalidOperation, ValueError, TypeError):
            return False, f"{field_name} must be a valid number", None
        
        # Check decimal places
        if decimal_value.as_tuple().exponent < -decimal_places:
            return False, f"{field_name} can have at most {decimal_places} decimal places", None
        
        if min_value is not None and decimal_value < min_value:
            return False, f"{field_name} must be at least {min_value}", None
        
        if max_value is not None and decimal_value > max_value:
            return False, f"{field_name} must be no more than {max_value}", None
        
        return True, "Valid", decimal_value
    
    @staticmethod
    def validate_email_enhanced(email: str, required: bool = True) -> Tuple[bool, str, Optional[str]]:
        """
        Enhanced email validation with normalization.
        
        Returns:
            Tuple of (is_valid, error_message, normalized_email)
        """
        if not email:
            if required:
                return False, "Email address is required", None
            else:
                return True, "Valid", None
        
        if not isinstance(email, str):
            return False, "Email must be a string", None
        
        # Normalize email
        email = email.strip().lower()
        
        # Check length
        if len(email) > 254:  # RFC 5321 limit
            return False, "Email address is too long", None
        
        # Enhanced email validation
        email_pattern = r'^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        
        if not re.match(email_pattern, email):
            return False, "Email address format is invalid", None
        
        # Check for common invalid patterns
        if '..' in email or email.startswith('.') or email.endswith('.'):
            return False, "Email address format is invalid", None
        
        return True, "Valid", email
    
    @staticmethod
    def validate_date(date_str: str, field_name: str, date_format: str = "%Y-%m-%d",
                     min_date: datetime = None, max_date: datetime = None,
                     required: bool = True) -> Tuple[bool, str, Optional[datetime]]:
        """
        Validate date string and convert to datetime object.
        
        Returns:
            Tuple of (is_valid, error_message, datetime_object)
        """
        if not date_str:
            if required:
                return False, f"{field_name} is required", None
            else:
                return True, "Valid", None
        
        try:
            date_obj = datetime.strptime(date_str, date_format)
        except ValueError:
            return False, f"{field_name} must be in format {date_format}", None
        
        if min_date and date_obj < min_date:
            return False, f"{field_name} must be after {min_date.strftime(date_format)}", None
        
        if max_date and date_obj > max_date:
            return False, f"{field_name} must be before {max_date.strftime(date_format)}", None
        
        return True, "Valid", date_obj
    
    @staticmethod
    def validate_choice(value: str, field_name: str, choices: List[str],
                       required: bool = True, case_sensitive: bool = True) -> Tuple[bool, str, Optional[str]]:
        """
        Validate that a value is one of the allowed choices.
        
        Returns:
            Tuple of (is_valid, error_message, normalized_value)
        """
        if not value:
            if required:
                return False, f"{field_name} is required", None
            else:
                return True, "Valid", None
        
        if not case_sensitive:
            value = value.lower()
            choices = [choice.lower() for choice in choices]
        
        if value not in choices:
            return False, f"{field_name} must be one of: {', '.join(choices)}", None
        
        return True, "Valid", value


# =============================================================================
# OUTPUT ENCODING AND SANITIZATION
# =============================================================================

class OutputEncoder:
    """Handles safe output encoding to prevent XSS attacks."""
    
    @staticmethod
    def html_escape(value: Any) -> str:
        """
        Safely encode output for HTML context.
        
        Args:
            value: Value to encode
            
        Returns:
            HTML-escaped string safe for output
        """
        if value is None:
            return ""
        
        return html.escape(str(value), quote=True)
    
    @staticmethod
    def html_attribute(value: Any) -> str:
        """
        Safely encode output for HTML attribute context.
        
        Args:
            value: Value to encode
            
        Returns:
            Attribute-safe string
        """
        if value is None:
            return ""
        
        # HTML escape and also escape additional characters for attribute context
        escaped = html.escape(str(value), quote=True)
        
        # Additional escaping for attribute context
        escaped = escaped.replace("'", "&#x27;")
        escaped = escaped.replace("/", "&#x2F;")
        
        return escaped
    
    @staticmethod
    def javascript_escape(value: Any) -> str:
        """
        Safely encode output for JavaScript context.
        
        Args:
            value: Value to encode
            
        Returns:
            JavaScript-safe string
        """
        if value is None:
            return "null"
        
        # Convert to JSON string which handles JavaScript escaping
        return json.dumps(str(value))
    
    @staticmethod
    def url_encode(value: Any) -> str:
        """
        Safely encode output for URL context.
        
        Args:
            value: Value to encode
            
        Returns:
            URL-encoded string
        """
        if value is None:
            return ""
        
        return urllib.parse.quote(str(value), safe='')
    
    @staticmethod
    def css_escape(value: Any) -> str:
        """
        Safely encode output for CSS context.
        
        Args:
            value: Value to encode
            
        Returns:
            CSS-safe string
        """
        if value is None:
            return ""
        
        # Basic CSS escaping - escape special characters
        css_safe = str(value)
        css_safe = re.sub(r'[<>"\'&\\]', lambda m: f'\\{ord(m.group(0)):06x} ', css_safe)
        
        return css_safe
    
    @staticmethod
    def safe_html(value: str, allowed_tags: List[str] = None) -> Markup:
        """
        Clean HTML input to allow only safe tags.
        
        Args:
            value: HTML string to clean
            allowed_tags: List of allowed HTML tags
            
        Returns:
            Markup object with safe HTML
        """
        if not value:
            return Markup("")
        
        if allowed_tags is None:
            allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li', 'a']
        
        allowed_attributes = {
            'a': ['href', 'title'],
        }
        
        cleaned = bleach.clean(
            value, 
            tags=allowed_tags, 
            attributes=allowed_attributes,
            protocols=['http', 'https', 'mailto'],
            strip=True
        )
        
        return Markup(cleaned)


# =============================================================================
# VALIDATION SCHEMAS
# =============================================================================

class ValidationSchema:
    """Base class for validation schemas."""
    
    def __init__(self):
        self.errors = {}
        self.cleaned_data = {}
    
    def validate(self, data: Dict[str, Any]) -> Tuple[bool, Dict[str, List[str]], Dict[str, Any]]:
        """
        Validate data against the schema.
        
        Args:
            data: Dictionary of data to validate
            
        Returns:
            Tuple of (is_valid, errors_dict, cleaned_data)
        """
        self.errors = {}
        self.cleaned_data = {}
        
        for field_name, field_config in self.get_fields().items():
            value = data.get(field_name)
            
            try:
                cleaned_value = self.validate_field(field_name, value, field_config)
                self.cleaned_data[field_name] = cleaned_value
            except ValidationError as e:
                if field_name not in self.errors:
                    self.errors[field_name] = []
                self.errors[field_name].append(e.message)
        
        return len(self.errors) == 0, self.errors, self.cleaned_data
    
    def validate_field(self, field_name: str, value: Any, field_config: Dict[str, Any]) -> Any:
        """Validate a single field based on its configuration."""
        field_type = field_config.get('type', 'string')
        required = field_config.get('required', True)
        
        if field_type == 'string':
            is_valid, error, cleaned_value = self._validate_string_field(
                value, field_name, field_config
            )
        elif field_type == 'integer':
            is_valid, error, cleaned_value = self._validate_integer_field(
                value, field_name, field_config
            )
        elif field_type == 'decimal':
            is_valid, error, cleaned_value = self._validate_decimal_field(
                value, field_name, field_config
            )
        elif field_type == 'email':
            is_valid, error, cleaned_value = InputValidator.validate_email_enhanced(
                value, required
            )
        elif field_type == 'date':
            is_valid, error, cleaned_value = self._validate_date_field(
                value, field_name, field_config
            )
        elif field_type == 'choice':
            is_valid, error, cleaned_value = self._validate_choice_field(
                value, field_name, field_config
            )
        else:
            raise ValidationError(f"Unknown field type: {field_type}", field_name)
        
        if not is_valid:
            raise ValidationError(error, field_name)
        
        return cleaned_value
    
    def _validate_string_field(self, value: Any, field_name: str, config: Dict[str, Any]) -> Tuple[bool, str, Any]:
        """Validate string field with configuration."""
        return InputValidator.validate_string(
            value, field_name,
            min_length=config.get('min_length', 0),
            max_length=config.get('max_length', 1000),
            pattern=config.get('pattern'),
            required=config.get('required', True),
            allow_empty=config.get('allow_empty', False)
        )
    
    def _validate_integer_field(self, value: Any, field_name: str, config: Dict[str, Any]) -> Tuple[bool, str, Any]:
        """Validate integer field with configuration."""
        return InputValidator.validate_integer(
            value, field_name,
            min_value=config.get('min_value'),
            max_value=config.get('max_value'),
            required=config.get('required', True)
        )
    
    def _validate_decimal_field(self, value: Any, field_name: str, config: Dict[str, Any]) -> Tuple[bool, str, Any]:
        """Validate decimal field with configuration."""
        return InputValidator.validate_decimal(
            value, field_name,
            min_value=config.get('min_value'),
            max_value=config.get('max_value'),
            decimal_places=config.get('decimal_places', 2),
            required=config.get('required', True)
        )
    
    def _validate_date_field(self, value: Any, field_name: str, config: Dict[str, Any]) -> Tuple[bool, str, Any]:
        """Validate date field with configuration."""
        return InputValidator.validate_date(
            value, field_name,
            date_format=config.get('format', '%Y-%m-%d'),
            min_date=config.get('min_date'),
            max_date=config.get('max_date'),
            required=config.get('required', True)
        )
    
    def _validate_choice_field(self, value: Any, field_name: str, config: Dict[str, Any]) -> Tuple[bool, str, Any]:
        """Validate choice field with configuration."""
        return InputValidator.validate_choice(
            value, field_name,
            choices=config.get('choices', []),
            required=config.get('required', True),
            case_sensitive=config.get('case_sensitive', True)
        )
    
    def get_fields(self) -> Dict[str, Dict[str, Any]]:
        """Override this method to define field configurations."""
        return {}
