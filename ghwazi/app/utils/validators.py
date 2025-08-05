"""
Validation functions for the application.
"""

import re
from email.utils import parseaddr


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
