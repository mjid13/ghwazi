"""
Helper functions for the application.
"""

import os
import random
import string

from werkzeug.utils import secure_filename


def allowed_file(filename, allowed_extensions=None):
    """Check if a file has an allowed extension."""
    if allowed_extensions is None:
        allowed_extensions = {"pdf"}
    return "." in filename and filename.rsplit(".", 1)[1].lower() in allowed_extensions


def generate_random_string(length=10):
    """Generate a random string of specified length."""
    letters = string.ascii_lowercase
    return "".join(random.choice(letters) for i in range(length))


def safe_filename(filename):
    """Make a filename safe for storage."""
    return secure_filename(filename)


def format_currency(amount):
    """Format amount as currency."""
    if amount is None:
        return "0.00"
    return f"{amount:,.2f}"


def truncate_string(text, max_length=50):
    """Truncate string to specified length."""
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."
