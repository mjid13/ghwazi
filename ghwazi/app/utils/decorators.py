"""
Decorators for the Flask application.
"""

from functools import wraps
from flask import session, redirect, url_for, flash


def login_required(f):
    """Decorator to require login for a route."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to access this page", "error")
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)

    return decorated_function
