"""
Admin views for the Flask application.
"""

import logging

from flask import Blueprint

from ..models.database import Database

# Create blueprint
admin_bp = Blueprint("admin", __name__)

# Initialize database and logger
db = Database()
logger = logging.getLogger(__name__)
