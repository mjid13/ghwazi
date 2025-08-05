"""
Admin views for the Flask application.
"""

import logging

from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)

from app.models import Category, CategoryMapping, EmailConfiguration
from app.models.database import Database
from app.models.transaction import TransactionRepository
from app.models.user import User
from app.utils.decorators import login_required

# Create blueprint
admin_bp = Blueprint("admin", __name__)

# Initialize database and logger
db = Database()
logger = logging.getLogger(__name__)
