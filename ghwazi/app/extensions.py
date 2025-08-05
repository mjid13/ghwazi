"""
Flask extensions initialization.
"""

from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
