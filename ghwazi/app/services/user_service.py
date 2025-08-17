"""
User service providing user-related operations.
"""

from typing import Optional

from ..models.database import Database
from ..models.user import User


class UserService:
    """Service for user-related database operations."""

    def __init__(self):
        self.db = Database()

    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Fetch a user by primary key ID."""
        session = self.db.get_session()
        try:
            return session.query(User).filter(User.id == user_id).first()
        finally:
            self.db.close_session(session)
