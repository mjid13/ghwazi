"""
Enhanced database session management utilities to ensure proper session cleanup.
"""

import logging
import time
from contextlib import contextmanager
from typing import Any, Optional, Type, TypeVar, Union

from ..models.database import Database

logger = logging.getLogger(__name__)

T = TypeVar('T')


class DatabaseSessionManager:
    """Enhanced database session manager with automatic cleanup and monitoring."""
    
    def __init__(self):
        self.db = Database()
        self._active_sessions = set()
        self._session_stats = {
            'created': 0,
            'closed': 0,
            'leaked': 0,
            'total_duration': 0.0
        }
    
    @contextmanager
    def session_scope(self, auto_commit: bool = True, auto_rollback: bool = True):
        """
        Context manager for database sessions with automatic cleanup.
        
        Args:
            auto_commit: Automatically commit successful transactions
            auto_rollback: Automatically rollback on exceptions
            
        Yields:
            Database session
        """
        session = None
        session_id = None
        start_time = time.time()
        
        try:
            session = self.db.get_session()
            session_id = id(session)
            self._active_sessions.add(session_id)
            self._session_stats['created'] += 1
            
            logger.debug(f"Created DB session {session_id}")
            yield session
            
            # Auto-commit if no exceptions occurred
            if auto_commit and session.is_active:
                try:
                    session.commit()
                    logger.debug(f"Committed DB session {session_id}")
                except Exception as commit_error:
                    logger.error(f"Failed to commit session {session_id}: {commit_error}")
                    if auto_rollback:
                        session.rollback()
                    raise
                    
        except Exception as e:
            # Auto-rollback on exceptions
            if session and auto_rollback:
                try:
                    session.rollback()
                    logger.debug(f"Rolled back DB session {session_id} due to error: {e}")
                except Exception as rollback_error:
                    logger.error(f"Failed to rollback session {session_id}: {rollback_error}")
            raise
            
        finally:
            # Ensure session is always cleaned up
            if session and session_id:
                try:
                    self.db.close_session(session)
                    self._active_sessions.discard(session_id)
                    self._session_stats['closed'] += 1
                    
                    duration = time.time() - start_time
                    self._session_stats['total_duration'] += duration
                    
                    logger.debug(f"Closed DB session {session_id} (duration: {duration:.3f}s)")
                    
                except Exception as close_error:
                    logger.error(f"Failed to close session {session_id}: {close_error}")
                    self._session_stats['leaked'] += 1
    
    @contextmanager
    def transaction_scope(self):
        """
        Context manager for database transactions with automatic commit/rollback.
        
        Yields:
            Database session with transaction management
        """
        with self.session_scope(auto_commit=False, auto_rollback=True) as session:
            try:
                yield session
                session.commit()
                logger.debug("Transaction committed successfully")
            except Exception as e:
                session.rollback()
                logger.debug(f"Transaction rolled back due to error: {e}")
                raise
    
    def execute_with_session(self, func: callable, *args, **kwargs) -> Any:
        """
        Execute a function with a managed database session.
        
        Args:
            func: Function to execute (should accept session as first parameter)
            *args: Additional positional arguments for func
            **kwargs: Additional keyword arguments for func
            
        Returns:
            Result of func execution
        """
        with self.session_scope() as session:
            return func(session, *args, **kwargs)
    
    def execute_transaction(self, func: callable, *args, **kwargs) -> Any:
        """
        Execute a function within a managed transaction.
        
        Args:
            func: Function to execute (should accept session as first parameter)
            *args: Additional positional arguments for func
            **kwargs: Additional keyword arguments for func
            
        Returns:
            Result of func execution
        """
        with self.transaction_scope() as session:
            return func(session, *args, **kwargs)
    
    def get_session_stats(self) -> dict:
        """Get session management statistics."""
        stats = self._session_stats.copy()
        stats['active_sessions'] = len(self._active_sessions)
        stats['average_duration'] = (
            stats['total_duration'] / max(stats['closed'], 1)
        )
        return stats
    
    def force_cleanup_leaked_sessions(self) -> int:
        """
        Force cleanup of any leaked sessions (use with caution).
        
        Returns:
            Number of sessions cleaned up
        """
        cleaned_count = 0
        leaked_sessions = self._active_sessions.copy()
        
        for session_id in leaked_sessions:
            try:
                logger.warning(f"Force cleaning leaked session {session_id}")
                # We can't actually close the session without the session object
                # This is mainly for tracking purposes
                self._active_sessions.discard(session_id)
                self._session_stats['leaked'] += 1
                cleaned_count += 1
            except Exception as e:
                logger.error(f"Failed to force clean session {session_id}: {e}")
        
        if cleaned_count > 0:
            logger.warning(f"Force cleaned {cleaned_count} leaked sessions")
        
        return cleaned_count
    
    def reset_stats(self):
        """Reset session statistics."""
        self._session_stats = {
            'created': 0,
            'closed': 0,
            'leaked': 0,
            'total_duration': 0.0
        }
        logger.info("Database session stats reset")


# Global session manager instance
_session_manager: Optional[DatabaseSessionManager] = None


def get_session_manager() -> DatabaseSessionManager:
    """Get or create global session manager instance."""
    global _session_manager
    
    if _session_manager is None:
        _session_manager = DatabaseSessionManager()
        logger.info("Database session manager initialized")
    
    return _session_manager


# Convenience decorators and functions
def with_database_session(auto_commit: bool = True, auto_rollback: bool = True):
    """
    Decorator to automatically provide a database session to a function.
    
    Args:
        auto_commit: Automatically commit successful transactions
        auto_rollback: Automatically rollback on exceptions
    
    Usage:
        @with_database_session()
        def my_function(session, other_args):
            # Use session here
            return result
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            manager = get_session_manager()
            with manager.session_scope(auto_commit=auto_commit, auto_rollback=auto_rollback) as session:
                return func(session, *args, **kwargs)
        return wrapper
    return decorator


def with_database_transaction():
    """
    Decorator to automatically provide a database session within a transaction.
    
    Usage:
        @with_database_transaction()
        def my_function(session, other_args):
            # Use session here - will be committed or rolled back automatically
            return result
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            manager = get_session_manager()
            with manager.transaction_scope() as session:
                return func(session, *args, **kwargs)
        return wrapper
    return decorator


@contextmanager
def database_session(auto_commit: bool = True, auto_rollback: bool = True):
    """
    Context manager for database sessions (convenience function).
    
    Args:
        auto_commit: Automatically commit successful transactions
        auto_rollback: Automatically rollback on exceptions
    
    Usage:
        with database_session() as session:
            # Use session here
            result = session.query(...).all()
    """
    manager = get_session_manager()
    with manager.session_scope(auto_commit=auto_commit, auto_rollback=auto_rollback) as session:
        yield session


@contextmanager
def database_transaction():
    """
    Context manager for database transactions (convenience function).
    
    Usage:
        with database_transaction() as session:
            # Use session here - will be committed or rolled back automatically
            session.add(new_object)
    """
    manager = get_session_manager()
    with manager.transaction_scope() as session:
        yield session


def execute_with_db_session(func: callable, *args, **kwargs) -> Any:
    """
    Execute a function with a managed database session (convenience function).
    
    Args:
        func: Function to execute (should accept session as first parameter)
        *args: Additional positional arguments for func
        **kwargs: Additional keyword arguments for func
    
    Returns:
        Result of func execution
    
    Usage:
        def my_db_operation(session, user_id):
            return session.query(User).filter(User.id == user_id).first()
        
        user = execute_with_db_session(my_db_operation, 123)
    """
    manager = get_session_manager()
    return manager.execute_with_session(func, *args, **kwargs)


def execute_db_transaction(func: callable, *args, **kwargs) -> Any:
    """
    Execute a function within a managed database transaction (convenience function).
    
    Args:
        func: Function to execute (should accept session as first parameter)
        *args: Additional positional arguments for func
        **kwargs: Additional keyword arguments for func
    
    Returns:
        Result of func execution
    
    Usage:
        def create_user(session, user_data):
            user = User(**user_data)
            session.add(user)
            return user
        
        new_user = execute_db_transaction(create_user, {'name': 'John'})
    """
    manager = get_session_manager()
    return manager.execute_transaction(func, *args, **kwargs)