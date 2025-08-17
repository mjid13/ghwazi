"""
Enhanced session management service for secure session handling.
"""

import hashlib
import logging
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from flask import current_app, request, session

from ..models.database import Database
from ..models.user import User
from .session_lifecycle import SessionLifecycleManager, SessionEvent

logger = logging.getLogger(__name__)


class SessionService:
    """Enhanced session management with security features."""
    
    # In-memory store for active sessions (in production, use Redis)
    _active_sessions: Dict[str, Dict] = {}
    _user_sessions: Dict[int, List[str]] = {}
    _last_cleanup = time.time()
    
    @classmethod
    def create_session(cls, user_id: int, user_agent: str = None, ip_address: str = None) -> str:
        """Create a new secure session for a user."""
        try:
            # Generate secure session ID
            session_id = cls._generate_session_id()
            
            # Get user info
            db = Database()
            db_session = db.get_session()
            try:
                user = db_session.query(User).filter(User.id == user_id).first()
                if not user:
                    raise ValueError(f"User {user_id} not found")
                
                # Check concurrent session limit
                cls._enforce_session_limit(user_id)
                
                # Create session data
                session_data = {
                    'session_id': session_id,
                    'user_id': user_id,
                    'username': user.username,
                    'created_at': time.time(),
                    'last_activity': time.time(),
                    'last_rotation': time.time(),
                    'user_agent': user_agent or request.headers.get('User-Agent', ''),
                    'ip_address': ip_address or request.remote_addr,
                    'is_active': True,
                    'login_attempts': 0,
                    'security_flags': {
                        'ip_changed': False,
                        'user_agent_changed': False,
                        'suspicious_activity': False
                    }
                }
                
                # Initialize lifecycle management
                lifecycle_data = SessionLifecycleManager.create_session_lifecycle(session_data)
                
                # Store session
                cls._active_sessions[session_id] = lifecycle_data
                
                # Track user sessions
                if user_id not in cls._user_sessions:
                    cls._user_sessions[user_id] = []
                cls._user_sessions[user_id].append(session_id)
                
                logger.info(f"Session created for user {user_id}: {session_id[:8]}...")
                return session_id
                
            finally:
                db.close_session(db_session)
                
        except Exception as e:
            logger.error(f"Failed to create session for user {user_id}: {e}")
            raise
    
    @classmethod
    def validate_session(cls, session_id: str) -> Tuple[bool, Optional[Dict]]:
        """Validate session using comprehensive lifecycle management."""
        if not session_id or session_id not in cls._active_sessions:
            return False, None
        
        session_data = cls._active_sessions[session_id]
        
        # Use lifecycle manager for comprehensive validation
        is_valid, updated_data, warnings = SessionLifecycleManager.validate_session_lifecycle(
            session_id, session_data
        )
        
        if not is_valid:
            cls._invalidate_session(session_id)
            return False, None
        
        # Update session data with lifecycle information
        cls._active_sessions[session_id] = updated_data
        
        # Log warnings if any
        if warnings:
            logger.warning(f"Session {session_id[:8]}... validation warnings: {', '.join(warnings)}")
        
        # Check if rotation is needed
        current_time = time.time()
        rotation_interval = current_app.config.get('SESSION_ROTATION_INTERVAL', 900)
        if (current_time - updated_data.get('last_rotation', current_time)) > rotation_interval:
            new_session_id = cls._rotate_session(session_id)
            if new_session_id:
                updated_data = cls._active_sessions[new_session_id]
        
        return True, updated_data
    
    @classmethod
    def update_session_activity(cls, session_id: str) -> bool:
        """Update session last activity timestamp."""
        if session_id in cls._active_sessions:
            cls._active_sessions[session_id]['last_activity'] = time.time()
            return True
        return False
    
    @classmethod
    def invalidate_session(cls, session_id: str, reason: str = "Manual invalidation") -> bool:
        """Invalidate a specific session."""
        return cls._invalidate_session(session_id, reason)
    
    @classmethod
    def invalidate_user_sessions(cls, user_id: int, except_session: str = None) -> int:
        """Invalidate all sessions for a user except the specified one."""
        count = 0
        if user_id in cls._user_sessions:
            sessions_to_invalidate = cls._user_sessions[user_id].copy()
            for session_id in sessions_to_invalidate:
                if session_id != except_session:
                    if cls._invalidate_session(session_id):
                        count += 1
        
        logger.info(f"Invalidated {count} sessions for user {user_id}")
        return count
    
    @classmethod
    def get_user_sessions(cls, user_id: int) -> List[Dict]:
        """Get all active sessions for a user."""
        sessions = []
        if user_id in cls._user_sessions:
            for session_id in cls._user_sessions[user_id]:
                if session_id in cls._active_sessions:
                    session_data = cls._active_sessions[session_id].copy()
                    # Remove sensitive data
                    session_data.pop('session_id', None)
                    sessions.append(session_data)
        return sessions
    
    @classmethod
    def cleanup_expired_sessions(cls) -> int:
        """Clean up expired sessions."""
        current_time = time.time()
        cleanup_interval = current_app.config.get('SESSION_CLEANUP_INTERVAL', 3600)
        
        # Only run cleanup periodically
        if (current_time - cls._last_cleanup) < cleanup_interval:
            return 0
        
        cls._last_cleanup = current_time
        expired_sessions = []
        
        for session_id, session_data in cls._active_sessions.items():
            max_lifetime_config = current_app.config.get('PERMANENT_SESSION_LIFETIME', 3600)
            # Handle both timedelta objects and integer seconds
            if hasattr(max_lifetime_config, 'total_seconds'):
                max_lifetime = max_lifetime_config.total_seconds()
            else:
                max_lifetime = max_lifetime_config
            
            idle_timeout = current_app.config.get('SESSION_IDLE_TIMEOUT', 1800)
            
            # Check if session is expired
            if not session_data.get('is_active', False) or \
               (current_time - session_data['created_at']) > max_lifetime or \
               (current_time - session_data['last_activity']) > idle_timeout:
                expired_sessions.append(session_id)
        
        # Clean up expired sessions
        count = 0
        for session_id in expired_sessions:
            if cls._invalidate_session(session_id):
                count += 1
        
        if count > 0:
            logger.info(f"Cleaned up {count} expired sessions")
        
        return count
    
    @classmethod
    def get_session_stats(cls) -> Dict:
        """Get session statistics."""
        current_time = time.time()
        active_count = sum(1 for s in cls._active_sessions.values() if s.get('is_active', False))
        
        return {
            'total_sessions': len(cls._active_sessions),
            'active_sessions': active_count,
            'unique_users': len(cls._user_sessions),
            'last_cleanup': cls._last_cleanup,
            'next_cleanup': cls._last_cleanup + current_app.config.get('SESSION_CLEANUP_INTERVAL', 3600)
        }
    
    @classmethod
    def _generate_session_id(cls) -> str:
        """Generate a cryptographically secure session ID."""
        random_data = secrets.token_bytes(32)
        timestamp = str(time.time()).encode()
        combined = random_data + timestamp
        return hashlib.sha256(combined).hexdigest()
    
    @classmethod
    def _enforce_session_limit(cls, user_id: int) -> None:
        """Enforce maximum concurrent sessions per user."""
        max_sessions = current_app.config.get('MAX_SESSIONS_PER_USER', 3)
        
        if user_id in cls._user_sessions:
            active_sessions = [
                sid for sid in cls._user_sessions[user_id]
                if sid in cls._active_sessions and cls._active_sessions[sid].get('is_active', False)
            ]
            
            # Remove oldest sessions if limit exceeded
            if len(active_sessions) >= max_sessions:
                sessions_to_remove = len(active_sessions) - max_sessions + 1
                oldest_sessions = sorted(
                    active_sessions,
                    key=lambda sid: cls._active_sessions[sid]['created_at']
                )[:sessions_to_remove]
                
                for session_id in oldest_sessions:
                    cls._invalidate_session(session_id)
                    logger.info(f"Invalidated old session {session_id[:8]}... due to session limit")
    
    @classmethod
    def _check_security_violations(cls, session_id: str, session_data: Dict) -> bool:
        """Check for potential security violations."""
        current_ip = request.remote_addr
        current_ua = request.headers.get('User-Agent', '')
        
        # Check IP address change
        if session_data['ip_address'] != current_ip:
            session_data['security_flags']['ip_changed'] = True
            logger.warning(f"IP address changed for session {session_id[:8]}...")
            # In production, you might want to invalidate or require re-authentication
        
        # Check User-Agent change (might indicate session hijacking)
        if session_data['user_agent'] != current_ua:
            session_data['security_flags']['user_agent_changed'] = True
            logger.warning(f"User-Agent changed for session {session_id[:8]}...")
        
        # For now, log violations but don't invalidate
        # In production, you might want stricter policies
        return False
    
    @classmethod
    def _rotate_session(cls, old_session_id: str) -> Optional[str]:
        """Rotate session ID for security."""
        if old_session_id not in cls._active_sessions:
            return None
        
        try:
            old_data = cls._active_sessions[old_session_id]
            new_session_id = cls._generate_session_id()
            
            # Copy data to new session
            new_data = old_data.copy()
            new_data['session_id'] = new_session_id
            new_data['last_rotation'] = time.time()
            
            # Store new session
            cls._active_sessions[new_session_id] = new_data
            
            # Update user session tracking
            user_id = old_data['user_id']
            if user_id in cls._user_sessions:
                try:
                    cls._user_sessions[user_id].remove(old_session_id)
                    cls._user_sessions[user_id].append(new_session_id)
                except ValueError:
                    pass
            
            # Use lifecycle manager for rotation
            SessionLifecycleManager.rotate_session_lifecycle(
                old_session_id, new_session_id, new_data
            )
            
            # Remove old session from active store
            del cls._active_sessions[old_session_id]
            
            logger.debug(f"Session rotated: {old_session_id[:8]}... -> {new_session_id[:8]}...")
            return new_session_id
            
        except Exception as e:
            logger.error(f"Failed to rotate session {old_session_id[:8]}...: {e}")
            return None
    
    @classmethod
    def _invalidate_session(cls, session_id: str, reason: str = "Invalidated") -> bool:
        """Internal method to invalidate a session with lifecycle management."""
        if session_id not in cls._active_sessions:
            return False
        
        try:
            session_data = cls._active_sessions[session_id]
            user_id = session_data.get('user_id')
            
            # Use lifecycle manager for cleanup
            SessionLifecycleManager.cleanup_session_lifecycle(session_id, reason)
            
            # Mark as inactive
            session_data['is_active'] = False
            
            # Remove from user session tracking
            if user_id and user_id in cls._user_sessions:
                try:
                    cls._user_sessions[user_id].remove(session_id)
                    if not cls._user_sessions[user_id]:
                        del cls._user_sessions[user_id]
                except ValueError:
                    pass
            
            # Remove session data
            del cls._active_sessions[session_id]
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to invalidate session {session_id[:8]}...: {e}")
            return False
    
    @classmethod
    def get_active_session_count(cls) -> int:
        """Get the number of currently active sessions."""
        try:
            active_count = sum(1 for session_data in cls._active_sessions.values() 
                             if session_data.get('is_active', True))
            return active_count
        except Exception as e:
            logger.error(f"Failed to get active session count: {e}")
            return 0
    
    @classmethod
    def get_total_session_count(cls) -> int:
        """Get the total number of sessions (active and inactive)."""
        try:
            return len(cls._active_sessions)
        except Exception as e:
            logger.error(f"Failed to get total session count: {e}")
            return 0