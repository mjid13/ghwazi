"""
Comprehensive session lifecycle management with events, hooks, and persistence.
"""

import json
import logging
import time
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Callable, Any

from flask import current_app, g, request

from .session_persistence import get_persistence_manager

logger = logging.getLogger(__name__)


class SessionEvent(Enum):
    """Session lifecycle events."""
    CREATED = "session_created"
    VALIDATED = "session_validated"
    ROTATED = "session_rotated"
    EXPIRED = "session_expired"
    INVALIDATED = "session_invalidated"
    SECURITY_VIOLATION = "session_security_violation"
    CLEANUP = "session_cleanup"
    EXTENDED = "session_extended"
    SUSPENDED = "session_suspended"
    RESUMED = "session_resumed"


class SessionState(Enum):
    """Session states in the lifecycle."""
    ACTIVE = "active"
    EXPIRED = "expired"
    INVALIDATED = "invalidated"
    SUSPENDED = "suspended"
    ROTATED = "rotated"
    CLEANED = "cleaned"


class SessionLifecycleManager:
    """Manages complete session lifecycle with events and persistence."""
    
    # Event hooks registry
    _event_hooks: Dict[SessionEvent, List[Callable]] = {event: [] for event in SessionEvent}
    
    # Session persistence store (in production, use Redis/Database)
    _persistent_sessions: Dict[str, Dict] = {}
    _session_history: Dict[str, List[Dict]] = {}
    
    @classmethod
    def register_hook(cls, event: SessionEvent, callback: Callable) -> None:
        """Register a callback for a session event."""
        if event not in cls._event_hooks:
            cls._event_hooks[event] = []
        cls._event_hooks[event].append(callback)
        logger.debug(f"Registered hook for {event.value}: {callback.__name__}")
    
    @classmethod
    def unregister_hook(cls, event: SessionEvent, callback: Callable) -> bool:
        """Unregister a callback for a session event."""
        if event in cls._event_hooks and callback in cls._event_hooks[event]:
            cls._event_hooks[event].remove(callback)
            logger.debug(f"Unregistered hook for {event.value}: {callback.__name__}")
            return True
        return False
    
    @classmethod
    def emit_event(cls, event: SessionEvent, session_data: Dict, **kwargs) -> None:
        """Emit a session lifecycle event to registered hooks."""
        try:
            # Create event context
            event_context = {
                'event': event.value,
                'session_id': session_data.get('session_id'),
                'user_id': session_data.get('user_id'),
                'timestamp': time.time(),
                'request_info': {
                    'ip': getattr(request, 'remote_addr', None) if request else None,
                    'user_agent': getattr(request, 'headers', {}).get('User-Agent') if request else None,
                    'path': getattr(request, 'path', None) if request else None
                },
                **kwargs
            }
            
            # Log the event
            cls._log_event(event_context)
            
            # Store in session history
            cls._store_event_history(session_data.get('session_id'), event_context)
            
            # Persist event to storage
            try:
                persistence_manager = get_persistence_manager()
                persistence_manager.store_event(
                    session_data.get('session_id'), 
                    event.value, 
                    event_context
                )
            except Exception as e:
                logger.error(f"Failed to persist event {event.value}: {e}")
            
            # Execute hooks
            for hook in cls._event_hooks.get(event, []):
                try:
                    hook(event_context, session_data)
                except Exception as e:
                    logger.error(f"Error executing hook {hook.__name__} for {event.value}: {e}")
        
        except Exception as e:
            logger.error(f"Error emitting event {event.value}: {e}")
    
    @classmethod
    def create_session_lifecycle(cls, session_data: Dict) -> Dict:
        """Initialize session lifecycle tracking."""
        session_id = session_data.get('session_id')
        
        # Enhance session data with lifecycle info
        lifecycle_data = {
            **session_data,
            'lifecycle': {
                'state': SessionState.ACTIVE.value,
                'created_at': time.time(),
                'last_state_change': time.time(),
                'total_requests': 0,
                'extensions': 0,
                'rotations': 0,
                'security_events': 0,
                'warning_count': 0,
                'grace_period_expires': None,
                'metadata': {}
            }
        }
        
        # Store persistent session data
        cls._persistent_sessions[session_id] = lifecycle_data.copy()
        
        # Persist to storage
        try:
            persistence_manager = get_persistence_manager()
            persistence_manager.persist_session(session_id, session_data, lifecycle_data)
        except Exception as e:
            logger.error(f"Failed to persist session {session_id[:8]}...: {e}")
        
        # Initialize history
        if session_id not in cls._session_history:
            cls._session_history[session_id] = []
        
        # Emit creation event
        cls.emit_event(SessionEvent.CREATED, lifecycle_data)
        
        return lifecycle_data
    
    @classmethod
    def validate_session_lifecycle(cls, session_id: str, session_data: Dict) -> tuple[bool, Dict, List[str]]:
        """Validate session with comprehensive lifecycle checks."""
        warnings = []
        
        # Get persistent session data
        persistent_data = cls._persistent_sessions.get(session_id, session_data)
        lifecycle = persistent_data.get('lifecycle', {})
        
        # Increment request counter
        lifecycle['total_requests'] = lifecycle.get('total_requests', 0) + 1
        
        # Basic validation checks
        current_time = time.time()
        
        # Check session state
        current_state = SessionState(lifecycle.get('state', SessionState.ACTIVE.value))
        if current_state in [SessionState.EXPIRED, SessionState.INVALIDATED, SessionState.CLEANED]:
            cls.emit_event(SessionEvent.INVALIDATED, persistent_data, reason=f"Session in {current_state.value} state")
            return False, persistent_data, ["Session not in active state"]
        
        # Check if session is suspended
        if current_state == SessionState.SUSPENDED:
            grace_expires = lifecycle.get('grace_period_expires', 0)
            if current_time > grace_expires:
                cls._change_state(session_id, SessionState.EXPIRED, "Grace period expired")
                cls.emit_event(SessionEvent.EXPIRED, persistent_data, reason="Grace period expired")
                return False, persistent_data, ["Session suspended and grace period expired"]
            warnings.append("Session is suspended but within grace period")
        
        # Age-based checks
        max_lifetime_config = current_app.config.get('PERMANENT_SESSION_LIFETIME', 3600)
        if hasattr(max_lifetime_config, 'total_seconds'):
            max_lifetime = max_lifetime_config.total_seconds()
        else:
            max_lifetime = max_lifetime_config
        
        session_age = current_time - lifecycle.get('created_at', current_time)
        if session_age > max_lifetime:
            cls._change_state(session_id, SessionState.EXPIRED, "Maximum lifetime exceeded")
            cls.emit_event(SessionEvent.EXPIRED, persistent_data, age=session_age)
            return False, persistent_data, ["Session exceeded maximum lifetime"]
        
        # Idle timeout checks
        idle_timeout = current_app.config.get('SESSION_IDLE_TIMEOUT', 1800)
        last_activity = session_data.get('last_activity', current_time)
        idle_time = current_time - last_activity
        
        if idle_time > idle_timeout:
            cls._change_state(session_id, SessionState.EXPIRED, "Idle timeout exceeded")
            cls.emit_event(SessionEvent.EXPIRED, persistent_data, idle_time=idle_time)
            return False, persistent_data, ["Session idle timeout exceeded"]
        
        # Security validation
        security_warnings = cls._validate_security(session_data, persistent_data)
        warnings.extend(security_warnings)
        
        # Update persistent data
        persistent_data.update(session_data)
        persistent_data['lifecycle'] = lifecycle
        cls._persistent_sessions[session_id] = persistent_data
        
        # Persist updates to storage
        try:
            persistence_manager = get_persistence_manager()
            persistence_manager.persist_session(session_id, session_data, persistent_data)
        except Exception as e:
            logger.error(f"Failed to update persistent session {session_id[:8]}...: {e}")
        
        # Emit validation event
        cls.emit_event(SessionEvent.VALIDATED, persistent_data, warnings=warnings)
        
        return True, persistent_data, warnings
    
    @classmethod
    def extend_session(cls, session_id: str, extension_time: Optional[int] = None) -> bool:
        """Extend session lifetime."""
        if session_id not in cls._persistent_sessions:
            return False
        
        session_data = cls._persistent_sessions[session_id]
        lifecycle = session_data.get('lifecycle', {})
        
        # Default extension is half the idle timeout
        if extension_time is None:
            extension_time = current_app.config.get('SESSION_IDLE_TIMEOUT', 1800) // 2
        
        # Update last activity
        current_time = time.time()
        session_data['last_activity'] = current_time + extension_time
        lifecycle['extensions'] = lifecycle.get('extensions', 0) + 1
        lifecycle['last_state_change'] = current_time
        
        cls.emit_event(SessionEvent.EXTENDED, session_data, extension_seconds=extension_time)
        logger.info(f"Extended session {session_id[:8]}... by {extension_time} seconds")
        
        return True
    
    @classmethod
    def suspend_session(cls, session_id: str, reason: str = "Security violation", 
                       grace_period: int = 300) -> bool:
        """Suspend a session with optional grace period."""
        if session_id not in cls._persistent_sessions:
            return False
        
        session_data = cls._persistent_sessions[session_id]
        lifecycle = session_data.get('lifecycle', {})
        
        # Set suspension state
        cls._change_state(session_id, SessionState.SUSPENDED, reason)
        
        # Set grace period
        lifecycle['grace_period_expires'] = time.time() + grace_period
        lifecycle['metadata']['suspension_reason'] = reason
        
        cls.emit_event(SessionEvent.SUSPENDED, session_data, 
                      reason=reason, grace_period=grace_period)
        
        logger.warning(f"Suspended session {session_id[:8]}... - {reason}")
        return True
    
    @classmethod
    def resume_session(cls, session_id: str, reason: str = "Manual resume") -> bool:
        """Resume a suspended session."""
        if session_id not in cls._persistent_sessions:
            return False
        
        session_data = cls._persistent_sessions[session_id]
        lifecycle = session_data.get('lifecycle', {})
        
        if lifecycle.get('state') != SessionState.SUSPENDED.value:
            return False
        
        # Resume to active state
        cls._change_state(session_id, SessionState.ACTIVE, reason)
        lifecycle.pop('grace_period_expires', None)
        
        cls.emit_event(SessionEvent.RESUMED, session_data, reason=reason)
        
        logger.info(f"Resumed session {session_id[:8]}... - {reason}")
        return True
    
    @classmethod
    def rotate_session_lifecycle(cls, old_session_id: str, new_session_id: str, 
                                session_data: Dict) -> bool:
        """Handle session rotation in lifecycle."""
        if old_session_id not in cls._persistent_sessions:
            return False
        
        old_data = cls._persistent_sessions[old_session_id]
        old_lifecycle = old_data.get('lifecycle', {})
        
        # Create new session with inherited lifecycle
        new_lifecycle = old_lifecycle.copy()
        new_lifecycle['rotations'] = new_lifecycle.get('rotations', 0) + 1
        new_lifecycle['last_state_change'] = time.time()
        
        # Update session data
        new_session_data = session_data.copy()
        new_session_data['lifecycle'] = new_lifecycle
        
        # Store new session
        cls._persistent_sessions[new_session_id] = new_session_data
        
        # Transfer history
        if old_session_id in cls._session_history:
            cls._session_history[new_session_id] = cls._session_history[old_session_id]
            del cls._session_history[old_session_id]
        
        # Mark old session as rotated
        cls._change_state(old_session_id, SessionState.ROTATED, 
                         f"Rotated to {new_session_id[:8]}...")
        
        # Emit events
        cls.emit_event(SessionEvent.ROTATED, new_session_data, 
                      old_session_id=old_session_id, new_session_id=new_session_id)
        
        # Clean up old session after delay
        cls._schedule_cleanup(old_session_id, delay=30)
        
        logger.info(f"Rotated session {old_session_id[:8]}... -> {new_session_id[:8]}...")
        return True
    
    @classmethod
    def recover_session(cls, session_id: str) -> Optional[Dict]:
        """Recover session from persistent storage."""
        try:
            persistence_manager = get_persistence_manager()
            recovery_data = persistence_manager.recover_session(session_id)
            
            if recovery_data:
                session_data, lifecycle_data = recovery_data
                
                # Restore to memory stores
                cls._persistent_sessions[session_id] = lifecycle_data
                
                # Initialize history if not exists
                if session_id not in cls._session_history:
                    cls._session_history[session_id] = []
                
                # Emit recovery event
                cls.emit_event(SessionEvent.RESUMED, lifecycle_data, reason="Session recovered")
                
                logger.info(f"Recovered session {session_id[:8]}... from persistent storage")
                return lifecycle_data
            
        except Exception as e:
            logger.error(f"Failed to recover session {session_id[:8]}...: {e}")
        
        return None
    
    @classmethod
    def recover_user_sessions(cls, user_id: int) -> List[Dict]:
        """Recover all sessions for a user from persistent storage."""
        recovered_sessions = []
        
        try:
            persistence_manager = get_persistence_manager()
            sessions_data = persistence_manager.recover_user_sessions(user_id)
            
            for session_id, session_data, lifecycle_data in sessions_data:
                # Restore to memory stores
                cls._persistent_sessions[session_id] = lifecycle_data
                
                # Initialize history
                if session_id not in cls._session_history:
                    cls._session_history[session_id] = []
                
                recovered_sessions.append(lifecycle_data)
                
                # Emit recovery event
                cls.emit_event(SessionEvent.RESUMED, lifecycle_data, 
                             reason=f"User {user_id} sessions recovered")
            
            if recovered_sessions:
                logger.info(f"Recovered {len(recovered_sessions)} sessions for user {user_id}")
        
        except Exception as e:
            logger.error(f"Failed to recover sessions for user {user_id}: {e}")
        
        return recovered_sessions
    
    @classmethod
    def cleanup_session_lifecycle(cls, session_id: str, reason: str = "Cleanup") -> bool:
        """Clean up session lifecycle data."""
        if session_id in cls._persistent_sessions:
            session_data = cls._persistent_sessions[session_id]
            
            cls._change_state(session_id, SessionState.CLEANED, reason)
            cls.emit_event(SessionEvent.CLEANUP, session_data, reason=reason)
            
            # Archive session history before cleanup
            cls._archive_session(session_id)
            
            # Remove from persistent storage
            try:
                persistence_manager = get_persistence_manager()
                persistence_manager.remove_session(session_id)
            except Exception as e:
                logger.error(f"Failed to remove persistent session {session_id[:8]}...: {e}")
            
            # Remove from active stores
            del cls._persistent_sessions[session_id]
            if session_id in cls._session_history:
                del cls._session_history[session_id]
            
            logger.debug(f"Cleaned up lifecycle for session {session_id[:8]}...")
            return True
        return False
    
    @classmethod
    def get_session_lifecycle_info(cls, session_id: str) -> Optional[Dict]:
        """Get comprehensive session lifecycle information."""
        if session_id not in cls._persistent_sessions:
            return None
        
        session_data = cls._persistent_sessions[session_id]
        lifecycle = session_data.get('lifecycle', {})
        history = cls._session_history.get(session_id, [])
        
        return {
            'session_id': session_id,
            'state': lifecycle.get('state'),
            'created_at': datetime.fromtimestamp(lifecycle.get('created_at', 0)),
            'age_seconds': time.time() - lifecycle.get('created_at', time.time()),
            'total_requests': lifecycle.get('total_requests', 0),
            'extensions': lifecycle.get('extensions', 0),
            'rotations': lifecycle.get('rotations', 0),
            'security_events': lifecycle.get('security_events', 0),
            'warning_count': lifecycle.get('warning_count', 0),
            'event_count': len(history),
            'recent_events': history[-5:] if history else [],
            'metadata': lifecycle.get('metadata', {})
        }
    
    @classmethod
    def get_lifecycle_statistics(cls) -> Dict:
        """Get system-wide session lifecycle statistics."""
        current_time = time.time()
        stats = {
            'total_sessions': len(cls._persistent_sessions),
            'active_sessions': 0,
            'suspended_sessions': 0,
            'expired_sessions': 0,
            'total_events': sum(len(hist) for hist in cls._session_history.values()),
            'state_distribution': {},
            'average_age': 0,
            'total_requests': 0,
            'total_rotations': 0,
            'total_extensions': 0
        }
        
        ages = []
        for session_data in cls._persistent_sessions.values():
            lifecycle = session_data.get('lifecycle', {})
            state = lifecycle.get('state', SessionState.ACTIVE.value)
            
            # Count states
            stats['state_distribution'][state] = stats['state_distribution'].get(state, 0) + 1
            
            if state == SessionState.ACTIVE.value:
                stats['active_sessions'] += 1
            elif state == SessionState.SUSPENDED.value:
                stats['suspended_sessions'] += 1
            elif state == SessionState.EXPIRED.value:
                stats['expired_sessions'] += 1
            
            # Accumulate metrics
            created_at = lifecycle.get('created_at', current_time)
            ages.append(current_time - created_at)
            stats['total_requests'] += lifecycle.get('total_requests', 0)
            stats['total_rotations'] += lifecycle.get('rotations', 0)
            stats['total_extensions'] += lifecycle.get('extensions', 0)
        
        if ages:
            stats['average_age'] = sum(ages) / len(ages)
        
        return stats
    
    # Private helper methods
    
    @classmethod
    def _change_state(cls, session_id: str, new_state: SessionState, reason: str) -> None:
        """Change session state with logging."""
        if session_id in cls._persistent_sessions:
            session_data = cls._persistent_sessions[session_id]
            lifecycle = session_data.get('lifecycle', {})
            old_state = lifecycle.get('state', SessionState.ACTIVE.value)
            
            lifecycle['state'] = new_state.value
            lifecycle['last_state_change'] = time.time()
            lifecycle['metadata'][f'state_change_{time.time()}'] = {
                'from': old_state,
                'to': new_state.value,
                'reason': reason
            }
            
            logger.debug(f"Session {session_id[:8]}... state: {old_state} -> {new_state.value} ({reason})")
    
    @classmethod
    def _validate_security(cls, session_data: Dict, persistent_data: Dict) -> List[str]:
        """Validate session security and return warnings."""
        warnings = []
        lifecycle = persistent_data.get('lifecycle', {})
        
        try:
            # Check IP address consistency
            current_ip = request.remote_addr if request else None
            stored_ip = session_data.get('ip_address')
            
            if current_ip and stored_ip and current_ip != stored_ip:
                warnings.append(f"IP address changed from {stored_ip} to {current_ip}")
                lifecycle['security_events'] = lifecycle.get('security_events', 0) + 1
                cls.emit_event(SessionEvent.SECURITY_VIOLATION, persistent_data, 
                             violation_type="ip_change", old_ip=stored_ip, new_ip=current_ip)
            
            # Check User-Agent consistency
            current_ua = request.headers.get('User-Agent') if request else None
            stored_ua = session_data.get('user_agent')
            
            if current_ua and stored_ua and current_ua != stored_ua:
                warnings.append("User-Agent changed")
                lifecycle['security_events'] = lifecycle.get('security_events', 0) + 1
                cls.emit_event(SessionEvent.SECURITY_VIOLATION, persistent_data,
                             violation_type="user_agent_change")
            
            # Update warning count
            if warnings:
                lifecycle['warning_count'] = lifecycle.get('warning_count', 0) + len(warnings)
                
                # Suspend session if too many warnings
                max_warnings = current_app.config.get('MAX_SESSION_WARNINGS', 5)
                if lifecycle['warning_count'] >= max_warnings:
                    cls.suspend_session(session_data['session_id'], 
                                      f"Too many security warnings ({lifecycle['warning_count']})")
        
        except Exception as e:
            logger.error(f"Error in security validation: {e}")
            warnings.append("Security validation error")
        
        return warnings
    
    @classmethod
    def _log_event(cls, event_context: Dict) -> None:
        """Log session lifecycle event."""
        event_type = event_context.get('event')
        session_id = event_context.get('session_id', 'unknown')[:8]
        user_id = event_context.get('user_id')
        
        log_msg = f"Session {session_id}... (user {user_id}) - {event_type}"
        
        if event_type in [SessionEvent.SECURITY_VIOLATION.value, SessionEvent.SUSPENDED.value]:
            logger.warning(log_msg)
        elif event_type in [SessionEvent.EXPIRED.value, SessionEvent.INVALIDATED.value]:
            logger.info(log_msg)
        else:
            logger.debug(log_msg)
    
    @classmethod
    def _store_event_history(cls, session_id: str, event_context: Dict) -> None:
        """Store event in session history."""
        if not session_id:
            return
        
        if session_id not in cls._session_history:
            cls._session_history[session_id] = []
        
        # Limit history size
        max_history = current_app.config.get('MAX_SESSION_HISTORY', 100) if current_app else 100
        history = cls._session_history[session_id]
        
        history.append(event_context)
        
        # Trim history if too large
        if len(history) > max_history:
            cls._session_history[session_id] = history[-max_history:]
    
    @classmethod
    def _schedule_cleanup(cls, session_id: str, delay: int = 60) -> None:
        """Schedule delayed cleanup of a session."""
        # In production, use a task queue like Celery
        # For now, just mark it for cleanup
        if session_id in cls._persistent_sessions:
            lifecycle = cls._persistent_sessions[session_id].get('lifecycle', {})
            lifecycle['scheduled_cleanup'] = time.time() + delay
    
    @classmethod
    def _archive_session(cls, session_id: str) -> None:
        """Archive session data before cleanup."""
        # In production, store in permanent storage
        session_data = cls._persistent_sessions.get(session_id)
        history = cls._session_history.get(session_id, [])
        
        if session_data:
            archive_data = {
                'session_id': session_id,
                'lifecycle': session_data.get('lifecycle', {}),
                'archived_at': time.time(),
                'event_history': history
            }
            
            # For now, just log the archive
            logger.info(f"Archived session {session_id[:8]}... with {len(history)} events")