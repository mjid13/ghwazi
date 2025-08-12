"""
Session migration and upgrade system for handling schema changes and data migrations.
"""

import json
import logging
import time
from datetime import datetime
from typing import Dict, List, Optional, Callable, Any

from flask import current_app

from .session_persistence import get_persistence_manager
from .session_lifecycle import SessionLifecycleManager, SessionEvent, SessionState

logger = logging.getLogger(__name__)


class SessionMigrationError(Exception):
    """Exception raised during session migration."""
    pass


class SessionMigration:
    """Represents a single session migration."""
    
    def __init__(self, version: int, description: str, migrate_func: Callable):
        self.version = version
        self.description = description
        self.migrate_func = migrate_func
        self.applied = False
        self.applied_at: Optional[float] = None
    
    def apply(self, session_data: Dict) -> Dict:
        """Apply the migration to session data."""
        try:
            migrated_data = self.migrate_func(session_data)
            self.applied = True
            self.applied_at = time.time()
            return migrated_data
        except Exception as e:
            logger.error(f"Migration v{self.version} failed: {e}")
            raise SessionMigrationError(f"Migration v{self.version} failed: {e}")


class SessionMigrationManager:
    """Manages session data migrations and schema upgrades."""
    
    CURRENT_VERSION = 3  # Current session schema version
    
    def __init__(self):
        self._migrations: Dict[int, SessionMigration] = {}
        self._migration_history: List[Dict] = []
        self._register_builtin_migrations()
    
    def _register_builtin_migrations(self):
        """Register built-in migrations."""
        
        # Migration 1->2: Add lifecycle tracking
        self.register_migration(
            version=2,
            description="Add lifecycle tracking to session data",
            migrate_func=self._migrate_v1_to_v2
        )
        
        # Migration 2->3: Add security metadata
        self.register_migration(
            version=3,
            description="Add security metadata and enhanced tracking",
            migrate_func=self._migrate_v2_to_v3
        )
    
    def register_migration(self, version: int, description: str, migrate_func: Callable):
        """Register a new migration."""
        if version in self._migrations:
            raise ValueError(f"Migration for version {version} already exists")
        
        migration = SessionMigration(version, description, migrate_func)
        self._migrations[version] = migration
        
        logger.info(f"Registered migration v{version}: {description}")
    
    def migrate_session(self, session_data: Dict, from_version: Optional[int] = None) -> Dict:
        """Migrate session data to current version."""
        if from_version is None:
            from_version = self._detect_session_version(session_data)
        
        if from_version == self.CURRENT_VERSION:
            return session_data  # Already current
        
        if from_version > self.CURRENT_VERSION:
            logger.warning(f"Session version {from_version} is newer than current {self.CURRENT_VERSION}")
            return session_data
        
        # Apply migrations sequentially
        migrated_data = session_data.copy()
        applied_migrations = []
        
        for version in range(from_version + 1, self.CURRENT_VERSION + 1):
            if version in self._migrations:
                migration = self._migrations[version]
                
                logger.info(f"Applying migration v{version}: {migration.description}")
                migrated_data = migration.apply(migrated_data)
                applied_migrations.append({
                    'version': version,
                    'description': migration.description,
                    'applied_at': time.time()
                })
        
        # Update version in migrated data
        if 'lifecycle' not in migrated_data:
            migrated_data['lifecycle'] = {}
        migrated_data['lifecycle']['schema_version'] = self.CURRENT_VERSION
        migrated_data['lifecycle']['migration_history'] = migrated_data.get('lifecycle', {}).get('migration_history', [])
        migrated_data['lifecycle']['migration_history'].extend(applied_migrations)
        
        # Record migration in history
        self._migration_history.append({
            'session_id': session_data.get('session_id'),
            'from_version': from_version,
            'to_version': self.CURRENT_VERSION,
            'applied_migrations': applied_migrations,
            'timestamp': time.time()
        })
        
        logger.info(f"Migrated session {session_data.get('session_id', 'unknown')[:8]}... "
                   f"from v{from_version} to v{self.CURRENT_VERSION}")
        
        return migrated_data
    
    def batch_migrate_sessions(self, session_filter: Optional[Callable] = None) -> Dict:
        """Migrate multiple sessions in batch."""
        results = {
            'total_sessions': 0,
            'migrated_sessions': 0,
            'failed_sessions': 0,
            'skipped_sessions': 0,
            'migration_details': []
        }
        
        try:
            persistence_manager = get_persistence_manager()
            
            # Get all sessions that need migration
            # This is a simplified implementation - in production, you'd query the database
            lifecycle_stats = SessionLifecycleManager.get_lifecycle_statistics()
            
            logger.info(f"Starting batch migration of {results['total_sessions']} sessions")
            
            # For now, just log that batch migration is available
            logger.info("Batch migration system is ready - implement database query for production use")
            
        except Exception as e:
            logger.error(f"Batch migration failed: {e}")
            results['error'] = str(e)
        
        return results
    
    def rollback_migration(self, session_id: str, to_version: int) -> bool:
        """Rollback a session to a previous version (if possible)."""
        # This is complex and potentially dangerous - implement carefully
        logger.warning(f"Migration rollback requested for session {session_id[:8]}... to v{to_version}")
        
        # For now, just log the request
        # In production, you'd need to:
        # 1. Validate the target version is safe
        # 2. Have reverse migration functions
        # 3. Update the session data carefully
        
        return False
    
    def get_migration_status(self) -> Dict:
        """Get status of all migrations."""
        return {
            'current_version': self.CURRENT_VERSION,
            'available_migrations': {
                version: {
                    'description': migration.description,
                    'applied': migration.applied,
                    'applied_at': migration.applied_at
                }
                for version, migration in self._migrations.items()
            },
            'migration_history_count': len(self._migration_history),
            'recent_migrations': self._migration_history[-10:] if self._migration_history else []
        }
    
    def validate_session_schema(self, session_data: Dict) -> tuple[bool, List[str]]:
        """Validate session data against current schema."""
        issues = []
        
        # Check for required fields
        required_fields = ['session_id', 'user_id', 'created_at', 'last_activity']
        for field in required_fields:
            if field not in session_data:
                issues.append(f"Missing required field: {field}")
        
        # Check lifecycle structure
        lifecycle = session_data.get('lifecycle', {})
        if not isinstance(lifecycle, dict):
            issues.append("Lifecycle data must be a dictionary")
        else:
            required_lifecycle_fields = ['state', 'created_at', 'total_requests']
            for field in required_lifecycle_fields:
                if field not in lifecycle:
                    issues.append(f"Missing lifecycle field: {field}")
        
        # Check data types
        if 'user_id' in session_data and not isinstance(session_data['user_id'], int):
            issues.append("user_id must be an integer")
        
        if 'created_at' in session_data and not isinstance(session_data['created_at'], (int, float)):
            issues.append("created_at must be a number")
        
        # Check security flags structure
        security_flags = session_data.get('security_flags', {})
        if not isinstance(security_flags, dict):
            issues.append("security_flags must be a dictionary")
        
        return len(issues) == 0, issues
    
    def upgrade_session_format(self, old_session_data: Dict) -> Dict:
        """Upgrade old session format to new format with full lifecycle support."""
        # Detect if this is an old-style session without lifecycle
        if 'lifecycle' not in old_session_data:
            logger.info("Upgrading legacy session format")
            
            # Create new lifecycle structure
            current_time = time.time()
            upgraded_data = {
                **old_session_data,
                'lifecycle': {
                    'state': SessionState.ACTIVE.value,
                    'created_at': old_session_data.get('created_at', current_time),
                    'last_state_change': current_time,
                    'total_requests': old_session_data.get('request_count', 0),
                    'extensions': 0,
                    'rotations': old_session_data.get('rotation_count', 0),
                    'security_events': 0,
                    'warning_count': 0,
                    'schema_version': self.CURRENT_VERSION,
                    'metadata': {
                        'upgraded_from_legacy': True,
                        'upgrade_timestamp': current_time
                    }
                }
            }
            
            # Add missing security flags if not present
            if 'security_flags' not in upgraded_data:
                upgraded_data['security_flags'] = {
                    'ip_changed': False,
                    'user_agent_changed': False,
                    'suspicious_activity': False
                }
            
            return upgraded_data
        
        return old_session_data
    
    def _detect_session_version(self, session_data: Dict) -> int:
        """Detect the version of session data."""
        # Check for explicit version
        lifecycle = session_data.get('lifecycle', {})
        if 'schema_version' in lifecycle:
            return lifecycle['schema_version']
        
        # Detect based on structure
        if 'lifecycle' in session_data:
            if 'security_events' in lifecycle:
                return 3  # Has security metadata
            else:
                return 2  # Has lifecycle but no security metadata
        else:
            return 1  # Legacy format
    
    def _migrate_v1_to_v2(self, session_data: Dict) -> Dict:
        """Migrate from version 1 to 2 - add lifecycle tracking."""
        current_time = time.time()
        
        migrated = session_data.copy()
        migrated['lifecycle'] = {
            'state': SessionState.ACTIVE.value,
            'created_at': session_data.get('created_at', current_time),
            'last_state_change': current_time,
            'total_requests': session_data.get('request_count', 0),
            'extensions': 0,
            'rotations': session_data.get('rotation_count', 0),
            'security_events': 0,
            'warning_count': 0,
            'metadata': {
                'migrated_from_v1': True,
                'migration_timestamp': current_time
            }
        }
        
        return migrated
    
    def _migrate_v2_to_v3(self, session_data: Dict) -> Dict:
        """Migrate from version 2 to 3 - add security metadata."""
        migrated = session_data.copy()
        lifecycle = migrated.get('lifecycle', {})
        
        # Add security tracking fields
        lifecycle['security_events'] = 0
        lifecycle['warning_count'] = 0
        
        # Add security flags if missing
        if 'security_flags' not in migrated:
            migrated['security_flags'] = {
                'ip_changed': False,
                'user_agent_changed': False,
                'suspicious_activity': False
            }
        
        # Update metadata
        if 'metadata' not in lifecycle:
            lifecycle['metadata'] = {}
        
        lifecycle['metadata']['migrated_from_v2'] = True
        lifecycle['metadata']['v3_migration_timestamp'] = time.time()
        
        migrated['lifecycle'] = lifecycle
        return migrated


# Global migration manager instance
_migration_manager: Optional[SessionMigrationManager] = None


def get_migration_manager() -> SessionMigrationManager:
    """Get or create global migration manager instance."""
    global _migration_manager
    
    if _migration_manager is None:
        _migration_manager = SessionMigrationManager()
        logger.info("Session migration manager initialized")
    
    return _migration_manager


def initialize_session_migrations(app) -> SessionMigrationManager:
    """Initialize session migrations for Flask app."""
    manager = SessionMigrationManager()
    
    # Set as global instance
    global _migration_manager
    _migration_manager = manager
    
    logger.info("Session migration system initialized")
    return manager