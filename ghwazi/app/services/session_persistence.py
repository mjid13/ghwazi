"""
Session persistence and recovery system for maintaining session state across restarts.
"""

import json
import logging
import os
import pickle
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from flask import current_app

try:
    import psycopg2  # PostgreSQL support for Heroku
except Exception:  # pragma: no cover
    psycopg2 = None

logger = logging.getLogger(__name__)


class SessionPersistenceManager:
    """Manages session persistence using SQLite by default and PostgreSQL on Heroku."""
    
    def __init__(self, db_path: Optional[str] = None):
        """Initialize persistence manager with database path or DATABASE_URL."""
        # Determine backend from Flask config or environment
        db_url = None
        try:
            if current_app:
                db_url = (
                    current_app.config.get("DATABASE_URL")
                    or current_app.config.get("SQLALCHEMY_DATABASE_URI")
                )
        except Exception:
            db_url = None
        if not db_url:
            db_url = os.environ.get("DATABASE_URL")
        if isinstance(db_url, str):
            db_url = db_url.replace("postgres://", "postgresql://")
        self._db_url = db_url
        self._backend = "postgres" if (isinstance(db_url, str) and db_url.startswith("postgresql")) else "sqlite"
        
        if self._backend == "sqlite":
            if db_path is None:
                db_path = self._get_default_db_path()
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        else:
            self.db_path = None
        
        self._init_database()
    
    def _get_default_db_path(self) -> str:
        """Get default database path based on Flask config."""
        if current_app:
            app_instance_path = getattr(current_app, 'instance_path', '.')
            return os.path.join(app_instance_path, 'sessions.db')
        return './sessions.db'
    
    def _init_database(self) -> None:
        """Initialize the session persistence database."""
        try:
            if self._backend == "postgres":
                if not psycopg2:
                    raise RuntimeError("psycopg2 is required for PostgreSQL session persistence")
                # Create tables in PostgreSQL
                with psycopg2.connect(self._db_url) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            CREATE TABLE IF NOT EXISTS sessions (
                                session_id VARCHAR(128) PRIMARY KEY,
                                user_id INTEGER NOT NULL,
                                session_data TEXT NOT NULL,
                                lifecycle_data TEXT NOT NULL,
                                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                expires_at TIMESTAMP,
                                state VARCHAR(32) DEFAULT 'active',
                                metadata TEXT DEFAULT '{}'
                            )
                            """
                        )
                        cur.execute(
                            """
                            CREATE TABLE IF NOT EXISTS session_events (
                                id SERIAL PRIMARY KEY,
                                session_id VARCHAR(128) NOT NULL,
                                event_type VARCHAR(64) NOT NULL,
                                event_data TEXT NOT NULL,
                                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                CONSTRAINT fk_session FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
                            )
                            """
                        )
                        cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id)")
                        cur.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at)")
                        cur.execute("CREATE INDEX IF NOT EXISTS idx_session_events_session_id ON session_events (session_id)")
                        conn.commit()
                logger.info("Session persistence database initialized (PostgreSQL)")
            else:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute('''
                        CREATE TABLE IF NOT EXISTS sessions (
                            session_id TEXT PRIMARY KEY,
                            user_id INTEGER NOT NULL,
                            session_data TEXT NOT NULL,
                            lifecycle_data TEXT NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            expires_at TIMESTAMP,
                            state TEXT DEFAULT 'active',
                            metadata TEXT DEFAULT '{}'
                        )
                    ''')
                    
                    conn.execute('''
                        CREATE TABLE IF NOT EXISTS session_events (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            session_id TEXT NOT NULL,
                            event_type TEXT NOT NULL,
                            event_data TEXT NOT NULL,
                            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (session_id) REFERENCES sessions (session_id)
                        )
                    ''')
                    
                    conn.execute('''
                        CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id)
                    ''')
                    
                    conn.execute('''
                        CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at)
                    ''')
                    
                    conn.execute('''
                        CREATE INDEX IF NOT EXISTS idx_session_events_session_id ON session_events (session_id)
                    ''')
                    
                    conn.commit()
                    logger.info(f"Session persistence database initialized: {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to initialize session database: {e}")
            raise
    
    def persist_session(self, session_id: str, session_data: Dict, lifecycle_data: Dict) -> bool:
        """Persist session data to storage."""
        try:
            # Calculate expiration
            created_at = lifecycle_data.get('lifecycle', {}).get('created_at', time.time())
            max_lifetime = self._get_max_lifetime()
            expires_at = datetime.fromtimestamp(created_at + max_lifetime)
            
            # Serialize data
            session_json = json.dumps(session_data, default=str)
            lifecycle_json = json.dumps(lifecycle_data, default=str)
            state = lifecycle_data.get('lifecycle', {}).get('state', 'active')
            user_id = session_data.get('user_id')
            
            if self._backend == 'postgres':
                with psycopg2.connect(self._db_url) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO sessions (session_id, user_id, session_data, lifecycle_data, last_updated, expires_at, state)
                            VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, %s, %s)
                            ON CONFLICT (session_id)
                            DO UPDATE SET
                                user_id = EXCLUDED.user_id,
                                session_data = EXCLUDED.session_data,
                                lifecycle_data = EXCLUDED.lifecycle_data,
                                last_updated = CURRENT_TIMESTAMP,
                                expires_at = EXCLUDED.expires_at,
                                state = EXCLUDED.state
                            """,
                            (session_id, user_id, session_json, lifecycle_json, expires_at, state)
                        )
                        conn.commit()
            else:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute('''
                        INSERT OR REPLACE INTO sessions 
                        (session_id, user_id, session_data, lifecycle_data, 
                         last_updated, expires_at, state)
                        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?)
                    ''', (session_id, user_id, session_json, 
                          lifecycle_json, expires_at, state))
                    conn.commit()
            
            logger.debug(f"Persisted session {session_id[:8]}...")
            return True
            
        except Exception as e:
            logger.error(f"Failed to persist session {session_id[:8]}...: {e}")
            return False
    
    def recover_session(self, session_id: str) -> Optional[tuple[Dict, Dict]]:
        """Recover session data from persistent storage."""
        try:
            if self._backend == 'postgres':
                with psycopg2.connect(self._db_url) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT session_data, lifecycle_data, state
                            FROM sessions 
                            WHERE session_id = %s AND expires_at > CURRENT_TIMESTAMP
                            """,
                            (session_id,)
                        )
                        row = cur.fetchone()
                        if row:
                            session_json, lifecycle_json, state = row
                            if state in ('active', 'suspended'):
                                return json.loads(session_json), json.loads(lifecycle_json)
                            return None
                return None
            else:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.execute('''
                        SELECT session_data, lifecycle_data, expires_at, state
                        FROM sessions 
                        WHERE session_id = ? AND expires_at > CURRENT_TIMESTAMP
                    ''', (session_id,))
                    
                    row = cursor.fetchone()
                    
                    if row:
                        session_data = json.loads(row['session_data'])
                        lifecycle_data = json.loads(row['lifecycle_data'])
                        
                        # Check if session is still valid
                        if row['state'] in ['active', 'suspended']:
                            logger.info(f"Recovered session {session_id[:8]}...")
                            return session_data, lifecycle_data
                        else:
                            logger.debug(f"Session {session_id[:8]}... in state {row['state']}, not recoverable")
                    
                    return None
        except Exception as e:
            logger.error(f"Failed to recover session {session_id[:8]}...: {e}")
            return None
    
    def recover_user_sessions(self, user_id: int) -> List[tuple[str, Dict, Dict]]:
        """Recover all active sessions for a user."""
        sessions = []
        
        try:
            if self._backend == 'postgres':
                with psycopg2.connect(self._db_url) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT session_id, session_data, lifecycle_data
                            FROM sessions 
                            WHERE user_id = %s AND expires_at > CURRENT_TIMESTAMP 
                              AND state IN ('active', 'suspended')
                            ORDER BY last_updated DESC
                            """,
                            (user_id,)
                        )
                        for sid, session_json, lifecycle_json in cur.fetchall():
                            sessions.append((sid, json.loads(session_json), json.loads(lifecycle_json)))
                logger.info(f"Recovered {len(sessions)} sessions for user {user_id}")
            else:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.execute('''
                        SELECT session_id, session_data, lifecycle_data
                        FROM sessions 
                        WHERE user_id = ? AND expires_at > CURRENT_TIMESTAMP 
                          AND state IN ('active', 'suspended')
                        ORDER BY last_updated DESC
                    ''', (user_id,))
                    
                    for row in cursor.fetchall():
                        session_data = json.loads(row['session_data'])
                        lifecycle_data = json.loads(row['lifecycle_data'])
                        sessions.append((row['session_id'], session_data, lifecycle_data))
                logger.info(f"Recovered {len(sessions)} sessions for user {user_id}")
        except Exception as e:
            logger.error(f"Failed to recover sessions for user {user_id}: {e}")
        
        return sessions
    
    def remove_session(self, session_id: str) -> bool:
        """Remove session from persistent storage."""
        try:
            if self._backend == 'postgres':
                with psycopg2.connect(self._db_url) as conn:
                    with conn.cursor() as cur:
                        cur.execute("DELETE FROM session_events WHERE session_id = %s", (session_id,))
                        cur.execute("DELETE FROM sessions WHERE session_id = %s", (session_id,))
                        deleted = cur.rowcount
                        conn.commit()
                        return deleted > 0
            else:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute('''
                        DELETE FROM sessions WHERE session_id = ?
                    ''', (session_id,))
                    
                    # Also remove associated events
                    conn.execute('''
                        DELETE FROM session_events WHERE session_id = ?
                    ''', (session_id,))
                    
                    conn.commit()
                    
                    if cursor.rowcount > 0:
                        logger.debug(f"Removed persisted session {session_id[:8]}...")
                        return True
        except Exception as e:
            logger.error(f"Failed to remove session {session_id[:8]}...: {e}")
        
        return False
    
    def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions from persistent storage."""
        try:
            if self._backend == 'postgres':
                with psycopg2.connect(self._db_url) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            DELETE FROM sessions 
                            WHERE expires_at <= CURRENT_TIMESTAMP OR state = 'cleaned'
                            """
                        )
                        expired_count = cur.rowcount
                        cur.execute(
                            """
                            DELETE FROM session_events 
                            WHERE session_id NOT IN (SELECT session_id FROM sessions)
                            """
                        )
                        conn.commit()
                        if expired_count > 0:
                            logger.info(f"Cleaned up {expired_count} expired persisted sessions")
                        return expired_count
            else:
                with sqlite3.connect(self.db_path) as conn:
                    # Remove expired sessions
                    cursor = conn.execute('''
                        DELETE FROM sessions 
                        WHERE expires_at <= CURRENT_TIMESTAMP OR state = 'cleaned'
                    ''')
                    
                    expired_count = cursor.rowcount
                    
                    # Remove orphaned events
                    conn.execute('''
                        DELETE FROM session_events 
                        WHERE session_id NOT IN (SELECT session_id FROM sessions)
                    ''')
                    
                    conn.commit()
                    
                    if expired_count > 0:
                        logger.info(f"Cleaned up {expired_count} expired persisted sessions")
                    
                    return expired_count
        except Exception as e:
            logger.error(f"Failed to cleanup expired sessions: {e}")
            return 0
    
    def store_event(self, session_id: str, event_type: str, event_data: Dict) -> bool:
        """Store session event in persistent storage."""
        try:
            event_json = json.dumps(event_data, default=str)
            if self._backend == 'postgres':
                with psycopg2.connect(self._db_url) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            INSERT INTO session_events (session_id, event_type, event_data, timestamp)
                            VALUES (%s, %s, %s, CURRENT_TIMESTAMP)
                            """,
                            (session_id, event_type, event_json)
                        )
                        conn.commit()
            else:
                with sqlite3.connect(self.db_path) as conn:
                    conn.execute('''
                        INSERT INTO session_events (session_id, event_type, event_data, timestamp)
                        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                    ''', (session_id, event_type, event_json))
                    conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to store event for session {session_id[:8]}...: {e}")
            return False
    
    def get_session_events(self, session_id: str, limit: int = 50) -> List[Dict]:
        """Get session events from persistent storage."""
        events = []
        
        try:
            if self._backend == 'postgres':
                with psycopg2.connect(self._db_url) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT event_type, event_data, timestamp
                            FROM session_events 
                            WHERE session_id = %s
                            ORDER BY timestamp DESC 
                            LIMIT %s
                            """,
                            (session_id, limit)
                        )
                        for event_type, event_json, ts in cur.fetchall():
                            data = json.loads(event_json)
                            events.append({
                                'event_type': event_type,
                                'timestamp': ts,
                                **data
                            })
            else:
                with sqlite3.connect(self.db_path) as conn:
                    conn.row_factory = sqlite3.Row
                    cursor = conn.execute('''
                        SELECT event_type, event_data, timestamp
                        FROM session_events 
                        WHERE session_id = ?
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    ''', (session_id, limit))
                    
                    for row in cursor.fetchall():
                        event_data = json.loads(row['event_data'])
                        events.append({
                            'event_type': row['event_type'],
                            'timestamp': row['timestamp'],
                            **event_data
                        })
        except Exception as e:
            logger.error(f"Failed to get events for session {session_id[:8]}...: {e}")
        
        return events
    
    def get_persistence_statistics(self) -> Dict:
        """Get persistence system statistics."""
        stats = {
            'total_persisted_sessions': 0,
            'active_sessions': 0,
            'suspended_sessions': 0,
            'expired_sessions': 0,
            'total_events': 0,
            'database_size_mb': 0
        }
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Count sessions by state
                cursor = conn.execute('''
                    SELECT state, COUNT(*) as count
                    FROM sessions 
                    GROUP BY state
                ''')
                
                for row in cursor.fetchall():
                    if row['state'] == 'active':
                        stats['active_sessions'] = row['count']
                    elif row['state'] == 'suspended':
                        stats['suspended_sessions'] = row['count']
                    elif row['state'] in ['expired', 'cleaned']:
                        stats['expired_sessions'] += row['count']
                
                stats['total_persisted_sessions'] = sum([
                    stats['active_sessions'], 
                    stats['suspended_sessions'], 
                    stats['expired_sessions']
                ])
                
                # Count total events
                cursor = conn.execute('SELECT COUNT(*) as count FROM session_events')
                row = cursor.fetchone()
                stats['total_events'] = row['count'] if row else 0
                
                # Get database file size
                if self.db_path.exists():
                    stats['database_size_mb'] = round(self.db_path.stat().st_size / (1024 * 1024), 2)
                
        except Exception as e:
            logger.error(f"Failed to get persistence statistics: {e}")
        
        return stats
    
    def backup_sessions(self, backup_path: str) -> bool:
        """Create a backup of session data."""
        try:
            backup_file = Path(backup_path)
            backup_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Create backup by copying database
            import shutil
            shutil.copy2(self.db_path, backup_file)
            
            logger.info(f"Session database backed up to {backup_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to backup sessions: {e}")
            return False
    
    def restore_sessions(self, backup_path: str) -> bool:
        """Restore session data from backup."""
        try:
            backup_file = Path(backup_path)
            if not backup_file.exists():
                logger.error(f"Backup file not found: {backup_file}")
                return False
            
            # Close any existing connections and restore
            import shutil
            shutil.copy2(backup_file, self.db_path)
            
            # Reinitialize to ensure schema is current
            self._init_database()
            
            logger.info(f"Session database restored from {backup_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore sessions: {e}")
            return False
    
    def migrate_sessions(self) -> bool:
        """Migrate session data to current schema version."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Check current schema version
                cursor = conn.execute('''
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name='schema_version'
                ''')
                
                has_version_table = cursor.fetchone() is not None
                
                if not has_version_table:
                    # Create version table and set initial version
                    conn.execute('''
                        CREATE TABLE schema_version (version INTEGER)
                    ''')
                    conn.execute('INSERT INTO schema_version (version) VALUES (1)')
                    conn.commit()
                    
                    logger.info("Initialized session schema version 1")
                    return True
                
                # Future migrations would go here
                logger.debug("Session schema is current")
                return True
                
        except Exception as e:
            logger.error(f"Failed to migrate sessions: {e}")
            return False
    
    def _get_max_lifetime(self) -> int:
        """Get maximum session lifetime in seconds."""
        if current_app:
            max_lifetime_config = current_app.config.get('PERMANENT_SESSION_LIFETIME', 3600)
            if hasattr(max_lifetime_config, 'total_seconds'):
                return int(max_lifetime_config.total_seconds())
            return int(max_lifetime_config)
        return 3600
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup if needed."""
        pass


# Global persistence manager instance
_persistence_manager: Optional[SessionPersistenceManager] = None


def get_persistence_manager() -> SessionPersistenceManager:
    """Get or create global persistence manager instance."""
    global _persistence_manager
    
    if _persistence_manager is None:
        _persistence_manager = SessionPersistenceManager()
    
    return _persistence_manager


def initialize_session_persistence(app) -> SessionPersistenceManager:
    """Initialize session persistence for Flask app."""
    db_path = os.path.join(app.instance_path, 'sessions.db')
    persistence_manager = SessionPersistenceManager(db_path)
    
    # Run migrations
    persistence_manager.migrate_sessions()
    
    # Set as global instance
    global _persistence_manager
    _persistence_manager = persistence_manager
    
    logger.info("Session persistence system initialized")
    return persistence_manager