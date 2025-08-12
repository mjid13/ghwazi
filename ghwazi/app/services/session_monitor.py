"""
Session lifecycle monitoring and alerting system.
"""

import json
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta
from threading import Lock
from typing import Dict, List, Optional, Set, Tuple

from flask import current_app, request

from .session_lifecycle import SessionLifecycleManager, SessionEvent, SessionState
from .session_persistence import get_persistence_manager

logger = logging.getLogger(__name__)


class SessionAlert:
    """Represents a session-related alert."""
    
    def __init__(self, alert_type: str, severity: str, session_id: str, 
                 user_id: int, message: str, metadata: Dict = None):
        self.alert_type = alert_type
        self.severity = severity  # critical, warning, info
        self.session_id = session_id
        self.user_id = user_id
        self.message = message
        self.metadata = metadata or {}
        self.timestamp = time.time()
        self.acknowledged = False
        self.alert_id = f"{alert_type}_{session_id}_{int(self.timestamp)}"
    
    def to_dict(self) -> Dict:
        """Convert alert to dictionary."""
        return {
            'alert_id': self.alert_id,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'session_id': self.session_id,
            'user_id': self.user_id,
            'message': self.message,
            'metadata': self.metadata,
            'timestamp': self.timestamp,
            'acknowledged': self.acknowledged
        }


class SessionMonitor:
    """Monitors session lifecycle and generates alerts."""
    
    def __init__(self):
        self._lock = Lock()
        
        # Alert storage
        self._active_alerts: Dict[str, SessionAlert] = {}
        self._alert_history: deque = deque(maxlen=1000)
        
        # Metrics tracking
        self._session_metrics = {
            'total_created': 0,
            'total_expired': 0,
            'total_invalidated': 0,
            'total_rotated': 0,
            'total_security_violations': 0,
            'concurrent_sessions': 0,
            'average_lifetime': 0.0,
            'peak_concurrent': 0,
            'last_reset': time.time()
        }
        
        # Performance tracking
        self._performance_metrics = {
            'session_creation_times': deque(maxlen=100),
            'validation_times': deque(maxlen=100),
            'rotation_times': deque(maxlen=100),
            'cleanup_times': deque(maxlen=100)
        }
        
        # Anomaly detection
        self._anomaly_thresholds = {
            'max_failed_logins_per_hour': 10,
            'max_concurrent_sessions_per_user': 5,
            'max_session_extensions': 10,
            'max_security_violations_per_session': 3,
            'min_session_lifetime': 60,  # seconds
            'max_idle_extensions': 5
        }
        
        # Rate tracking
        self._rate_tracking = defaultdict(lambda: defaultdict(deque))
        
        # Register with lifecycle manager
        self._register_hooks()
    
    def _register_hooks(self):
        """Register monitoring hooks with session lifecycle manager."""
        SessionLifecycleManager.register_hook(SessionEvent.CREATED, self._on_session_created)
        SessionLifecycleManager.register_hook(SessionEvent.VALIDATED, self._on_session_validated)
        SessionLifecycleManager.register_hook(SessionEvent.ROTATED, self._on_session_rotated)
        SessionLifecycleManager.register_hook(SessionEvent.EXPIRED, self._on_session_expired)
        SessionLifecycleManager.register_hook(SessionEvent.INVALIDATED, self._on_session_invalidated)
        SessionLifecycleManager.register_hook(SessionEvent.SECURITY_VIOLATION, self._on_security_violation)
        SessionLifecycleManager.register_hook(SessionEvent.EXTENDED, self._on_session_extended)
        SessionLifecycleManager.register_hook(SessionEvent.SUSPENDED, self._on_session_suspended)
        SessionLifecycleManager.register_hook(SessionEvent.CLEANUP, self._on_session_cleanup)
    
    def _on_session_created(self, event_context: Dict, session_data: Dict):
        """Handle session creation event."""
        with self._lock:
            self._session_metrics['total_created'] += 1
            self._session_metrics['concurrent_sessions'] += 1
            
            if self._session_metrics['concurrent_sessions'] > self._session_metrics['peak_concurrent']:
                self._session_metrics['peak_concurrent'] = self._session_metrics['concurrent_sessions']
            
            # Track creation performance
            creation_time = event_context.get('processing_time', 0)
            if creation_time > 0:
                self._performance_metrics['session_creation_times'].append(creation_time)
            
            # Check for anomalies
            self._check_concurrent_user_sessions(session_data.get('user_id'))
            
            # Generate info alert for new session
            self._create_alert(
                'session_created',
                'info',
                session_data.get('session_id'),
                session_data.get('user_id'),
                f"New session created for user {session_data.get('username')}",
                {'ip': event_context.get('request_info', {}).get('ip')}
            )
    
    def _on_session_validated(self, event_context: Dict, session_data: Dict):
        """Handle session validation event."""
        warnings = event_context.get('warnings', [])
        
        if warnings:
            with self._lock:
                # Create warning alert
                self._create_alert(
                    'validation_warnings',
                    'warning',
                    session_data.get('session_id'),
                    session_data.get('user_id'),
                    f"Session validation warnings: {', '.join(warnings)}",
                    {'warnings': warnings}
                )
        
        # Track validation performance
        validation_time = event_context.get('processing_time', 0)
        if validation_time > 0:
            self._performance_metrics['validation_times'].append(validation_time)
    
    def _on_session_rotated(self, event_context: Dict, session_data: Dict):
        """Handle session rotation event."""
        with self._lock:
            self._session_metrics['total_rotated'] += 1
            
            # Track rotation performance
            rotation_time = event_context.get('processing_time', 0)
            if rotation_time > 0:
                self._performance_metrics['rotation_times'].append(rotation_time)
            
            # Generate info alert
            self._create_alert(
                'session_rotated',
                'info',
                session_data.get('session_id'),
                session_data.get('user_id'),
                f"Session rotated for security",
                {
                    'old_session_id': event_context.get('old_session_id'),
                    'new_session_id': event_context.get('new_session_id')
                }
            )
    
    def _on_session_expired(self, event_context: Dict, session_data: Dict):
        """Handle session expiration event."""
        with self._lock:
            self._session_metrics['total_expired'] += 1
            self._session_metrics['concurrent_sessions'] = max(0, 
                self._session_metrics['concurrent_sessions'] - 1)
            
            # Check for anomalous short session lifetime
            lifecycle = session_data.get('lifecycle', {})
            created_at = lifecycle.get('created_at', time.time())
            lifetime = time.time() - created_at
            
            if lifetime < self._anomaly_thresholds['min_session_lifetime']:
                self._create_alert(
                    'short_session_lifetime',
                    'warning',
                    session_data.get('session_id'),
                    session_data.get('user_id'),
                    f"Unusually short session lifetime: {lifetime:.1f} seconds",
                    {'lifetime': lifetime, 'reason': event_context.get('reason')}
                )
            
            # Update average lifetime
            self._update_average_lifetime(lifetime)
    
    def _on_session_invalidated(self, event_context: Dict, session_data: Dict):
        """Handle session invalidation event."""
        with self._lock:
            self._session_metrics['total_invalidated'] += 1
            self._session_metrics['concurrent_sessions'] = max(0, 
                self._session_metrics['concurrent_sessions'] - 1)
            
            # Generate warning alert
            self._create_alert(
                'session_invalidated',
                'warning',
                session_data.get('session_id'),
                session_data.get('user_id'),
                f"Session invalidated: {event_context.get('reason', 'Unknown reason')}",
                {'reason': event_context.get('reason')}
            )
    
    def _on_security_violation(self, event_context: Dict, session_data: Dict):
        """Handle security violation event."""
        with self._lock:
            self._session_metrics['total_security_violations'] += 1
            
            violation_type = event_context.get('violation_type', 'unknown')
            session_id = session_data.get('session_id')
            user_id = session_data.get('user_id')
            
            # Track violations per session
            lifecycle = session_data.get('lifecycle', {})
            security_events = lifecycle.get('security_events', 0)
            
            severity = 'warning'
            if security_events >= self._anomaly_thresholds['max_security_violations_per_session']:
                severity = 'critical'
            
            # Generate security alert
            self._create_alert(
                'security_violation',
                severity,
                session_id,
                user_id,
                f"Security violation detected: {violation_type}",
                {
                    'violation_type': violation_type,
                    'security_events': security_events,
                    'old_ip': event_context.get('old_ip'),
                    'new_ip': event_context.get('new_ip')
                }
            )
            
            # Track rate of violations
            self._track_rate('security_violations', user_id)
    
    def _on_session_extended(self, event_context: Dict, session_data: Dict):
        """Handle session extension event."""
        lifecycle = session_data.get('lifecycle', {})
        extensions = lifecycle.get('extensions', 0)
        
        # Check for excessive extensions
        if extensions > self._anomaly_thresholds['max_session_extensions']:
            with self._lock:
                self._create_alert(
                    'excessive_extensions',
                    'warning',
                    session_data.get('session_id'),
                    session_data.get('user_id'),
                    f"Excessive session extensions: {extensions}",
                    {'extensions': extensions}
                )
    
    def _on_session_suspended(self, event_context: Dict, session_data: Dict):
        """Handle session suspension event."""
        with self._lock:
            self._create_alert(
                'session_suspended',
                'critical',
                session_data.get('session_id'),
                session_data.get('user_id'),
                f"Session suspended: {event_context.get('reason', 'Unknown reason')}",
                {
                    'reason': event_context.get('reason'),
                    'grace_period': event_context.get('grace_period', 0)
                }
            )
    
    def _on_session_cleanup(self, event_context: Dict, session_data: Dict):
        """Handle session cleanup event."""
        cleanup_time = event_context.get('processing_time', 0)
        if cleanup_time > 0:
            self._performance_metrics['cleanup_times'].append(cleanup_time)
    
    def _check_concurrent_user_sessions(self, user_id: int):
        """Check for too many concurrent sessions for a user."""
        if not user_id:
            return
        
        try:
            lifecycle_stats = SessionLifecycleManager.get_lifecycle_statistics()
            # This is a simplified check - in production, query actual user sessions
            concurrent_count = lifecycle_stats.get('active_sessions', 0)
            
            if concurrent_count > self._anomaly_thresholds['max_concurrent_sessions_per_user']:
                self._create_alert(
                    'excessive_concurrent_sessions',
                    'warning',
                    'system',
                    user_id,
                    f"User has {concurrent_count} concurrent sessions",
                    {'concurrent_count': concurrent_count}
                )
        except Exception as e:
            logger.error(f"Error checking concurrent sessions for user {user_id}: {e}")
    
    def _track_rate(self, metric_type: str, identifier: int, window_hours: int = 1):
        """Track rate of events for anomaly detection."""
        current_time = time.time()
        window_start = current_time - (window_hours * 3600)
        
        # Clean old entries
        rate_data = self._rate_tracking[metric_type][identifier]
        while rate_data and rate_data[0] < window_start:
            rate_data.popleft()
        
        # Add current event
        rate_data.append(current_time)
        
        # Check threshold
        if metric_type == 'security_violations':
            threshold = self._anomaly_thresholds['max_failed_logins_per_hour']
            if len(rate_data) > threshold:
                self._create_alert(
                    'high_violation_rate',
                    'critical',
                    'system',
                    identifier,
                    f"High security violation rate: {len(rate_data)} in {window_hours} hour(s)",
                    {'rate': len(rate_data), 'window_hours': window_hours}
                )
    
    def _create_alert(self, alert_type: str, severity: str, session_id: str,
                     user_id: int, message: str, metadata: Dict = None):
        """Create and store a new alert."""
        alert = SessionAlert(alert_type, severity, session_id, user_id, message, metadata)
        
        # Store active alert
        self._active_alerts[alert.alert_id] = alert
        
        # Add to history
        self._alert_history.append(alert.to_dict())
        
        # Log based on severity
        if severity == 'critical':
            logger.critical(f"Session Alert: {message}")
        elif severity == 'warning':
            logger.warning(f"Session Alert: {message}")
        else:
            logger.info(f"Session Alert: {message}")
    
    def _update_average_lifetime(self, lifetime: float):
        """Update running average of session lifetime."""
        current_avg = self._session_metrics['average_lifetime']
        total_sessions = self._session_metrics['total_expired'] + self._session_metrics['total_invalidated']
        
        if total_sessions > 0:
            self._session_metrics['average_lifetime'] = (
                (current_avg * (total_sessions - 1) + lifetime) / total_sessions
            )
    
    def get_active_alerts(self, severity: str = None, limit: int = 50) -> List[Dict]:
        """Get active alerts, optionally filtered by severity."""
        with self._lock:
            alerts = list(self._active_alerts.values())
            
            if severity:
                alerts = [a for a in alerts if a.severity == severity]
            
            # Sort by timestamp (most recent first)
            alerts.sort(key=lambda x: x.timestamp, reverse=True)
            
            return [alert.to_dict() for alert in alerts[:limit]]
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Acknowledge an alert."""
        with self._lock:
            if alert_id in self._active_alerts:
                self._active_alerts[alert_id].acknowledged = True
                logger.info(f"Alert acknowledged: {alert_id}")
                return True
            return False
    
    def dismiss_alert(self, alert_id: str) -> bool:
        """Dismiss an active alert."""
        with self._lock:
            if alert_id in self._active_alerts:
                del self._active_alerts[alert_id]
                logger.info(f"Alert dismissed: {alert_id}")
                return True
            return False
    
    def get_session_metrics(self) -> Dict:
        """Get comprehensive session metrics."""
        with self._lock:
            metrics = self._session_metrics.copy()
            
            # Add performance metrics
            metrics['performance'] = {}
            for metric_name, times in self._performance_metrics.items():
                if times:
                    metrics['performance'][metric_name] = {
                        'avg': sum(times) / len(times),
                        'max': max(times),
                        'min': min(times),
                        'count': len(times)
                    }
            
            # Add alert summary
            alert_counts = defaultdict(int)
            for alert in self._active_alerts.values():
                alert_counts[alert.severity] += 1
            
            metrics['alerts'] = dict(alert_counts)
            metrics['total_active_alerts'] = len(self._active_alerts)
            
            # Add uptime
            metrics['uptime_hours'] = (time.time() - metrics['last_reset']) / 3600
            
            return metrics
    
    def get_user_session_health(self, user_id: int) -> Dict:
        """Get session health metrics for a specific user."""
        user_alerts = []
        user_sessions = []
        
        with self._lock:
            # Get user-specific alerts
            for alert in self._active_alerts.values():
                if alert.user_id == user_id:
                    user_alerts.append(alert.to_dict())
            
            # Get user session info from lifecycle manager
            try:
                sessions = SessionLifecycleManager.get_user_sessions(user_id)
                user_sessions = sessions
            except:
                pass
        
        return {
            'user_id': user_id,
            'active_sessions': len(user_sessions),
            'active_alerts': len(user_alerts),
            'alert_breakdown': {
                alert['severity']: len([a for a in user_alerts if a['severity'] == alert['severity']])
                for alert in user_alerts
            },
            'recent_alerts': user_alerts[:5]
        }
    
    def reset_metrics(self):
        """Reset all metrics (useful for testing or periodic resets)."""
        with self._lock:
            self._session_metrics = {
                'total_created': 0,
                'total_expired': 0,
                'total_invalidated': 0,
                'total_rotated': 0,
                'total_security_violations': 0,
                'concurrent_sessions': 0,
                'average_lifetime': 0.0,
                'peak_concurrent': 0,
                'last_reset': time.time()
            }
            
            for metric_deque in self._performance_metrics.values():
                metric_deque.clear()
            
            logger.info("Session metrics reset")
    
    def export_metrics(self, format_type: str = 'json') -> str:
        """Export metrics in specified format."""
        metrics = self.get_session_metrics()
        
        if format_type.lower() == 'json':
            return json.dumps(metrics, indent=2, default=str)
        elif format_type.lower() == 'csv':
            # Simple CSV export - could be enhanced
            lines = []
            lines.append("metric,value")
            
            for key, value in metrics.items():
                if isinstance(value, (int, float)):
                    lines.append(f"{key},{value}")
            
            return '\n'.join(lines)
        else:
            raise ValueError(f"Unsupported format: {format_type}")


# Global monitor instance
_session_monitor: Optional[SessionMonitor] = None


def get_session_monitor() -> SessionMonitor:
    """Get or create global session monitor instance."""
    global _session_monitor
    
    if _session_monitor is None:
        _session_monitor = SessionMonitor()
        logger.info("Session monitor initialized")
    
    return _session_monitor


def initialize_session_monitoring(app) -> SessionMonitor:
    """Initialize session monitoring for Flask app."""
    monitor = SessionMonitor()
    
    # Set as global instance
    global _session_monitor
    _session_monitor = monitor
    
    logger.info("Session monitoring system initialized")
    return monitor