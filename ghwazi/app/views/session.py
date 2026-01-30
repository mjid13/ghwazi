"""
Session management endpoints for monitoring and administration.
"""

import logging
from datetime import datetime

from flask import Blueprint, jsonify, render_template, request, session, flash, redirect, url_for
from flask_babel import gettext as _

from ..services.session_service import SessionService
from ..services.session_lifecycle import SessionLifecycleManager
from ..services.session_monitor import get_session_monitor
from ..services.session_migration import get_migration_manager
from ..services.session_persistence import get_persistence_manager
from ..services.user_service import UserService
from ..utils.decorators import login_required

session_bp = Blueprint("session", __name__)
logger = logging.getLogger(__name__)


def _is_admin_user(user_id):
    if not user_id:
        return False
    try:
        user = UserService().get_user_by_id(user_id)
        return bool(user and user.has_permission("admin_access"))
    except Exception as e:
        logger.error(f"Failed to load user for admin check: {e}")
        return False


@session_bp.route("/set-lang")
def set_language():
    """Set the UI language for the current session via ?lang=en|ar."""
    lang = request.args.get('lang', '').lower()
    if lang not in ['en', 'ar']:
        flash(_('Invalid language selection'), 'error')
        return redirect(request.referrer or url_for('main.index'))
    session['lang'] = lang
    flash(_('Language updated'), 'success')
    return redirect(request.referrer or url_for('main.index'))


@session_bp.route("/sessions")
@login_required
def list_sessions():
    """List all active sessions for the current user."""
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("auth.login"))
    
    try:
        user_sessions = SessionService.get_user_sessions(user_id)
        current_session_id = session.get("session_id")
        
        # Format session data for display
        sessions_data = []
        for sess in user_sessions:
            session_info = {
                'created_at': datetime.fromtimestamp(sess['created_at']).strftime('%Y-%m-%d %H:%M:%S'),
                'last_activity': datetime.fromtimestamp(sess['last_activity']).strftime('%Y-%m-%d %H:%M:%S'),
                'ip_address': sess.get('ip_address', 'Unknown'),
                'user_agent': sess.get('user_agent', 'Unknown'),
                'is_current': sess.get('session_id') == current_session_id,
                'security_flags': sess.get('security_flags', {})
            }
            sessions_data.append(session_info)
        
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'sessions': sessions_data})
        
        return render_template('session/list.html', sessions=sessions_data)
        
    except Exception as e:
        logger.error(f"Failed to list sessions for user {user_id}: {e}")
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'error': 'Failed to retrieve sessions'}), 500
        flash('Error retrieving session information', 'error')
        return redirect(url_for('main.dashboard'))


@session_bp.route("/sessions/stats")
@login_required
def session_stats():
    """Get session statistics (admin only)."""
    user_id = session.get("user_id")
    
    if not _is_admin_user(user_id):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        stats = SessionService.get_session_stats()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Failed to get session stats: {e}")
        return jsonify({'error': 'Failed to retrieve stats'}), 500


@session_bp.route("/sessions/invalidate", methods=["POST"])
@login_required
def invalidate_other_sessions():
    """Invalidate all other sessions for the current user."""
    user_id = session.get("user_id")
    current_session_id = session.get("session_id")
    
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        count = SessionService.invalidate_user_sessions(user_id, except_session=current_session_id)
        
        message = f"Invalidated {count} other session{'s' if count != 1 else ''}"
        
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'message': message, 'invalidated_count': count})
        
        flash(message, 'success')
        return redirect(url_for('session.list_sessions'))
        
    except Exception as e:
        logger.error(f"Failed to invalidate sessions for user {user_id}: {e}")
        if request.headers.get('Accept') == 'application/json':
            return jsonify({'error': 'Failed to invalidate sessions'}), 500
        flash('Error invalidating sessions', 'error')
        return redirect(url_for('session.list_sessions'))


@session_bp.route("/sessions/cleanup", methods=["POST"])
@login_required
def force_cleanup():
    """Force cleanup of expired sessions (admin only)."""
    user_id = session.get("user_id")
    
    if not _is_admin_user(user_id):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        count = SessionService.cleanup_expired_sessions()
        return jsonify({
            'message': f'Cleaned up {count} expired sessions',
            'cleaned_count': count
        })
    except Exception as e:
        logger.error(f"Failed to force cleanup sessions: {e}")
        return jsonify({'error': 'Failed to cleanup sessions'}), 500


@session_bp.route("/session/info")
@login_required
def current_session_info():
    """Get information about the current session."""
    session_id = session.get("session_id")
    
    if not session_id:
        return jsonify({'error': 'No session ID found'}), 400
    
    try:
        is_valid, session_data = SessionService.validate_session(session_id)
        
        if not is_valid:
            return jsonify({'error': 'Session invalid or expired'}), 401
        
        # Remove sensitive data
        safe_data = {
            'created_at': datetime.fromtimestamp(session_data['created_at']).isoformat(),
            'last_activity': datetime.fromtimestamp(session_data['last_activity']).isoformat(),
            'last_rotation': datetime.fromtimestamp(session_data['last_rotation']).isoformat(),
            'ip_address': session_data.get('ip_address'),
            'security_flags': session_data.get('security_flags', {}),
            'is_active': session_data.get('is_active', False)
        }
        
        return jsonify({'session': safe_data})
        
    except Exception as e:
        logger.error(f"Failed to get session info: {e}")
        return jsonify({'error': 'Failed to retrieve session info'}), 500


@session_bp.route("/lifecycle/info/<session_id>")
@login_required
def lifecycle_info(session_id: str):
    """Get comprehensive lifecycle information for a session."""
    user_id = session.get("user_id")
    current_session_id = session.get("session_id")
    
    # Only allow users to see their own sessions or admin to see all
    if not _is_admin_user(user_id) and session_id != current_session_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        lifecycle_info = SessionLifecycleManager.get_session_lifecycle_info(session_id)
        if not lifecycle_info:
            return jsonify({'error': 'Session not found'}), 404
        
        return jsonify({'lifecycle': lifecycle_info})
        
    except Exception as e:
        logger.error(f"Failed to get lifecycle info for {session_id}: {e}")
        return jsonify({'error': 'Failed to retrieve lifecycle info'}), 500


@session_bp.route("/monitoring/alerts")
@login_required
def monitoring_alerts():
    """Get session monitoring alerts."""
    user_id = session.get("user_id")
    
    if not _is_admin_user(user_id):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        monitor = get_session_monitor()
        severity = request.args.get('severity')
        limit = int(request.args.get('limit', 50))
        
        alerts = monitor.get_active_alerts(severity=severity, limit=limit)
        return jsonify({'alerts': alerts})
        
    except Exception as e:
        logger.error(f"Failed to get alerts: {e}")
        return jsonify({'error': 'Failed to retrieve alerts'}), 500


@session_bp.route("/monitoring/metrics")
@login_required
def monitoring_metrics():
    """Get comprehensive session metrics."""
    user_id = session.get("user_id")
    
    if not _is_admin_user(user_id):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        monitor = get_session_monitor()
        metrics = monitor.get_session_metrics()
        
        # Add persistence stats
        persistence_manager = get_persistence_manager()
        persistence_stats = persistence_manager.get_persistence_statistics()
        metrics['persistence'] = persistence_stats
        
        # Add lifecycle stats
        lifecycle_stats = SessionLifecycleManager.get_lifecycle_statistics()
        metrics['lifecycle'] = lifecycle_stats
        
        return jsonify({'metrics': metrics})
        
    except Exception as e:
        logger.error(f"Failed to get metrics: {e}")
        return jsonify({'error': 'Failed to retrieve metrics'}), 500


@session_bp.route("/monitoring/user/<int:target_user_id>")
@login_required
def user_session_health(target_user_id: int):
    """Get session health for a specific user."""
    user_id = session.get("user_id")
    
    # Users can only see their own health, admins can see all
    if not _is_admin_user(user_id) and user_id != target_user_id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        monitor = get_session_monitor()
        health_info = monitor.get_user_session_health(target_user_id)
        return jsonify({'health': health_info})
        
    except Exception as e:
        logger.error(f"Failed to get user health for {target_user_id}: {e}")
        return jsonify({'error': 'Failed to retrieve user health'}), 500


@session_bp.route("/migration/status")
@login_required
def migration_status():
    """Get migration system status."""
    user_id = session.get("user_id")
    
    if not _is_admin_user(user_id):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        migration_manager = get_migration_manager()
        status = migration_manager.get_migration_status()
        return jsonify({'status': status})
        
    except Exception as e:
        logger.error(f"Failed to get migration status: {e}")
        return jsonify({'error': 'Failed to retrieve migration status'}), 500


@session_bp.route("/lifecycle/extend", methods=["POST"])
@login_required
def extend_current_session():
    """Extend the current session lifetime."""
    session_id = session.get("session_id")
    
    if not session_id:
        return jsonify({'error': 'No active session found'}), 400
    
    try:
        extension_time = request.json.get('extension_seconds') if request.json else None
        success = SessionLifecycleManager.extend_session(session_id, extension_time)
        
        if success:
            return jsonify({'message': 'Session extended successfully'})
        else:
            return jsonify({'error': 'Failed to extend session'}), 400
            
    except Exception as e:
        logger.error(f"Failed to extend session {session_id}: {e}")
        return jsonify({'error': 'Failed to extend session'}), 500


@session_bp.route("/persistence/backup", methods=["POST"])
@login_required
def backup_sessions():
    """Create a backup of session data."""
    user_id = session.get("user_id")
    
    if not _is_admin_user(user_id):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        persistence_manager = get_persistence_manager()
        backup_file = persistence_manager.backup_sessions()
        
        if backup_file:
            return jsonify({'message': f'Sessions backed up to {backup_file}'})
        else:
            return jsonify({'error': 'Backup failed'}), 500
            
    except Exception as e:
        logger.error(f"Failed to backup sessions: {e}")
        return jsonify({'error': 'Failed to create backup'}), 500


@session_bp.route("/alerts/<alert_id>/acknowledge", methods=["POST"])
@login_required
def acknowledge_alert(alert_id: str):
    """Acknowledge a session monitoring alert."""
    user_id = session.get("user_id")
    
    if not _is_admin_user(user_id):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        monitor = get_session_monitor()
        success = monitor.acknowledge_alert(alert_id)
        
        if success:
            return jsonify({'message': 'Alert acknowledged'})
        else:
            return jsonify({'error': 'Alert not found'}), 404
            
    except Exception as e:
        logger.error(f"Failed to acknowledge alert {alert_id}: {e}")
        return jsonify({'error': 'Failed to acknowledge alert'}), 500


@session_bp.route("/database/stats")
@login_required
def database_session_stats():
    """Get database session management statistics."""
    user_id = session.get("user_id")
    
    if not _is_admin_user(user_id):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        from ..utils.db_session_manager import get_session_manager
        
        session_manager = get_session_manager()
        stats = session_manager.get_session_stats()
        
        # Add additional database info
        from ..models.database import Database
        db = Database()
        
        # Add Flask-SQLAlchemy stats if available
        try:
            from .. import db as flask_db
            flask_stats = {
                'flask_sqlalchemy_active': True,
                'pool_size': getattr(flask_db.engine.pool, 'size', 'unknown'),
                'checked_out_connections': getattr(flask_db.engine.pool, 'checkedout', 'unknown'),
                'overflow_connections': getattr(flask_db.engine.pool, 'overflow', 'unknown'),
            }
        except Exception:
            flask_stats = {'flask_sqlalchemy_active': False}
        
        return jsonify({
            'session_manager_stats': stats,
            'flask_sqlalchemy_stats': flask_stats,
            'database_url_type': 'sqlite' if 'sqlite' in str(db.database_url).lower() else 'postgresql'
        })
        
    except Exception as e:
        logger.error(f"Failed to get database session stats: {e}")
        return jsonify({'error': 'Failed to retrieve database stats'}), 500


@session_bp.route("/database/cleanup", methods=["POST"])
@login_required
def database_force_cleanup():
    """Force cleanup of leaked database sessions (admin only)."""
    user_id = session.get("user_id")
    
    if not _is_admin_user(user_id):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        from ..utils.db_session_manager import get_session_manager
        
        session_manager = get_session_manager()
        cleaned_count = session_manager.force_cleanup_leaked_sessions()
        
        return jsonify({
            'message': f'Cleaned up {cleaned_count} leaked sessions',
            'cleaned_count': cleaned_count
        })
        
    except Exception as e:
        logger.error(f"Failed to force cleanup database sessions: {e}")
        return jsonify({'error': 'Failed to cleanup database sessions'}), 500
