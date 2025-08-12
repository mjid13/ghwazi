"""
OAuth views for Google authentication.
"""

import logging
from flask import (Blueprint, flash, redirect, render_template, request, 
                   session, url_for, current_app, jsonify)

from ..models.database import Database
from ..models import OAuthUser, EmailAuthConfig
from ..models.user import User
from ..services.google_oauth_service import GoogleOAuthService
from ..services.gmail_service import GmailService
from ..utils.decorators import login_required

# Create blueprint
oauth_bp = Blueprint("oauth", __name__)

# Initialize services
oauth_service = GoogleOAuthService()
gmail_service = GmailService()
db = Database()
logger = logging.getLogger(__name__)


@oauth_bp.route("/google/login")
def google_login():
    """Initiate Google OAuth login flow."""
    try:
        # Generate authorization URL
        auth_url = oauth_service.get_authorization_url()
        return redirect(auth_url)
        
    except Exception as e:
        logger.error(f"Error initiating Google OAuth: {e}")
        flash("Failed to connect to Google. Please try again.", "error")
        return redirect(url_for("auth.login"))


@oauth_bp.route("/google/callback")
def google_callback():
    """Handle Google OAuth callback."""
    try:
        # Get authorization code and state
        code = request.args.get('code')
        state = request.args.get('state')
        error = request.args.get('error')
        
        if error:
            logger.error(f"Google OAuth error: {error}")
            flash("Google authentication failed. Please try again.", "error")
            return redirect(url_for("auth.login"))
        
        if not code:
            flash("No authorization code received from Google.", "error")
            return redirect(url_for("auth.login"))
        
        # Handle OAuth callback
        success, message, user_data = oauth_service.handle_oauth_callback(code, state)
        
        if not success:
            flash(f"OAuth failed: {message}", "error")
            return redirect(url_for("auth.login"))
        
        # Get OAuth user data
        oauth_user = user_data.get('oauth_user')
        if not oauth_user:
            flash("Failed to create user account.", "error")
            return redirect(url_for("auth.login"))
        
        # Log in the user (rotate session to prevent fixation)
        session.clear()
        session['user_id'] = oauth_user['user_id']
        session['google_oauth'] = True
        session['username'] = oauth_user['name']
        session['last_activity'] = __import__('time').time()
        session.permanent = True

        flash(f"Successfully connected with Google account: {oauth_user['name']}", "success")
        logger.info(f"User {oauth_user['user_id']} logged in via Google OAuth")
        
        # Redirect to dashboard
        return redirect(url_for("main.dashboard"))
        
    except Exception as e:
        logger.error(f"Error handling Google OAuth callback: {e}")
        flash("An error occurred during Google authentication.", "error")
        return redirect(url_for("auth.login"))


@oauth_bp.route("/google/disconnect", methods=['POST'])
@login_required
def google_disconnect():
    """Disconnect Google OAuth integration."""
    user_id = session.get('user_id')
    
    try:
        # Get OAuth user
        oauth_user = oauth_service.get_oauth_user_by_user_id(user_id)
        if not oauth_user:
            flash("No Google account connected.", "warning")
            return redirect(url_for("main.profile"))
        
        # Revoke OAuth access
        success = oauth_service.revoke_oauth_access(oauth_user)
        
        if success:
            flash("Successfully disconnected from Google account.", "success")
            # Clear Google OAuth session flag
            session.pop('google_oauth', None)
        else:
            flash("Failed to disconnect from Google account.", "error")
        
    except Exception as e:
        logger.error(f"Error disconnecting Google OAuth: {e}")
        flash("An error occurred while disconnecting from Google.", "error")
    
    return redirect(url_for("main.profile"))


@oauth_bp.route("/gmail/settings")
@login_required
def gmail_settings():
    """Gmail integration settings page."""
    user_id = session.get('user_id')
    
    try:
        # Get OAuth user and Gmail config
        oauth_user = oauth_service.get_oauth_user_by_user_id(user_id)
        email_config = oauth_service.get_email_config(user_id)
        
        # Get Gmail profile and labels if connected
        profile = None
        labels = []
        
        if oauth_user and oauth_user.is_active:
            profile = gmail_service.get_user_profile(oauth_user)
            labels = gmail_service.list_labels(oauth_user)
        
        return render_template(
            "oauth/gmail_settings.html",
            oauth_user=oauth_user,
            email_config=email_config,
            profile=profile,
            labels=labels
        )
        
    except Exception as e:
        logger.error(f"Error loading Gmail settings: {e}")
        flash("Failed to load Gmail settings.", "error")
        return redirect(url_for("main.dashboard"))


@oauth_bp.route("/gmail/settings", methods=['POST'])
@login_required
def update_gmail_settings():
    """Update Gmail integration settings."""
    user_id = session.get('user_id')
    
    try:
        # Get OAuth user first
        oauth_user = oauth_service.get_oauth_user_by_user_id(user_id)
        if not oauth_user:
            flash("Google account not connected.", "error")
            return redirect(url_for("oauth.gmail_settings"))
        
        db_session = db.get_session()

        try:
            # Get Email config within the same session
            email_config = db_session.query(EmailAuthConfig).filter_by(
                oauth_user_id=oauth_user.id
            ).first()

            if not email_config:
                flash("Email integration not found.", "error")
                return redirect(url_for("oauth.gmail_settings"))

            # Update settings
            email_config.enabled = request.form.get('enabled') == 'on'
            email_config.auto_sync = request.form.get('auto_sync') == 'on'

            # Update sync frequency
            try:
                email_config.sync_frequency_hours = int(request.form.get('sync_frequency_hours', 24))
            except ValueError:
                email_config.sync_frequency_hours = 24

            # Update label filters
            selected_labels = request.form.getlist('labels')
            if selected_labels:
                email_config.labels_list = selected_labels

            # Update sender filters
            sender_filters = request.form.get('sender_filters', '').strip()
            if sender_filters:
                email_config.sender_filter_list = [
                    f.strip() for f in sender_filters.split('\n') if f.strip()
                ]
            else:
                email_config.sender_filter_list = []

            # Update subject filters
            subject_filters = request.form.get('subject_filters', '').strip()
            if subject_filters:
                email_config.subject_filter_list = [
                    f.strip() for f in subject_filters.split('\n') if f.strip()
                ]
            else:
                email_config.subject_filter_list = []
            
            db_session.commit()
            flash("Gmail settings updated successfully.", "success")
            
        except Exception as e:
            logger.error(f"Error updating Gmail settings: {e}")
            db_session.rollback()
            flash("Failed to update Gmail settings.", "error")
        finally:
            db.close_session(db_session)
            
    except Exception as e:
        logger.error(f"Error updating Gmail settings: {e}")
        flash("An error occurred while updating settings.", "error")
    
    return redirect(url_for("oauth.gmail_settings"))


@oauth_bp.route("/gmail/sync", methods=['POST'])
@login_required
def sync_gmail():
    """Manually trigger Gmail sync."""
    user_id = session.get('user_id')
    
    try:
        # Check if sync is already in progress
        email_config = oauth_service.get_email_config(user_id)
        if email_config and email_config.sync_status == 'syncing':
            return jsonify({
                'success': False,
                'message': 'Gmail sync is already in progress'
            })
        
        # Start sync process (this could be moved to a background task)
        success, message, stats = gmail_service.sync_gmail_messages(user_id)
        
        return jsonify({
            'success': success,
            'message': message,
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"Error syncing Gmail: {e}")
        return jsonify({
            'success': False,
            'message': f'Sync failed: {str(e)}'
        })


@oauth_bp.route("/gmail/status")
@login_required
def gmail_status():
    """Get Gmail integration status."""
    user_id = session.get('user_id')
    
    try:
        oauth_user = oauth_service.get_oauth_user_by_user_id(user_id)
        email_config = oauth_service.get_email_config(user_id)

        status = {
            'connected': oauth_user is not None and oauth_user.is_active,
            'enabled': email_config.enabled if email_config else False,
            'auto_sync': email_config.auto_sync if email_config else False,
            'last_sync': email_config.last_sync_at.isoformat() if email_config and email_config.last_sync_at else None,
            'sync_status': email_config.sync_status if email_config else 'idle',
            'sync_error': email_config.sync_error if email_config else None,
            'needs_sync': email_config.needs_sync if email_config else False,
            'token_expired': oauth_user.is_token_expired if oauth_user else True,
            'needs_refresh': oauth_user.needs_refresh if oauth_user else True
        }
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Error getting Gmail status: {e}")
        return jsonify({
            'connected': False,
            'error': str(e)
        })


@oauth_bp.errorhandler(Exception)
def handle_oauth_error(error):
    """Handle OAuth-related errors."""
    logger.error(f"OAuth error: {error}")
    flash("An authentication error occurred. Please try again.", "error")
    return redirect(url_for("main.index"))