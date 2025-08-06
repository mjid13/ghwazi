"""
Google OAuth and Gmail API integration service.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from flask import current_app, session, url_for
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from ..models.database import Database
from ..models.oauth import GoogleOAuthUser, GmailConfig
from ..models.user import User

logger = logging.getLogger(__name__)


class GoogleOAuthService:
    """Service for handling Google OAuth authentication and Gmail API integration."""
    
    # Required OAuth scopes
    SCOPES = [
        'openid',
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile',
        'https://www.googleapis.com/auth/gmail.readonly'
    ]
    
    def __init__(self):
        self.db = Database()
    
    def get_redirect_uri(self) -> str:
        """Get the correct redirect URI for OAuth callback."""
        # Use environment variable if set
        redirect_uri = current_app.config.get('GOOGLE_REDIRECT_URI')
        if redirect_uri:
            return redirect_uri
        
        # Fallback: generate from current request context
        try:
            return url_for('oauth.google_callback', _external=True)
        except RuntimeError:
            # If we're outside request context, use default for development
            if current_app.config.get('FLASK_ENV') == 'development':
                return 'http://localhost:5000/oauth/google/callback'
            else:
                raise ValueError("GOOGLE_REDIRECT_URI must be set in production")

    def get_authorization_url(self, state: str = None) -> str:
        """
        Generate Google OAuth authorization URL.
        
        Args:
            state: Optional state parameter for security
            
        Returns:
            Authorization URL for redirect
        """
        try:
            redirect_uri = self.get_redirect_uri()
            
            flow = Flow.from_client_config(
                {
                    "web": {
                        "client_id": current_app.config.get('GOOGLE_CLIENT_ID'),
                        "client_secret": current_app.config.get('GOOGLE_CLIENT_SECRET'),
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "redirect_uris": [redirect_uri]
                    }
                },
                scopes=self.SCOPES
            )
            
            flow.redirect_uri = redirect_uri
            
            authorization_url, state = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true',
                prompt='consent',  # Force consent screen to get refresh token
                state=state
            )
            
            # Store state in session for security
            session['oauth_state'] = state
            
            return authorization_url
            
        except Exception as e:
            logger.error(f"Error generating authorization URL: {e}")
            raise
    
    def handle_oauth_callback(self, code: str, state: str = None) -> Tuple[bool, str, Optional[Dict]]:
        """
        Handle OAuth callback from Google.
        
        Args:
            code: Authorization code from Google
            state: State parameter for security validation
            
        Returns:
            Tuple of (success, message, user_data)
        """
        try:
            # Validate state parameter
            if state != session.get('oauth_state'):
                return False, "Invalid state parameter", None
            
            redirect_uri = self.get_redirect_uri()
            
            # Exchange code for tokens
            flow = Flow.from_client_config(
                {
                    "web": {
                        "client_id": current_app.config.get('GOOGLE_CLIENT_ID'),
                        "client_secret": current_app.config.get('GOOGLE_CLIENT_SECRET'),
                        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                        "token_uri": "https://oauth2.googleapis.com/token",
                        "redirect_uris": [redirect_uri]
                    }
                },
                scopes=self.SCOPES,
                state=state
            )
            
            flow.redirect_uri = redirect_uri
            flow.fetch_token(code=code)
            
            credentials = flow.credentials
            
            # Get user info from Google
            user_info = self._get_user_info(credentials)
            if not user_info:
                return False, "Failed to retrieve user information", None
            
            # Store or update user OAuth data
            oauth_user = self._create_or_update_oauth_user(credentials, user_info)
            if not oauth_user:
                return False, "Failed to create/update user OAuth data", None
            
            return True, "OAuth authentication successful", {
                'oauth_user': oauth_user,
                'user_info': user_info
            }
            
        except Exception as e:
            logger.error(f"Error handling OAuth callback: {e}")
            return False, f"OAuth error: {str(e)}", None
    
    def _get_user_info(self, credentials: Credentials) -> Optional[Dict]:
        """
        Get user information from Google using OAuth credentials.
        
        Args:
            credentials: Google OAuth credentials
            
        Returns:
            User information dictionary or None
        """
        try:
            # Build the OAuth2 service to get user info
            service = build('oauth2', 'v2', credentials=credentials)

            # Get user profile info using the simpler userinfo endpoint
            profile = service.userinfo().get().execute()

            # Extract user information - OAuth2 userinfo has a simpler structure
            user_info = {
                'id': profile.get('id', ''),
                'name': profile.get('name', ''),
                'email': profile.get('email', ''),
                'picture': profile.get('picture', '')
            }
            
            return user_info
            
        except HttpError as e:
            logger.error(f"Google API error getting user info: {e}")
            return None
        except Exception as e:
            logger.error(f"Error getting user info: {e}")
            return None
    
    def _create_or_update_oauth_user(self, credentials: Credentials, user_info: Dict) -> Optional[GoogleOAuthUser]:
        """
        Create or update Google OAuth user record.
        
        Args:
            credentials: Google OAuth credentials
            user_info: User information from Google
            
        Returns:
            GoogleOAuthUser instance or None
        """
        db_session = self.db.get_session()
        
        try:
            # Find existing OAuth user by Google ID
            google_user_id = user_info['id']
            oauth_user = db_session.query(GoogleOAuthUser).filter_by(
                google_user_id=google_user_id
            ).first()
            
            if oauth_user:
                # Update existing OAuth user
                oauth_user.email = user_info['email']
                oauth_user.name = user_info['name']
                oauth_user.picture = user_info['picture']
                oauth_user.update_tokens(
                    access_token=credentials.token,
                    refresh_token=credentials.refresh_token,
                    expires_in=3600,  # Default 1 hour
                    scope=credentials.scopes
                )
                oauth_user.is_active = True
                
                logger.info(f"Updated existing OAuth user: {oauth_user.email}")
                
            else:
                # Check if we need to link to existing app user
                current_user_id = session.get('user_id')
                if current_user_id:
                    # User is already logged in, link OAuth to existing account
                    user = db_session.query(User).filter_by(id=current_user_id).first()
                    if not user:
                        logger.error(f"Current user {current_user_id} not found")
                        return None
                else:
                    # Check if user exists by email
                    user = db_session.query(User).filter_by(email=user_info['email']).first()
                    if not user:
                        # Create new app user
                        user = User(
                            username=user_info['email'].split('@')[0],
                            email=user_info['email'],
                            password_hash='google_oauth_user'  # Placeholder
                        )
                        db_session.add(user)
                        db_session.flush()  # Get user ID
                        
                        logger.info(f"Created new app user: {user.email}")
                
                # Create new OAuth user
                oauth_user = GoogleOAuthUser(
                    user_id=user.id,
                    google_user_id=google_user_id,
                    email=user_info['email'],
                    name=user_info['name'],
                    picture=user_info['picture']
                )
                
                oauth_user.update_tokens(
                    access_token=credentials.token,
                    refresh_token=credentials.refresh_token,
                    expires_in=3600,
                    scope=credentials.scopes
                )
                
                db_session.add(oauth_user)
                
                # Flush to get the oauth_user.id before creating Gmail config
                db_session.flush()

                # Create default Gmail config
                gmail_config = GmailConfig(
                    oauth_user_id=oauth_user.id,
                    user_id=user.id,
                    enabled=True,
                    auto_sync=False,
                    sync_frequency_hours=24
                )
                gmail_config.labels_list = ['INBOX']
                
                db_session.add(gmail_config)
                
                logger.info(f"Created new OAuth user: {oauth_user.email}")
            
            db_session.commit()
            return oauth_user
            
        except Exception as e:
            logger.error(f"Error creating/updating OAuth user: {e}")
            db_session.rollback()
            return None
        finally:
            self.db.close_session(db_session)
    
    def refresh_access_token(self, oauth_user: GoogleOAuthUser) -> bool:
        """
        Refresh OAuth access token for user.
        
        Args:
            oauth_user: GoogleOAuthUser instance
            
        Returns:
            True if token refreshed successfully
        """
        if not oauth_user.refresh_token:
            logger.error(f"No refresh token available for user {oauth_user.email}")
            return False
        
        try:
            credentials = Credentials(
                token=oauth_user.access_token,
                refresh_token=oauth_user.refresh_token,
                token_uri="https://oauth2.googleapis.com/token",
                client_id=current_app.config.get('GOOGLE_CLIENT_ID'),
                client_secret=current_app.config.get('GOOGLE_CLIENT_SECRET'),
                scopes=oauth_user.scopes
            )
            
            # Refresh the token
            credentials.refresh(Request())
            
            # Update stored tokens
            db_session = self.db.get_session()
            try:
                oauth_user.update_tokens(
                    access_token=credentials.token,
                    refresh_token=credentials.refresh_token,
                    expires_in=3600,
                    scope=credentials.scopes
                )
                
                db_session.commit()
                logger.info(f"Refreshed access token for user {oauth_user.email}")
                return True
                
            except Exception as e:
                logger.error(f"Error updating refreshed tokens: {e}")
                db_session.rollback()
                return False
            finally:
                self.db.close_session(db_session)
                
        except Exception as e:
            logger.error(f"Error refreshing access token: {e}")
            return False
    
    def get_valid_credentials(self, oauth_user: GoogleOAuthUser) -> Optional[Credentials]:
        """
        Get valid OAuth credentials, refreshing if necessary.
        
        Args:
            oauth_user: GoogleOAuthUser instance
            
        Returns:
            Valid Credentials or None
        """
        if not oauth_user or not oauth_user.is_active:
            return None
        
        # Check if token needs refresh
        if oauth_user.needs_refresh:
            if not self.refresh_access_token(oauth_user):
                return None
        
        try:
            credentials = Credentials(
                token=oauth_user.access_token,
                refresh_token=oauth_user.refresh_token,
                token_uri="https://oauth2.googleapis.com/token",
                client_id=current_app.config.get('GOOGLE_CLIENT_ID'),
                client_secret=current_app.config.get('GOOGLE_CLIENT_SECRET'),
                scopes=oauth_user.scopes
            )
            
            return credentials
            
        except Exception as e:
            logger.error(f"Error creating credentials: {e}")
            return None
    
    def revoke_oauth_access(self, oauth_user: GoogleOAuthUser) -> bool:
        """
        Revoke OAuth access for user.
        
        Args:
            oauth_user: GoogleOAuthUser instance
            
        Returns:
            True if revoked successfully
        """
        try:
            # Get credentials for revocation
            credentials = self.get_valid_credentials(oauth_user)
            
            if credentials:
                # Revoke token with Google
                try:
                    credentials.revoke(Request())
                    logger.info(f"Revoked Google OAuth token for user {oauth_user.email}")
                except Exception as e:
                    logger.warning(f"Failed to revoke token with Google: {e}")
            
            # Update local OAuth record
            db_session = self.db.get_session()
            try:
                oauth_user.revoke_access()
                db_session.commit()
                
                logger.info(f"Revoked local OAuth access for user {oauth_user.email}")
                return True
                
            except Exception as e:
                logger.error(f"Error revoking local OAuth access: {e}")
                db_session.rollback()
                return False
            finally:
                self.db.close_session(db_session)
                
        except Exception as e:
            logger.error(f"Error revoking OAuth access: {e}")
            return False
    
    def get_oauth_user_by_user_id(self, user_id: int) -> Optional[GoogleOAuthUser]:
        """
        Get Google OAuth user by app user ID.
        
        Args:
            user_id: App user ID
            
        Returns:
            GoogleOAuthUser instance or None
        """
        db_session = self.db.get_session()
        try:
            return db_session.query(GoogleOAuthUser).filter_by(
                user_id=user_id,
                is_active=True
            ).first()
        finally:
            self.db.close_session(db_session)
    
    def get_gmail_config(self, user_id: int) -> Optional[GmailConfig]:
        """
        Get Gmail configuration for user.
        
        Args:
            user_id: App user ID
            
        Returns:
            GmailConfig instance or None
        """
        db_session = self.db.get_session()
        try:
            return db_session.query(GmailConfig).filter_by(user_id=user_id).first()
        finally:
            self.db.close_session(db_session)