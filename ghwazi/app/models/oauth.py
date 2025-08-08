"""
OAuth models for user authentication and token management.
Supports multiple OAuth providers (Google, Microsoft, etc.) and their email configurations.
"""

import base64
import json
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from flask import current_app
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey, UniqueConstraint
from sqlalchemy.orm import relationship
from .database import Base
from .user import User


class OAuthUser(Base):
    """Model to store OAuth user information and tokens for various providers."""

    __tablename__ = 'oauth_users'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    # Provider information
    provider = Column(String(50), nullable=False, default='google')  # google, microsoft, yahoo, etc.
    provider_user_id = Column(String(255), nullable=False)  # User ID from the OAuth provider
    email = Column(String(255), nullable=False)
    name = Column(String(255), nullable=False)
    picture = Column(String(500))
    
    # Encrypted tokens
    access_token_encrypted = Column(Text, nullable=False)
    refresh_token_encrypted = Column(Text)
    
    # Token metadata
    token_expires_at = Column(DateTime)
    scope = Column(Text)  # JSON string of granted scopes
    
    # OAuth metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    # Relationships
    user = relationship("User", back_populates="oauth_users")
    email_configs = relationship("EmailAuthConfig", back_populates="oauth_user", cascade="all, delete-orphan")
    
    # Unique constraints
    __table_args__ = (
        UniqueConstraint('user_id', 'provider', name='uq_user_provider'),
        UniqueConstraint('provider', 'provider_user_id', name='uq_provider_user_id'),
    )
    
    @property
    def encryption_key(self):
        """Get encryption key for tokens."""
        secret_key = current_app.config.get('SECRET_KEY')
        if not secret_key:
            raise ValueError("SECRET_KEY not configured")
        
        # Use a consistent key derivation from the secret key
        import hashlib
        key_material = hashlib.sha256(secret_key.encode()).digest()[:32]
        return base64.urlsafe_b64encode(key_material)
    
    def encrypt_token(self, token):
        """Encrypt a token for secure storage."""
        if not token:
            return None
        
        f = Fernet(self.encryption_key)
        return f.encrypt(token.encode()).decode()
    
    def decrypt_token(self, encrypted_token):
        """Decrypt a stored token."""
        if not encrypted_token:
            return None
        
        try:
            f = Fernet(self.encryption_key)
            return f.decrypt(encrypted_token.encode()).decode()
        except Exception as e:
            current_app.logger.error(f"Failed to decrypt token: {e}")
            return None
    
    @property
    def access_token(self):
        """Get decrypted access token."""
        return self.decrypt_token(self.access_token_encrypted)
    
    @access_token.setter
    def access_token(self, token):
        """Set encrypted access token."""
        self.access_token_encrypted = self.encrypt_token(token)
    
    @property
    def refresh_token(self):
        """Get decrypted refresh token."""
        return self.decrypt_token(self.refresh_token_encrypted)
    
    @refresh_token.setter
    def refresh_token(self, token):
        """Set encrypted refresh token."""
        self.refresh_token_encrypted = self.encrypt_token(token) if token else None
    
    @property
    def scopes(self):
        """Get list of granted scopes."""
        if not self.scope:
            return []
        try:
            return json.loads(self.scope)
        except (json.JSONDecodeError, TypeError):
            return []
    
    @scopes.setter
    def scopes(self, scope_list):
        """Set list of granted scopes."""
        if isinstance(scope_list, list):
            self.scope = json.dumps(scope_list)
        elif isinstance(scope_list, str):
            # Handle space-separated scopes from OAuth
            self.scope = json.dumps(scope_list.split())
        else:
            self.scope = None
    
    @property
    def is_token_expired(self):
        """Check if access token has expired."""
        if not self.token_expires_at:
            return True
        return datetime.utcnow() >= self.token_expires_at
    
    @property
    def needs_refresh(self):
        """Check if token needs refresh (expires within 5 minutes)."""
        if not self.token_expires_at:
            return True
        return datetime.utcnow() >= (self.token_expires_at - timedelta(minutes=5))
    
    def update_tokens(self, access_token, refresh_token=None, expires_in=None, scope=None):
        """Update OAuth tokens and metadata."""
        self.access_token = access_token
        
        if refresh_token:
            self.refresh_token = refresh_token
        
        if expires_in:
            self.token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
        
        if scope:
            self.scopes = scope
        
        self.updated_at = datetime.utcnow()
    
    def revoke_access(self):
        """Revoke OAuth access by clearing tokens."""
        self.access_token_encrypted = None
        self.refresh_token_encrypted = None
        self.token_expires_at = None
        self.is_active = False
        self.updated_at = datetime.utcnow()
    
    @property
    def is_google(self):
        """Check if this is a Google OAuth user."""
        return self.provider == 'google'
    
    @property
    def is_microsoft(self):
        """Check if this is a Microsoft OAuth user."""
        return self.provider == 'microsoft'
    
    def to_dict(self):
        """Convert to dictionary (without sensitive data)."""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'provider': self.provider,
            'provider_user_id': self.provider_user_id,
            'email': self.email,
            'name': self.name,
            'picture': self.picture,
            'scopes': self.scopes,
            'token_expires_at': self.token_expires_at.isoformat() if self.token_expires_at else None,
            'is_active': self.is_active,
            'is_token_expired': self.is_token_expired,
            'needs_refresh': self.needs_refresh,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
    
    def __repr__(self):
        return f'<OAuthUser {self.provider}:{self.email}>'


class EmailAuthConfig(Base):
    """Configuration for email provider API integration per user (Gmail, Outlook, etc.)."""

    __tablename__ = 'email_auth_configs'

    id = Column(Integer, primary_key=True)
    oauth_user_id = Column(Integer, ForeignKey('oauth_users.id'), nullable=False)
    
    # Email API settings
    enabled = Column(Boolean, default=True)
    auto_sync = Column(Boolean, default=False)
    sync_frequency_hours = Column(Integer, default=24)  # How often to sync
    
    # Email filtering settings - JSON fields to support different provider formats
    labels_to_sync = Column(Text)  # JSON list of labels/folders to sync
    sender_filters = Column(Text)  # JSON list of sender email patterns
    subject_filters = Column(Text)  # JSON list of subject patterns
    
    # Last sync information
    last_sync_at = Column(DateTime)
    last_sync_message_id = Column(String(255))  # Last processed message ID
    sync_status = Column(String(50), default='idle')  # idle, syncing, error
    sync_error = Column(Text)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    oauth_user = relationship("OAuthUser", back_populates="email_configs")
    
    # Unique constraint - one config per oauth user
    __table_args__ = (
        UniqueConstraint('oauth_user_id', name='uq_oauth_user_config'),
    )
    
    @property
    def is_google(self):
        """Check if this is a Google provider config."""
        return self.oauth_user.provider == 'google'
    
    @property
    def is_microsoft(self):
        """Check if this is a Microsoft provider config."""
        return self.oauth_user.provider == 'microsoft'
    
    @property
    def labels_list(self):
        """Get list of labels/folders to sync."""
        if not self.labels_to_sync:
            # Default based on provider
            if self.is_google:
                return ['INBOX']
            elif self.is_microsoft:
                return ['Inbox']
            else:
                return ['INBOX']
        try:
            return json.loads(self.labels_to_sync)
        except (json.JSONDecodeError, TypeError):
            return ['INBOX'] if self.is_google else ['Inbox']
    
    @labels_list.setter
    def labels_list(self, labels):
        """Set list of labels/folders to sync."""
        if isinstance(labels, list):
            self.labels_to_sync = json.dumps(labels)
        else:
            # Default based on provider
            default_label = 'INBOX' if self.is_google else 'Inbox'
            self.labels_to_sync = json.dumps([default_label])
    
    @property
    def sender_filter_list(self):
        """Get list of sender filters."""
        if not self.sender_filters:
            return []
        try:
            return json.loads(self.sender_filters)
        except (json.JSONDecodeError, TypeError):
            return []
    
    @sender_filter_list.setter
    def sender_filter_list(self, filters):
        """Set list of sender filters."""
        if isinstance(filters, list):
            self.sender_filters = json.dumps(filters)
        else:
            self.sender_filters = None
    
    @property
    def subject_filter_list(self):
        """Get list of subject filters."""
        if not self.subject_filters:
            return []
        try:
            return json.loads(self.subject_filters)
        except (json.JSONDecodeError, TypeError):
            return []
    
    @subject_filter_list.setter
    def subject_filter_list(self, filters):
        """Set list of subject filters."""
        if isinstance(filters, list):
            self.subject_filters = json.dumps(filters)
        else:
            self.subject_filters = None
    
    @property
    def needs_sync(self):
        """Check if Gmail sync is needed."""
        if not self.enabled or not self.auto_sync:
            return False
        
        if not self.last_sync_at:
            return True
        
        next_sync = self.last_sync_at + timedelta(hours=self.sync_frequency_hours)
        return datetime.utcnow() >= next_sync
    
    def update_sync_status(self, status, error=None, message_id=None):
        """Update sync status and metadata."""
        self.sync_status = status
        self.sync_error = error
        
        if status == 'completed':
            self.last_sync_at = datetime.utcnow()
            if message_id:
                self.last_sync_message_id = message_id
        
        self.updated_at = datetime.utcnow()
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            'id': self.id,
            'oauth_user_id': self.oauth_user_id,
            'user_id': self.oauth_user.user_id,
            'provider': self.oauth_user.provider,
            'enabled': self.enabled,
            'auto_sync': self.auto_sync,
            'sync_frequency_hours': self.sync_frequency_hours,
            'labels_to_sync': self.labels_list,
            'sender_filters': self.sender_filter_list,
            'subject_filters': self.subject_filter_list,
            'last_sync_at': self.last_sync_at.isoformat() if self.last_sync_at else None,
            'last_sync_message_id': self.last_sync_message_id,
            'sync_status': self.sync_status,
            'sync_error': self.sync_error,
            'needs_sync': self.needs_sync,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
        }
    
    def __repr__(self):
        return f'<EmailAuthConfig {self.oauth_user.provider} user_id={self.oauth_user.user_id} enabled={self.enabled}>'