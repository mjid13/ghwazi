import logging
from typing import List, Optional, Union, cast
from datetime import datetime, timedelta

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from .database import Database
from .models import OAuthUser, EmailAuthConfig

logger = logging.getLogger(__name__)


class OAuthUserRepository:
    """Repository for managing OAuthUser records."""
    @staticmethod
    def create_oauth_user(
        session: Session,
        user_id: int,
        provider: str,
        provider_user_id: str,
        email: str,
        name: str,
        access_token: str,
        refresh_token: Optional[str] = None,
        expires_in: Optional[int] = None,
        scope: Optional[Union[List[str], str]] = None,
        picture: Optional[str] = None,
    ) -> OAuthUser:
        """Create a new OAuthUser. access_token is required (encrypted at model level)."""
        try:
            oauth_user = OAuthUser(
                user_id=user_id,
                provider=provider,
                provider_user_id=provider_user_id,
                email=email,
                name=name,
                picture=picture,
                is_active=True,
            )
            oauth_user.update_tokens(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=expires_in,
                scope=scope,
            )
            session.add(oauth_user)
            session.commit()
            session.refresh(oauth_user)
            return oauth_user
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Failed to create OAuthUser: {e}")
            raise


    @staticmethod
    def get_by_id(session: Session, oauth_user_id: int) -> Optional[OAuthUser]:
        try:
            return session.get(OAuthUser, oauth_user_id)
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Failed to create OAuthUser: {e}")
            raise

    @staticmethod
    def get_by_user_and_provider(session: Session, user_id: int, provider: str) -> Optional[OAuthUser]:
        try:
            return (
                session.query(OAuthUser)
                .filter(OAuthUser.user_id == user_id, OAuthUser.provider == provider)
                .one_or_none()
            )
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Failed to get OAuthUser by user and provider: {e}")
            raise

    @staticmethod
    def get_by_provider_user_id(session: Session, provider: str, provider_user_id: str) -> Optional[OAuthUser]:
        try:
            return (
                session.query(OAuthUser)
                .filter(
                    OAuthUser.provider == provider,
                    OAuthUser.provider_user_id == provider_user_id,
                )
                .one_or_none()
            )
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Failed to get OAuthUser by provider user id: {e}")
            raise

    @staticmethod
    def list_for_user(session: Session, user_id: int) -> List[OAuthUser]:
        try:
            return session.query(OAuthUser) \
                .filter(OAuthUser.user_id == user_id) \
                .order_by(OAuthUser.created_at.desc()) \
                .all()
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Failed to list OAuthUsers for user: {e}")
            raise

    @staticmethod
    def update_tokens(
        session: Session,
        oauth_user_id: int,
        access_token: str,
        refresh_token: Optional[str] = None,
        expires_in: Optional[int] = None,
        scope: Optional[Union[List[str], str]] = None,
    ) -> OAuthUser:
        try:
            oauth_user = session.get(OAuthUser, oauth_user_id)
            if not oauth_user:
                raise ValueError(f"OAuthUser {oauth_user_id} not found")

            oauth_user.update_tokens(
                access_token=access_token,
                refresh_token=refresh_token,
                expires_in=expires_in,
                scope=scope,
            )
            session.commit()
            session.refresh(oauth_user)
            return oauth_user
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Failed to update tokens for OAuthUser {oauth_user_id}: {e}")
            raise

    @staticmethod
    def revoke_access(session: Session, oauth_user_id: int) -> OAuthUser:
        try:
            oauth_user = session.get(OAuthUser, oauth_user_id)
            if not oauth_user:
                raise ValueError(f"OAuthUser {oauth_user_id} not found")

            oauth_user.revoke_access()
            session.commit()
            session.refresh(oauth_user)
            return oauth_user
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Failed to revoke access for OAuthUser {oauth_user_id}: {e}")
            raise

    @staticmethod
    def delete(session: Session, oauth_user_id: int) -> None:
        try:
            oauth_user = session.get(OAuthUser, oauth_user_id)
            if not oauth_user:
                return
            session.delete(oauth_user)
            session.commit()
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Failed to delete OAuthUser {oauth_user_id}: {e}")
            raise


class EmailAuthConfigRepository:
    """Repository for managing EmailAuthConfig records."""

    @staticmethod
    def create(
        session: Session,
        oauth_user_id: int,
        enabled: bool = True,
        auto_sync: bool = False,
        sync_frequency_hours: int = 24,
        labels: Optional[List[str]] = None,
        sender_filters: Optional[List[str]] = None,
        subject_filters: Optional[List[str]] = None,
    ) -> EmailAuthConfig:
        try:
            cfg = EmailAuthConfig(
                oauth_user_id=oauth_user_id,
                enabled=enabled,
                auto_sync=auto_sync,
                sync_frequency_hours=sync_frequency_hours,
                sync_status="idle",
            )
            if labels is not None:
                cfg.labels_list = labels
            if sender_filters is not None:
                cfg.sender_filter_list = sender_filters
            if subject_filters is not None:
                cfg.subject_filter_list = subject_filters

            session.add(cfg)
            session.commit()
            session.refresh(cfg)
            return cfg
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Failed to create EmailAuthConfig: {e}")
            raise

    @staticmethod
    def get_by_id(session: Session, config_id: int) -> Optional[EmailAuthConfig]:
        try:
            return session.get(EmailAuthConfig, config_id)
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Failed to get EmailAuthConfig by id: {e}")
            raise

    @staticmethod
    def get_by_oauth_user_id(session: Session, oauth_user_id: int) -> Optional[EmailAuthConfig]:
        """EmailAuthConfig has a unique constraint per oauth_user_id."""
        try:
            return (
                session.query(EmailAuthConfig)
                .filter(EmailAuthConfig.oauth_user_id == oauth_user_id)
                .one_or_none()
            )
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Failed to get EmailAuthConfig by oauth user id: {e}")
            raise

    @staticmethod
    def list_for_user(session: Session, user_id: int) -> List[EmailAuthConfig]:
        """List all configs for a given app user (join via OAuthUser)."""
        try:
            return (
                session.query(EmailAuthConfig)
                .join(OAuthUser, OAuthUser.id == EmailAuthConfig.oauth_user_id)
                .filter(OAuthUser.user_id == user_id)
                .order_by(EmailAuthConfig.created_at.desc())
                .all()
            )
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Failed to list EmailAuthConfigs for user: {e}")
            raise

    @staticmethod
    def update_settings(
        session: Session,
        config_id: int,
        *,
        enabled: Optional[bool] = None,
        auto_sync: Optional[bool] = None,
        sync_frequency_hours: Optional[int] = None,
        labels: Optional[List[str]] = None,
        sender_filters: Optional[List[str]] = None,
        subject_filters: Optional[List[str]] = None,
    ) -> EmailAuthConfig:
        try:
            cfg = session.get(EmailAuthConfig, config_id)
            if not cfg:
                raise ValueError(f"EmailAuthConfig {config_id} not found")

            if enabled is not None:
                cfg.enabled = enabled
            if auto_sync is not None:
                cfg.auto_sync = auto_sync
            if sync_frequency_hours is not None:
                cfg.sync_frequency_hours = sync_frequency_hours
            if labels is not None:
                cfg.labels_list = labels
            if sender_filters is not None:
                cfg.sender_filter_list = sender_filters
            if subject_filters is not None:
                cfg.subject_filter_list = subject_filters

            cfg.updated_at = datetime.utcnow()
            session.commit()
            session.refresh(cfg)
            return cfg
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Failed to update EmailAuthConfig {config_id}: {e}")
            raise

    @staticmethod
    def update_sync_status(
        session: Session,
        config_id: int,
        status: str,
        error: Optional[str] = None,
        message_id: Optional[str] = None,
    ) -> EmailAuthConfig:
        try:
            cfg = session.get(EmailAuthConfig, config_id)
            if not cfg:
                raise ValueError(f"EmailAuthConfig {config_id} not found")
            cfg.update_sync_status(status=status, error=error, message_id=message_id)
            session.commit()
            session.refresh(cfg)
            return cfg
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Failed to update sync status for EmailAuthConfig {config_id}: {e}")
            raise

    @staticmethod
    def delete(session: Session, config_id: int) -> None:
        try:
            cfg = session.get(EmailAuthConfig, config_id)
            if not cfg:
                return
            session.delete(cfg)
            session.commit()
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Failed to delete EmailAuthConfig {config_id}: {e}")
            raise
