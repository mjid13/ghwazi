"""
Gmail API integration service for email processing.
"""

import base64
import email
import json
import logging
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from ..models.database import Database
from ..models.models import Transaction, Account, TransactionType, OAuthUser, EmailAuthConfig
from ..models.transaction import TransactionRepository
from .google_oauth_service import GoogleOAuthService
from .parser_service import TransactionParser

logger = logging.getLogger(__name__)


class GmailService:
    """Service for Gmail API integration and email processing."""
    
    def __init__(self):
        self.db = Database()
        self.oauth_service = GoogleOAuthService()
        self.parser = TransactionParser()
        self.transaction_repo = TransactionRepository()
    
    def get_gmail_service(self, oauth_user: OAuthUser):
        """
        Build Gmail API service with valid credentials.
        
        Args:
            oauth_user: OAuthUser instance
            
        Returns:
            Gmail service instance or None
        """
        credentials = self.oauth_service.get_valid_credentials(oauth_user)
        if not credentials:
            logger.error(f"No valid credentials for user {oauth_user.email}")
            return None
        
        try:
            return build('gmail', 'v1', credentials=credentials)
        except Exception as e:
            logger.error(f"Error building Gmail service: {e}")
            return None
    
    def get_user_profile(self, oauth_user: OAuthUser) -> Optional[Dict]:
        """
        Get Gmail user profile information.
        
        Args:
            oauth_user: OAuthUser instance
            
        Returns:
            Profile information dict or None
        """
        service = self.get_gmail_service(oauth_user)
        if not service:
            return None
        
        try:
            profile = service.users().getProfile(userId='me').execute()
            return {
                'email': profile.get('emailAddress'),
                'messages_total': profile.get('messagesTotal', 0),
                'threads_total': profile.get('threadsTotal', 0),
                'history_id': profile.get('historyId')
            }
        except HttpError as e:
            logger.error(f"Gmail API error getting profile: {e}")
            return None
        except Exception as e:
            logger.error(f"Error getting Gmail profile: {e}")
            return None
    
    def list_labels(self, oauth_user: OAuthUser) -> List[Dict]:
        """
        Get list of Gmail labels for user.
        
        Args:
            oauth_user: OAuthUser instance
            
        Returns:
            List of label dictionaries
        """
        service = self.get_gmail_service(oauth_user)
        if not service:
            return []
        
        try:
            response = service.users().labels().list(userId='me').execute()
            labels = response.get('labels', [])
            
            return [
                {
                    'id': label.get('id'),
                    'name': label.get('name'),
                    'type': label.get('type'),
                    'message_count': label.get('messagesTotal', 0),
                    'unread_count': label.get('messagesUnread', 0)
                }
                for label in labels
            ]
            
        except HttpError as e:
            logger.error(f"Gmail API error listing labels: {e}")
            return []
        except Exception as e:
            logger.error(f"Error listing Gmail labels: {e}")
            return []
    
    def search_messages(self, oauth_user: OAuthUser, gmail_config: EmailAuthConfig,
                       max_results: int = 50) -> List[Dict]:
        """
        Search for messages based on Gmail configuration.
        
        Args:
            oauth_user: OAuthUser instance
            gmail_config: EmailAuthConfig instance
            max_results: Maximum number of messages to return
            
        Returns:
            List of message dictionaries
        """
        service = self.get_gmail_service(oauth_user)
        if not service:
            return []
        
        try:
            # Build search query
            query_parts = []
            
            # Add label filters
            labels = gmail_config.labels_list
            if labels:
                label_query = ' OR '.join([f'label:{label}' for label in labels])
                if len(labels) > 1:
                    query_parts.append(f'({label_query})')
                else:
                    query_parts.append(label_query)
            
            # Add sender filters
            sender_filters = gmail_config.sender_filter_list
            if sender_filters:
                sender_query = ' OR '.join([f'from:{sender}' for sender in sender_filters])
                if len(sender_filters) > 1:
                    query_parts.append(f'({sender_query})')
                else:
                    query_parts.append(sender_query)
            
            # Add subject filters
            subject_filters = gmail_config.subject_filter_list
            if subject_filters:
                subject_query = ' OR '.join([f'subject:{subject}' for subject in subject_filters])
                if len(subject_filters) > 1:
                    query_parts.append(f'({subject_query})')
                else:
                    query_parts.append(subject_query)
            
            # Add date filter for new messages
            # Use incremental sync only if we have previously processed at least one message.
            # Otherwise, treat as first-time sync and use a reasonable historical window.
            # Determine if this is a first-time sync based on absence of any last_sync_at
            is_first_sync = not bool(gmail_config.last_sync_at)
            first_window_days = 180
            try:
                # Prefer app config when available
                from flask import current_app
                try:
                    cfg_days = current_app.config.get('GMAIL_FIRST_SYNC_DAYS')
                    if isinstance(cfg_days, int) and cfg_days > 0:
                        first_window_days = cfg_days
                except RuntimeError:
                    # Outside application context; keep default
                    pass
            except Exception:
                pass

            if not is_first_sync and gmail_config.last_sync_at:
                # Only get messages newer than last completed sync, using epoch seconds for time precision
                cutoff_dt = gmail_config.last_sync_at
                try:
                    if cutoff_dt.tzinfo is None:
                        cutoff_dt_utc = cutoff_dt.replace(tzinfo=timezone.utc)
                    else:
                        cutoff_dt_utc = cutoff_dt.astimezone(timezone.utc)
                    cutoff_epoch = int(cutoff_dt_utc.timestamp())
                except Exception:
                    # Fallback to date-only if timestamp conversion fails
                    cutoff_epoch = None
                if cutoff_epoch is not None:
                    query_parts.append(f'after:{cutoff_epoch}')
                    logger.info(
                        f"Using incremental Gmail sync after epoch {cutoff_epoch} (UTC {cutoff_dt.isoformat()}), has last_sync_at"
                    )
                else:
                    last_sync_date = cutoff_dt.strftime('%Y/%m/%d')
                    query_parts.append(f'after:{last_sync_date}')
                    logger.info(f"Using incremental Gmail sync after:{last_sync_date} (fallback, has last_sync_at)")
            else:
                # First sync: fetch a historical window to seed data
                query_parts.append(f'newer_than:{first_window_days}d')
                logger.info(f"Using first Gmail sync window newer_than:{first_window_days}d (no last_sync_at)")
            
            # Combine query parts
            query = ' '.join(query_parts) if query_parts else 'in:inbox'
            
            logger.debug(f"Gmail search query: {query}")
            
            # Search messages
            response = service.users().messages().list(
                userId='me',
                q=query,
                maxResults=max_results
            ).execute()
            
            messages = response.get('messages', [])
            logger.info(f"Found {len(messages)} messages for user {oauth_user.email}")
            
            # Get detailed message information
            detailed_messages = []
            for message in messages:
                message_detail = self.get_message_detail(service, message['id'])
                if message_detail:
                    detailed_messages.append(message_detail)
            
            return detailed_messages
            
        except HttpError as e:
            logger.error(f"Gmail API error searching messages: {e}")
            return []
        except Exception as e:
            logger.error(f"Error searching Gmail messages: {e}")
            return []
    
    def get_message_detail(self, service, message_id: str) -> Optional[Dict]:
        """
        Get detailed information for a specific message.
        
        Args:
            service: Gmail API service instance
            message_id: Gmail message ID
            
        Returns:
            Message detail dictionary or None
        """
        try:
            message = service.users().messages().get(
                userId='me',
                id=message_id,
                format='full'
            ).execute()
            
            # Extract message details
            payload = message.get('payload', {})
            headers = payload.get('headers', [])
            
            # Get header values
            header_dict = {header['name'].lower(): header['value'] for header in headers}
            
            # Get message body
            body_text = self._extract_message_body(payload)
            
            # Parse date
            date_str = header_dict.get('date', '')
            parsed_date = self._parse_email_date(date_str)
            
            return {
                'id': message_id,
                'thread_id': message.get('threadId'),
                'label_ids': message.get('labelIds', []),
                'snippet': message.get('snippet', ''),
                'history_id': message.get('historyId'),
                'internal_date': message.get('internalDate'),
                'size_estimate': message.get('sizeEstimate', 0),
                'subject': header_dict.get('subject', ''),
                'sender': header_dict.get('from', ''),
                'recipient': header_dict.get('to', ''),
                'date': parsed_date,
                'date_string': date_str,
                'body_text': body_text,
                'headers': header_dict
            }
            
        except HttpError as e:
            logger.error(f"Gmail API error getting message {message_id}: {e}")
            return None
        except Exception as e:
            logger.error(f"Error getting message detail {message_id}: {e}")
            return None
    
    def _extract_message_body(self, payload: Dict) -> str:
        """
        Extract text body from Gmail message payload.
        
        Args:
            payload: Gmail message payload
            
        Returns:
            Extracted text body
        """
        body = ""
        
        try:
            if 'parts' in payload:
                # Multipart message
                for part in payload['parts']:
                    if part.get('mimeType') == 'text/plain':
                        data = part.get('body', {}).get('data')
                        if data:
                            body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                            break
                    elif part.get('mimeType') == 'text/html' and not body:
                        # Fallback to HTML if no plain text
                        data = part.get('body', {}).get('data')
                        if data:
                            html_body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                            body = self.parser.clean_text(html_body)
            else:
                # Single part message
                if payload.get('mimeType') == 'text/plain':
                    data = payload.get('body', {}).get('data')
                    if data:
                        body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                elif payload.get('mimeType') == 'text/html':
                    data = payload.get('body', {}).get('data')
                    if data:
                        html_body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
                        body = self.parser.clean_text(html_body)
        
        except Exception as e:
            logger.error(f"Error extracting message body: {e}")
        
        return body.strip()
    
    def _html_to_text(self, html_content: str) -> str:
        """
        Convert HTML content to plain text.
        
        Args:
            html_content: HTML content string
            
        Returns:
            Plain text content
        """
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html_content, 'html.parser')
            return soup.get_text(separator=' ', strip=True)
        except ImportError:
            # Fallback to regex if BeautifulSoup not available
            text = re.sub(r'<[^>]+>', '', html_content)
            return re.sub(r'\s+', ' ', text).strip()
        except Exception as e:
            logger.error(f"Error converting HTML to text: {e}")
            return html_content
    
    def _parse_email_date(self, date_str: str) -> Optional[datetime]:
        """
        Parse email date string to datetime object.
        
        Args:
            date_str: Email date string
            
        Returns:
            Parsed datetime or None
        """
        if not date_str:
            return None
        
        try:
            # Try to parse using email.utils
            import email.utils
            timestamp = email.utils.parsedate_tz(date_str)
            if timestamp:
                return datetime.fromtimestamp(email.utils.mktime_tz(timestamp))
        except Exception:
            pass
        
        # Fallback parsing attempts
        date_formats = [
            '%a, %d %b %Y %H:%M:%S %z',
            '%d %b %Y %H:%M:%S %z',
            '%a, %d %b %Y %H:%M:%S',
            '%d %b %Y %H:%M:%S',
            '%Y-%m-%d %H:%M:%S'
        ]
        
        for fmt in date_formats:
            try:
                return datetime.strptime(date_str.strip(), fmt)
            except ValueError:
                continue
        
        logger.warning(f"Could not parse email date: {date_str}")
        return None
    
    def sync_gmail_messages(self, user_id: int, account_number: str) -> Tuple[bool, str, Dict]:
        """
        Sync Gmail messages for a user.
        
        Args:
            user_id: App user ID
            
        Returns:
            Tuple of (success, message, stats)
        """
        db_session = self.db.get_session()
        gmail_config = None
        
        try:
            # Get OAuth user and Gmail config
            oauth_user = db_session.query(OAuthUser).filter_by(
                user_id=user_id,
                provider='google',
                is_active=True
            ).first()
            
            if not oauth_user:
                return False, "No Google OAuth connection found", {}
            
            gmail_config = db_session.query(EmailAuthConfig).filter_by(
                oauth_user_id=oauth_user.id,
                enabled=True
            ).first()
            if not gmail_config:
                return False, "Gmail sync not enabled", {}

            # Guard: prevent concurrent syncs using DB row lock and clean up stale 'syncing'
            try:
                from flask import current_app
                stuck_minutes = int(current_app.config.get('GMAIL_SYNC_STUCK_MINUTES', 15))
                cooldown_sec = int(current_app.config.get('GMAIL_SYNC_COOLDOWN_SECONDS', 60))
            except Exception:
                stuck_minutes = 15
                cooldown_sec = 60

            # Acquire row-level lock on the config to coordinate across processes
            try:
                locked_cfg = (
                    db_session.query(EmailAuthConfig)
                    .filter_by(oauth_user_id=oauth_user.id, enabled=True)
                    .with_for_update(nowait=False)
                    .one_or_none()
                )
                if not locked_cfg:
                    return False, "Gmail sync not enabled", {}
                gmail_config = locked_cfg
                logger.debug(f"Sync status before start: {gmail_config.sync_status}")
                # Evaluate current status under the lock
                if gmail_config.sync_status == 'syncing':
                    last_update = gmail_config.updated_at
                    is_stale = True
                    if last_update:
                        age_sec = (datetime.utcnow() - last_update).total_seconds()
                        is_stale = age_sec > stuck_minutes * 60
                    if is_stale:
                        stale_msg = f"Previous sync stuck > {stuck_minutes} minutes; resetting"
                        logger.warning(stale_msg)
                        gmail_config.update_sync_status('error', error=stale_msg)
                        db_session.commit()
                    else:
                        logger.info("Gmail sync requested but one is already running (recent). Skipping new start.")
                        db_session.commit()  # release lock
                        return False, "Sync already in progress", {}

                # Respect cooldown after recent completion
                if gmail_config.sync_status == 'completed' and gmail_config.updated_at:
                    age_sec = (datetime.utcnow() - gmail_config.updated_at).total_seconds()
                    if age_sec < cooldown_sec:
                        logger.info(f"Gmail sync requested within cooldown window ({int(age_sec)}s < {cooldown_sec}s). Skipping.")
                        db_session.commit()  # release lock
                        return False, "Sync recently completed; cooldown in effect", {}

                # Mark this run as syncing while holding the lock
                gmail_config.update_sync_status('syncing')
                db_session.commit()
            except Exception as guard_e:
                logger.error(f"Error during sync guard: {guard_e}")


            logger.debug("Starting Gmail message search")
            # Search and process messages
            messages = self.search_messages(oauth_user, gmail_config, max_results=200)

            stats = {
                'messages_found': len(messages),
                'messages_processed': 0,
                'transactions_created': 0,
                'errors': 0
            }
            logger.info(f"Found {stats['messages_found']} messages for user {oauth_user.email}")
            # Enforce strict cutoff: skip any messages received at or before last_sync_at
            cutoff = gmail_config.last_sync_at if gmail_config.last_sync_at else None

            logger.info(f"Syncing messages with cutoff {cutoff}")
            # Process each message for financial data
            for message in messages:
                try:
                    # Strictly skip messages received at or before last sync time
                    if cutoff:
                        try:
                            msg_dt = None
                            if message.get('internal_date'):
                                # Gmail internalDate is in milliseconds since epoch (UTC)
                                msg_dt = datetime.utcfromtimestamp(int(message['internal_date'])/1000.0)
                            elif message.get('date'):
                                msg_dt = message.get('date')
                            if msg_dt and msg_dt <= cutoff:
                                logger.info(f"Skipping message {message.get('id')} at {msg_dt} <= last_sync_at {cutoff}")
                                continue
                        except Exception as _:
                            # On parsing issues, fall back to processing
                            pass
                    # Extract financial transactions from message
                    transactions = self._extract_transactions_from_message(db_session, message, user_id, account_number)
                    
                    if transactions:
                        # Store transactions in database
                        for transaction_data in transactions:
                            try:
                                if isinstance(transaction_data, dict):
                                    # Extract optional meta not part of Transaction model
                                    balance_after = transaction_data.pop('balance_after', None)

                                    # Create Transaction object
                                    transaction = Transaction(**transaction_data)
                                    db_session.add(transaction)

                                    # Update account balance if balance_after is provided
                                    if balance_after is not None:
                                        account = db_session.query(Account).filter_by(
                                            id=transaction_data.get('account_id')
                                        ).first()
                                        if account:
                                            account.balance = balance_after
                                            account.updated_at = datetime.now()

                                    stats['transactions_created'] += 1
                                    logger.info(f"Saved transaction: {(transaction.transaction_details or '')[:50]}...")
                                else:
                                    # Already a Transaction object created by repository
                                    transaction = transaction_data
                                    stats['transactions_created'] += 1
                                    logger.info(f"Saved transaction (repo): {(transaction.transaction_details or '')[:50]}...")
                                
                            except Exception as trans_error:
                                logger.error(f"Error saving transaction: {trans_error}")
                                stats['errors'] += 1
                    
                    stats['messages_processed'] += 1
                    
                except Exception as e:
                    logger.error(f"Error processing message {message['id']}: {e}")
                    stats['errors'] += 1
            
            # Commit all transaction changes
            db_session.commit()
            
            # Update sync completion (use most recent message id by time)
            last_message_id = None
            if messages:
                def _msg_time(m):
                    try:
                        if m.get('internal_date'):
                            return int(m.get('internal_date'))
                        dt = m.get('date')
                        if isinstance(dt, datetime):
                            return int(dt.timestamp() * 1000)
                    except Exception:
                        return 0
                    return 0
                most_recent = max(messages, key=_msg_time)
                last_message_id = most_recent.get('id')

            logger.debug(f"last_message_id: {last_message_id}")
            logger.debug(f"stats: {stats}")

            # Mark sync as completed (even if no messages found). This sets last_sync_at; message_id may be None.
            gmail_config.update_sync_status('completed', message_id=last_message_id)
            logger.info(f"Sync completed: {stats['messages_processed']} messages processed, {stats['transactions_created']} transactions created, {stats['errors']} errors")
            db_session.commit()

            # Reconcile: ensure status persisted as 'completed' and not left as 'syncing' by any race.
            try:
                cfg = db_session.get(EmailAuthConfig, gmail_config.id)
                if cfg and cfg.sync_status != 'completed':
                    logger.warning(
                        f"Sync status persisted as '{cfg.sync_status}' after completion; forcing 'completed'."
                    )
                    cfg.update_sync_status('completed', message_id=last_message_id)
                    db_session.commit()
            except Exception as recon_e:
                logger.error(f"Error during sync status reconciliation: {recon_e}")
            
            return True, f"Sync completed: {stats['messages_processed']} messages processed", stats
            
        except Exception as e:
            logger.error(f"Error syncing Gmail messages: {e}")
            # Rollback DB session to ensure clean state
            try:
                db_session.rollback()
            except Exception:
                pass
            
            # Update sync error status
            try:
                if gmail_config:
                    gmail_config.update_sync_status('error', error=str(e))
                    db_session.commit()
            except Exception:
                pass
            
            return False, f"Sync failed: {str(e)}", {}
            
        finally:
            self.db.close_session(db_session)
    
    def _extract_transactions_from_message(self, db_session, message: Dict, user_id: int, account_number: str) -> List[Dict]:
        """
        Extract financial transactions from an email message using the TransactionParser.
        
        Args:
            db_session: Active SQLAlchemy session from the caller
            message: Message dictionary
            user_id: App user ID
            account_number: Bank account number to associate with transactions
        
        Returns:
            List of transaction objects or dicts compatible with Transaction model
        """
        transactions = []

        try:
            subject = message.get('subject', '')

            # Try to parse transaction data using the parser service
            parsed = self.parser.parse_email(message, subject)
            logger.debug(f"Parsed account check for {account_number}: parsed account={parsed.get('account_number') if isinstance(parsed, dict) else None}")
            if parsed:
                acct_field = parsed.get("account_number") if isinstance(parsed, dict) else None
                acct_field_str = str(acct_field) if acct_field is not None else ""
                if account_number and len(account_number) >= 4 and account_number[-3:] not in acct_field_str:
                    return transactions

                # Add user_id, account_number, and email_metadata_id to transaction data
                parsed["user_id"] = user_id
                parsed["account_number"] = account_number
                # Find the appropriate account for this transaction
                account = None

                email_metadata = self.transaction_repo.create_email_metadata(
                    db_session,
                    {
                        "user_id": user_id,
                        "id": message.get("id"),
                        "subject": message.get("subject", ""),
                        "from": message.get("sender", ""),
                        "date": message.get("date", ""),
                        "body": message.get("body_text", ""),
                        "cleaned_body": parsed.get("transaction_content", ""),
                        "processed": True,
                    },
                )
                if email_metadata:
                    parsed["email_metadata_id"] = email_metadata.id

                if account_number:
                    # Try to find existing account by account number
                    account = db_session.query(Account).filter_by(
                        user_id=user_id,
                        account_number=account_number
                    ).first()

                if not account:
                    # If no specific account found, use the first account for this user
                    account = db_session.query(Account).filter_by(user_id=user_id).first()

                if account:
                    transaction = self.transaction_repo.create_transaction(
                        db_session, parsed
                    )

                    if transaction:
                        transactions.append(transaction)
                    else:
                        # Duplicate or failed creation
                        try:
                            details = getattr(transaction, 'transaction_details', None)
                            if details is None and isinstance(transaction, dict):
                                details = (transaction.get('transaction_details') or '')
                            logger.info(f"Duplicate transaction skipped: {(details or '')[:50]}...")
                        except Exception:
                            logger.info("Duplicate transaction skipped")
                else:
                    logger.warning(f"No account found for transaction in message {message.get('id')}")
            else:
                # Log that no transaction data could be parsed
                logger.debug(f"No transaction data parsed from message: {subject[:50]}...")
        
        except Exception as e:
            logger.error(f"Error extracting transactions from message {message.get('id', 'unknown')}: {e}")
        
        return transactions
    
    def _extract_counterparty(self, subject: str, body: str, sender: str) -> str:
        """Extract counterparty/merchant name from email content."""
        # This is a simplified implementation
        # You would enhance this based on specific patterns from banks
        
        # Try to extract from sender domain
        if '@' in sender:
            domain = sender.split('@')[1].split('.')[0]
            return domain.title()
        
        return "Unknown"
    
    def _classify_transaction(self, subject: str, body: str, sender: str) -> str:
        """Classify transaction into category based on email content."""
        # This is a simplified implementation
        # You would enhance this with more sophisticated classification
        
        text = f"{subject} {body}".lower()
        
        if any(word in text for word in ['grocery', 'supermarket', 'food']):
            return 'Groceries'
        elif any(word in text for word in ['gas', 'fuel', 'station']):
            return 'Transportation'
        elif any(word in text for word in ['restaurant', 'dining', 'coffee']):
            return 'Dining'
        else:
            return 'Other'