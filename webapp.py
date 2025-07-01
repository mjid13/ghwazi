"""
Bank Email Parser & Account Tracker Web Application

This is a web application that allows users to connect their email, upload, or paste email content,
process it using the existing parsing logic, and display the extracted transaction data.
"""

import os
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
from datetime import datetime
from functools import wraps

from money_tracker.services.parser_service import TransactionParser
from money_tracker.services.email_service import EmailService
from money_tracker.models.database import Database
from money_tracker.models.models import TransactionRepository, User, Account, EmailConfiguration, EmailMetadata, Transaction
from money_tracker.config import settings

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    # level=getattr(logging, settings.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, template_folder='templates')
app.secret_key = os.getenv('SECRET_KEY', 'dev_key_for_development_only')
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload size

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize services
parser = TransactionParser()
db = Database()
db.connect()
db.create_tables()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Home page with options to input email data."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Register a new user."""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if not username or not email or not password:
            flash('All fields are required', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')

        db_session = db.get_session()
        try:
            # Check if user already exists
            existing_user = db_session.query(User).filter(
                (User.username == username) | (User.email == email)
            ).first()

            if existing_user:
                flash('Username or email already exists', 'error')
                return render_template('register.html')

            # Create new user
            user_data = {
                'username': username,
                'email': email,
                'password': password
            }

            user = TransactionRepository.create_user(db_session, user_data)
            if user:
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Error creating user', 'error')
                return render_template('register.html')

        except Exception as e:
            logger.error(f"Error registering user: {str(e)}")
            flash(f'Error registering user: {str(e)}', 'error')
            return render_template('register.html')
        finally:
            db.close_session(db_session)

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Log in a user."""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html')

        db_session = db.get_session()
        try:
            user = db_session.query(User).filter(User.username == username).first()

            if not user or not user.check_password(password):
                flash('Invalid username or password', 'error')
                return render_template('login.html')

            # Set user session
            session['user_id'] = user.id
            session['username'] = user.username

            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            logger.error(f"Error logging in: {str(e)}")
            flash(f'Error logging in: {str(e)}', 'error')
            return render_template('login.html')
        finally:
            db.close_session(db_session)

    return render_template('login.html')

@app.route('/logout')
def logout():
    """Log out a user."""
    session.clear()
    flash('You have been logged out', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard."""
    user_id = session.get('user_id')
    db_session = db.get_session()

    try:
        # Get user's accounts
        accounts = TransactionRepository.get_user_accounts(db_session, user_id)

        # Get user's email configuration
        email_config = db_session.query(EmailConfiguration).filter(
            EmailConfiguration.user_id == user_id
        ).first()

        return render_template('dashboard.html', 
                              accounts=accounts, 
                              email_config=email_config)
    except Exception as e:
        logger.error(f"Error loading dashboard: {str(e)}")
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return redirect(url_for('index'))
    finally:
        db.close_session(db_session)

@app.route('/profile')
@login_required
def profile():
    """User profile page."""
    user_id = session.get('user_id')
    db_session = db.get_session()

    try:
        user = db_session.query(User).filter(User.id == user_id).first()
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('dashboard'))

        return render_template('profile.html', user=user)
    except Exception as e:
        logger.error(f"Error loading profile: {str(e)}")
        flash(f'Error loading profile: {str(e)}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        db.close_session(db_session)

@app.route('/accounts/add', methods=['GET', 'POST'])
@login_required
def add_account():
    """Add a new bank account."""
    if request.method == 'POST':
        user_id = session.get('user_id')
        account_number = request.form.get('account_number')
        bank_name = request.form.get('bank_name')
        account_holder = request.form.get('account_holder')
        balance = request.form.get('balance', 0.0)
        currency = request.form.get('currency', 'OMR')

        if not account_number or not bank_name:
            flash('Account number and bank name are required', 'error')
            return render_template('add_account.html')

        db_session = db.get_session()
        try:
            # Create account data
            account_data = {
                'user_id': user_id,
                'account_number': account_number,
                'bank_name': bank_name,
                'account_holder': account_holder,
                'balance': float(balance) if balance else 0.0,
                'currency': currency
            }

            account = TransactionRepository.create_account(db_session, account_data)
            if account:
                flash('Account added successfully', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Error adding account', 'error')
                return render_template('add_account.html')

        except Exception as e:
            logger.error(f"Error adding account: {str(e)}")
            flash(f'Error adding account: {str(e)}', 'error')
            return render_template('add_account.html')
        finally:
            db.close_session(db_session)

    return render_template('add_account.html')

@app.route('/accounts/<int:account_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_account(account_id):
    """Edit a bank account."""
    user_id = session.get('user_id')
    db_session = db.get_session()

    try:
        account = db_session.query(Account).filter(
            Account.id == account_id,
            Account.user_id == user_id
        ).first()

        if not account:
            flash('Account not found or you do not have permission to edit it', 'error')
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            account.account_number = request.form.get('account_number')
            account.bank_name = request.form.get('bank_name')
            account.account_holder = request.form.get('account_holder')
            account.balance = float(request.form.get('balance', 0.0))
            account.currency = request.form.get('currency', 'OMR')

            db_session.commit()
            flash('Account updated successfully', 'success')
            return redirect(url_for('dashboard'))

        return render_template('edit_account.html', account=account)
    except Exception as e:
        logger.error(f"Error editing account: {str(e)}")
        flash(f'Error editing account: {str(e)}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        db.close_session(db_session)

@app.route('/accounts/<int:account_id>/delete', methods=['POST'])
@login_required
def delete_account(account_id):
    """Delete a bank account."""
    user_id = session.get('user_id')
    db_session = db.get_session()

    try:
        account = db_session.query(Account).filter(
            Account.id == account_id,
            Account.user_id == user_id
        ).first()

        if not account:
            flash('Account not found or you do not have permission to delete it', 'error')
            return redirect(url_for('dashboard'))

        # Check if account has transactions
        transactions = db_session.query(Transaction).filter(
            Transaction.account_id == account.id
        ).first()

        if transactions:
            flash('Cannot delete account with transactions', 'error')
            return redirect(url_for('dashboard'))

        db_session.delete(account)
        db_session.commit()
        flash('Account deleted successfully', 'success')
        return redirect(url_for('dashboard'))
    except Exception as e:
        logger.error(f"Error deleting account: {str(e)}")
        flash(f'Error deleting account: {str(e)}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        db.close_session(db_session)

@app.route('/email-config', methods=['GET', 'POST'])
@login_required
def email_config():
    """Manage email configuration."""
    user_id = session.get('user_id')
    db_session = db.get_session()

    try:
        # Get existing email configuration
        email_config = db_session.query(EmailConfiguration).filter(
            EmailConfiguration.user_id == user_id
        ).first()

        if request.method == 'POST':
            config_data = {
                'user_id': user_id,
                'email_host': request.form.get('email_host'),
                'email_port': int(request.form.get('email_port')),
                'email_username': request.form.get('email_username'),
                'email_password': request.form.get('email_password'),
                'email_use_ssl': 'email_use_ssl' in request.form,
                'bank_email_addresses': request.form.get('bank_email_addresses', ''),
                'bank_email_subjects': request.form.get('bank_email_subjects', '')
            }

            result = TransactionRepository.create_email_config(db_session, config_data)
            if result:
                flash('Email configuration saved successfully', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Error saving email configuration', 'error')

        return render_template('email_config.html', email_config=email_config)
    except Exception as e:
        logger.error(f"Error managing email configuration: {str(e)}")
        flash(f'Error managing email configuration: {str(e)}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        db.close_session(db_session)

@app.route('/parse', methods=['POST'])
@login_required
def parse_email():
    """Parse email data from various sources."""
    user_id = session.get('user_id')
    email_data = {}
    source = request.form.get('source')
    account_number = request.form.get('account_number')

    if not account_number:
        flash('Please select an account', 'error')
        return redirect(url_for('dashboard'))

    if source == 'paste':
        # Handle pasted email content
        email_content = request.form.get('email_content')
        if not email_content:
            flash('Please paste email content', 'error')
            return redirect(url_for('dashboard'))

        email_data = {
            'id': f'manual_{datetime.now().strftime("%Y%m%d%H%M%S")}',
            'subject': request.form.get('subject', 'Manual Entry'),
            'from': request.form.get('from', 'manual@example.com'),
            'date': datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z'),
            'body': email_content
        }

    elif source == 'upload':
        # Handle uploaded email file
        if 'email_file' not in request.files:
            flash('No file part', 'error')
            return redirect(url_for('dashboard'))

        file = request.files['email_file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(url_for('dashboard'))

        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    email_content = f.read()

                email_data = {
                    'id': f'upload_{datetime.now().strftime("%Y%m%d%H%M%S")}',
                    'subject': filename,
                    'from': request.form.get('from', 'upload@example.com'),
                    'date': datetime.now().strftime('%a, %d %b %Y %H:%M:%S %z'),
                    'body': email_content
                }

                # Clean up the uploaded file
                os.remove(filepath)
            except Exception as e:
                logger.error(f"Error reading uploaded file: {str(e)}")
                flash(f'Error reading file: {str(e)}', 'error')
                return redirect(url_for('dashboard'))

    else:
        flash('Invalid source', 'error')
        return redirect(url_for('dashboard'))

    # Parse the email data
    transaction_data = parser.parse_email(email_data)

    if not transaction_data:
        flash('Failed to parse email content. Make sure it contains valid transaction data.', 'error')
        return redirect(url_for('dashboard'))

    # Add user_id and account_number to transaction data
    transaction_data['user_id'] = user_id
    transaction_data['account_number'] = account_number
    transaction_data['email_data'] = email_data

    # Store the transaction data in session for display
    session['transaction_data'] = transaction_data

    # Optionally save to database if requested
    save_to_db = 'save_to_db' in request.form
    if save_to_db:
        db_session = db.get_session()
        try:
            transaction = TransactionRepository.create_transaction(db_session, transaction_data)
            if transaction:
                flash('Transaction saved to database', 'success')
            else:
                flash('Failed to save transaction to database', 'error')
        except Exception as e:
            logger.error(f"Error saving transaction to database: {str(e)}")
            flash(f'Error saving to database: {str(e)}', 'error')
        finally:
            db.close_session(db_session)

    return redirect(url_for('results'))

@app.route('/results')
@login_required
def results():
    """Display the parsed transaction data."""
    transaction_data = session.get('transaction_data')
    if not transaction_data:
        flash('No transaction data available', 'error')
        return redirect(url_for('dashboard'))

    return render_template('results.html', transaction=transaction_data)

@app.route('/accounts')
@login_required
def accounts():
    """Display all accounts and their summaries."""
    user_id = session.get('user_id')
    db_session = db.get_session()
    try:
        # Get user's accounts
        accounts = TransactionRepository.get_user_accounts(db_session, user_id)

        summaries = []
        for account in accounts:
            summary = TransactionRepository.get_account_summary(db_session, user_id, account.account_number)
            if summary:
                summaries.append(summary)

        return render_template('accounts.html', summaries=summaries)
    except Exception as e:
        logger.error(f"Error getting account summaries: {str(e)}")
        flash(f'Error getting account summaries: {str(e)}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        db.close_session(db_session)

@app.route('/account/<account_number>')
@login_required
def account_details(account_number):
    """Display details for a specific account."""
    user_id = session.get('user_id')
    db_session = db.get_session()
    try:
        # Get account for this user
        account = db_session.query(Account).filter(
            Account.user_id == user_id,
            Account.account_number == account_number
        ).first()

        if not account:
            flash(f'Account {account_number} not found or you do not have permission to view it', 'error')
            return redirect(url_for('accounts'))

        transactions = db_session.query(Transaction).filter(
            Transaction.account_id == account.id
        ).order_by(Transaction.date_time.desc()).all()

        summary = TransactionRepository.get_account_summary(db_session, user_id, account_number)

        return render_template('account_details.html', 
                              account=account, 
                              transactions=transactions, 
                              summary=summary)
    except Exception as e:
        logger.error(f"Error getting account details: {str(e)}")
        flash(f'Error getting account details: {str(e)}', 'error')
        return redirect(url_for('accounts'))
    finally:
        db.close_session(db_session)

@app.route('/transactions/<int:transaction_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_transaction(transaction_id):
    """Edit a transaction."""
    user_id = session.get('user_id')
    db_session = db.get_session()

    try:
        # Get transaction and verify it belongs to the user
        transaction = db_session.query(Transaction).join(Account).filter(
            Transaction.id == transaction_id,
            Account.user_id == user_id
        ).first()

        if not transaction:
            flash('Transaction not found or you do not have permission to edit it', 'error')
            return redirect(url_for('accounts'))

        if request.method == 'POST':
            # Update transaction data
            transaction_data = {
                'amount': float(request.form.get('amount', 0.0)),
                'transaction_type': request.form.get('transaction_type', 'unknown'),
                'date_time': datetime.strptime(request.form.get('date_time'), '%Y-%m-%dT%H:%M'),
                'description': request.form.get('description', ''),
                'transaction_details': request.form.get('transaction_details', '')
            }

            updated_transaction = TransactionRepository.update_transaction(
                db_session, transaction_id, transaction_data
            )

            if updated_transaction:
                flash('Transaction updated successfully', 'success')
                return redirect(url_for('account_details', account_number=transaction.account.account_number))
            else:
                flash('Error updating transaction', 'error')

        return render_template('edit_transaction.html', transaction=transaction)
    except Exception as e:
        logger.error(f"Error editing transaction: {str(e)}")
        flash(f'Error editing transaction: {str(e)}', 'error')
        return redirect(url_for('accounts'))
    finally:
        db.close_session(db_session)

@app.route('/transactions/<int:transaction_id>/delete', methods=['POST'])
@login_required
def delete_transaction(transaction_id):
    """Delete a transaction."""
    user_id = session.get('user_id')
    db_session = db.get_session()

    try:
        # Get transaction and verify it belongs to the user
        transaction = db_session.query(Transaction).join(Account).filter(
            Transaction.id == transaction_id,
            Account.user_id == user_id
        ).first()

        if not transaction:
            flash('Transaction not found or you do not have permission to delete it', 'error')
            return redirect(url_for('accounts'))

        account_number = transaction.account.account_number

        result = TransactionRepository.delete_transaction(db_session, transaction_id)
        if result:
            flash('Transaction deleted successfully', 'success')
        else:
            flash('Error deleting transaction', 'error')

        return redirect(url_for('account_details', account_number=account_number))
    except Exception as e:
        logger.error(f"Error deleting transaction: {str(e)}")
        flash(f'Error deleting transaction: {str(e)}', 'error')
        return redirect(url_for('accounts'))
    finally:
        db.close_session(db_session)

@app.route('/fetch_emails', methods=['POST'])
@login_required
def fetch_emails():
    """Fetch emails directly from the email account."""
    user_id = session.get('user_id')
    account_number = request.form.get('account_number')

    if not account_number:
        flash('Please select an account', 'error')
        return redirect(url_for('dashboard'))

    db_session = db.get_session()
    try:
        # Create email service from user's configuration
        email_service = EmailService.from_user_config(db_session, user_id)

        if not email_service:
            flash('Email configuration not found. Please set up your email first.', 'error')
            return redirect(url_for('email_config'))

        # Connect to email
        if not email_service.connect():
            flash('Failed to connect to email server. Check your email settings.', 'error')
            return redirect(url_for('dashboard'))

        # Get bank emails
        folder = request.form.get('folder', 'INBOX')
        unread_only = 'unread_only' in request.form

        emails = email_service.get_bank_emails(folder=folder, unread_only=unread_only)

        if not emails:
            flash('No bank emails found', 'info')
            return redirect(url_for('dashboard'))

        # Parse each email and store results
        parsed_emails = []
        saved_count = 0

        for email_data in emails:
            # Save email metadata
            email_metadata = TransactionRepository.create_email_metadata(db_session, {
                'user_id': user_id,
                'id': email_data.get('id'),
                'subject': email_data.get('subject', ''),
                'from': email_data.get('from', ''),
                'to': email_data.get('to', ''),
                'date': email_data.get('date', ''),
                'body': email_data.get('body', ''),
                'processed': True
            })

            # Parse email to extract transaction data
            transaction_data = parser.parse_email(email_data)

            if transaction_data:
                # Add user_id, account_number, and email_metadata_id to transaction data
                transaction_data['user_id'] = user_id
                transaction_data['account_number'] = account_number

                if email_metadata:
                    transaction_data['email_metadata_id'] = email_metadata.id

                parsed_emails.append({
                    'email': email_data,
                    'transaction': transaction_data
                })

                # Save to database if requested
                save_to_db = 'save_to_db' in request.form
                if save_to_db:
                    transaction = TransactionRepository.create_transaction(
                        db_session, transaction_data
                    )
                    if transaction:
                        saved_count += 1

        if not parsed_emails:
            flash('No transaction data found in the emails', 'info')
            return redirect(url_for('dashboard'))

        # Store the first transaction in session for display
        session['transaction_data'] = parsed_emails[0]['transaction']

        if 'save_to_db' in request.form:
            if saved_count > 0:
                flash(f'Saved {saved_count} transactions to database', 'success')
            else:
                flash('Failed to save transactions to database', 'error')

        # Disconnect from email
        email_service.disconnect()

        return redirect(url_for('results'))
    except Exception as e:
        logger.error(f"Error fetching emails: {str(e)}")
        flash(f'Error fetching emails: {str(e)}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        db.close_session(db_session)

if __name__ == '__main__':
    app.run(debug=True)
