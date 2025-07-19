"""
Bank Email Parser & Account Tracker Web Application

This is a web application that allows users to connect their email, upload, or paste email content,
process it using the existing parsing logic, and display the extracted transaction data.
"""

import os
import logging
import threading
import time
import uuid
import json
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps
import random
import string
from threading import Lock

from money_tracker.services.parser_service import TransactionParser
from money_tracker.services.email_service import EmailService
from money_tracker.services.counterparty_service import CounterpartyService
from money_tracker.services.pdf_parser_service import PDFParser
from money_tracker.models.database import Database
from money_tracker.models.models import TransactionRepository, User, Account, EmailConfiguration, Transaction, Category, CategoryMapping, CategoryType
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
app.config['ALLOWED_EXTENSIONS'] = {'pdf'}

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize services
parser = TransactionParser()
db = Database()
db.connect()
db.create_tables()
counterparty_service = CounterpartyService()

# Task manager for tracking email fetching tasks
email_tasks = {}
email_tasks_lock = Lock()

# Helper function to check if a file has an allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Dictionary to track which accounts are currently being scraped
# Format: {account_number: {'user_id': user_id, 'task_id': task_id, 'start_time': time.time()}}
scraping_accounts = {}

def process_emails_task(task_id, user_id, account_number, bank_name, folder, unread_only, save_to_db, preserve_balance):
    """Background task for processing emails."""
    logger.debug(f"Starting background task {task_id} for user {user_id} on account {account_number}")

    try:

        db_session = db.get_session()
        email_service = EmailService.from_user_config(db_session, user_id)
        if not email_service:
            logger.error(f"Failed to create email service for user {user_id}")
            return

        logger.debug(f"Email service created successfully for user {user_id}")

        # Check if connection succeeds
        if not email_service.connect():
            logger.error(f"Failed to connect to email server for user {user_id}")
            return

        logger.debug(f"Connected to email server for user {user_id}")

        # Update task status
        with email_tasks_lock:
            email_tasks[task_id]['status'] = 'processing'
            email_tasks[task_id]['progress'] = 0
            email_tasks[task_id]['start_time'] = time.time()

        # Get the account to find its associated email configuration
        account = db_session.query(Account).filter(
            Account.user_id == user_id,
            Account.account_number == account_number
        ).first()

        if not account:
            with email_tasks_lock:
                email_tasks[task_id]['status'] = 'error'
                email_tasks[task_id]['message'] = 'Account not found'
            logger.error(f"Account {account_number} not found for user {user_id}")
            return

        # Check if the account has an associated email configuration
        if not account.email_config_id:
            with email_tasks_lock:
                email_tasks[task_id]['status'] = 'error'
                email_tasks[task_id]['message'] = 'This account does not have an associated email configuration'
            logger.error(f"Account {account_number} does not have an associated email configuration for user {user_id}")
            return

        # Get the email configuration for this account
        email_config = db_session.query(EmailConfiguration).filter(
            EmailConfiguration.id == account.email_config_id
        ).first()

        if not email_config:
            with email_tasks_lock:
                email_tasks[task_id]['status'] = 'error'
                email_tasks[task_id]['message'] = 'Email configuration not found'
            logger.error(f"Email configuration not found for account {account_number} of user {user_id}")
            return

        # Create email service from the account's email configuration
        logger.debug(f"Creating email service for account {account_number}")
        email_service = EmailService(
            host=email_config.email_host,
            port=email_config.email_port,
            username=email_config.email_username,
            password=email_config.email_password,
            use_ssl=email_config.email_use_ssl,
            bank_email_addresses=email_config.bank_email_addresses.split(',') if email_config.bank_email_addresses else [],
            bank_email_subjects=email_config.bank_email_subjects.split(',') if email_config.bank_email_subjects else []
        )

        # Connect to email
        if not email_service.connect():
            with email_tasks_lock:
                email_tasks[task_id]['status'] = 'error'
                email_tasks[task_id]['message'] = 'Failed to connect to email server'
            logger.debug(f"Failed to connect to email server for account {account_number}")
            return

        # Get bank emails
        emails = email_service.get_bank_emails(folder=folder, unread_only=unread_only)
        logger.debug(f"Fetched {len(emails)} emails for account {account_number} in folder '{folder}'")

        if not emails:
            with email_tasks_lock:
                email_tasks[task_id]['status'] = 'completed'
                email_tasks[task_id]['message'] = 'No bank emails found'
                email_tasks[task_id]['progress'] = 100
                email_tasks[task_id]['end_time'] = time.time()
            logger.debug(f"No bank emails found for account {account_number}")
            return

        # Parse each email and store results
        parsed_emails = []
        saved_count = 0
        total_emails = len(emails)

        for i, email_data in enumerate(emails):
            # Update progress
            progress = int((i / total_emails) * 100)

            # Calculate estimated time remaining
            if i > 0:
                with email_tasks_lock:
                    email_tasks[task_id]['progress'] = progress
                    elapsed_time = time.time() - email_tasks[task_id]['start_time']
                    emails_per_second = i / elapsed_time
                    remaining_emails = total_emails - i
                    estimated_seconds = remaining_emails / emails_per_second if emails_per_second > 0 else 0
                    email_tasks[task_id]['estimated_seconds'] = estimated_seconds
            else:
                with email_tasks_lock:
                    email_tasks[task_id]['progress'] = progress

            # Parse email to extract transaction data
            transaction_data = parser.parse_email(email_data, bank_name)


            if transaction_data:
                # Check if the account is different
                if account_number[-4:] not in transaction_data.get('account_number'):
                    continue

                # Save email metadata
                email_metadata = TransactionRepository.create_email_metadata(db_session, {
                    'user_id': user_id,
                    'id': email_data.get('id'),
                    'subject': email_data.get('subject', ''),
                    'from': email_data.get('from', ''),
                    'date': email_data.get('date', ''),
                    'body': email_data.get('body', ''),
                    'cleaned_body': transaction_data.get('transaction_content', ''),
                    'processed': True
                })

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
                if save_to_db:
                    # Add preserve_balance flag to transaction data
                    transaction_data['preserve_balance'] = preserve_balance
                    transaction = TransactionRepository.create_transaction(
                        db_session, transaction_data
                    )
                    if transaction:
                        saved_count += 1

        # Disconnect from email
        email_service.disconnect()

        # Update task status
        with email_tasks_lock:
            email_tasks[task_id]['status'] = 'completed'
            email_tasks[task_id]['progress'] = 100
            email_tasks[task_id]['end_time'] = time.time()
            email_tasks[task_id]['parsed_count'] = len(parsed_emails)
            email_tasks[task_id]['saved_count'] = saved_count

            # Store the first transaction in session for display
            if parsed_emails:
                email_tasks[task_id]['first_transaction'] = parsed_emails[0]['transaction']

    except Exception as e:
        logger.error(f"Error in background task: {str(e)}")
        with email_tasks_lock:
            email_tasks[task_id]['status'] = 'error'
            email_tasks[task_id]['message'] = str(e)
    finally:
        # Remove the account from scraping_accounts
        with email_tasks_lock:
            scraping_accounts.pop(account_number, None)
        db.close_session(db_session)

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
    """Home page with landing content."""
    return render_template('index.html', year=datetime.now().year)

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

            # Debug logging
            logger.info(f"Attempting to create user with username: {username}, email: {email}")

            user = TransactionRepository.create_user(db_session, user_data)
            if user:
                logger.info(f"User created successfully: {user.username}")
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            else:
                logger.error("TransactionRepository.create_user returned None")
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
            flash('Error logging in. Please try again.', 'error')
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

        # Get user's email configurations
        email_configs = db_session.query(EmailConfiguration).filter(
            EmailConfiguration.user_id == user_id
        ).all()

        # Get the list of accounts that are currently being scraped
        with email_tasks_lock:
            scraping_account_numbers = list(scraping_accounts.keys())
            
        # Prepare data for charts
        chart_data = {}
        
        if accounts:
            # Import necessary modules for data aggregation
            from sqlalchemy import func, case, extract
            from datetime import datetime, timedelta
            from money_tracker.models.models import Transaction, Category, TransactionType
            
            # 1. Income vs. Expense Comparison Chart
            income_expense_data = db_session.query(
                func.sum(case((Transaction.transaction_type == TransactionType.INCOME, Transaction.amount), else_=0)).label('total_income'),
                func.sum(case((Transaction.transaction_type == TransactionType.EXPENSE, Transaction.amount), else_=0)).label('total_expense')
            ).join(Account).filter(
                Account.user_id == user_id
            ).first()
            
            chart_data['income_expense'] = {
                'labels': ['Income', 'Expense'],
                'datasets': [{
                    'data': [
                        float(income_expense_data.total_income or 0),
                        float(income_expense_data.total_expense or 0)
                    ],
                    'backgroundColor': ['#4CAF50', '#F44336']
                }]
            }
            
            # 2. Category Distribution Pie Chart
            # Get expense transactions with categories
            category_data = db_session.query(
                Category.name,
                Category.color,
                func.sum(Transaction.amount).label('total_amount')
            ).join(
                Transaction, Transaction.category_id == Category.id
            ).join(
                Account, Transaction.account_id == Account.id
            ).filter(
                Account.user_id == user_id,
                Transaction.transaction_type == TransactionType.EXPENSE
            ).group_by(
                Category.name,
                Category.color
            ).order_by(
                func.sum(Transaction.amount).desc()
            ).limit(10).all()
            
            # Format data for pie chart
            category_labels = [cat.name for cat in category_data]
            category_values = [float(cat.total_amount) for cat in category_data]
            
            # Use category colors from database, or fallback to defaults
            default_colors = [
                '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF',
                '#FF9F40', '#8AC249', '#EA5545', '#F46A9B', '#EF9B20'
            ]
            category_colors = []
            for i, cat in enumerate(category_data):
                if cat.color:
                    category_colors.append(cat.color)
                else:
                    # Use default color if category doesn't have one
                    category_colors.append(default_colors[i % len(default_colors)])
            
            chart_data['category_distribution'] = {
                'labels': category_labels,
                'datasets': [{
                    'data': category_values,
                    'backgroundColor': category_colors[:len(category_labels)]
                }]
            }
            
            # 3. Monthly Transaction Trend Line Chart
            # Get data for the last 6 months
            end_date = datetime.now()
            start_date = end_date - timedelta(days=180)  # Approximately 6 months
            
            # Query monthly aggregates
            monthly_data = db_session.query(
                extract('year', Transaction.value_date).label('year'),
                extract('month', Transaction.value_date).label('month'),
                func.sum(case((Transaction.transaction_type == TransactionType.INCOME, Transaction.amount), else_=0)).label('income'),
                func.sum(case((Transaction.transaction_type == TransactionType.EXPENSE, Transaction.amount), else_=0)).label('expense')
            ).join(
                Account, Transaction.account_id == Account.id
            ).filter(
                Account.user_id == user_id,
                Transaction.value_date.between(start_date, end_date)
            ).group_by(
                extract('year', Transaction.value_date),
                extract('month', Transaction.value_date)
            ).order_by(
                extract('year', Transaction.value_date),
                extract('month', Transaction.value_date)
            ).all()
            
            # Format data for line chart
            months = []
            income_values = []
            expense_values = []
            
            for data in monthly_data:
                month_name = datetime(int(data.year), int(data.month), 1).strftime('%b %Y')
                months.append(month_name)
                income_values.append(float(data.income or 0))
                expense_values.append(float(data.expense or 0))
            
            chart_data['monthly_trend'] = {
                'labels': months,
                'datasets': [
                    {
                        'label': 'Income',
                        'data': income_values,
                        'borderColor': '#4CAF50',
                        'backgroundColor': 'rgba(76, 175, 80, 0.1)',
                        'fill': True
                    },
                    {
                        'label': 'Expense',
                        'data': expense_values,
                        'borderColor': '#F44336',
                        'backgroundColor': 'rgba(244, 67, 54, 0.1)',
                        'fill': True
                    }
                ]
            }
            
            # 4. Account Balance Comparison Chart
            account_data = []
            for account in accounts:
                account_data.append({
                    'account_number': account.account_number,
                    'bank_name': account.bank_name,
                    'balance': float(account.balance),
                    'currency': account.currency
                })
            
            # Sort accounts by balance (descending)
            account_data.sort(key=lambda x: x['balance'], reverse=True)
            
            # Format data for bar chart
            account_labels = [f"{acc['bank_name']} ({acc['account_number'][-4:]})" for acc in account_data]
            account_balances = [acc['balance'] for acc in account_data]
            account_currencies = [acc['currency'] for acc in account_data]
            
            chart_data['account_balance'] = {
                'labels': account_labels,
                'datasets': [{
                    'label': 'Balance',
                    'data': account_balances,
                    'backgroundColor': '#2196F3',
                    'borderColor': '#1976D2',
                    'borderWidth': 1
                }],
                'currencies': account_currencies
            }
        
        # Convert chart data to JSON for the template
        chart_data_json = json.dumps(chart_data)

        return render_template('dashboard.html', 
                              accounts=accounts, 
                              email_configs=email_configs,
                              scraping_account_numbers=scraping_account_numbers,
                              chart_data=chart_data_json)
    except Exception as e:
        logger.error(f"Error loading dashboard: {str(e)}")
        flash('Error loading dashboard. Please try again.', 'error')
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
        flash('Error loading profile. Please try again.', 'error')
        return redirect(url_for('dashboard'))
    finally:
        db.close_session(db_session)

@app.route('/accounts/add', methods=['GET', 'POST'])
@login_required
def add_account():
    """Add a new bank account."""
    user_id = session.get('user_id')
    db_session = db.get_session()

    try:
        # Get all email configurations for this user
        email_configs = db_session.query(EmailConfiguration).filter(
            EmailConfiguration.user_id == user_id
        ).all()

        if request.method == 'POST':
            account_number = request.form.get('account_number')
            bank_name = request.form.get('bank_name')
            account_holder = request.form.get('account_holder')
            balance = request.form.get('balance', 0.0)
            currency = request.form.get('currency', 'OMR')
            email_config_id = request.form.get('email_config_id')

            if not account_number or not bank_name:
                flash('Account number and bank name are required', 'error')
                return render_template('add_account.html', email_configs=email_configs)

            # Validate balance
            try:
                balance_float = float(balance) if balance else 0.0
            except ValueError:
                flash('Balance must be a valid number', 'error')
                return render_template('add_account.html', email_configs=email_configs)

            # Create account data
            account_data = {
                'user_id': user_id,
                'account_number': account_number,
                'bank_name': bank_name,
                'account_holder': account_holder,
                'balance': balance_float,
                'currency': currency
            }

            # Add email_config_id if provided
            if email_config_id:
                try:
                    account_data['email_config_id'] = int(email_config_id)
                except ValueError:
                    flash('Invalid email configuration selected', 'error')
                    return render_template('add_account.html', email_configs=email_configs)

            account = TransactionRepository.create_account(db_session, account_data)
            if account:
                flash('Account added successfully', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Error adding account', 'error')
                return render_template('add_account.html', email_configs=email_configs)

        return render_template('add_account.html', email_configs=email_configs)
    except Exception as e:
        logger.error(f"Error adding account: {str(e)}")
        flash('Error adding account. Please try again.', 'error')
        return render_template('add_account.html', email_configs=[])
    finally:
        db.close_session(db_session)

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

        # Get all email configurations for this user
        email_configs = db_session.query(EmailConfiguration).filter(
            EmailConfiguration.user_id == user_id
        ).all()

        if request.method == 'POST':
            account.account_number = request.form.get('account_number')
            account.bank_name = request.form.get('bank_name')
            account.account_holder = request.form.get('account_holder')
            account.balance = float(request.form.get('balance', 0.0))
            account.currency = request.form.get('currency', 'OMR')

            # Update email_config_id
            email_config_id = request.form.get('email_config_id')
            if email_config_id:
                account.email_config_id = int(email_config_id)
            else:
                account.email_config_id = None

            db_session.commit()
            flash('Account updated successfully', 'success')
            return redirect(url_for('dashboard'))

        return render_template('edit_account.html', account=account, email_configs=email_configs)
    except Exception as e:
        logger.error(f"Error editing account: {str(e)}")
        flash(f'Error editing account: {str(e)}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        db.close_session(db_session)

@app.route('/accounts/<int:account_id>/update-balance', methods=['POST'])
@login_required
def update_balance(account_id):
    """Update account balance."""
    user_id = session.get('user_id')
    db_session = db.get_session()

    try:
        account = db_session.query(Account).filter(
            Account.id == account_id,
            Account.user_id == user_id
        ).first()

        if not account:
            flash('Account not found or you do not have permission to update it', 'error')
            return redirect(url_for('dashboard'))

        new_balance = request.form.get('new_balance')
        if not new_balance:
            flash('No balance value provided', 'error')
            return redirect(url_for('account_details', account_number=account.account_number))

        try:
            new_balance = float(new_balance)
            account.balance = new_balance
            account.updated_at = datetime.now()  # Update the timestamp
            db_session.commit()
            flash('Balance updated successfully', 'success')
        except ValueError:
            flash('Invalid balance value provided', 'error')

        # Important: Redirect to the account details page using account_number
        return redirect(url_for('account_details', account_number=account.account_number))
    except Exception as e:
        logger.error(f"Error updating balance: {str(e)}")
        flash(f'Error updating balance: {str(e)}', 'error')
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

        # First delete all transactions associated with the account
        db_session.query(Transaction).filter(Transaction.account_id == account.id).delete()

        # Then delete the account
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

@app.route('/email-configs', methods=['GET'])
@login_required
def email_configs():
    """List all email configurations."""
    user_id = session.get('user_id')
    db_session = db.get_session()

    try:
        # Get all email configurations for this user
        email_configs = db_session.query(EmailConfiguration).filter(
            EmailConfiguration.user_id == user_id
        ).all()

        return render_template('email_configs.html', email_configs=email_configs)
    except Exception as e:
        logger.error(f"Error listing email configurations: {str(e)}")
        flash(f'Error listing email configurations: {str(e)}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        db.close_session(db_session)

@app.route('/email-config/add', methods=['GET', 'POST'])
@login_required
def add_email_config():
    """Add a new email configuration."""
    user_id = session.get('user_id')
    db_session = db.get_session()

    try:
        if request.method == 'POST':
            config_data = {
                'user_id': user_id,
                'name': request.form.get('name', 'Default'),
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
                flash('Email configuration added successfully', 'success')
                return redirect(url_for('email_configs'))
            else:
                flash('Error adding email configuration', 'error')

        return render_template('add_email_config.html')
    except Exception as e:
        logger.error(f"Error adding email configuration: {str(e)}")
        flash(f'Error adding email configuration: {str(e)}', 'error')
        return redirect(url_for('email_configs'))
    finally:
        db.close_session(db_session)

@app.route('/email-config/<int:config_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_email_config(config_id):
    """Edit an existing email configuration."""
    user_id = session.get('user_id')
    db_session = db.get_session()

    try:
        # Get the email configuration
        email_config = db_session.query(EmailConfiguration).filter(
            EmailConfiguration.id == config_id,
            EmailConfiguration.user_id == user_id
        ).first()

        if not email_config:
            flash('Email configuration not found or you do not have permission to edit it', 'error')
            return redirect(url_for('email_configs'))

        if request.method == 'POST':
            email_config.name = request.form.get('name', 'Default')
            email_config.email_host = request.form.get('email_host')
            email_config.email_port = int(request.form.get('email_port'))
            email_config.email_username = request.form.get('email_username')

            # Only update password if provided
            new_password = request.form.get('email_password')
            if new_password:
                email_config.email_password = new_password

            email_config.email_use_ssl = 'email_use_ssl' in request.form
            email_config.bank_email_addresses = request.form.get('bank_email_addresses', '')
            email_config.bank_email_subjects = request.form.get('bank_email_subjects', '')

            db_session.commit()
            flash('Email configuration updated successfully', 'success')
            return redirect(url_for('email_configs'))

        return render_template('edit_email_config.html', email_config=email_config)
    except Exception as e:
        logger.error(f"Error editing email configuration: {str(e)}")
        flash(f'Error editing email configuration: {str(e)}', 'error')
        return redirect(url_for('email_configs'))
    finally:
        db.close_session(db_session)

@app.route('/email-config/<int:config_id>/delete', methods=['POST'])
@login_required
def delete_email_config(config_id):
    """Delete an email configuration."""
    user_id = session.get('user_id')
    db_session = db.get_session()

    try:
        # Get the email configuration
        email_config = db_session.query(EmailConfiguration).filter(
            EmailConfiguration.id == config_id,
            EmailConfiguration.user_id == user_id
        ).first()

        if not email_config:
            flash('Email configuration not found or you do not have permission to delete it', 'error')
            return redirect(url_for('email_configs'))

        # Check if any accounts are using this configuration
        accounts = db_session.query(Account).filter(
            Account.email_config_id == config_id
        ).first()

        if accounts:
            flash('Cannot delete email configuration that is being used by accounts', 'error')
            return redirect(url_for('email_configs'))

        db_session.delete(email_config)
        db_session.commit()
        flash('Email configuration deleted successfully', 'success')
        return redirect(url_for('email_configs'))
    except Exception as e:
        logger.error(f"Error deleting email configuration: {str(e)}")
        flash(f'Error deleting email configuration: {str(e)}', 'error')
        return redirect(url_for('email_configs'))
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

    if source == 'email':
        # Parse the email data
        transaction_data = parser.parse_email(email_data)

        if not transaction_data:
            flash('Failed to parse email content. Make sure it contains valid transaction data.', 'error')
            return redirect(url_for('dashboard'))

        # Check if the account is different
        if account_number[-4:] not in transaction_data.get('account_number'):
            flash(
                f'Transaction account number {transaction_data.get("account_number")} does not match selected account {account_number}',
                'error')
            return redirect(url_for('dashboard'))

        # Add user_id and account_number to transaction data
        transaction_data['user_id'] = user_id
        transaction_data['account_number'] = account_number
        transaction_data['email_data'] = email_data

        # Store the transaction data in session for display
        session['transaction_data'] = transaction_data

        # Optionally save to database if requested
        save_to_db = 'save_to_db' in request.form
        preserve_balance = 'preserve_balance' in request.form

        if save_to_db:
            db_session = db.get_session()
            try:
                # Add preserve_balance flag to transaction data
                transaction_data['preserve_balance'] = preserve_balance
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


@app.route('/results')
@login_required
def results():
    """Display the parsed transaction data."""
    transaction_data = session.get('transaction_data')
    if not transaction_data:
        flash('No transaction data available', 'error')
        return redirect(url_for('dashboard'))

    return render_template('results.html', transaction=transaction_data)

@app.route('/upload_pdf', methods=['GET', 'POST'])
@login_required
def upload_pdf():
    """Upload and parse PDF bank statement."""
    if request.method == 'POST':
        user_id = session.get('user_id')
        account_number = request.form.get('account_number')

        if not account_number:
            flash('Please select an account', 'error')
            return redirect(url_for('dashboard'))

        # Check if the post request has the file part
        if 'pdf_file' not in request.files:
            flash('No file part', 'error')
            return redirect(url_for('dashboard'))

        file = request.files['pdf_file']
        
        # If user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(url_for('dashboard'))

        if file and allowed_file(file.filename):
            # Generate a unique filename to avoid collisions
            filename = secure_filename(f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            try:
                # Parse the PDF file
                pdf_parser = PDFParser()
                transactions = pdf_parser.parse_pdf(filepath)

                if not transactions:
                    flash('No transactions found in the PDF file', 'error')
                    # Clean up the uploaded file
                    os.remove(filepath)
                    return redirect(url_for('dashboard'))

                # Store transactions in the database
                db_session = db.get_session()
                try:
                    transaction_count = 0
                    for transaction_data in transactions:
                        if transaction_data["account_number"] != account_number:
                            logger.error(f"The account number {transaction_data['account_number']} in the PDF does not match the selected account {account_number}")
                            flash(f'Transaction account number {transaction_data["account_number"]} does not match selected account {account_number}', 'error')
                            return redirect(url_for('dashboard'))
                        # Add user_id and account_number to transaction data
                        transaction_data['user_id'] = user_id

                        # Add preserve_balance flag
                        preserve_balance = 'preserve_balance' in request.form
                        transaction_data['preserve_balance'] = preserve_balance
                        
                        # Create transaction in database
                        transaction = TransactionRepository.create_transaction(db_session, transaction_data)
                        if transaction:
                            transaction_count += 1
                    
                    if transaction_count > 0:
                        flash(f'Successfully imported {transaction_count} transactions from PDF', 'success')
                    else:
                        flash('No transactions were imported from the PDF', 'warning')
                    
                    # Clean up the uploaded file
                    os.remove(filepath)
                    return redirect(url_for('account_details', account_number=account_number))
                except Exception as e:
                    logger.error(f"Error saving transactions to database: {str(e)}")
                    flash(f'Error saving to database: {str(e)}', 'error')
                    return redirect(url_for('dashboard'))
                finally:
                    db.close_session(db_session)
            except Exception as e:
                logger.error(f"Error parsing PDF file: {str(e)}")
                flash(f'Error parsing PDF file: {str(e)}', 'error')
                # Clean up the uploaded file if it exists
                if os.path.exists(filepath):
                    os.remove(filepath)
                return redirect(url_for('dashboard'))
        else:
            flash('File type not allowed. Please upload a PDF file.', 'error')
            return redirect(url_for('dashboard'))

    # GET request - render the upload form
    db_session = db.get_session()
    try:
        # Get user accounts for the dropdown
        accounts = TransactionRepository.get_user_accounts(db_session, session.get('user_id'))
        return render_template('dashboard.html', accounts=accounts)
    except Exception as e:
        logger.error(f"Error getting user accounts: {str(e)}")
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('dashboard'))
    finally:
        db.close_session(db_session)

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
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 200, type=int)
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

        transactions_history = TransactionRepository.get_account_transaction_history(
            db_session, user_id, account_number, page=page, per_page=per_page
        )
        summary = TransactionRepository.get_account_summary(db_session, user_id, account_number)

        return render_template('account_details.html', 
                              account=account, 
                              transactions=transactions_history['transactions'],
                              pagination=transactions_history,
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

        # Get all categories for the current user
        categories = db_session.query(Category.id, Category.name).all()

        if request.method == 'POST':

            # Update transaction data

            counterparty_name = request.form.get('counterparty_name', '').strip()
            logger.info(f'Counterparty name: {counterparty_name}')
            category_id = request.form.get('category')
            category_update_scope = request.form.get('category_update_scope', 'single')

            transaction_data = {
                "counterparty_name": counterparty_name,
                'amount': float(request.form.get('amount', 0.0)),
                'transaction_type': request.form.get('transaction_type', 'unknown'),
                'value_date': datetime.strptime(request.form.get('date_time'), '%Y-%m-%dT%H:%M'),
                'description': request.form.get('description', ''),
                'transaction_details': request.form.get('transaction_details', ''),
                'category_id': category_id
            }
            updated_transaction = TransactionRepository.update_transaction(
                db_session, transaction_id, transaction_data
            )

            if updated_transaction:
                if (category_update_scope == 'all_counterparty' and
                        counterparty_name and
                        category_id):

                    # Update all transactions from this counterparty
                    try:
                        success = counterparty_service.categorize_counterparty(
                            user_id=user_id,
                            counterparty_name=counterparty_name,
                            description=None,  # Only match by counterparty name
                            category_id=int(category_id)
                        )

                        if success:
                            flash(
                                f'Transaction updated successfully. All transactions from "{counterparty_name}" have been categorized.',
                                'success')
                        else:
                            flash(
                                'Transaction updated successfully, but failed to update other transactions from this counterparty.',
                                'warning')
                    except Exception as e:
                        logger.error(f"Error updating counterparty transactions: {str(e)}")
                        flash(
                            'Transaction updated successfully, but failed to update other transactions from this counterparty.',
                            'warning')
                else:
                    flash('Transaction updated successfully', 'success')
                    return redirect(url_for('account_details', account_number=transaction.account.account_number))

            else:
                flash('Error updating transaction', 'error')

        return render_template('edit_transaction.html', transaction=transaction, categories=categories)
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
    """Start asynchronous email fetching process."""
    user_id = session.get('user_id')
    account_number = request.form.get('account_number', '').split('|')[0] if '|' in request.form.get('account_number', '') else ''
    bank_name = request.form.get('account_number', '').split('|')[1] if '|' in request.form.get('account_number', '') else ''

    if not account_number:
        flash('Please select an account', 'error')
        return redirect(url_for('dashboard'))

    # Check if the account is already being scraped
    with email_tasks_lock:
        if account_number in scraping_accounts:
            flash('This account is already being scraped. Please wait until it completes.', 'error')
            return redirect(url_for('dashboard'))

        # Create a unique task ID
    try:
        task_id = str(uuid.uuid4())

        # Get form parameters
        folder = request.form.get('folder', 'INBOX')
        unread_only = 'unread_only' in request.form
        save_to_db = 'save_to_db' in request.form
        preserve_balance = 'preserve_balance' in request.form

        # Initialize task
        try:
            with email_tasks_lock:
                email_tasks[task_id] = {
                    'user_id': user_id,
                    'account_number': account_number,
                    'status': 'initializing',
                    'progress': 0,
                    'start_time': time.time(),
                    'folder': folder,
                    'unread_only': unread_only,
                    'save_to_db': save_to_db,
                    'preserve_balance': preserve_balance
                }

                # Mark the account as being scraped
                scraping_accounts[account_number] = {
                    'user_id': user_id,
                    'task_id': task_id,
                    'start_time': time.time()
                }
        except Exception as e:
            logger.error(f"Error initializing email task: {str(e)}")
            flash('Failed to initialize email processing task', 'error')
            return redirect(url_for('dashboard'))

        # Start background thread
        try:
            logger.debug('starting email processing thread')
            thread = threading.Thread(
                target=process_emails_task,
                args=(task_id, user_id, account_number, bank_name, folder, unread_only, save_to_db, preserve_balance)
            )
            logger.debug(f'Starting thread for task {task_id} for account {account_number}')
            thread.daemon = True
            thread.start()
        except Exception as e:
            logger.error(f"Error starting email processing thread: {str(e)}")
            with email_tasks_lock:
                email_tasks.pop(task_id, None)
                # Remove the account from scraping_accounts
                scraping_accounts.pop(account_number, None)
            flash('Failed to start email processing task', 'error')
            return redirect(url_for('dashboard'))

        # Store task ID in session
        try:
            session['email_task_id'] = task_id
        except Exception as e:
            logger.error(f"Error storing task ID in session: {str(e)}")
            with email_tasks_lock:
                email_tasks.pop(task_id, None)
                # Remove the account from scraping_accounts
                scraping_accounts.pop(account_number, None)
            flash('Failed to store task information', 'error')
            return redirect(url_for('dashboard'))

        # Redirect to email processing status page
        return redirect(url_for('email_processing_status'))

    except Exception as e:
        logger.error(f"Unexpected error in fetch_emails: {str(e)}")
        flash('An unexpected error occurred', 'error')
        return redirect(url_for('dashboard'))

@app.route('/email_processing_status')
@login_required
def email_processing_status():
    """Show email processing status page."""
    task_id = session.get('email_task_id')

    with email_tasks_lock:
        if not task_id or task_id not in email_tasks:
            flash('No email processing task found', 'error')
            return redirect(url_for('dashboard'))

        task = email_tasks[task_id].copy()  # Create a copy to avoid holding the lock

    return render_template('email_processing.html', task_id=task_id, task=task)

@app.route('/api/email_task_status/<task_id>')
@login_required
def email_task_status(task_id):
    """API endpoint for checking email task status."""
    with email_tasks_lock:
        if task_id not in email_tasks:
            return jsonify({'error': 'Task not found'}), 404

        task = email_tasks[task_id].copy()  # Create a copy to avoid holding the lock

    # Calculate elapsed time
    elapsed_time = time.time() - task['start_time']

    # Prepare response data
    response = {
        'status': task['status'],
        'progress': task['progress'],
        'elapsed_seconds': elapsed_time,
        'message': task.get('message', '')
    }

    # Add estimated time if available
    if 'estimated_seconds' in task:
        response['estimated_seconds'] = task['estimated_seconds']

    # Add completion data if task is completed
    if task['status'] == 'completed':
        response['parsed_count'] = task.get('parsed_count', 0)
        response['saved_count'] = task.get('saved_count', 0)

        # If there's a transaction, redirect to results
        if 'first_transaction' in task:
            # Store the transaction in session for the results page
            session['transaction_data'] = task['first_transaction']
            response['redirect_url'] = url_for('results')

    return jsonify(response)

@app.route('/api/test_email_connection/<int:config_id>')
@login_required
def test_email_connection(config_id):
    """Test the email connection for a specific configuration."""
    user_id = session.get('user_id')
    db_session = db.get_session()

    try:
        # Get the email configuration
        email_config = db_session.query(EmailConfiguration).filter(
            EmailConfiguration.id == config_id,
            EmailConfiguration.user_id == user_id
        ).first()

        if not email_config:
            return jsonify({
                'success': False,
                'message': 'Email configuration not found'
            }), 404

        # Create email service from the configuration
        email_service = EmailService(
            host=email_config.email_host,
            port=email_config.email_port,
            username=email_config.email_username,
            password=email_config.email_password,
            use_ssl=email_config.email_use_ssl,
            bank_email_addresses=[],
            bank_email_subjects=[]
        )

        # Test connection
        if email_service.connect():
            email_service.disconnect()
            # Update last tested timestamp
            email_config.last_tested = datetime.now()
            db_session.commit()
            return jsonify({
                'success': True,
                'message': 'Successfully connected to email server'
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to connect to email server'
            })

    except Exception as e:
        logger.error(f"Error testing email connection: {str(e)}")
        return jsonify({
            'success': False,
            'message': f'Error: {str(e)}'
        }), 500
    finally:
        db.close_session(db_session)

# Add session configuration
app.permanent_session_lifetime = timedelta(days=30)

@app.before_request
def before_request():
    """Ensure user session is handled properly."""
    # Make session permanent
    session.permanent = True

    # Check if user is logged in and update session timestamp
    if 'user_id' in session:
        session['last_activity'] = time.time()

    # Clear old tasks from email_tasks dict
    current_time = time.time()
    tasks_to_remove = []
    accounts_to_remove = []

    with email_tasks_lock:
        # Clean up old tasks
        for task_id, task in email_tasks.items():
            # Remove tasks older than 1 hour
            if 'end_time' in task and (current_time - task['end_time']) > 3600:
                tasks_to_remove.append(task_id)

        for task_id in tasks_to_remove:
            email_tasks.pop(task_id, None)

        # Clean up stale scraping_accounts entries (older than 30 minutes)
        for account_number, account_info in scraping_accounts.items():
            if (current_time - account_info['start_time']) > 1800:  # 30 minutes
                accounts_to_remove.append(account_number)

        for account_number in accounts_to_remove:
            scraping_accounts.pop(account_number, None)

@app.after_request
def after_request(response):
    """Add security headers to response."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# Error handlers
@app.route('/categories')
@login_required
def categories():
    """List all categories."""
    user_id = session.get('user_id')

    try:
        # Get all categories for this user
        categories = counterparty_service.get_categories(user_id)
        return render_template('categories.html', categories=categories)
    except Exception as e:
        logger.error(f"Error loading categories: {str(e)}")
        flash('Error loading categories. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/categories/add', methods=['GET', 'POST'])
@login_required
def add_category():
    """Add a new category."""
    user_id = session.get('user_id')

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        color = request.form.get('color')

        if not name:
            flash('Category name is required', 'error')
            return render_template('add_category.html')

        category = counterparty_service.create_category(user_id, name, description, color)
        if category:
            flash('Category added successfully', 'success')
            return redirect(url_for('categories'))
        else:
            flash('Error adding category', 'error')
            return render_template('add_category.html')

    return render_template('add_category.html')

@app.route('/categories/<int:category_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    """Edit a category."""
    user_id = session.get('user_id')

    # Get the category
    category = counterparty_service.get_category(category_id, user_id)
    if not category:
        flash('Category not found', 'error')
        return redirect(url_for('categories'))

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        color = request.form.get('color')

        if not name:
            flash('Category name is required', 'error')
            return render_template('edit_category.html', category=category)

        result = counterparty_service.update_category(category_id, user_id, name, description, color)
        if result:
            flash('Category updated successfully', 'success')
            return redirect(url_for('categories'))
        else:
            flash('Error updating category', 'error')
            return render_template('edit_category.html', category=category)

    return render_template('edit_category.html', category=category)

@app.route('/categories/<int:category_id>/delete', methods=['POST'])
@login_required
def delete_category(category_id):
    """Delete a category."""
    user_id = session.get('user_id')

    result = counterparty_service.delete_category(category_id, user_id)
    if result:
        flash('Category deleted successfully', 'success')
    else:
        flash('Error deleting category', 'error')

    return redirect(url_for('categories'))

@app.route('/categories/<int:category_id>/mappings')
@login_required
def category_mappings(category_id):
    """List all mappings for a category."""
    user_id = session.get('user_id')

    # Get the category
    category = counterparty_service.get_category(category_id, user_id)
    if not category:
        flash('Category not found', 'error')
        return redirect(url_for('categories'))

    # Get the mappings
    mappings = counterparty_service.get_category_mappings(category_id, user_id)

    return render_template('category_mappings.html', category=category, mappings=mappings)

@app.route('/categories/<int:category_id>/mappings/add', methods=['GET', 'POST'])
@login_required
def add_category_mapping(category_id):
    """Add a new category mapping."""
    user_id = session.get('user_id')

    # Get the category
    category = counterparty_service.get_category(category_id, user_id)
    if not category:
        flash('Category not found', 'error')
        return redirect(url_for('categories'))

    if request.method == 'POST':
        mapping_type = request.form.get('mapping_type')
        pattern = request.form.get('pattern')

        if not mapping_type or not pattern:
            flash('Mapping type and pattern are required', 'error')
            return render_template('add_category_mapping.html', category=category)

        # Convert mapping_type string to enum
        try:
            mapping_type_enum = CategoryType[mapping_type]
        except KeyError:
            flash('Invalid mapping type', 'error')
            return render_template('add_category_mapping.html', category=category)

        mapping = counterparty_service.create_category_mapping(category_id, user_id, mapping_type_enum, pattern)
        if mapping:
            flash('Category mapping added successfully', 'success')
            return redirect(url_for('category_mappings', category_id=category_id))
        else:
            flash('Error adding category mapping', 'error')
            return render_template('add_category_mapping.html', category=category)

    return render_template('add_category_mapping.html', category=category)

@app.route('/categories/mappings/<int:mapping_id>/delete', methods=['POST'])
@login_required
def delete_category_mapping(mapping_id):
    """Delete a category mapping."""
    user_id = session.get('user_id')

    # Get the category_id from the form
    category_id = request.form.get('category_id')
    if not category_id:
        flash('Category ID is required', 'error')
        return redirect(url_for('categories'))

    result = counterparty_service.delete_category_mapping(mapping_id, user_id)
    if result:
        flash('Category mapping deleted successfully', 'success')
    else:
        flash('Error deleting category mapping', 'error')

    return redirect(url_for('category_mappings', category_id=category_id))

@app.route('/counterparties')
@login_required
def counterparties():
    """List all unique counterparties."""
    user_id = session.get('user_id')

    try:
        # Get all unique counterparties for this user
        counterparties = counterparty_service.get_unique_counterparties(user_id)

        # Get all categories for this user (for the categorization form)
        categories = counterparty_service.get_categories(user_id)

        return render_template('counterparties.html', counterparties=counterparties, categories=categories)
    except Exception as e:
        logger.error(f"Error loading counterparties: {str(e)}")
        flash('Error loading counterparties. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/counterparties/categorize', methods=['POST'])
@login_required
def categorize_counterparty():
    """Categorize a counterparty."""
    user_id = session.get('user_id')

    counterparty_name = request.form.get('counterparty_name')
    description = request.form.get('description')
    category_id = request.form.get('category_id')

    if not counterparty_name or not category_id:
        flash('Counterparty name and category are required', 'error')
        return redirect(url_for('counterparties'))

    try:
        category_id = int(category_id)
    except ValueError:
        flash('Invalid category ID', 'error')
        return redirect(url_for('counterparties'))

    result = counterparty_service.categorize_counterparty(user_id, counterparty_name, description, category_id)
    if result:
        flash('Counterparty categorized successfully', 'success')
    else:
        flash('Error categorizing counterparty', 'error')

    return redirect(url_for('counterparties'))

@app.route('/auto-categorize')
@login_required
def auto_categorize():
    """Auto-categorize all uncategorized transactions."""
    user_id = session.get('user_id')

    count = counterparty_service.auto_categorize_all_transactions(user_id)
    flash(f'Auto-categorized {count} transactions', 'success')

    return redirect(url_for('dashboard'))

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

# Add CSRF protection
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
    return session['csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.before_request
def csrf_protect():
    if request.method == "POST":
        token = session.get('csrf_token', None)
        if not token or token != request.form.get('csrf_token'):
            flash('Invalid form submission, please try again', 'error')
            return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
