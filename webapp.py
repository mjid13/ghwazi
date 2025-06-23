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

from money_tracker.services.parser_service import TransactionParser
from money_tracker.services.email_service import EmailService
from money_tracker.models.database import Database
from money_tracker.models.models import TransactionRepository
from money_tracker.config import settings

# Setup logging
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL),
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
email_service = EmailService()
db = Database()
db.connect()
db.create_tables()

@app.route('/')
def index():
    """Home page with options to input email data."""
    return render_template('index.html')

@app.route('/parse', methods=['POST'])
def parse_email():
    """Parse email data from various sources."""
    email_data = {}
    source = request.form.get('source')

    if source == 'paste':
        # Handle pasted email content
        email_content = request.form.get('email_content')
        if not email_content:
            flash('Please paste email content', 'error')
            return redirect(url_for('index'))

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
            return redirect(url_for('index'))

        file = request.files['email_file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(url_for('index'))

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
                return redirect(url_for('index'))

    else:
        flash('Invalid source', 'error')
        return redirect(url_for('index'))

    # Parse the email data
    transaction_data = parser.parse_email(email_data)

    if not transaction_data:
        flash('Failed to parse email content. Make sure it contains valid transaction data.', 'error')
        return redirect(url_for('index'))

    # Store the transaction data in session for display
    session['transaction_data'] = transaction_data

    # Optionally save to database if requested
    if request.form.get('save_to_db') == 'yes':
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
def results():
    """Display the parsed transaction data."""
    transaction_data = session.get('transaction_data')
    if not transaction_data:
        flash('No transaction data available', 'error')
        return redirect(url_for('index'))

    return render_template('results.html', transaction=transaction_data)

@app.route('/accounts')
def accounts():
    """Display all accounts and their summaries."""
    db_session = db.get_session()
    try:
        from money_tracker.models.models import Account
        accounts = db_session.query(Account).all()

        summaries = []
        for account in accounts:
            summary = TransactionRepository.get_account_summary(db_session, account.account_number)
            if summary:
                summaries.append(summary)

        return render_template('accounts.html', summaries=summaries)
    except Exception as e:
        logger.error(f"Error getting account summaries: {str(e)}")
        flash(f'Error getting account summaries: {str(e)}', 'error')
        return redirect(url_for('index'))
    finally:
        db.close_session(db_session)

@app.route('/account/<account_number>')
def account_details(account_number):
    """Display details for a specific account."""
    db_session = db.get_session()
    try:
        from money_tracker.models.models import Account, Transaction

        account = db_session.query(Account).filter(
            Account.account_number == account_number
        ).first()

        if not account:
            flash(f'Account {account_number} not found', 'error')
            return redirect(url_for('accounts'))

        transactions = db_session.query(Transaction).filter(
            Transaction.account_id == account.id
        ).order_by(Transaction.date_time.desc()).all()

        summary = TransactionRepository.get_account_summary(db_session, account_number)

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

@app.route('/fetch_emails', methods=['POST'])
def fetch_emails():
    """Fetch emails directly from the email account."""
    try:
        # Get email settings from form
        email_host = request.form.get('email_host')
        email_port = request.form.get('email_port')
        email_username = request.form.get('email_username')
        email_password = request.form.get('email_password')
        email_use_ssl = request.form.get('email_use_ssl') == 'true'
        bank_email_addresses = request.form.get('bank_email_addresses')
        bank_email_subjects = request.form.get('bank_email_subjects')

        # Create a custom email service with user-provided settings
        custom_email_service = EmailService(
            host=email_host if email_host else None,
            port=int(email_port) if email_port and email_port.isdigit() else None,
            username=email_username if email_username else None,
            password=email_password if email_password else None,
            use_ssl=email_use_ssl,
            bank_email_addresses=bank_email_addresses.split(',') if bank_email_addresses else None,
            bank_email_subjects=bank_email_subjects.split(',') if bank_email_subjects else None
        )

        # Connect to email
        if not custom_email_service.connect():
            flash('Failed to connect to email server. Check your email settings.', 'error')
            return redirect(url_for('index'))

        # Get bank emails
        folder = request.form.get('folder', 'INBOX')
        unread_only = request.form.get('unread_only', 'true') == 'true'

        emails = custom_email_service.get_bank_emails(folder=folder, unread_only=unread_only)

        if not emails:
            flash('No bank emails found', 'info')
            return redirect(url_for('index'))

        # Parse each email and store results
        parsed_emails = []
        for email_data in emails:
            transaction_data = parser.parse_email(email_data)
            if transaction_data:
                parsed_emails.append({
                    'email': email_data,
                    'transaction': transaction_data
                })

        if not parsed_emails:
            flash('No transaction data found in the emails', 'info')
            return redirect(url_for('index'))

        # Store the first transaction in session for display
        session['transaction_data'] = parsed_emails[0]['transaction']

        # Optionally save to database if requested
        if request.form.get('save_to_db') == 'yes':
            db_session = db.get_session()
            try:
                saved_count = 0
                for parsed_email in parsed_emails:
                    transaction = TransactionRepository.create_transaction(
                        db_session, parsed_email['transaction']
                    )
                    if transaction:
                        saved_count += 1

                if saved_count > 0:
                    flash(f'Saved {saved_count} transactions to database', 'success')
                else:
                    flash('Failed to save transactions to database', 'error')
            except Exception as e:
                logger.error(f"Error saving transactions to database: {str(e)}")
                flash(f'Error saving to database: {str(e)}', 'error')
            finally:
                db.close_session(db_session)

        # Disconnect from email
        custom_email_service.disconnect()

        return redirect(url_for('results'))
    except Exception as e:
        logger.error(f"Error fetching emails: {str(e)}")
        flash(f'Error fetching emails: {str(e)}', 'error')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
