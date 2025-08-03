"""
API views for the Flask application.
"""
import logging
import json
import os
from datetime import time, datetime
from threading import Lock

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, current_app, Blueprint
from app.models import Database, TransactionRepository, Transaction, Account, Category
from app.utils.decorators import login_required
from werkzeug.utils import secure_filename

from ghwawzi.app.services.pdf_parser_service import PDFParser
from ghwawzi.app.utils.helpers import allowed_file

# Create blueprint
api_bp = Blueprint('api', __name__)

# Initialize database and logger
db = Database()
logger = logging.getLogger(__name__)


@api_bp.route('/get_chart_data')
@login_required
def get_chart_data():
    """Get chart data filtered by account and date range."""
    user_id = session.get('user_id')
    account_number = request.args.get('account_number', 'all')
    date_range = request.args.get('date_range', 'overall')

    db_session = db.get_session()

    try:
        # Prepare data for charts
        chart_data = {}

        # Import necessary modules for data aggregation
        from sqlalchemy import func, case, extract
        from datetime import datetime, timedelta
        from money_tracker.models.models import Transaction, Category, TransactionType

        # Calculate date range based on selection
        end_date = datetime.now()
        start_date = None

        if date_range == '2w':  # Last 2 weeks
            start_date = end_date - timedelta(days=14)
        elif date_range == '1m':  # Last month
            start_date = end_date - timedelta(days=30)
        elif date_range == '3m':  # Last 3 months
            start_date = end_date - timedelta(days=90)
        elif date_range == '6m':  # Last 6 months
            start_date = end_date - timedelta(days=180)
        elif date_range == '12m':  # Last 12 months
            start_date = end_date - timedelta(days=365)
        elif date_range == '24m':  # Last 24 months
            start_date = end_date - timedelta(days=730)
        # For 'overall', start_date remains None

        # Base query for transactions
        base_query = db_session.query(Transaction).join(Account)

        # Filter by user_id
        base_query = base_query.filter(Account.user_id == user_id)

        # Filter by account_number if specified
        if account_number != 'all':
            base_query = base_query.filter(Account.account_number == account_number)

        # 1. Income vs. Expense Comparison Chart
        income_expense_query = db_session.query(
            func.sum(case((Transaction.transaction_type == TransactionType.INCOME, Transaction.amount), else_=0)).label(
                'total_income'),
            func.sum(
                case((Transaction.transaction_type == TransactionType.EXPENSE, Transaction.amount), else_=0)).label(
                'total_expense')
        ).join(Account)

        # Filter by user_id
        income_expense_query = income_expense_query.filter(Account.user_id == user_id)

        # Filter by account_number if specified
        if account_number != 'all':
            income_expense_query = income_expense_query.filter(Account.account_number == account_number)

        # Apply date range filter
        if start_date:
            income_expense_query = income_expense_query.filter(Transaction.value_date >= start_date)

        income_expense_data = income_expense_query.first()

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
        category_query = db_session.query(
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
        )

        # Filter by account_number if specified
        if account_number != 'all':
            category_query = category_query.filter(Account.account_number == account_number)
        # Apply date range filter
        if start_date:
            category_query = category_query.filter(Transaction.value_date >= start_date)

        category_data = category_query.group_by(
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

        # Query monthly aggregates
        monthly_query = db_session.query(
            extract('year', Transaction.value_date).label('year'),
            extract('month', Transaction.value_date).label('month'),
            func.sum(case((Transaction.transaction_type == TransactionType.INCOME, Transaction.amount), else_=0)).label(
                'income'),
            func.sum(
                case((Transaction.transaction_type == TransactionType.EXPENSE, Transaction.amount), else_=0)).label(
                'expense')
        ).join(
            Account, Transaction.account_id == Account.id
        ).filter(
            Account.user_id == user_id,
            Transaction.value_date.between(start_date, end_date)
        )

        # Filter by account_number if specified
        if account_number != 'all':
            monthly_query = monthly_query.filter(Account.account_number == account_number)

        # Apply date range filter
        if start_date:
            monthly_query = monthly_query.filter(Transaction.value_date >= start_date)

        monthly_data = monthly_query.group_by(
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
        # For account balance chart, we'll only show the selected account if one is specified
        # Otherwise, show all accounts
        account_query = db_session.query(Account).filter(Account.user_id == user_id)

        if account_number != 'all':
            account_query = account_query.filter(Account.account_number == account_number)

        accounts_for_chart = account_query.all()

        account_data = []
        for account in accounts_for_chart:
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

        return jsonify(chart_data)
    except Exception as e:
        logger.error(f"Error getting chart data: {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close_session(db_session)


@api_bp.route('/get_category_chart_data')
@login_required
def get_category_chart_data():
    """Get category chart data filtered by account, date range, and category type."""
    user_id = session.get('user_id')
    account_number = request.args.get('account_number', 'all')
    date_range = request.args.get('date_range', 'overall')
    category_type = request.args.get('category_type', 'expense')

    db_session = db.get_session()

    try:
        from sqlalchemy import func
        from datetime import datetime, timedelta
        from money_tracker.models.models import Transaction, Category, TransactionType

        # Calculate date range based on selection
        end_date = datetime.now()
        start_date = None

        if date_range == '2w':
            start_date = end_date - timedelta(days=14)
        elif date_range == '1m':
            start_date = end_date - timedelta(days=30)
        elif date_range == '3m':
            start_date = end_date - timedelta(days=90)
        elif date_range == '6m':
            start_date = end_date - timedelta(days=180)
        elif date_range == '12m':
            start_date = end_date - timedelta(days=365)
        elif date_range == '24m':
            start_date = end_date - timedelta(days=730)

        # Determine transaction type based on category_type filter
        transaction_type = TransactionType.EXPENSE if category_type == 'expense' else TransactionType.INCOME

        # Get category distribution
        category_query = db_session.query(
            Category.name,
            Category.color,
            func.sum(Transaction.amount).label('total_amount')
        ).join(
            Transaction, Transaction.category_id == Category.id
        ).join(
            Account, Transaction.account_id == Account.id
        ).filter(
            Account.user_id == user_id,
            Transaction.transaction_type == transaction_type
        )

        # Apply date filter if specified
        if start_date:
            category_query = category_query.filter(Transaction.value_date >= start_date)

        # Filter by account_number if specified
        if account_number != 'all':
            category_query = category_query.filter(Account.account_number == account_number)

        category_data = category_query.group_by(
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
                category_colors.append(default_colors[i % len(default_colors)])

        chart_data = {
            'labels': category_labels,
            'datasets': [{
                'data': category_values,
                'backgroundColor': category_colors[:len(category_labels)]
            }]
        }

        return jsonify(chart_data)

    except Exception as e:
        logger.error(f"Error getting category chart data: {str(e)}")
        return jsonify({'error': str(e)}), 500
    finally:
        db.close_session(db_session)


@api_bp.route('/upload_pdf', methods=['GET', 'POST'])
@login_required
def upload_pdf():
    """Upload and parse PDF bank statement."""
    if request.method == 'POST':
        user_id = session.get('user_id')
        is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
        account_number = request.form.get('account_number')

        if not account_number:
            if is_ajax:
                return jsonify({'success': False, 'message': 'Please select an account'})
            flash('Please select an account', 'error')
            return redirect(url_for('dashboard'))

        # Check if the post request has the file part
        if 'pdf_file' not in request.files:
            if is_ajax:
                return jsonify({'success': False, 'message': 'No file part'})
            flash('No file part', 'error')
            return redirect(url_for('dashboard'))

        file = request.files['pdf_file']

        # If user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            if is_ajax:
                return jsonify({'success': False, 'message': 'No selected file'})
            flash('No selected file', 'error')
            return redirect(url_for('dashboard'))

        if file and allowed_file(file.filename):
            # Generate a unique filename to avoid collisions
            filename = secure_filename(f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
            filepath = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            try:
                # Parse the PDF file
                pdf_parser = PDFParser()
                transactions = pdf_parser.parse_pdf(filepath)

                if not transactions:
                    if is_ajax:
                        return jsonify({'success': False, 'message': 'No transactions found in the PDF file'})
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
                            logger.error(
                                f"The account number {transaction_data['account_number']} in the PDF does not match the selected account {account_number}")
                            if is_ajax:
                                return jsonify({'success': False,
                                                'message': f'Transaction account number {transaction_data["account_number"]} does not match selected account {account_number}'})
                            flash(
                                f'Transaction account number {transaction_data["account_number"]} does not match selected account {account_number}',
                                'error')
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

                    # Commit all transactions before cleanup
                    db_session.commit()

                    # Now safe to clean up the uploaded file
                    if filepath and os.path.exists(filepath):
                        os.remove(filepath)
                        logger.info(f"Successfully removed uploaded file: {filepath}")

                    if transaction_count > 0:
                        success_message = f'Successfully imported {transaction_count} transactions from PDF'
                        if is_ajax:
                            return jsonify({
                                'success': True,
                                'message': success_message,
                                'transaction_count': transaction_count,
                                'redirect': url_for('account_details', account_number=account_number)
                            })
                        flash(success_message, 'success')
                    else:
                        warning_message = 'No transactions were imported from the PDF'
                        if is_ajax:
                            return jsonify({
                                'success': True,
                                'message': warning_message,
                                'transaction_count': 0,
                                'redirect': url_for('account_details', account_number=account_number)
                            })
                        flash(warning_message, 'warning')

                    return redirect(url_for('account_details', account_number=account_number))
                except Exception as e:
                    logger.error(f"Error saving transactions to database: {str(e)}")
                    if is_ajax:
                        return jsonify({'success': False, 'message': f'Error saving to database: {str(e)}'})
                    flash(f'Error saving to database: {str(e)}', 'error')
                    return redirect(url_for('dashboard'))
                finally:
                    db.close_session(db_session)
                    if filepath and os.path.exists(filepath):
                        try:
                            os.remove(filepath)
                            logger.info(f"Cleaned up file in finally block: {filepath}")
                        except OSError as e:
                            logger.warning(f"Could not remove file {filepath}: {str(e)}")

            except Exception as e:
                logger.error(f"Error parsing PDF file: {str(e)}")
                if is_ajax:
                    return jsonify({'success': False, 'message': f'Error parsing PDF file: {str(e)}'})
                flash(f'Error parsing PDF file: {str(e)}', 'error')
                # Clean up the uploaded file if it exists
                if filepath and os.path.exists(filepath):
                    try:
                        os.remove(filepath)
                        logger.info(f"Cleaned up file after parsing error: {filepath}")
                    except OSError as e:
                        logger.warning(f"Could not remove file {filepath}: {str(e)}")
                return redirect(url_for('dashboard'))

        else:
            if is_ajax:
                return jsonify({'success': False, 'message': 'File type not allowed. Please upload a PDF file.'})
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