"""
Main views for the Flask application.
"""

import json
import logging
import os
from datetime import datetime
from threading import Lock

from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for, current_app, jsonify)
from werkzeug.utils import secure_filename

from ..models.database import Database
from ..models.models import Account, EmailManuConfigs
from ..models.transaction import TransactionRepository
from ..models.user import User
from ..services.counterparty_service import CounterpartyService
from ..services.pdf_parser_service import PDFParser
from ..utils.helpers import allowed_file
from ..utils.decorators import login_required
from ..utils.db_session_manager import database_session
from ..views.email import email_tasks_lock, scraping_accounts

# Create blueprint
main_bp = Blueprint("main", __name__)

@main_bp.route("/debug_dashboard_data")
@login_required  
def debug_dashboard_data():
    """Debug endpoint to check dashboard data."""
    user_id = session.get("user_id")
    
    try:
        with database_session() as db_session:
            # Get user's accounts
            accounts = TransactionRepository.get_user_accounts(db_session, user_id)
            
            debug_info = {
                "user_id": user_id,
                "accounts_count": len(accounts) if accounts else 0,
                "accounts": [{"id": acc.id, "account_number": acc.account_number, "bank_name": acc.bank_name, "balance": float(acc.balance)} for acc in accounts] if accounts else [],
            }
            
            if accounts:
                # Check if there are any transactions
                from ..models.models import Transaction
                transaction_count = db_session.query(Transaction).join(Account).filter(Account.user_id == user_id).count()
                debug_info["transaction_count"] = transaction_count
                
                # Check if there are any categories
                from ..models.models import Category
                category_count = db_session.query(Category).filter(Category.user_id == user_id).count()
                debug_info["category_count"] = category_count
            
            return jsonify(debug_info)
            
    except Exception as e:
        return jsonify({"error": str(e), "user_id": user_id})

# Initialize database and logger
db = Database()
logger = logging.getLogger(__name__)
counterparty_service = CounterpartyService()


# email_tasks_lock = Lock()
@main_bp.route("/")
def index():
    """Home page with landing content."""
    return render_template("main/index.html", year=datetime.now().year)


@main_bp.route("/dashboard")
@login_required
def dashboard():
    """User dashboard."""
    user_id = session.get("user_id")

    try:
        with database_session() as db_session:
            # Get user's accounts
            accounts = TransactionRepository.get_user_accounts(db_session, user_id)

            # Get user's email configurations
            email_configs = (
                db_session.query(EmailManuConfigs)
                .filter(EmailManuConfigs.user_id == user_id)
                .all()
            )

            # Get the list of accounts that are currently being scraped
            with email_tasks_lock:
                scraping_account_numbers = list(scraping_accounts.keys())

            # Prepare data for charts
            chart_data = {}
            category_labels = []

            logger.info(f"Dashboard: User {user_id} has {len(accounts) if accounts else 0} accounts")

            if accounts:
                # Import necessary modules for data aggregation
                from datetime import datetime, timedelta
                from sqlalchemy import case, extract, func
                from ..models.models import Category, Transaction, TransactionType

                logger.info("Generating chart data for dashboard")

                try:
                    # 1. Income vs. Expense Comparison Chart
                    income_expense_data = (
                        db_session.query(
                            func.sum(
                                case(
                                    (
                                        Transaction.transaction_type == TransactionType.INCOME,
                                        Transaction.amount,
                                    ),
                                    else_=0,
                                )
                            ).label("total_income"),
                            func.sum(
                                case(
                                    (
                                        Transaction.transaction_type == TransactionType.EXPENSE,
                                        Transaction.amount,
                                    ),
                                    else_=0,
                                )
                            ).label("total_expense"),
                        )
                        .join(Account)
                        .filter(Account.user_id == user_id)
                        .first()
                    )

                    chart_data["income_expense"] = {
                        "labels": ["Income", "Expense"],
                        "datasets": [
                            {
                                "data": [
                                    float(income_expense_data.total_income or 0),
                                    float(income_expense_data.total_expense or 0),
                                ],
                                "backgroundColor": ["#4CAF50", "#F44336"],
                            }
                        ],
                    }

                    # 2. Category Distribution Pie Chart
                    # Get expense transactions with categories
                    category_data = (
                        db_session.query(
                            Category.name,
                            Category.color,
                            func.sum(Transaction.amount).label("total_amount"),
                        )
                        .join(Transaction, Transaction.category_id == Category.id)
                        .join(Account, Transaction.account_id == Account.id)
                        .filter(
                            Account.user_id == user_id,
                            Transaction.transaction_type == TransactionType.EXPENSE,
                            )
                        .group_by(Category.name, Category.color)
                        .order_by(func.sum(Transaction.amount).desc())
                        .limit(10)
                        .all()
                    )

                    # Format data for pie chart
                    category_labels = [cat.name for cat in category_data]
                    category_values = [float(cat.total_amount) for cat in category_data]

                    # Use category colors from database, or fallback to defaults
                    default_colors = [
                        "#FF6384",
                        "#36A2EB",
                        "#FFCE56",
                        "#4BC0C0",
                        "#9966FF",
                        "#FF9F40",
                        "#8AC249",
                        "#EA5545",
                        "#F46A9B",
                        "#EF9B20",
                    ]
                    category_colors = []
                    for i, cat in enumerate(category_data):
                        if cat.color:
                            category_colors.append(cat.color)
                        else:
                            # Use default color if category doesn't have one
                            category_colors.append(default_colors[i % len(default_colors)])

                    chart_data["category_distribution"] = {
                        "labels": category_labels,
                        "datasets": [
                            {
                                "data": category_values,
                                "backgroundColor": category_colors[: len(category_labels)],
                            }
                        ],
                    }

                    # 2b. Separate expense categories for the filter
                    chart_data["expense_categories"] = chart_data["category_distribution"]

                    # 2c. Income categories for the filter
                    income_category_data = (
                        db_session.query(
                            Category.name,
                            Category.color,
                            func.sum(Transaction.amount).label("total_amount"),
                        )
                        .join(Transaction, Transaction.category_id == Category.id)
                        .join(Account, Transaction.account_id == Account.id)
                        .filter(
                            Account.user_id == user_id,
                            Transaction.transaction_type == TransactionType.INCOME,
                            )
                        .group_by(Category.name, Category.color)
                        .order_by(func.sum(Transaction.amount).desc())
                        .limit(10)
                        .all()
                    )

                    # Format income category data
                    income_labels = [cat.name for cat in income_category_data]
                    income_values = [float(cat.total_amount) for cat in income_category_data]
                    income_colors = []
                    for i, cat in enumerate(income_category_data):
                        if cat.color:
                            income_colors.append(cat.color)
                        else:
                            income_colors.append(default_colors[i % len(default_colors)])

                    chart_data["income_categories"] = {
                        "labels": income_labels,
                        "datasets": [
                            {
                                "data": income_values,
                                "backgroundColor": income_colors[: len(income_labels)],
                            }
                        ],
                    }

                    # 3. Monthly Transaction Trend Line Chart
                    # Get data for the last 6 months
                    end_date = datetime.now()
                    start_date = end_date - timedelta(days=365)


                    # Query monthly aggregates
                    monthly_data = (
                        db_session.query(
                            extract("year", Transaction.value_date).label("year"),
                            extract("month", Transaction.value_date).label("month"),
                            func.sum(
                                case(
                                    (
                                        Transaction.transaction_type == TransactionType.INCOME,
                                        Transaction.amount,
                                    ),
                                    else_=0,
                                )
                            ).label("income"),
                            func.sum(
                                case(
                                    (
                                        Transaction.transaction_type == TransactionType.EXPENSE,
                                        Transaction.amount,
                                    ),
                                    else_=0,
                                )
                            ).label("expense"),
                        )
                        .join(Account, Transaction.account_id == Account.id)
                        .filter(
                            Account.user_id == user_id,
                            Transaction.value_date.between(start_date, end_date),
                            )
                        .group_by(
                            extract("year", Transaction.value_date),
                            extract("month", Transaction.value_date),
                        )
                        .order_by(
                            extract("year", Transaction.value_date),
                            extract("month", Transaction.value_date),
                        )
                        .all()
                    )

                    # Format data for line chart
                    months = []
                    income_values = []
                    expense_values = []

                    for data in monthly_data:
                        month_name = datetime(int(data.year), int(data.month), 1).strftime(
                            "%b %Y"
                        )
                        months.append(month_name)
                        income_values.append(float(data.income or 0))
                        expense_values.append(float(data.expense or 0))

                    chart_data["monthly_trend"] = {
                        "labels": months,
                        "datasets": [
                            {
                                "label": "Income",
                                "data": income_values,
                                "borderColor": "#4CAF50",
                                "backgroundColor": "rgba(76, 175, 80, 0.1)",
                                "fill": True,
                            },
                            {
                                "label": "Expense",
                                "data": expense_values,
                                "borderColor": "#F44336",
                                "backgroundColor": "rgba(244, 67, 54, 0.1)",
                                "fill": True,
                            },
                        ],
                    }

                    # 4. Account Balance Comparison Chart
                    account_data = []
                    for account in accounts:
                        account_data.append(
                            {
                                "account_number": account.account_number,
                                "bank_name": account.bank_name,
                                "balance": float(account.balance),
                                "currency": account.currency,
                            }
                        )

                    # Sort accounts by balance (descending)
                    account_data.sort(key=lambda x: x["balance"], reverse=True)

                    # Format data for bar chart
                    account_labels = [
                        f"{acc['bank_name']} ({acc['account_number'][-4:]})"
                        for acc in account_data
                    ]
                    account_balances = [acc["balance"] for acc in account_data]
                    account_currencies = [acc["currency"] for acc in account_data]

                    chart_data["account_balance"] = {
                        "labels": account_labels,
                        "datasets": [
                            {
                                "label": "Balance",
                                "data": account_balances,
                                "backgroundColor": "#2196F3",
                                "borderColor": "#1976D2",
                                "borderWidth": 1,
                            }
                        ],
                        "currencies": account_currencies,
                    }

                except Exception as e:
                    logger.error(f"Error generating chart data: {str(e)}")
                    # Set empty chart data if there's an error
                    chart_data = {
                        "income_expense": {"labels": [], "datasets": []},
                        "category_distribution": {"labels": [], "datasets": []},
                        "expense_categories": {"labels": [], "datasets": []},
                        "income_categories": {"labels": [], "datasets": []},
                        "monthly_trend": {"labels": [], "datasets": []},
                        "account_balance": {"labels": [], "datasets": []},
                    }

            # Pass chart data as a Python dict; Jinja will JSON-encode it in the template with |tojson
            logger.info(f"Chart data keys: {list(chart_data.keys())}")

            return render_template(
                "main/dashboard.html",
                categories=True if len(category_labels) > 0 else False,
                accounts=accounts,
                email_configs=email_configs,
                scraping_account_numbers=scraping_account_numbers,
                chart_data=chart_data,
                show_charts=True if accounts else False,  # Only show charts if accounts exist
            )

    except Exception as e:
        logger.error(f"Error loading dashboard: {str(e)}")
        flash("Error loading dashboard. Please try again.", "error")
        return redirect(url_for("main.index"))


@main_bp.route("/profile")
@login_required
def profile():
    """User profile page."""
    user_id = session.get("user_id")
    db_session = db.get_session()

    try:
        user = db_session.query(User).filter(User.id == user_id).first()
        if not user:
            flash("User not found", "error")
            return redirect(url_for("main.dashboard"))

        return render_template("main/profile.html", user=user)

    except Exception as e:
        logger.error(f"Error loading profile: {str(e)}")
        flash("Error loading profile", "error")
        return redirect(url_for("main.dashboard"))
    finally:
        db.close_session(db_session)


@main_bp.route("/counterparties")
@login_required
def counterparties():
    """List all unique counterparties."""
    user_id = session.get("user_id")
    account_number = request.args.get("account_number", "all")
    db_session = db.get_session()

    try:
        # Get user's accounts
        accounts = TransactionRepository.get_user_accounts(db_session, user_id)

        # Get all unique counterparties for this user, filtered by account if specified
        counterparties = counterparty_service.get_unique_counterparties(
            user_id, account_number
        )

        # Get all categories for this user (for the categorization form)
        categories = counterparty_service.get_categories(user_id)

        return render_template(
            "main/counterparties.html",
            counterparties=counterparties,
            categories=categories,
            accounts=accounts,
            selected_account=account_number,
        )
    except Exception as e:
        logger.error(f"Error loading counterparties: {str(e)}")
        flash("Error loading counterparties. Please try again.", "error")
        return redirect(url_for("main.dashboard"))
    finally:
        db.close_session(db_session)


@main_bp.route("/results")
@login_required
def results():
    """Display the parsed transaction data."""
    transaction_data = session.get("transaction_data")
    if not transaction_data:
        flash("No transaction data available", "error")
        return redirect(url_for("main.dashboard"))

    return render_template("main/results.html", transaction=transaction_data)


@main_bp.route("/privacy-policy")
def privacy_policy():
    """Privacy policy page - publicly accessible."""
    return render_template("main/privacy_policy.html", year=datetime.now().year)


@main_bp.route("/terms-of-service")
def terms_of_service():
    """Terms of Service page - publicly accessible."""
    return render_template("main/terms_of_service.html", year=datetime.now().year)


@main_bp.route("/upload_statement", methods=["GET", "POST"])
@login_required
def upload_statement():
    """Upload and parse PDF bank statement (Main views)."""
    user_id = session.get("user_id")
    # Always load accounts for the form (GET) and for re-render on errors
    db_session = db.get_session()
    try:
        accounts = TransactionRepository.get_user_accounts(db_session, user_id)
    except Exception as e:
        logger.error(f"Error loading accounts: {str(e)}")
        flash("Error loading accounts or there is no accounts available", "error")
        return redirect(url_for("main.dashboard"))
    finally:
        db.close_session(db_session)

    if request.method == "POST":
        is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
        account_number = request.form.get("account_number")

        if not account_number:
            if is_ajax:
                return jsonify({"success": False, "message": "Please select an account"})
            flash("Please select an account", "error")
            return redirect(url_for("main.dashboard"))

        # Check if the post request has the file part
        if "pdf_file" not in request.files:
            if is_ajax:
                return jsonify({"success": False, "message": "No file part"})
            flash("No file part", "error")
            return redirect(url_for("main.dashboard"))

        file = request.files["pdf_file"]

        # If user does not select file, browser also submit an empty part without filename
        if file.filename == "":
            if is_ajax:
                return jsonify({"success": False, "message": "No selected file"})
            flash("No selected file", "error")
            return redirect(url_for("main.dashboard"))

        if file and allowed_file(file.filename):
            # Generate a unique filename to avoid collisions
            filename = secure_filename(f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
            filepath = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)

            try:
                # Parse the PDF file
                pdf_parser = PDFParser()
                transactions = pdf_parser.parse_pdf(filepath)

                if not transactions:
                    if is_ajax:
                        return jsonify({"success": False, "message": "No transactions found in the PDF file"})
                    flash("No transactions found in the PDF file", "error")
                    # Clean up the uploaded file
                    os.remove(filepath)
                    return redirect(url_for("main.dashboard"))

                # Store transactions in the database
                db_session = db.get_session()
                try:
                    transaction_count = 0
                    for transaction_data in transactions:
                        if transaction_data["account_number"] != account_number:
                            logger.error(
                                f"The account number {transaction_data['account_number']} in the PDF does not match the selected account {account_number}"
                            )
                            if is_ajax:
                                return jsonify({
                                    "success": False,
                                    "message": f"Transaction account number {transaction_data['account_number']} does not match selected account {account_number}"
                                })
                            flash(
                                f"Transaction account number {transaction_data['account_number']} does not match selected account {account_number}",
                                "error",
                            )
                            return redirect(url_for("main.dashboard"))
                        # Add user_id to transaction data
                        transaction_data["user_id"] = user_id

                        # Add preserve_balance flag
                        preserve_balance = "preserve_balance" in request.form
                        transaction_data["preserve_balance"] = preserve_balance

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
                        success_message = f"Successfully imported {transaction_count} transactions from PDF"
                        if is_ajax:
                            return jsonify({
                                "success": True,
                                "message": success_message,
                                "transaction_count": transaction_count,
                                "redirect": url_for("account.account_details", account_number=account_number)
                            })
                        flash(success_message, "success")
                    else:
                        warning_message = "No transactions were imported from the PDF"
                        if is_ajax:
                            return jsonify({
                                "success": True,
                                "message": warning_message,
                                "transaction_count": 0,
                                "redirect": url_for("account.account_details", account_number=account_number)
                            })
                        flash(warning_message, "warning")

                    return redirect(url_for("account.account_details", account_number=account_number))
                except Exception as e:
                    logger.error(f"Error saving transactions to database: {str(e)}")
                    if is_ajax:
                        return jsonify({"success": False, "message": f"Error saving to database: {str(e)}"})
                    flash(f"Error saving to database: {str(e)}", "error")
                    return redirect(url_for("main.dashboard"))
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
                    return jsonify({"success": False, "message": f"Error parsing PDF file: {str(e)}"})
                flash(f"Error parsing PDF file: {str(e)}", "error")
                # Clean up the uploaded file if it exists
                if filepath and os.path.exists(filepath):
                    try:
                        os.remove(filepath)
                        logger.info(f"Cleaned up file after parsing error: {filepath}")
                    except OSError as e:
                        logger.warning(f"Could not remove file {filepath}: {str(e)}")
                return redirect(url_for("main.dashboard"))

        else:
            if is_ajax:
                return jsonify({"success": False, "message": "File type not allowed. Please upload a PDF file."})
            flash("File type not allowed. Please upload a PDF file.", "error")
            return redirect(url_for("main.dashboard"))

    # GET request - render the upload form
    return render_template("main/upload_pdf.html", accounts=accounts)