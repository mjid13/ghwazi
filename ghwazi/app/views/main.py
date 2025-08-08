"""
Main views for the Flask application.
"""

import json
import logging
from datetime import datetime
from threading import Lock

from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)

from ..models.database import Database
from ..models.models import Account, EmailManuConfigs
from ..models.transaction import TransactionRepository
from ..models.user import User
from ..services.counterparty_service import CounterpartyService
from ..utils.decorators import login_required
from ..views.email import email_tasks_lock, scraping_accounts

# Create blueprint
main_bp = Blueprint("main", __name__)

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
    db_session = db.get_session()

    try:
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
        if accounts:
            # Import necessary modules for data aggregation
            from datetime import datetime, timedelta

            from sqlalchemy import case, extract, func

            from ..models.models import (Category, Transaction,
                                           TransactionType)

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

            # 3. Monthly Transaction Trend Line Chart
            # Get data for the last 6 months
            end_date = datetime.now()
            start_date = end_date - timedelta(days=180)  # Approximately 6 months

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

        # Convert chart data to JSON for the template
        chart_data_json = json.dumps(chart_data)

        return render_template(
            "main/dashboard.html",
            categories=True if len(category_labels) > 0 else False,
            accounts=accounts,
            email_configs=email_configs,
            scraping_account_numbers=scraping_account_numbers,
            chart_data=chart_data_json,
        )
    except Exception as e:
        logger.error(f"Error loading dashboard: {str(e)}")
        flash("Error loading dashboard. Please try again.", "error")
        return redirect(url_for("main.index"))
    finally:
        db.close_session(db_session)


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
