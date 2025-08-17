"""
Working dashboard function without indentation issues.
"""
import json
import logging
from datetime import datetime, timedelta

from flask import flash, redirect, render_template, session, url_for
from sqlalchemy import case, extract, func

from ..models.models import Account, Category, EmailManuConfigs, Transaction, TransactionType
from ..models.transaction import TransactionRepository
from ..utils.decorators import login_required
from ..utils.db_session_manager import database_session
from ..views.email import email_tasks_lock, scraping_accounts

logger = logging.getLogger(__name__)


@login_required
def dashboard():
    """User dashboard with working chart generation."""
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
            
            # Initialize chart data
            chart_data = {}
            category_labels = []
            
            logger.info(f"Dashboard: User {user_id} has {len(accounts) if accounts else 0} accounts")
            
            if accounts:
                logger.info("Generating chart data for dashboard")
                
                # 1. Income vs. Expense Comparison Chart
                income_expense_data = (
                    db_session.query(
                        func.sum(
                            case(
                                (Transaction.transaction_type == TransactionType.INCOME, Transaction.amount),
                                else_=0,
                            )
                        ).label("total_income"),
                        func.sum(
                            case(
                                (Transaction.transaction_type == TransactionType.EXPENSE, Transaction.amount),
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

                # Format category data
                if category_data:
                    category_labels = [cat.name for cat in category_data]
                    category_values = [float(cat.total_amount) for cat in category_data]
                    
                    default_colors = [
                        "#FF6384", "#36A2EB", "#FFCE56", "#4BC0C0", "#9966FF",
                        "#FF9F40", "#8AC249", "#EA5545", "#F46A9B", "#EF9B20",
                    ]
                    
                    category_colors = []
                    for i, cat in enumerate(category_data):
                        if cat.color:
                            category_colors.append(cat.color)
                        else:
                            category_colors.append(default_colors[i % len(default_colors)])

                    chart_data["category_distribution"] = {
                        "labels": category_labels,
                        "datasets": [
                            {
                                "data": category_values,
                                "backgroundColor": category_colors,
                            }
                        ],
                    }

                # 3. Monthly Transaction Trend Line Chart
                end_date = datetime.now()
                start_date = end_date - timedelta(days=180)  # 6 months

                monthly_data = (
                    db_session.query(
                        extract("year", Transaction.value_date).label("year"),
                        extract("month", Transaction.value_date).label("month"),
                        func.sum(
                            case(
                                (Transaction.transaction_type == TransactionType.INCOME, Transaction.amount),
                                else_=0,
                            )
                        ).label("income"),
                        func.sum(
                            case(
                                (Transaction.transaction_type == TransactionType.EXPENSE, Transaction.amount),
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

                # Format monthly trend data
                if monthly_data:
                    months = []
                    income_values = []
                    expense_values = []

                    for data in monthly_data:
                        month_name = datetime(int(data.year), int(data.month), 1).strftime("%b %Y")
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
                    account_data.append({
                        "account_number": account.account_number,
                        "bank_name": account.bank_name,
                        "balance": float(account.balance),
                        "currency": account.currency,
                    })

                # Sort by balance
                account_data.sort(key=lambda x: x["balance"], reverse=True)

                account_labels = [f"{acc['bank_name']} ({acc['account_number'][-4:]})" for acc in account_data]
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
            logger.info(f"Chart data JSON length: {len(chart_data_json)}")
            logger.info(f"Chart data keys: {list(chart_data.keys())}")

            return render_template(
                "main/dashboard.html",
                categories=True if len(category_labels) > 0 else False,
                accounts=accounts,
                email_configs=email_configs,
                scraping_account_numbers=scraping_account_numbers,
                chart_data=chart_data_json,
                show_charts=True,
            )

    except Exception as e:
        logger.error(f"Error loading dashboard: {str(e)}")
        flash("Error loading dashboard. Please try again.", "error")
        return redirect(url_for("main.index"))