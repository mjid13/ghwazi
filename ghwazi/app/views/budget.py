"""
Budget views for the Flask application.
"""
import logging
from datetime import datetime
from typing import Optional

from flask import (Blueprint, flash, jsonify, redirect, render_template, request,
                   session, url_for)
from sqlalchemy.orm import Session

from ..models.database import Database
from ..models.models import Budget, Category, Account
from ..services.budget_service import BudgetService
from ..utils.decorators import login_required

budget_bp = Blueprint("budget", __name__)

logger = logging.getLogger(__name__)
db = Database()


def _get_user_id():
    return session.get("user_id")


@budget_bp.route("/setup", methods=["GET", "POST"])
@login_required
def setup():
    """Budget setup page: list categories with options to set per-category budgets."""
    user_id = _get_user_id()
    db_session = db.get_session()
    try:
        if request.method == "POST":
            # Form submissions can create/update a single budget entry
            category_id = request.form.get("category_id")
            account_id = request.form.get("account_id") or None
            amount = request.form.get("amount")
            period = request.form.get("period", "monthly").lower()
            is_active = bool(request.form.get("is_active"))
            rollover_enabled = bool(request.form.get("rollover_enabled"))
            alert_threshold = float(request.form.get("alert_threshold") or 80.0)

            if not amount or float(amount) < 0:
                flash("Please enter a valid budget amount.", "error")
                return redirect(url_for("budget.setup"))

            # Create or update budget for this category/period/account tuple
            q = db_session.query(Budget).filter(Budget.user_id == user_id,
                                                Budget.category_id == (int(category_id) if category_id else None),
                                                Budget.period == period)
            if account_id:
                q = q.filter(Budget.account_id == int(account_id))
            else:
                q = q.filter(Budget.account_id == None)

            budget = q.first()
            if not budget:
                budget = Budget(
                    user_id=user_id,
                    category_id=int(category_id) if category_id else None,
                    account_id=int(account_id) if account_id else None,
                    amount=float(amount),
                    period=period,
                    is_active=is_active,
                    rollover_enabled=rollover_enabled,
                    alert_threshold=alert_threshold,
                    start_date=datetime.utcnow(),
                )
                db_session.add(budget)
            else:
                budget.amount = float(amount)
                budget.is_active = is_active
                budget.rollover_enabled = rollover_enabled
                budget.alert_threshold = alert_threshold

            db_session.commit()
            flash("Budget saved successfully.", "success")
            return redirect(url_for("budget.setup"))

        categories = db_session.query(Category).filter(Category.user_id == user_id).order_by(Category.name.asc()).all()
        accounts = db_session.query(Account).filter(Account.user_id == user_id).order_by(Account.account_number.asc()).all()
        budgets = db_session.query(Budget).filter(Budget.user_id == user_id).all()

        # Map budgets for quick lookup
        budgets_by_key = {}
        for b in budgets:
            key = (b.category_id, b.account_id, b.period)
            budgets_by_key[key] = b

        return render_template("budget/setup.html",
                               categories=categories,
                               accounts=accounts,
                               budgets=budgets_by_key,
                               periods=["weekly", "monthly", "yearly"]) 
    except Exception as e:
        logger.error(f"Error in budget setup: {e}")
        flash("Error loading budget setup.", "error")
        return redirect(url_for("main.dashboard"))
    finally:
        db.close_session(db_session)


@budget_bp.route("/dashboard")
@login_required
def dashboard():
    """Budget dashboard: overview with progress indicators and alerts."""
    user_id = _get_user_id()
    db_session = db.get_session()
    try:
        # Fetch all budgets with status
        statuses = BudgetService.list_budgets_with_status(db_session, user_id)
        # Enrich with names
        cat_map = {c.id: c.name for c in db_session.query(Category).filter(Category.user_id == user_id).all()}
        acc_map = {}
        for acc in db_session.query(Account).filter(Account.user_id == user_id).all():
            acc_map[acc.id] = f"{acc.bank_name} ({acc.account_number})"
        for s in statuses:
            s["category_name"] = cat_map.get(s.get("category_id")) if s.get("category_id") else "All Categories"
            s["account_label"] = acc_map.get(s.get("account_id")) if s.get("account_id") else "All Accounts"
        # Filter active budgets
        statuses = [s for s in statuses if s.get("is_active")]
        # Sort by percent used desc
        statuses.sort(key=lambda s: s.get("percent_used", 0), reverse=True)
        return render_template("budget/dashboard.html", budgets=statuses)
    except Exception as e:
        logger.error(f"Error loading budget dashboard: {e}")
        flash("Error loading budget dashboard.", "error")
        return redirect(url_for("main.dashboard"))
    finally:
        db.close_session(db_session)


@budget_bp.route("/toggle/<int:budget_id>", methods=["POST"])
@login_required
def toggle(budget_id: int):
    user_id = _get_user_id()
    db_session = db.get_session()
    try:
        budget = db_session.query(Budget).filter(Budget.id == budget_id, Budget.user_id == user_id).first()
        if not budget:
            flash("Budget not found.", "error")
            return redirect(url_for("budget.dashboard"))
        budget.is_active = not bool(budget.is_active)
        db_session.commit()
        flash("Budget updated.", "success")
    except Exception as e:
        logger.error(f"Error toggling budget: {e}")
        flash("Error updating budget.", "error")
    finally:
        db.close_session(db_session)
    return redirect(url_for("budget.dashboard"))


@budget_bp.route("/delete/<int:budget_id>", methods=["POST"])
@login_required
def delete(budget_id: int):
    user_id = _get_user_id()
    db_session = db.get_session()
    try:
        budget = db_session.query(Budget).filter(Budget.id == budget_id, Budget.user_id == user_id).first()
        if not budget:
            flash("Budget not found.", "error")
        else:
            db_session.delete(budget)
            db_session.commit()
            flash("Budget deleted.", "success")
    except Exception as e:
        logger.error(f"Error deleting budget: {e}")
        flash("Error deleting budget.", "error")
    finally:
        db.close_session(db_session)
    return redirect(url_for("budget.dashboard"))


@budget_bp.route("/status.json")
@login_required
def status_json():
    user_id = _get_user_id()
    db_session = db.get_session()
    try:
        statuses = BudgetService.list_budgets_with_status(db_session, user_id)
        return jsonify({"budgets": statuses})
    except Exception as e:
        logger.error(f"Error getting budget status JSON: {e}")
        return jsonify({"error": str(e)}), 500
    finally:
        db.close_session(db_session)
