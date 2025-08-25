"""
transaction views for the Flask application.
"""

import csv
import io
import json
import logging
from datetime import datetime, time, timedelta
from threading import Lock

from flask import (Blueprint, Flask, Response, flash, jsonify, redirect,
                   render_template, request, session, url_for)
from sqlalchemy.orm import selectinload

from ..models import (Account, Category, Database, Transaction,
                TransactionRepository)
from ..services import counterparty_service
from ..utils.decorators import login_required

# Create blueprint
transaction_bp = Blueprint("transaction", __name__)

# Initialize database and logger
db = Database()
logger = logging.getLogger(__name__)


@transaction_bp.route("/account/<account_number>/export")
@login_required
def export_transactions(account_number):
    """Export transactions for a specific account as CSV."""
    user_id = session.get("user_id")
    filter_type = request.args.get("filter", None)
    db_session = db.get_session()

    try:
        # Get account for this user
        account = (
            db_session.query(Account)
            .filter(
                Account.user_id == user_id, Account.account_number == account_number
            )
            .first()
        )

        if not account:
            flash(
                f"Account {account_number} not found or you do not have permission to view it",
                "error",
            )
            return redirect(url_for("account.accounts"))

        # Apply filters if specified
        filter_params = {}

        # Transaction type filter
        if filter_type:
            if filter_type == "income":
                filter_params["transaction_type"] = "INCOME"
            elif filter_type == "expense":
                filter_params["transaction_type"] = "EXPENSE"
            elif filter_type == "transfer":
                filter_params["transaction_type"] = "TRANSFER"
            elif filter_type == "recent":
                filter_params["date_from"] = datetime.now() - timedelta(days=30)

        # Date range filters
        date_from_str = request.args.get("date_from")
        date_to_str = request.args.get("date_to")

        if date_from_str:
            try:
                # Parse the date string from the format YYYY-MM-DD
                date_from = datetime.strptime(date_from_str, "%Y-%m-%d")
                filter_params["date_from"] = date_from
            except ValueError:
                logger.warning(f"Invalid date_from format: {date_from_str}")

        if date_to_str:
            try:
                # Parse the date string and set it to the end of the day
                date_to = datetime.strptime(date_to_str, "%Y-%m-%d")
                date_to = date_to.replace(hour=23, minute=59, second=59)
                filter_params["date_to"] = date_to
            except ValueError:
                logger.warning(f"Invalid date_to format: {date_to_str}")

        # Search text filter
        search_text = request.args.get("search")
        if search_text:
            filter_params["search_text"] = search_text

        # Get all transactions without pagination
        transactions_history = TransactionRepository.get_account_transaction_history(
            db_session, user_id, account_number, page=1, per_page=10000, **filter_params
        )

        # Create CSV file in memory
        output = io.StringIO()
        writer = csv.writer(output)

        # Write header row
        writer.writerow(
            [
                "Date",
                "Type",
                "Amount",
                "Currency",
                "Description",
                "Category",
                "Counterparty",
            ]
        )

        # Write transaction data
        for transaction in transactions_history["transactions"]:
            writer.writerow(
                [
                    (
                        transaction.date_time.strftime("%Y-%m-%d %H:%M:%S")
                        if transaction.date_time
                        else ""
                    ),
                    transaction.transaction_type,
                    transaction.amount,
                    transaction.currency,
                    transaction.transaction_details or "",
                    (
                        transaction.category.name
                        if transaction.category
                        else "Uncategorized"
                    ),
                    (transaction.counterparty.name if transaction.counterparty else ""),
                ]
            )

        # Prepare response
        output.seek(0)
        filename = f"{account.bank_name}_{account.account_number}_transactions_{datetime.now().strftime('%Y%m%d')}.csv"

        return Response(
            output,
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        logger.error(f"Error exporting transactions: {str(e)}")
        flash(f"Error exporting transactions: {str(e)}", "error")
        return redirect(
            url_for("account.account_details", account_number=account_number)
        )
    finally:
        db.close_session(db_session)


@transaction_bp.route(
    "/transactions/<int:transaction_id>/edit", methods=["GET", "POST"]
)
@login_required
def edit_transaction(transaction_id):
    """Edit a transaction."""
    user_id = session.get("user_id")
    db_session = db.get_session()

    try:
        # Get transaction and verify it belongs to the user
        transaction = (
            db_session.query(Transaction)
            .options(
                selectinload(Transaction.account),
                selectinload(Transaction.counterparty),
                selectinload(Transaction.category),
            )
            .join(Account)
            .filter(Transaction.id == transaction_id, Account.user_id == user_id)
            .first()
        )

        if not transaction:
            flash(
                "Transaction not found or you do not have permission to edit it",
                "error",
            )
            return redirect(url_for("account.accounts"))

        # Get all categories for the current user
        categories = (
            db_session.query(Category.id, Category.name)
            .filter(Category.user_id == user_id)
            .all()
        )

        if request.method == "POST":

            # Update transaction data

            counterparty_name = request.form.get("counterparty_name", "").strip()
            logger.info(f"Counterparty name: {counterparty_name}")
            category_id = request.form.get("category")
            category_update_scope = request.form.get("category_update_scope", "single")

            # Only include transaction_type if provided by the form to avoid overwriting existing value
            tx_type = request.form.get("transaction_type")
            transaction_data = {
                "counterparty_name": counterparty_name,
                "amount": float(request.form.get("amount", 0.0)),
                "value_date": datetime.strptime(
                    request.form.get("date_time"), "%Y-%m-%dT%H:%M"
                ),
                "description": request.form.get("description", ""),
                "transaction_details": request.form.get("transaction_details", ""),
                "category_id": category_id,
                **({"transaction_type": tx_type} if tx_type else {}),
            }
            updated_transaction = TransactionRepository.update_transaction(
                db_session, transaction_id, transaction_data
            )

            # Re-fetch the transaction with eager-loaded relationships to avoid lazy loads
            transaction = (
                db_session.query(Transaction)
                .options(
                    selectinload(Transaction.account),
                    selectinload(Transaction.counterparty),
                    selectinload(Transaction.category),
                )
                .filter(Transaction.id == transaction_id)
                .first()
            )
            # Precompute account_number for safe redirect after commit/teardown
            account_number = (
                transaction.account.account_number if transaction and transaction.account else None
            )

            if updated_transaction:
                if (
                    category_update_scope == "all_counterparty"
                    and counterparty_name
                    and category_id
                ):

                    # Update all transactions from this counterparty
                    try:
                        success = counterparty_service.categorize_counterparty(
                            user_id=user_id,
                            counterparty_name=counterparty_name,
                            description=None,  # Only match by counterparty name
                            category_id=int(category_id),
                        )

                        if success:
                            flash(
                                f'Transaction updated successfully. All transactions from "{counterparty_name}" have been categorized.',
                                "success",
                            )
                        else:
                            flash(
                                "Transaction updated successfully, but failed to update other transactions from this counterparty.",
                                "warning",
                            )
                    except Exception as e:
                        logger.error(
                            f"Error updating counterparty transactions: {str(e)}"
                        )
                        flash(
                            "Transaction updated successfully, but failed to update other transactions from this counterparty.",
                            "warning",
                        )
                else:
                    flash("Transaction updated successfully", "success")
                    return redirect(
                        url_for(
                            "account.account_details",
                            account_number=account_number,
                        )
                    )

            else:
                flash("Error updating transaction", "error")

        return render_template(
            "main/edit_transaction.html",
            transaction=transaction,
            categories=categories,
        )
    except Exception as e:
        logger.error(f"Error editing transaction: {str(e)}")
        flash(f"Error editing transaction: {str(e)}", "error")
        return redirect(url_for("account.accounts"))
    finally:
        db.close_session(db_session)


@transaction_bp.route("/transaction/<int:transaction_id>", methods=["POST", "DELETE"])
@login_required
def delete_transaction(transaction_id):
    """Delete a transaction."""
    user_id = session.get("user_id")
    db_session = db.get_session()
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"

    try:
        # Get transaction and verify it belongs to the user
        transaction = (
            db_session.query(Transaction)
            .join(Account)
            .filter(Transaction.id == transaction_id, Account.user_id == user_id)
            .first()
        )

        if not transaction:
            if is_ajax:
                return jsonify(
                    {
                        "success": False,
                        "message": "Transaction not found or you do not have permission to delete it",
                    }
                )
            flash(
                "Transaction not found or you do not have permission to delete it",
                "error",
            )
            return redirect(url_for("account.accounts"))

        account_number = transaction.account.account_number

        result = TransactionRepository.delete_transaction(db_session, transaction_id)
        if result:
            if is_ajax:
                return jsonify(
                    {
                        "success": True,
                        "message": "Transaction deleted successfully",
                        "transaction_id": transaction_id,
                    }
                )
            flash("Transaction deleted successfully", "success")
        else:
            if is_ajax:
                return jsonify(
                    {"success": False, "message": "Error deleting transaction"}
                )
            flash("Error deleting transaction", "error")

        return redirect(url_for("account.account_details", account_number=account_number))
    except Exception as e:
        logger.error(f"Error deleting transaction: {str(e)}")
        if is_ajax:
            return jsonify(
                {"success": False, "message": f"Error deleting transaction: {str(e)}"}
            )
        flash(f"Error deleting transaction: {str(e)}", "error")
        return redirect(url_for("account.accounts"))
    finally:
        db.close_session(db_session)


@transaction_bp.route("/transaction/<int:transaction_id>/category", methods=["POST", "PUT"])
@login_required
def update_transaction_category(transaction_id):
    """Update the category of a transaction."""
    user_id = session.get("user_id")
    db_session = db.get_session()
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"

    try:
        # Get transaction and verify it belongs to the user
        transaction = (
            db_session.query(Transaction)
            .join(Account)
            .filter(Transaction.id == transaction_id, Account.user_id == user_id)
            .first()
        )

        if not transaction:
            if is_ajax:
                return jsonify(
                    {
                        "success": False,
                        "message": "Transaction not found or you do not have permission to edit it",
                    }
                )
            flash(
                "Transaction not found or you do not have permission to edit it",
                "error",
            )
            return redirect(url_for("account.accounts"))

        # Get the category ID from the request
        category_id = request.form.get("category_id")
        if not category_id:
            if is_ajax:
                return jsonify({"success": False, "message": "Category ID is required"})
            flash("Category ID is required", "error")
            return redirect(
                url_for(
                    "account.account_details",
                    account_number=transaction.account.account_number,
                )
            )

        # Update the transaction category
        transaction_data = {"category_id": category_id}
        updated_transaction = TransactionRepository.update_transaction(
            db_session, transaction_id, transaction_data
        )

        if updated_transaction:
            # Get the category name for the response
            category = (
                db_session.query(Category).filter(Category.id == category_id).first()
            )
            category_name = category.name if category else "Uncategorized"

            if is_ajax:
                return jsonify(
                    {
                        "success": True,
                        "message": "Category updated successfully",
                        "category_name": category_name,
                    }
                )
            flash("Category updated successfully", "success")
            return redirect(
                url_for(
                    "account.account_details",
                    account_number=transaction.account.account_number,
                )
            )
        else:
            if is_ajax:
                return jsonify({"success": False, "message": "Error updating category"})
            flash("Error updating category", "error")
            return redirect(
                url_for(
                    "account.account_details",
                    account_number=transaction.account.account_number,
                )
            )
    except Exception as e:
        logger.error(f"Error updating transaction category: {str(e)}")
        if is_ajax:
            return jsonify(
                {
                    "success": False,
                    "message": f"Error updating transaction category: {str(e)}",
                }
            )
        flash(f"Error updating transaction category: {str(e)}", "error")
        return redirect(url_for("account.accounts"))
    finally:
        db.close_session(db_session)
