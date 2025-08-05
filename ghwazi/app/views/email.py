import logging
import os
import threading
import uuid
from datetime import datetime, time
from threading import Lock

from flask import (Blueprint, current_app, flash, jsonify, redirect,
                   render_template, request, session, url_for)
from werkzeug.utils import secure_filename

from app.models import (Account, Bank, Category, CategoryMapping,
                        EmailConfiguration, Transaction)
from app.models.database import Database
from app.models.transaction import TransactionRepository
from app.models.user import User
from app.services.email_service import EmailService
from app.services.parser_service import TransactionParser
from app.utils.decorators import login_required

# Create blueprint
email_bp = Blueprint("email", __name__)

# Initialize database and logger
db = Database()
logger = logging.getLogger(__name__)
parser = TransactionParser()

# Task manager for tracking email fetching tasks
email_tasks = {}
email_tasks_lock = Lock()
# Dictionary to track which accounts are currently being scraped
# Format: {account_number: {'user_id': user_id, 'task_id': task_id, 'start_time': time.time()}}
scraping_accounts = {}


def process_emails_task(
    task_id,
    user_id,
    account_number,
    bank_name,
    folder,
    time_period,
    save_to_db,
    preserve_balance,
):
    """Background task for processing emails."""
    logger.debug(
        f"Starting background task {task_id} for user {user_id} on account {account_number}"
    )

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
            email_tasks[task_id]["status"] = "processing"
            email_tasks[task_id]["progress"] = 0
            email_tasks[task_id]["start_time"] = time.time()

        # Get the account to find its associated email configuration
        account = (
            db_session.query(Account)
            .filter(
                Account.user_id == user_id, Account.account_number == account_number
            )
            .first()
        )

        if not account:
            with email_tasks_lock:
                email_tasks[task_id]["status"] = "error"
                email_tasks[task_id]["message"] = "Account not found"
            logger.error(f"Account {account_number} not found for user {user_id}")
            return

        # Check if the account has an associated email configuration
        if not account.email_config_id:
            with email_tasks_lock:
                email_tasks[task_id]["status"] = "error"
                email_tasks[task_id][
                    "message"
                ] = "This account does not have an associated email configuration"
            logger.error(
                f"Account {account_number} does not have an associated email configuration for user {user_id}"
            )
            return

        # Get the email configuration for this account
        email_config = (
            db_session.query(EmailConfiguration)
            .filter(EmailConfiguration.id == account.email_config_id)
            .first()
        )

        if not email_config:
            with email_tasks_lock:
                email_tasks[task_id]["status"] = "error"
                email_tasks[task_id]["message"] = "Email configuration not found"
            logger.error(
                f"Email configuration not found for account {account_number} of user {user_id}"
            )
            return

        # Create email service from the account's email configuration
        logger.debug(f"Creating email service for account {account_number}")
        email_service = EmailService(
            host=email_config.email_host,
            port=email_config.email_port,
            username=email_config.email_username,
            password=email_config.email_password,
            use_ssl=email_config.email_use_ssl,
            bank_email_addresses=(
                email_config.bank_email_addresses.split(",")
                if email_config.bank_email_addresses
                else []
            ),
            bank_email_subjects=(
                email_config.bank_email_subjects.split(",")
                if email_config.bank_email_subjects
                else []
            ),
        )

        # Connect to email
        if not email_service.connect():
            with email_tasks_lock:
                email_tasks[task_id]["status"] = "error"
                email_tasks[task_id]["message"] = "Failed to connect to email server"
            logger.debug(
                f"Failed to connect to email server for account {account_number}"
            )
            return

        # Get bank emails
        emails = email_service.get_bank_emails(folder=folder, time_period=time_period)
        logger.debug(
            f"Fetched {len(emails)} emails for account {account_number} in folder '{folder}'"
        )

        if not emails:
            with email_tasks_lock:
                email_tasks[task_id]["status"] = "completed"
                email_tasks[task_id]["message"] = "No bank emails found"
                email_tasks[task_id]["progress"] = 100
                email_tasks[task_id]["end_time"] = time.time()
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
                    email_tasks[task_id]["progress"] = progress
                    elapsed_time = time.time() - email_tasks[task_id]["start_time"]
                    emails_per_second = i / elapsed_time
                    remaining_emails = total_emails - i
                    estimated_seconds = (
                        remaining_emails / emails_per_second
                        if emails_per_second > 0
                        else 0
                    )
                    email_tasks[task_id]["estimated_seconds"] = estimated_seconds
            else:
                with email_tasks_lock:
                    email_tasks[task_id]["progress"] = progress

            # Parse email to extract transaction data
            transaction_data = parser.parse_email(email_data, bank_name)

            if transaction_data:
                # Check if the account is different
                if account_number[-4:] not in transaction_data.get("account_number"):
                    continue

                # Save email metadata
                email_metadata = TransactionRepository.create_email_metadata(
                    db_session,
                    {
                        "user_id": user_id,
                        "id": email_data.get("id"),
                        "subject": email_data.get("subject", ""),
                        "from": email_data.get("from", ""),
                        "date": email_data.get("date", ""),
                        "body": email_data.get("body", ""),
                        "cleaned_body": transaction_data.get("transaction_content", ""),
                        "processed": True,
                    },
                )

                # Add user_id, account_number, and email_metadata_id to transaction data
                transaction_data["user_id"] = user_id
                transaction_data["account_number"] = account_number

                if email_metadata:
                    transaction_data["email_metadata_id"] = email_metadata.id

                parsed_emails.append(
                    {"email": email_data, "transaction": transaction_data}
                )

                # Save to database if requested
                if save_to_db:
                    # Add preserve_balance flag to transaction data
                    transaction_data["preserve_balance"] = preserve_balance
                    transaction = TransactionRepository.create_transaction(
                        db_session, transaction_data
                    )
                    if transaction:
                        saved_count += 1

        # Disconnect from email
        email_service.disconnect()

        # Update task status
        with email_tasks_lock:
            email_tasks[task_id]["status"] = "completed"
            email_tasks[task_id]["progress"] = 100
            email_tasks[task_id]["end_time"] = time.time()
            email_tasks[task_id]["parsed_count"] = len(parsed_emails)
            email_tasks[task_id]["saved_count"] = saved_count

            # Store the first transaction in session for display
            if parsed_emails:
                email_tasks[task_id]["first_transaction"] = parsed_emails[0][
                    "transaction"
                ]

    except Exception as e:
        logger.error(f"Error in background task: {str(e)}")
        with email_tasks_lock:
            email_tasks[task_id]["status"] = "error"
            email_tasks[task_id]["message"] = str(e)
    finally:
        # Remove the account from scraping_accounts
        with email_tasks_lock:
            scraping_accounts.pop(account_number, None)
        db.close_session(db_session)


@email_bp.route("/email-configs", methods=["GET"])
@login_required
def email_configs():
    """List all email configurations."""
    user_id = session.get("user_id")
    db_session = db.get_session()

    try:
        # Get all email configurations for this user
        email_configs = (
            db_session.query(EmailConfiguration)
            .filter(EmailConfiguration.user_id == user_id)
            .all()
        )

        return render_template("email/email_configs.html", email_configs=email_configs)
    except Exception as e:
        logger.error(f"Error listing email configurations: {str(e)}")
        flash(f"Error listing email configurations: {str(e)}", "error")
        return redirect(url_for("main.dashboard"))
    finally:
        db.close_session(db_session)


@email_bp.route("/email-config/add", methods=["GET", "POST"])
@login_required
def add_email_config():
    """Add a new email configuration."""
    user_id = session.get("user_id")
    db_session = db.get_session()

    try:
        # Get all available banks
        banks = db_session.query(Bank).all()

        if request.method == "POST":
            email_username = request.form.get("email_username")

            # Extract provider from email
            provider_name = EmailService.extract_provider_from_email(email_username)

            # Get provider configuration if available
            provider_config = None
            if provider_name:
                provider_config = EmailService.get_provider_config(
                    db_session, provider_name
                )

                # Get the provider record to set the relationship
                from app.models.models import EmailServiceProvider

                provider = (
                    db_session.query(EmailServiceProvider)
                    .filter_by(provider_name=provider_name)
                    .first()
                )

            # Get bank information
            bank_ids = request.form.getlist("bank_ids[]")
            selected_banks = []

            # For backward compatibility, keep track of the first bank
            first_bank = None

            if bank_ids:
                for bank_id in bank_ids:
                    try:
                        bank = db_session.query(Bank).filter_by(id=int(bank_id)).first()
                        if bank:
                            selected_banks.append(bank)
                            if first_bank is None:
                                first_bank = bank
                    except ValueError:
                        logger.warning(f"Invalid bank ID: {bank_id}")

                if not selected_banks:
                    flash("No valid banks selected", "error")
                    return render_template("email/add_email_config.html", banks=banks)

            # Prepare configuration data
            config_data = {
                "user_id": user_id,
                "name": request.form.get("name", "Default"),
                "email_username": email_username,
                "email_password": request.form.get("email_password"),
                "bank_email_addresses": request.form.get("bank_email_addresses", ""),
                "bank_email_subjects": request.form.get("bank_email_subjects", ""),
            }

            # Add bank_id of the first selected bank for backward compatibility
            if first_bank:
                config_data["bank_id"] = first_bank.id

            # If provider configuration is available, use it
            if provider_config and provider:
                config_data["email_host"] = provider_config["host"]
                config_data["email_port"] = provider_config["port"]
                config_data["email_use_ssl"] = provider_config["use_ssl"]
                config_data["service_provider_id"] = provider.id
                logger.info(f"Using configuration for provider: {provider_name}")
            else:
                # Fall back to manual configuration if provider not recognized
                config_data["email_host"] = request.form.get("email_host")
                config_data["email_port"] = int(request.form.get("email_port", 993))
                config_data["email_use_ssl"] = "email_use_ssl" in request.form
                logger.info(
                    f"Using manual configuration (provider not recognized or not found)"
                )

            # Create the email configuration
            email_config = TransactionRepository.create_email_config(
                db_session, config_data
            )
            if email_config:
                # Create the many-to-many relationships with selected banks
                if selected_banks:
                    from app.models.models import EmailConfigBank

                    for bank in selected_banks:
                        # Check if the relationship already exists
                        existing = (
                            db_session.query(EmailConfigBank)
                            .filter_by(email_config_id=email_config.id, bank_id=bank.id)
                            .first()
                        )

                        if not existing:
                            # Create a new relationship
                            email_config_bank = EmailConfigBank(
                                email_config_id=email_config.id, bank_id=bank.id
                            )
                            db_session.add(email_config_bank)

                    # Commit the changes
                    db_session.commit()

                flash("Email configuration added successfully", "success")
                return redirect(url_for("email.email_configs"))
            else:
                flash("Error adding email configuration", "error")
                return render_template("email/add_email_config.html", banks=banks)

        # For GET requests, render the form
        return render_template("email/add_email_config.html", banks=banks)
    except Exception as e:
        logger.error(f"Error adding email configuration: {str(e)}")
        flash(f"Error adding email configuration: {str(e)}", "error")
        return redirect(url_for("email.email_configs"))
    finally:
        db.close_session(db_session)


@email_bp.route("/email-config/<int:config_id>/edit", methods=["GET", "POST"])
@login_required
def edit_email_config(config_id):
    """Edit an existing email configuration."""
    user_id = session.get("user_id")
    db_session = db.get_session()

    try:
        # Get the email configuration
        email_config = (
            db_session.query(EmailConfiguration)
            .filter(
                EmailConfiguration.id == config_id,
                EmailConfiguration.user_id == user_id,
            )
            .first()
        )

        if not email_config:
            flash(
                "Email configuration not found or you do not have permission to edit it",
                "error",
            )
            return redirect(url_for("email.email_configs"))

        # Get all available banks
        banks = db_session.query(Bank).all()

        # Get all banks associated with this email configuration
        from app.models.models import EmailConfigBank

        associated_bank_ids = [
            rel.bank_id
            for rel in db_session.query(EmailConfigBank)
            .filter_by(email_config_id=email_config.id)
            .all()
        ]

        if request.method == "POST":
            email_username = request.form.get("email_username")

            # Extract provider from email
            provider_name = EmailService.extract_provider_from_email(email_username)

            # Get provider configuration if available
            provider_config = None
            if provider_name:
                provider_config = EmailService.get_provider_config(
                    db_session, provider_name
                )

                # Get the provider record to set the relationship
                from app.models.models import EmailServiceProvider

                provider = (
                    db_session.query(EmailServiceProvider)
                    .filter_by(provider_name=provider_name)
                    .first()
                )

            # Get bank information
            bank_ids = request.form.getlist("bank_ids[]")
            selected_banks = []

            # For backward compatibility, keep track of the first bank
            first_bank = None

            if bank_ids:
                for bank_id in bank_ids:
                    try:
                        bank = db_session.query(Bank).filter_by(id=int(bank_id)).first()
                        if bank:
                            selected_banks.append(bank)
                            if first_bank is None:
                                first_bank = bank
                    except ValueError:
                        logger.warning(f"Invalid bank ID: {bank_id}")

                if not selected_banks:
                    flash("No valid banks selected", "error")
                    return render_template(
                        "email/edit_email_config.html",
                        email_config=email_config,
                        banks=banks,
                    )

                # Update bank_id for backward compatibility
                email_config.bank_id = first_bank.id
            else:
                email_config.bank_id = None

            # Update basic fields
            email_config.name = request.form.get("name", "Default")
            email_config.email_username = email_username

            # Only update password if provided
            new_password = request.form.get("email_password")
            if new_password:
                email_config.email_password = new_password

            email_config.bank_email_addresses = request.form.get(
                "bank_email_addresses", ""
            )
            email_config.bank_email_subjects = request.form.get(
                "bank_email_subjects", ""
            )

            # If provider configuration is available, use it
            if provider_config and provider:
                email_config.email_host = provider_config["host"]
                email_config.email_port = provider_config["port"]
                email_config.email_use_ssl = provider_config["use_ssl"]
                email_config.service_provider_id = provider.id
                logger.info(f"Using configuration for provider: {provider_name}")
            else:
                # Fall back to manual configuration if provider not recognized
                email_config.email_host = request.form.get("email_host")
                email_config.email_port = int(request.form.get("email_port", 993))
                email_config.email_use_ssl = "email_use_ssl" in request.form
                email_config.service_provider_id = None
                logger.info(
                    f"Using manual configuration (provider not recognized or not found)"
                )

            # Update the many-to-many relationships with selected banks
            if selected_banks:
                from app.models.models import EmailConfigBank

                # Get existing relationships
                existing_relationships = (
                    db_session.query(EmailConfigBank)
                    .filter_by(email_config_id=email_config.id)
                    .all()
                )

                # Create a set of existing bank IDs for easy lookup
                existing_bank_ids = {rel.bank_id for rel in existing_relationships}

                # Create a set of selected bank IDs
                selected_bank_ids = {bank.id for bank in selected_banks}

                # Remove relationships that are no longer needed
                for rel in existing_relationships:
                    if rel.bank_id not in selected_bank_ids:
                        db_session.delete(rel)

                # Add new relationships
                for bank in selected_banks:
                    if bank.id not in existing_bank_ids:
                        email_config_bank = EmailConfigBank(
                            email_config_id=email_config.id, bank_id=bank.id
                        )
                        db_session.add(email_config_bank)

            # Commit all changes
            db_session.commit()
            flash("Email configuration updated successfully", "success")
            return redirect(url_for("email.email_configs"))

        return render_template(
            "email/edit_email_config.html",
            email_config=email_config,
            banks=banks,
            associated_bank_ids=associated_bank_ids,
        )
    except Exception as e:
        logger.error(f"Error editing email configuration: {str(e)}")
        flash(f"Error editing email configuration: {str(e)}", "error")
        return redirect(url_for("email.email_configs"))
    finally:
        db.close_session(db_session)


@email_bp.route("/email-config/<int:config_id>/delete", methods=["POST"])
@login_required
def delete_email_config(config_id):
    """Delete an email configuration."""
    user_id = session.get("user_id")
    db_session = db.get_session()

    try:
        # Get the email configuration
        email_config = (
            db_session.query(EmailConfiguration)
            .filter(
                EmailConfiguration.id == config_id,
                EmailConfiguration.user_id == user_id,
            )
            .first()
        )

        if not email_config:
            flash(
                "Email configuration not found or you do not have permission to delete it",
                "error",
            )
            return redirect(url_for("email.email_configs"))

        # Check if any accounts are using this configuration
        accounts = (
            db_session.query(Account)
            .filter(Account.email_config_id == config_id)
            .first()
        )

        if accounts:
            flash(
                "Cannot delete email configuration that is being used by accounts",
                "error",
            )
            return redirect(url_for("email.email_configs"))

        db_session.delete(email_config)
        db_session.commit()
        flash("Email configuration deleted successfully", "success")
        return redirect(url_for("email.email_configs"))
    except Exception as e:
        logger.error(f"Error deleting email configuration: {str(e)}")
        flash(f"Error deleting email configuration: {str(e)}", "error")
        return redirect(url_for("email.email_configs"))
    finally:
        db.close_session(db_session)


@email_bp.route("/parse", methods=["POST"])
@login_required
def parse_email():
    """Parse email data from various sources."""
    user_id = session.get("user_id")
    email_data = {}
    source = request.form.get("source")
    account_number = request.form.get("account_number")

    if not account_number:
        flash("Please select an account", "error")
        return redirect(url_for("dashboard"))

    if source == "email":
        # Parse the email data
        transaction_data = parser.parse_email(email_data)

        if not transaction_data:
            flash(
                "Failed to parse email content. Make sure it contains valid transaction data.",
                "error",
            )
            return redirect(url_for("dashboard"))

        # Check if the account is different
        if account_number[-4:] not in transaction_data.get("account_number"):
            flash(
                f'Transaction account number {transaction_data.get("account_number")} does not match selected account {account_number}',
                "error",
            )
            return redirect(url_for("dashboard"))

        # Add user_id and account_number to transaction data
        transaction_data["user_id"] = user_id
        transaction_data["account_number"] = account_number
        transaction_data["email_data"] = email_data

        # Store the transaction data in session for display
        session["transaction_data"] = transaction_data

        # Optionally save to database if requested
        save_to_db = "save_to_db" in request.form
        preserve_balance = "preserve_balance" in request.form

        if save_to_db:
            db_session = db.get_session()
            try:
                # Add preserve_balance flag to transaction data
                transaction_data["preserve_balance"] = preserve_balance
                transaction = TransactionRepository.create_transaction(
                    db_session, transaction_data
                )
                if transaction:
                    flash("Transaction saved to database", "success")
                else:
                    flash("Failed to save transaction to database", "error")
            except Exception as e:
                logger.error(f"Error saving transaction to database: {str(e)}")
                flash(f"Error saving to database: {str(e)}", "error")
            finally:
                db.close_session(db_session)

        return redirect(url_for("main.results"))

    elif source == "upload":
        # Handle uploaded email file
        if "email_file" not in request.files:
            flash("No file part", "error")
            return redirect(url_for("dashboard"))

        file = request.files["email_file"]
        if file.filename == "":
            flash("No selected file", "error")
            return redirect(url_for("dashboard"))

        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)

            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    email_content = f.read()

                email_data = {
                    "id": f'upload_{datetime.now().strftime("%Y%m%d%H%M%S")}',
                    "subject": filename,
                    "from": request.form.get("from", "upload@example.com"),
                    "date": datetime.now().strftime("%a, %d %b %Y %H:%M:%S %z"),
                    "body": email_content,
                }

                # Clean up the uploaded file
                os.remove(filepath)
            except Exception as e:
                logger.error(f"Error reading uploaded file: {str(e)}")
                flash(f"Error reading file: {str(e)}", "error")
                return redirect(url_for("dashboard"))

    else:
        flash("Invalid source", "error")
        return redirect(url_for("dashboard"))


@email_bp.route("/email/task/<task_id>/status")
@login_required
def email_task_status(task_id):
    """API endpoint for checking email task status."""
    with email_tasks_lock:
        if task_id not in email_tasks:
            return jsonify({"error": "Task not found"}), 404

        task = email_tasks[task_id].copy()  # Create a copy to avoid holding the lock

    # Calculate elapsed time
    elapsed_time = time.time() - task["start_time"]

    # Prepare response data
    response = {
        "status": task["status"],
        "progress": task["progress"],
        "elapsed_seconds": elapsed_time,
        "message": task.get("message", ""),
    }

    # Add estimated time if available
    if "estimated_seconds" in task:
        response["estimated_seconds"] = task["estimated_seconds"]

    # Add completion data if task is completed
    if task["status"] == "completed":
        response["parsed_count"] = task.get("parsed_count", 0)
        response["saved_count"] = task.get("saved_count", 0)

        # If there's a transaction, redirect to results
        if "first_transaction" in task:
            # Store the transaction in session for the results page
            session["transaction_data"] = task["first_transaction"]
            response["redirect_url"] = url_for("results")

    return jsonify(response)


@email_bp.route("/test_email_connection/<int:config_id>")
@login_required
def test_email_connection(config_id):
    """Test the email connection for a specific configuration."""
    user_id = session.get("user_id")
    db_session = db.get_session()

    try:
        # Get the email configuration
        email_config = (
            db_session.query(EmailConfiguration)
            .filter(
                EmailConfiguration.id == config_id,
                EmailConfiguration.user_id == user_id,
            )
            .first()
        )

        if not email_config:
            return (
                jsonify({"success": False, "message": "Email configuration not found"}),
                404,
            )

        # Create email service from the configuration
        email_service = EmailService(
            host=email_config.email_host,
            port=email_config.email_port,
            username=email_config.email_username,
            password=email_config.email_password,
            use_ssl=email_config.email_use_ssl,
            bank_email_addresses=[],
            bank_email_subjects=[],
        )

        # Test connection
        if email_service.connect():
            email_service.disconnect()
            # Update last tested timestamp
            email_config.last_tested = datetime.now()
            db_session.commit()
            return jsonify(
                {"success": True, "message": "Successfully connected to email server"}
            )
        else:
            return jsonify(
                {"success": False, "message": "Failed to connect to email server"}
            )

    except Exception as e:
        logger.error(f"Error testing email connection: {str(e)}")
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500
    finally:
        db.close_session(db_session)


@email_bp.route("/fetch_emails", methods=["POST"])
@login_required
def fetch_emails():
    """Start asynchronous email fetching process."""
    user_id = session.get("user_id")
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    account_number = (
        request.form.get("account_number", "").split("|")[0]
        if "|" in request.form.get("account_number", "")
        else ""
    )
    bank_name = (
        request.form.get("account_number", "").split("|")[1]
        if "|" in request.form.get("account_number", "")
        else ""
    )

    if not account_number:
        if is_ajax:
            return jsonify({"success": False, "message": "Please select an account"})
        flash("Please select an account", "error")
        return redirect(url_for("dashboard"))

    # Check if the account is already being scraped
    with email_tasks_lock:
        if account_number in scraping_accounts:
            if is_ajax:
                return jsonify(
                    {
                        "success": False,
                        "message": "This account is already being scraped. Please wait until it completes.",
                    }
                )
            flash(
                "This account is already being scraped. Please wait until it completes.",
                "error",
            )
            return redirect(url_for("dashboard"))

        # Create a unique task ID
    try:
        task_id = str(uuid.uuid4())

        # Get form parameters
        folder = "INBOX"  # Always use INBOX as the default folder
        time_period = request.form.get("time_period", "only_unread")
        save_to_db = True  # Always save transactions to the database
        preserve_balance = "preserve_balance" in request.form

        # Initialize task
        try:
            with email_tasks_lock:
                email_tasks[task_id] = {
                    "user_id": user_id,
                    "account_number": account_number,
                    "status": "initializing",
                    "progress": 0,
                    "start_time": time.time(),
                    "folder": folder,
                    "time_period": time_period,
                    "save_to_db": save_to_db,
                    "preserve_balance": preserve_balance,
                }

                # Mark the account as being scraped
                scraping_accounts[account_number] = {
                    "user_id": user_id,
                    "task_id": task_id,
                    "start_time": time.time(),
                }
        except Exception as e:
            logger.error(f"Error initializing email task: {str(e)}")
            if is_ajax:
                return jsonify(
                    {
                        "success": False,
                        "message": "Failed to initialize email processing task",
                    }
                )
            flash("Failed to initialize email processing task", "error")
            return redirect(url_for("dashboard"))

        # Start background thread
        try:
            logger.debug("starting email processing thread")
            thread = threading.Thread(
                target=process_emails_task,
                args=(
                    task_id,
                    user_id,
                    account_number,
                    bank_name,
                    folder,
                    time_period,
                    save_to_db,
                    preserve_balance,
                ),
            )
            logger.debug(
                f"Starting thread for task {task_id} for account {account_number}"
            )
            thread.daemon = True
            thread.start()
        except Exception as e:
            logger.error(f"Error starting email processing thread: {str(e)}")
            with email_tasks_lock:
                email_tasks.pop(task_id, None)
                # Remove the account from scraping_accounts
                scraping_accounts.pop(account_number, None)
            if is_ajax:
                return jsonify(
                    {
                        "success": False,
                        "message": "Failed to start email processing task",
                    }
                )
            flash("Failed to start email processing task", "error")
            return redirect(url_for("dashboard"))

        # Store task ID in session
        try:
            session["email_task_id"] = task_id
        except Exception as e:
            logger.error(f"Error storing task ID in session: {str(e)}")
            with email_tasks_lock:
                email_tasks.pop(task_id, None)
                # Remove the account from scraping_accounts
                scraping_accounts.pop(account_number, None)
            if is_ajax:
                return jsonify(
                    {"success": False, "message": "Failed to store task information"}
                )
            flash("Failed to store task information", "error")
            return redirect(url_for("dashboard"))

        # Return response based on request type
        if is_ajax:
            return jsonify(
                {
                    "success": True,
                    "message": "Email fetching started successfully",
                    "task_id": task_id,
                    "account_number": account_number,
                }
            )
        else:
            # Redirect to email processing status page for non-AJAX requests
            return redirect(url_for("email_processing_status"))

    except Exception as e:
        logger.error(f"Unexpected error in fetch_emails: {str(e)}")
        if is_ajax:
            return jsonify(
                {"success": False, "message": f"An unexpected error occurred: {str(e)}"}
            )
        flash("An unexpected error occurred", "error")
        return redirect(url_for("dashboard"))


@email_bp.route("/email_processing_status")
@login_required
def email_processing_status():
    """Show email processing status page."""
    task_id = session.get("email_task_id")

    with email_tasks_lock:
        if not task_id or task_id not in email_tasks:
            flash("No email processing task found", "error")
            return redirect(url_for("dashboard"))

        task = email_tasks[task_id].copy()  # Create a copy to avoid holding the lock

    return render_template("email/email_processing.html", task_id=task_id, task=task)
