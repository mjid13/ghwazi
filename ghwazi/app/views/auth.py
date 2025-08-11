"""
Authentication views for the Flask application.
"""

import logging
from datetime import datetime

from flask import (Blueprint, flash, redirect, render_template, request,
                   session, url_for)

from ..models.database import Database
from ..models.transaction import TransactionRepository
from ..models.user import User

# Create blueprint
auth_bp = Blueprint("auth", __name__)

# Initialize database and logger
db = Database()
logger = logging.getLogger(__name__)


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """Register a new user."""
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if not username or not email or not password:
            flash("All fields are required", "error")
            return render_template("auth/register.html")

        if password != confirm_password:
            flash("Passwords do not match", "error")
            return render_template("auth/register.html")

        db_session = db.get_session()
        try:
            # Check if user already exists
            existing_user = (
                db_session.query(User)
                .filter((User.username == username) | (User.email == email))
                .first()
            )

            if existing_user:
                flash("Username or email already exists", "error")
                return render_template("auth/register.html")

            # Create new user
            user_data = {"username": username, "email": email, "password": password}

            # Debug logging
            logger.info(
                f"Attempting to create user with username: {username}, email: {email}"
            )

            user = TransactionRepository.create_user(db_session, user_data)
            if user:
                logger.info(f"User created successfully: {user.username}")
                flash("Registration successful! Please log in.", "success")
                return redirect(url_for("auth.login"))
            else:
                logger.error("TransactionRepository.create_user returned None")
                flash("Error creating user", "error")
                return render_template("auth/register.html")

        except Exception as e:
            logger.error(f"Error registering user: {str(e)}")
            flash(f"Error registering user: {str(e)}", "error")
            return render_template("auth/register.html")
        finally:
            db.close_session(db_session)

    return render_template("auth/register.html")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Log in a user."""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            flash("Username and password are required", "error")
            return render_template("auth/login.html")

        db_session = db.get_session()
        try:
            user = db_session.query(User).filter(User.username == username).first()

            if not user or not user.check_password(password):
                flash("Invalid username or password", "error")
                return render_template("auth/login.html")

            # Rotate and set user session
            session.clear()
            session["user_id"] = user.id
            session["username"] = user.username
            session["last_activity"] = datetime.now().timestamp()
            session.permanent = True

            flash(f"Welcome back, {user.username}!", "success")
            return redirect(url_for("main.dashboard"))

        except Exception as e:
            logger.error(f"Error logging in: {str(e)}")
            flash("Error logging in. Please try again.", "error")
            return render_template("auth/login.html")
        finally:
            db.close_session(db_session)

    return render_template("auth/login.html")


@auth_bp.route("/logout")
def logout():
    """Log out a user."""
    session.clear()
    flash("You have been logged out", "success")
    return redirect(url_for("main.index"))
