"""
category views for the Flask application.
"""

import logging

from flask import (Blueprint, flash, jsonify, redirect, render_template,
                   request, session, url_for)

from ..models import (Category, CategoryMapping, CategoryType,
                EmailManuConfigs)
from ..models.database import Database
from ..models.transaction import TransactionRepository
from ..models.user import User
from ..services.category_service import CategoryService
from ..services.counterparty_service import CounterpartyService
from ..utils.decorators import login_required

# Create blueprint
category_bp = Blueprint("category", __name__)

# Initialize database and logger
db = Database()
logger = logging.getLogger(__name__)
category_service = CategoryService()
counterparty_service = CounterpartyService()


@category_bp.route("/categories")
@login_required
def categories():
    """Display categories management page."""
    user_id = session.get("user_id")
    db_session = db.get_session()

    try:
        categories = (
            db_session.query(Category).filter(Category.user_id == user_id).all()
        )
        return render_template("category/categories.html", categories=categories)

    except Exception as e:
        logger.error(f"Error loading categories: {str(e)}")
        flash("Error loading categories", "error")
        return render_template("category/categories.html", categories=[])
    finally:
        db.close_session(db_session)


@category_bp.route("/categories/add", methods=["GET", "POST"])
@login_required
def add_category():
    """Add a new category."""
    if request.method == "POST":
        user_id = session.get("user_id")
        name = request.form.get("name")
        color = request.form.get("color")

        if not name:
            flash("Category name is required", "error")
            return render_template("category/add_category.html")

        db_session = db.get_session()
        try:
            category = Category(name=name, color=color, user_id=user_id)
            db_session.add(category)
            db_session.commit()

            flash("Category added successfully", "success")
            return redirect(url_for("category.categories"))

        except Exception as e:
            logger.error(f"Error adding category: {str(e)}")
            flash("Error adding category", "error")
            return render_template("category/add_category.html")
        finally:
            db.close_session(db_session)

    return render_template("category/add_category.html")


@category_bp.route("/categories/<int:category_id>/edit", methods=["GET", "POST"])
@login_required
def edit_category(category_id):
    """Edit a category."""
    user_id = session.get("user_id")
    db_session = db.get_session()

    try:
        category = (
            db_session.query(Category)
            .filter(Category.id == category_id, Category.user_id == user_id)
            .first()
        )

        if not category:
            flash("Category not found", "error")
            return redirect(url_for("category.categories"))

        if request.method == "POST":
            category.name = request.form.get("name")
            category.color = request.form.get("color")
            db_session.commit()

            flash("Category updated successfully", "success")
            return redirect(url_for("category.categories"))

        return render_template("category/edit_category.html", category=category)

    except Exception as e:
        logger.error(f"Error editing category: {str(e)}")
        flash("Error editing category", "error")
        return redirect(url_for("category.categories"))
    finally:
        db.close_session(db_session)


@category_bp.route("/categories/<int:category_id>/delete", methods=["POST"])
@login_required
def delete_category(category_id):
    """Delete a category."""
    user_id = session.get("user_id")
    db_session = db.get_session()

    try:
        category = (
            db_session.query(Category)
            .filter(Category.id == category_id, Category.user_id == user_id)
            .first()
        )

        if not category:
            flash("Category not found", "error")
            return redirect(url_for("category.categories"))

        db_session.delete(category)
        db_session.commit()

        flash("Category deleted successfully", "success")
        return redirect(url_for("category.categories"))

    except Exception as e:
        logger.error(f"Error deleting category: {str(e)}")
        flash("Error deleting category", "error")
        return redirect(url_for("category.categories"))
    finally:
        db.close_session(db_session)


@category_bp.route("/categories/<int:category_id>/mappings")
@login_required
def category_mappings(category_id):
    """List all mappings for a category."""
    user_id = session.get("user_id")

    # Get the category
    category = counterparty_service.get_category(category_id, user_id)
    if not category:
        flash("Category not found", "error")
        return redirect(url_for("category.categories"))

    # Get the mappings
    mappings = counterparty_service.get_category_mappings(category_id, user_id)

    return render_template(
        "category/category_mappings.html", category=category, mappings=mappings
    )


@category_bp.route(
    "/categories/<int:category_id>/mappings/add", methods=["GET", "POST"]
)
@login_required
def add_category_mapping(category_id):
    """Add a new category mapping."""
    user_id = session.get("user_id")

    # Get the category
    category = counterparty_service.get_category(category_id, user_id)
    if not category:
        flash("Category not found", "error")
        return redirect(url_for("category.categories"))

    if request.method == "POST":
        mapping_type = request.form.get("mapping_type")
        pattern = request.form.get("pattern")

        if not mapping_type or not pattern:
            flash("Mapping type and pattern are required", "error")
            return render_template(
                "category/add_category_mapping.html", category=category
            )

        # Convert mapping_type string to enum
        try:
            mapping_type_enum = CategoryType[mapping_type]
        except KeyError:
            flash("Invalid mapping type", "error")
            return render_template(
                "category/add_category_mapping.html", category=category
            )

        mapping = counterparty_service.create_category_mapping(
            category_id, user_id, mapping_type_enum, pattern
        )
        if mapping:
            flash("Category mapping added successfully", "success")
            return redirect(
                url_for("category.category_mappings", category_id=category_id)
            )
        else:
            flash("Error adding category mapping", "error")
            return render_template(
                "category/add_category_mapping.html", category=category
            )

    return render_template("category/add_category_mapping.html", category=category)


@category_bp.route("/categories/mappings/<int:mapping_id>/delete", methods=["POST"])
@login_required
def delete_category_mapping(mapping_id):
    """Delete a category mapping."""
    user_id = session.get("user_id")

    # Get the category_id from the form
    category_id = request.form.get("category_id")
    if not category_id:
        flash("Category ID is required", "error")
        return redirect(url_for("category.categories"))

    result = counterparty_service.delete_category_mapping(mapping_id, user_id)
    if result:
        flash("Category mapping deleted successfully", "success")
    else:
        flash("Error deleting category mapping", "error")

    return redirect(url_for("category.category_mappings", category_id=category_id))


@category_bp.route("/categorize_counterparty", methods=["POST"])
@login_required
def categorize_counterparty():
    counterparty_name = request.form.get("counterparty_name")
    description = request.form.get("description", "")
    category_id = request.form.get("category_id")
    user_id = session.get("user_id")

    if not counterparty_name or not category_id:
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "message": "Missing required fields"})
        flash("Missing required fields", "error")
        return redirect(url_for("main.counterparties"))

    try:
        success = counterparty_service.categorize_counterparty(
            user_id, counterparty_name, description, int(category_id)
        )

        if success:
            # Get category name for response
            db_session = db.get_session()
            category = (
                db_session.query(Category)
                .filter_by(id=category_id, user_id=user_id)
                .first()
            )
            category_name = category.name if category else "Unknown"

            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify(
                    {
                        "success": True,
                        "message": "Counterparty categorized successfully",
                        "category_name": category_name,
                    }
                )
            flash("Counterparty categorized successfully!", "success")
        else:
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify(
                    {"success": False, "message": "Failed to categorize counterparty"}
                )
            flash("Failed to categorize counterparty", "error")
    except Exception as e:
        logger.error(f"Error categorizing counterparty: {e}")
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return jsonify({"success": False, "message": "An error occurred"})
        flash("An error occurred", "error")

    return redirect(url_for("main.counterparties"))


@category_bp.route("/auto-categorize")
@login_required
def auto_categorize():
    """Auto-categorize all uncategorized transactions."""
    user_id = session.get("user_id")

    count = counterparty_service.auto_categorize_all_transactions(user_id)
    flash(f"Auto-categorized {count} transactions", "success")

    return redirect(url_for("main.dashboard"))
