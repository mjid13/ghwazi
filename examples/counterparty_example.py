"""
Example usage of the CounterpartyService.
"""

import sys
import os
import logging
from typing import List, Dict, Any

# Add the parent directory to the path so we can import the money_tracker package
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from money_tracker.services.counterparty_service import CounterpartyService
from money_tracker.models.models import CategoryType

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def print_separator():
    """Print a separator line."""
    print("\n" + "-" * 80 + "\n")

def print_counterparties(counterparties: List[Dict[str, Any]]):
    """Print a list of counterparties."""
    print("Counterparties:")
    for cp in counterparties:
        print(f"  - {cp['counterparty_name']} | {cp['description']} | {cp['transaction_details']} | Category: {cp['category_name'] or 'Uncategorized'}")

def print_categories(categories):
    """Print a list of categories."""
    print("Categories:")
    for category in categories:
        print(f"  - {category.id}: {category.name} - {category.description or ''}")

def main():
    """Main function to demonstrate CounterpartyService usage."""
    try:
        # Create a CounterpartyService instance
        service = CounterpartyService()
        
        # User ID for the example (you should replace this with a real user ID)
        user_id = 1
        
        print_separator()
        print("1. Get all unique counterparties")
        counterparties = service.get_unique_counterparties(user_id)
        print_counterparties(counterparties)
        
        print_separator()
        print("2. Get all categories")
        categories = service.get_categories(user_id)
        print_categories(categories)
        
        print_separator()
        print("3. Create a new category")
        new_category = service.create_category(user_id, "Groceries", "Food and household items")
        if new_category:
            print(f"Created category: {new_category.name} - {new_category.description}")
            
            print_separator()
            print("4. Categorize a counterparty")
            # Assuming there's at least one counterparty
            if counterparties:
                cp = counterparties[0]
                result = service.categorize_counterparty(
                    user_id, 
                    cp['counterparty_name'], 
                    cp['description'], 
                    new_category.id
                )
                if result:
                    print(f"Categorized {cp['counterparty_name']} as {new_category.name}")
                else:
                    print(f"Failed to categorize {cp['counterparty_name']}")
            else:
                print("No counterparties found to categorize")
            
            print_separator()
            print("5. Create a category mapping for pattern matching")
            # Create a mapping for a pattern
            pattern = "GROCERY"
            mapping = service.create_category_mapping(
                new_category.id, 
                user_id, 
                CategoryType.DESCRIPTION, 
                pattern
            )
            if mapping:
                print(f"Created mapping: {pattern} -> {new_category.name}")
            else:
                print(f"Failed to create mapping for {pattern}")
            
            print_separator()
            print("6. Auto-categorize all transactions")
            count = service.auto_categorize_all_transactions(user_id)
            print(f"Auto-categorized {count} transactions")
            
            print_separator()
            print("7. Get updated counterparties")
            counterparties = service.get_unique_counterparties(user_id)
            print_counterparties(counterparties)
            
            print_separator()
            print("8. Update a category")
            result = service.update_category(new_category.id, user_id, name="Food & Groceries")
            if result:
                updated_category = service.get_category(new_category.id, user_id)
                print(f"Updated category: {updated_category.name} - {updated_category.description}")
            else:
                print(f"Failed to update category {new_category.id}")
            
            print_separator()
            print("9. Delete a category")
            result = service.delete_category(new_category.id, user_id)
            if result:
                print(f"Deleted category {new_category.id}")
            else:
                print(f"Failed to delete category {new_category.id}")
        else:
            print("Failed to create category")
        
    except Exception as e:
        logger.error(f"Error in example: {str(e)}")
    finally:
        # Close the service
        if 'service' in locals():
            service.close()
