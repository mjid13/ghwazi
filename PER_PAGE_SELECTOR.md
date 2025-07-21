# Per-Page Selector Implementation

## Overview

This document describes the implementation of a feature that allows users to change the number of transactions displayed per page in the account details view. This enhancement improves user experience by giving users control over the pagination density according to their preferences.

## Changes Made

### 1. UI Addition in account_details.html

Added a dropdown selector in the filter section of the account details page:

```html
<div class="per-page-selector">
    <div class="input-group input-group-sm">
        <label class="input-group-text" for="per-page-select">Show</label>
        <select class="form-select form-select-sm" id="per-page-select">
            <option value="10">10</option>
            <option value="25">25</option>
            <option value="50" selected>50</option>
            <option value="100">100</option>
            <option value="200">200</option>
        </select>
        <span class="input-group-text">per page</span>
    </div>
</div>
```

The dropdown is placed alongside the filter controls, allowing users to select from 10, 25, 50, 100, or 200 transactions per page, with 50 as the default value.

### 2. JavaScript Implementation in account_details.js

#### 2.1 Added Initialization Function

Added a new function `initPerPageSelector()` to initialize the per-page selector:

```javascript
function initPerPageSelector() {
    const perPageSelect = document.getElementById('per-page-select');
    if (!perPageSelect) return;
    
    // Set initial value from URL parameter
    const url = new URL(window.location.href);
    const perPage = url.searchParams.get('per_page');
    if (perPage) {
        // Find and select the option with the matching value
        const option = perPageSelect.querySelector(`option[value="${perPage}"]`);
        if (option) {
            option.selected = true;
        }
    }
    
    // Add event listener for changes
    perPageSelect.addEventListener('change', function() {
        // Get the current URL
        const url = new URL(window.location.href);
        
        // Update the per_page parameter
        url.searchParams.set('per_page', this.value);
        
        // Reset to page 1 when changing per_page
        url.searchParams.set('page', 1);
        
        // Load the content via AJAX
        Ajax.loadContent(url.toString(), '#transaction-container', function(data) {
            // Update the URL in the browser's address bar without reloading the page
            history.pushState({}, '', url.toString());
            
            // Re-initialize transaction actions for the new content
            initTransactionActions();
            
            // Re-initialize pagination links for the new content
            initPaginationLinks();
            
            // Re-initialize category editing for the new content
            initCategoryEditing();
        });
    });
}
```

This function:
- Sets the initial selected option based on the URL parameter
- Adds an event listener to handle changes to the dropdown
- When the dropdown value changes, it updates the URL with the new per_page parameter, resets to page 1, and reloads the transaction list via AJAX

#### 2.2 Updated Pagination Links Handling

Modified the `initPaginationLinks()` function to preserve the per_page parameter when changing pages:

```javascript
function initPaginationLinks() {
    const paginationLinks = document.querySelectorAll('.pagination .page-link');
    paginationLinks.forEach(link => {
        link.addEventListener('click', function(event) {
            // Only handle links that aren't disabled
            if (!link.parentElement.classList.contains('disabled') && !link.parentElement.classList.contains('active')) {
                event.preventDefault();
                
                // Get the URL from the link
                let url = new URL(link.getAttribute('href'), window.location.origin);
                
                // Preserve the per_page parameter if it exists in the current URL
                const currentUrl = new URL(window.location.href);
                const perPage = currentUrl.searchParams.get('per_page');
                if (perPage) {
                    url.searchParams.set('per_page', perPage);
                }
                
                // Load the content via AJAX
                Ajax.loadContent(url.toString(), '#transaction-container', function(data) {
                    // Update the URL in the browser's address bar without reloading the page
                    history.pushState({}, '', url.toString());
                    
                    // Re-initialize transaction actions for the new content
                    initTransactionActions();
                    
                    // Re-initialize pagination links for the new content
                    initPaginationLinks();
                    
                    // Re-initialize category editing for the new content
                    initCategoryEditing();
                });
            }
        });
    });
}
```

#### 2.3 Updated Filter Functions

Modified the `applyFilters()` and `clearFilters()` functions to preserve the per_page parameter when applying or clearing filters:

```javascript
function applyFilters() {
    // ... existing code ...
    
    // Preserve the per_page parameter if it exists
    const perPage = url.searchParams.get('per_page');
    
    // ... update filter parameters ...
    
    // Restore the per_page parameter if it existed
    if (perPage) {
        url.searchParams.set('per_page', perPage);
    }
    
    // ... load content ...
}

function clearFilters() {
    // ... existing code ...
    
    // Preserve the per_page parameter if it exists
    const perPage = url.searchParams.get('per_page');
    
    // ... clear filter parameters ...
    
    // Restore the per_page parameter if it existed
    if (perPage) {
        url.searchParams.set('per_page', perPage);
    }
    
    // ... load content ...
}
```

### 3. Backend Support

The backend already supported the per_page parameter in the account_details route:

```python
@app.route('/account/<account_number>')
@login_required
def account_details(account_number):
    # ...
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    # ...
    transactions_history = TransactionRepository.get_account_transaction_history(
        db_session, user_id, account_number, page=page, per_page=per_page, **filter_params
    )
    # ...
```

## Benefits

This enhancement provides several benefits to users:

1. **Customized View Density**: Users can choose between a dense view with many transactions or a sparse view with fewer transactions per page.
2. **Improved Performance**: Users with slower connections can choose to load fewer transactions per page for faster loading.
3. **Better Navigation**: Users can adjust the pagination to their preference, making it easier to find specific transactions.
4. **Persistent Settings**: The selected per_page value is preserved when applying filters or navigating between pages.

## Usage

To change the number of transactions displayed per page:

1. Navigate to the account details page
2. Locate the "Show [x] per page" dropdown in the filter section
3. Select the desired number of transactions per page (10, 25, 50, 100, or 200)
4. The page will automatically refresh to display the selected number of transactions

The selected setting will be preserved when:
- Applying filters
- Clearing filters
- Navigating between pages