/**
 * Account Details Page JavaScript
 * Handles AJAX functionality for the account details page
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize update balance form
    initUpdateBalanceForm();
    
    // Initialize delete account form
    initDeleteAccountForm();
    
    // Initialize transaction actions
    initTransactionActions();
    
    // Initialize pagination links
    initPaginationLinks();
    
    // Initialize filter buttons
    initFilterButtons();
    
    // Initialize per-page selector
    initPerPageSelector();
    
    // Initialize category editing
    initCategoryEditing();
});

/**
 * Initialize the update balance form
 */
function initUpdateBalanceForm() {
    const form = document.getElementById('updateBalanceForm');
    if (!form) return;
    
    // Add AJAX submission to the form
    Ajax.submitForm(form, function(response) {
        // Handle successful response
        if (typeof response === 'string') {
            // If the response is HTML, the server returned a full page
            // Reload the page to show the updated balance
            window.location.reload();
        } else {
            // If the response is JSON, update the balance display
            if (response.success) {
                // Update the balance display
                const balanceElement = document.querySelector('.balance-section h3');
                if (balanceElement) {
                    const currencyElement = balanceElement.querySelector('small');
                    const currency = currencyElement ? currencyElement.textContent : '';
                    
                    // Update the balance value
                    balanceElement.innerHTML = `
                        <span class="me-2">${response.formatted_balance}</span>
                        <small class="text-body-secondary">${currency}</small>
                    `;
                }
                
                // Close the modal
                const modal = bootstrap.Modal.getInstance(document.getElementById('updateBalanceModal'));
                if (modal) {
                    modal.hide();
                }
                
                // Show success notification
                Ajax.showNotification('Balance updated successfully!', 'success');
            } else {
                // Show error notification
                Ajax.showNotification(response.message || 'Failed to update balance.', 'error');
            }
        }
    });
}

/**
 * Initialize the delete account form
 */
function initDeleteAccountForm() {
    const form = document.querySelector('form[action*="delete_account"]');
    if (!form) return;
    
    // Add AJAX submission to the form
    Ajax.submitForm(form, function(response) {
        // Handle successful response
        if (typeof response === 'string') {
            // If the response is HTML, the server returned a full page
            // Redirect to the accounts page
            window.location.href = '/accounts';
        } else {
            // If the response is JSON, check for success
            if (response.success) {
                // Redirect to the accounts page
                window.location.href = response.redirect || '/accounts';
            } else {
                // Show error notification
                Ajax.showNotification(response.message || 'Failed to delete account.', 'error');
                
                // Close the modal
                const modal = bootstrap.Modal.getInstance(document.getElementById('deleteAccountModal'));
                if (modal) {
                    modal.hide();
                }
            }
        }
    });
}

/**
 * Initialize transaction actions (edit, delete)
 */
function initTransactionActions() {
    // Handle delete transaction forms
    const deleteForms = document.querySelectorAll('form[action*="delete_transaction"]');
    deleteForms.forEach(form => {
        Ajax.submitForm(form, function(response) {
            // Handle successful response
            if (response.success) {
                // Remove the transaction row from the table
                const row = form.closest('tr');
                if (row) {
                    row.remove();
                }
                
                // Show success notification
                Ajax.showNotification('Transaction deleted successfully!', 'success');
                
                // If there are no more transactions, reload the page to show the empty state
                const tbody = document.querySelector('table tbody');
                if (tbody && tbody.children.length === 0) {
                    window.location.reload();
                }
            } else {
                // Show error notification
                Ajax.showNotification(response.message || 'Failed to delete transaction.', 'error');
            }
        });
    });
}

/**
 * Initialize pagination links
 */
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
                    
                    // Re-initialize transaction table with DataTables
                    if (typeof reinitTransactionTable === 'function') {
                        reinitTransactionTable();
                    }
                });
            }
        });
    });
}

/**
 * Initialize filter controls
 */
function initFilterButtons() {
    // Initialize transaction type filter
    const transactionTypeSelect = document.getElementById('transaction-type');
    
    // Initialize date range picker
    const dateFromInput = document.getElementById('date-from');
    const dateToInput = document.getElementById('date-to');
    
    // Initialize search text input
    const searchTextInput = document.getElementById('search-text');
    const searchButton = document.getElementById('search-button');
    
    // Initialize apply and clear filter buttons
    const applyFiltersButton = document.getElementById('apply-filters');
    const clearFiltersButton = document.getElementById('clear-filters');
    
    // Initialize active filters container
    const activeFiltersContainer = document.getElementById('active-filters');
    
    // Set initial values from URL parameters
    setInitialFilterValues();
    
    // Add event listener to apply filters button
    if (applyFiltersButton) {
        applyFiltersButton.addEventListener('click', function() {
            applyFilters();
        });
    }
    
    // Add event listener to clear filters button
    if (clearFiltersButton) {
        clearFiltersButton.addEventListener('click', function() {
            clearFilters();
        });
    }
    
    // Add event listener to search button
    if (searchButton) {
        searchButton.addEventListener('click', function() {
            applyFilters();
        });
    }
    
    // Add event listener to search text input for Enter key
    if (searchTextInput) {
        searchTextInput.addEventListener('keypress', function(event) {
            if (event.key === 'Enter') {
                event.preventDefault();
                applyFilters();
            }
        });
    }
    
    /**
     * Set initial filter values from URL parameters
     */
    function setInitialFilterValues() {
        const url = new URL(window.location.href);
        
        // Set transaction type
        const filterType = url.searchParams.get('filter');
        if (transactionTypeSelect && filterType) {
            transactionTypeSelect.value = filterType;
        }
        
        // Set date range
        const dateFrom = url.searchParams.get('date_from');
        const dateTo = url.searchParams.get('date_to');
        
        if (dateFromInput && dateFrom) {
            dateFromInput.value = dateFrom;
        }
        
        if (dateToInput && dateTo) {
            dateToInput.value = dateTo;
        }
        
        // Set search text
        const searchText = url.searchParams.get('search');
        if (searchTextInput && searchText) {
            searchTextInput.value = searchText;
        }
        
        // Update active filters display
        updateActiveFiltersDisplay();
    }
    
    /**
     * Apply filters and update the transaction list
     */
    function applyFilters() {
        // Get the current URL
        const url = new URL(window.location.href);
        
        // Reset to page 1 when changing filters
        url.searchParams.delete('page');
        
        // Get filter values
        const transactionType = transactionTypeSelect ? transactionTypeSelect.value : '';
        const dateFrom = dateFromInput ? dateFromInput.value : '';
        const dateTo = dateToInput ? dateToInput.value : '';
        const searchText = searchTextInput ? searchTextInput.value : '';
        
        // Preserve the per_page parameter if it exists
        const perPage = url.searchParams.get('per_page');
        
        // Update URL parameters
        if (transactionType) {
            url.searchParams.set('filter', transactionType);
        } else {
            url.searchParams.delete('filter');
        }
        
        if (dateFrom) {
            url.searchParams.set('date_from', dateFrom);
        } else {
            url.searchParams.delete('date_from');
        }
        
        if (dateTo) {
            url.searchParams.set('date_to', dateTo);
        } else {
            url.searchParams.delete('date_to');
        }
        
        if (searchText) {
            url.searchParams.set('search', searchText);
        } else {
            url.searchParams.delete('search');
        }
        
        // Restore the per_page parameter if it existed
        if (perPage) {
            url.searchParams.set('per_page', perPage);
        }
        
        // Load the filtered content via AJAX
        Ajax.loadContent(url.toString(), '#transaction-container', function(data) {
            // Update the URL in the browser's address bar without reloading the page
            history.pushState({}, '', url.toString());
            
            // Re-initialize transaction actions for the new content
            initTransactionActions();
            
            // Re-initialize pagination links for the new content
            initPaginationLinks();
            
            // Re-initialize category editing for the new content
            initCategoryEditing();
            
            // Update active filters display
            updateActiveFiltersDisplay();
            
            // Re-initialize transaction table with DataTables
            if (typeof reinitTransactionTable === 'function') {
                reinitTransactionTable();
            }
        });
    }
    
    /**
     * Clear all filters and reset the transaction list
     */
    function clearFilters() {
        // Reset filter controls
        if (transactionTypeSelect) transactionTypeSelect.value = '';
        if (dateFromInput) dateFromInput.value = '';
        if (dateToInput) dateToInput.value = '';
        if (searchTextInput) searchTextInput.value = '';
        
        // Get the current URL and remove filter parameters
        const url = new URL(window.location.href);
        
        // Preserve the per_page parameter if it exists
        const perPage = url.searchParams.get('per_page');
        
        // Clear all filter parameters
        url.searchParams.delete('filter');
        url.searchParams.delete('date_from');
        url.searchParams.delete('date_to');
        url.searchParams.delete('search');
        url.searchParams.delete('page');
        
        // Restore the per_page parameter if it existed
        if (perPage) {
            url.searchParams.set('per_page', perPage);
        }
        
        // Load the unfiltered content via AJAX
        Ajax.loadContent(url.toString(), '#transaction-container', function(data) {
            // Update the URL in the browser's address bar without reloading the page
            history.pushState({}, '', url.toString());
            
            // Re-initialize transaction actions for the new content
            initTransactionActions();
            
            // Re-initialize pagination links for the new content
            initPaginationLinks();
            
            // Re-initialize category editing for the new content
            initCategoryEditing();
            
            // Update active filters display
            updateActiveFiltersDisplay();
            
            // Re-initialize transaction table with DataTables
            if (typeof reinitTransactionTable === 'function') {
                reinitTransactionTable();
            }
        });
    }
    
    /**
     * Update the active filters display
     */
    function updateActiveFiltersDisplay() {
        if (!activeFiltersContainer) return;
        
        const url = new URL(window.location.href);
        const filterType = url.searchParams.get('filter');
        const dateFrom = url.searchParams.get('date_from');
        const dateTo = url.searchParams.get('date_to');
        const searchText = url.searchParams.get('search');
        
        // Check if any filters are active
        const hasActiveFilters = filterType || dateFrom || dateTo || searchText;
        
        // Show or hide the active filters container
        if (hasActiveFilters) {
            activeFiltersContainer.classList.remove('d-none');
            
            // Clear existing filter badges
            const filterBadgesContainer = activeFiltersContainer.querySelector('.d-flex');
            if (filterBadgesContainer) {
                filterBadgesContainer.innerHTML = '';
                
                // Add filter badges
                if (filterType) {
                    let filterLabel = '';
                    if (filterType === 'income') filterLabel = 'Income Only';
                    else if (filterType === 'expense') filterLabel = 'Expenses Only';
                    else if (filterType === 'transfer') filterLabel = 'Transfers Only';
                    
                    addFilterBadge(filterBadgesContainer, filterLabel, () => {
                        if (transactionTypeSelect) transactionTypeSelect.value = '';
                        url.searchParams.delete('filter');
                        applyFilters();
                    });
                }
                
                if (dateFrom || dateTo) {
                    let dateLabel = 'Date: ';
                    if (dateFrom) dateLabel += dateFrom;
                    if (dateFrom && dateTo) dateLabel += ' to ';
                    if (dateTo) dateLabel += dateTo;
                    
                    addFilterBadge(filterBadgesContainer, dateLabel, () => {
                        if (dateFromInput) dateFromInput.value = '';
                        if (dateToInput) dateToInput.value = '';
                        url.searchParams.delete('date_from');
                        url.searchParams.delete('date_to');
                        applyFilters();
                    });
                }
                
                if (searchText) {
                    addFilterBadge(filterBadgesContainer, `Search: ${searchText}`, () => {
                        if (searchTextInput) searchTextInput.value = '';
                        url.searchParams.delete('search');
                        applyFilters();
                    });
                }
            }
        } else {
            activeFiltersContainer.classList.add('d-none');
        }
    }
    
    /**
     * Add a filter badge to the container
     */
    function addFilterBadge(container, label, removeCallback) {
        const badge = document.createElement('div');
        badge.className = 'badge bg-light text-dark d-flex align-items-center p-2';
        badge.innerHTML = `
            <span>${label}</span>
            <button type="button" class="btn-close btn-close-sm ms-2" aria-label="Remove filter"></button>
        `;
        
        // Add click event to the close button
        const closeButton = badge.querySelector('.btn-close');
        if (closeButton && removeCallback) {
            closeButton.addEventListener('click', removeCallback);
        }
        
        container.appendChild(badge);
    }
}

/**
 * Initialize per-page selector functionality
 */
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
            
            // Re-initialize transaction table with DataTables
            if (typeof reinitTransactionTable === 'function') {
                reinitTransactionTable();
            }
        });
    });
}

/**
 * Initialize category editing functionality
 */
function initCategoryEditing() {
    // Add event listeners to edit buttons
    const editButtons = document.querySelectorAll('.edit-category-btn');
    editButtons.forEach(button => {
        button.addEventListener('click', function(event) {
            event.preventDefault();
            
            // Get the transaction ID
            const transactionId = button.closest('.category-display').dataset.transactionId;
            
            // Hide the display view and show the edit view
            document.querySelector(`.category-display[data-transaction-id="${transactionId}"]`).classList.add('d-none');
            document.querySelector(`.category-edit[data-transaction-id="${transactionId}"]`).classList.remove('d-none');
        });
    });
    
    // Add event listeners to cancel buttons
    const cancelButtons = document.querySelectorAll('.cancel-category-btn');
    cancelButtons.forEach(button => {
        button.addEventListener('click', function(event) {
            event.preventDefault();
            
            // Get the transaction ID
            const transactionId = button.closest('.category-edit').dataset.transactionId;
            
            // Hide the edit view and show the display view
            document.querySelector(`.category-edit[data-transaction-id="${transactionId}"]`).classList.add('d-none');
            document.querySelector(`.category-display[data-transaction-id="${transactionId}"]`).classList.remove('d-none');
        });
    });
    
    // Add AJAX submission to category forms
    const categoryForms = document.querySelectorAll('.category-form');
    categoryForms.forEach(form => {
        Ajax.submitForm(form, function(response) {
            // Get the transaction ID
            const transactionId = form.closest('.category-edit').dataset.transactionId;
            
            if (response.success) {
                // Update the category badge
                const badge = document.querySelector(`.category-display[data-transaction-id="${transactionId}"] .category-badge`);
                badge.textContent = response.category_name;
                
                // Update badge color based on category name
                if (response.category_name === 'Uncategorized') {
                    badge.className = 'badge bg-secondary category-badge';
                } else {
                    badge.className = 'badge bg-info category-badge';
                }
                
                // Hide the edit view and show the display view
                document.querySelector(`.category-edit[data-transaction-id="${transactionId}"]`).classList.add('d-none');
                document.querySelector(`.category-display[data-transaction-id="${transactionId}"]`).classList.remove('d-none');
                
                // Show success notification
                Ajax.showNotification('Category updated successfully!', 'success');
            } else {
                // Show error notification
                Ajax.showNotification(response.message || 'Failed to update category.', 'error');
            }
        });
    });
}