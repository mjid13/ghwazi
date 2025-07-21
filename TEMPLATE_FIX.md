# Template Fixes Documentation

This document outlines the issues found in the Money Tracker application templates and the changes made to fix them.

## Issues Found and Fixed

### 1. Loading Spinner HTML Commented Out in base.html

**Issue Description:**
The loading spinner HTML in base.html was commented out, which prevented the JavaScript code in main.js from properly showing and hiding the loading spinner during page navigation and AJAX requests.

**Fix:**
Uncommented the loading spinner HTML in base.html to ensure it works properly with the JavaScript code.

**Files Modified:**
- `/templates/base.html`

**Before:**
```html
<!--    <div class="loading-spinner position-fixed top-0 start-0 w-100 h-100 d-flex justify-content-center align-items-center" style="background-color: rgba(0,0,0,0.3); backdrop-filter: blur(2px); z-index: 9999;">-->
<!--        <div class="bg-white p-4 rounded-4 shadow-lg d-flex flex-column align-items-center">-->
<!--            <div class="spinner-border text-primary mb-3" style="width: 3rem; height: 3rem;" role="status">-->
<!--                <span class="visually-hidden">Loading...</span>-->
<!--            </div>-->
<!--            <p class="mb-0 fw-medium">Loading...</p>-->
<!--        </div>-->
<!--    </div>-->
```

**After:**
```html
    <div class="loading-spinner position-fixed top-0 start-0 w-100 h-100 d-flex justify-content-center align-items-center" style="background-color: rgba(0,0,0,0.3); backdrop-filter: blur(2px); z-index: 9999;">
        <div class="bg-white p-4 rounded-4 shadow-lg d-flex flex-column align-items-center">
            <div class="spinner-border text-primary mb-3" style="width: 3rem; height: 3rem;" role="status">
                <span class="visually-hidden">Loading...</span>
            </div>
            <p class="mb-0 fw-medium">Loading...</p>
        </div>
    </div>
```

### 2. Indentation Issue in dashboard.html

**Issue Description:**
There was an indentation issue in the dashboard.html template in the email configuration section. The closing `</div>` tag on line 183 was incorrectly indented, making it appear to be part of the wrong conditional block.

**Fix:**
Corrected the indentation of the closing `</div>` tag to match the indentation level of its corresponding opening tag.

**Files Modified:**
- `/templates/dashboard.html`

**Before:**
```html
                                </div>
                            </div>
                        {% endif %}
```

**After:**
```html
                                </div>
                        </div>
                    {% endif %}
```

### 3. Filter Links in account_details.html Have Placeholder href Values

**Issue Description:**
The filter links in the account_details.html template had placeholder href values (`href="#"`), which meant they didn't actually do anything when clicked. This was inconsistent with the AJAX functionality implemented in account_details.js.

**Fix:**
Updated the filter links with proper URLs that include the appropriate filter parameters, so that the AJAX filtering functionality works correctly.

**Files Modified:**
- `/templates/account_details.html`

**Before:**
```html
<ul class="dropdown-menu">
    <li><a class="dropdown-item" href="#"><i class="bi bi-arrow-up-circle me-2"></i>Income Only</a></li>
    <li><a class="dropdown-item" href="#"><i class="bi bi-arrow-down-circle me-2"></i>Expenses Only</a></li>
    <li><a class="dropdown-item" href="#"><i class="bi bi-arrow-left-right me-2"></i>Transfers Only</a></li>
    <li><hr class="dropdown-divider"></li>
    <li><a class="dropdown-item" href="#"><i class="bi bi-calendar3 me-2"></i>Last 30 Days</a></li>
</ul>
```

**After:**
```html
<ul class="dropdown-menu">
    <li><a class="dropdown-item" href="{{ url_for('account_details', account_number=account.account_number, filter='income') }}"><i class="bi bi-arrow-up-circle me-2"></i>Income Only</a></li>
    <li><a class="dropdown-item" href="{{ url_for('account_details', account_number=account.account_number, filter='expense') }}"><i class="bi bi-arrow-down-circle me-2"></i>Expenses Only</a></li>
    <li><a class="dropdown-item" href="{{ url_for('account_details', account_number=account.account_number, filter='transfer') }}"><i class="bi bi-arrow-left-right me-2"></i>Transfers Only</a></li>
    <li><hr class="dropdown-divider"></li>
    <li><a class="dropdown-item" href="{{ url_for('account_details', account_number=account.account_number, filter='recent') }}"><i class="bi bi-calendar3 me-2"></i>Last 30 Days</a></li>
</ul>
```

### 4. Export Button in account_details.html Has No Functionality

**Issue Description:**
The Export button in the account_details.html template was a non-functional button element with no associated action.

**Fix:**
Changed the button to an anchor tag with a proper URL that points to the new export_transactions route, allowing users to download their transaction data as a CSV file.

**Files Modified:**
- `/templates/account_details.html`

**Before:**
```html
<button type="button" class="btn btn-outline-primary btn-sm">
    <i class="bi bi-download me-2"></i>Export
</button>
```

**After:**
```html
<a href="{{ url_for('export_transactions', account_number=account.account_number) }}" class="btn btn-outline-primary btn-sm">
    <i class="bi bi-download me-2"></i>Export
</a>
```

### 5. Export Transactions Route Doesn't Exist in webapp.py

**Issue Description:**
The export_transactions route referenced by the Export button in account_details.html didn't exist in webapp.py, which would result in a 404 error when users clicked the button.

**Fix:**
Added the export_transactions route to webapp.py, which retrieves transactions for an account, formats them as CSV, and returns the CSV file as a download.

**Files Modified:**
- `/webapp.py`

**Added Code:**
```python
@app.route('/account/<account_number>/export')
@login_required
def export_transactions(account_number):
    """Export transactions for a specific account as CSV."""
    user_id = session.get('user_id')
    filter_type = request.args.get('filter', None)
    db_session = db.get_session()
    
    try:
        # Get account for this user
        account = db_session.query(Account).filter(
            Account.user_id == user_id,
            Account.account_number == account_number
        ).first()

        if not account:
            flash(f'Account {account_number} not found or you do not have permission to view it', 'error')
            return redirect(url_for('accounts'))

        # Apply filters if specified
        filter_params = {}
        if filter_type:
            if filter_type == 'income':
                filter_params['transaction_type'] = 'INCOME'
            elif filter_type == 'expense':
                filter_params['transaction_type'] = 'EXPENSE'
            elif filter_type == 'transfer':
                filter_params['transaction_type'] = 'TRANSFER'
            elif filter_type == 'recent':
                filter_params['date_from'] = datetime.now() - timedelta(days=30)

        # Get all transactions without pagination
        transactions_history = TransactionRepository.get_account_transaction_history(
            db_session, user_id, account_number, page=1, per_page=10000, **filter_params
        )
        
        # Create CSV file in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header row
        writer.writerow(['Date', 'Type', 'Amount', 'Currency', 'Description', 'Category', 'Counterparty'])
        
        # Write transaction data
        for transaction in transactions_history['transactions']:
            writer.writerow([
                transaction.date_time.strftime('%Y-%m-%d %H:%M:%S') if transaction.date_time else '',
                transaction.transaction_type,
                transaction.amount,
                transaction.currency,
                transaction.transaction_details or '',
                transaction.category.name if transaction.category else 'Uncategorized',
                transaction.counterparty_name or ''
            ])
        
        # Prepare response
        output.seek(0)
        filename = f"{account.bank_name}_{account.account_number}_transactions_{datetime.now().strftime('%Y%m%d')}.csv"
        
        return Response(
            output,
            mimetype='text/csv',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )
    except Exception as e:
        logger.error(f"Error exporting transactions: {str(e)}")
        flash(f'Error exporting transactions: {str(e)}', 'error')
        return redirect(url_for('account_details', account_number=account_number))
    finally:
        db.close_session(db_session)
```

## Summary of Changes

1. **Loading Spinner Fix**: Uncommented the loading spinner HTML in base.html to ensure it works properly with the JavaScript code.
2. **Indentation Fix**: Corrected the indentation in dashboard.html to improve code readability and maintainability.
3. **Filter Links Fix**: Updated the filter links in account_details.html with proper URLs to enable AJAX filtering functionality.
4. **Export Button Fix**: Changed the Export button to an anchor tag with a proper URL to enable CSV export functionality.
5. **Export Route Implementation**: Added the export_transactions route to webapp.py to handle CSV export functionality.

These changes ensure that the templates work correctly with the JavaScript code and provide a better user experience.