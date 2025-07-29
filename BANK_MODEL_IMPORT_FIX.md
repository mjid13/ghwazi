# Bank Model Import Fix

## Issue Description

The application was encountering the following error when trying to add an email configuration:

```
2025-07-29 17:18:49,588 - __main__ - ERROR - Error adding email configuration: name 'Bank' is not defined
2025-07-29 17:18:49,593 - werkzeug - INFO - 127.0.0.1 - - [29/Jul/2025 17:18:49] "GET /email-config/add HTTP/1.1" 302 -
```

This error occurred because the `Bank` model was being used in the `add_email_config` route but was not imported in the `app.py` file.

## Root Cause

The `Bank` model was recently added to the application as part of the Bank Model Implementation, but the import statement in `app.py` was not updated to include this new model. Specifically, the `Bank` model was being used in the following places:

1. In the `add_email_config` route:
   ```python
   # Get all available banks
   banks = db_session.query(Bank).all()
   ```

2. In the `edit_email_config` route:
   ```python
   # Get all available banks
   banks = db_session.query(Bank).all()
   ```

Without the proper import, Python raised a `NameError` when trying to access the `Bank` class.

## Solution

The solution was to update the import statement in `app.py` to include the `Bank` model:

```python
# Before
from money_tracker.models.models import TransactionRepository, User, Account, EmailConfiguration, Transaction, Category, CategoryMapping, CategoryType

# After
from money_tracker.models.models import TransactionRepository, User, Account, EmailConfiguration, Transaction, Category, CategoryMapping, CategoryType, Bank
```

This change ensures that the `Bank` model is available for use in the routes that need it.

## Verification

After making the change, the application was able to initialize successfully without any import errors. The logs showed that the database connected successfully, the email service providers were initialized, and the banks were initialized.

## Lessons Learned

When adding new models to the application, it's important to:

1. Update all import statements in files that use the new model
2. Test all routes and functionality that interact with the new model
3. Consider using wildcard imports (e.g., `from money_tracker.models.models import *`) for large applications with many models, although this approach has its own drawbacks

## Related Documentation

- [BANK_MODEL_IMPLEMENTATION.md](BANK_MODEL_IMPLEMENTATION.md) - Documentation of the Bank model implementation
- [DATABASE_MIGRATION_FIX.md](DATABASE_MIGRATION_FIX.md) - Documentation of the database migration fix for the Bank model