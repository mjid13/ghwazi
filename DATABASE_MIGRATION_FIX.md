# Database Migration Fix

## Issue Description

The application was encountering the following errors when trying to access the database:

```
2025-07-29 16:35:06,897 - money_tracker.models.models - ERROR - Error getting user accounts: (sqlite3.OperationalError) no such column: accounts.bank_id
[SQL: SELECT accounts.id AS accounts_id, accounts.user_id AS accounts_user_id, accounts.email_config_id AS accounts_email_config_id, accounts.bank_id AS accounts_bank_id, accounts.account_number AS accounts_account_number, accounts.bank_name AS accounts_bank_name, accounts.account_holder AS accounts_account_holder, accounts.branch AS accounts_branch, accounts.balance AS accounts_balance, accounts.currency AS accounts_currency, accounts.created_at AS accounts_created_at, accounts.updated_at AS accounts_updated_at 
FROM accounts 
WHERE accounts.user_id = ?]
[parameters: (1,)]
```

```
2025-07-29 16:35:06,904 - __main__ - ERROR - Error loading dashboard: (sqlite3.OperationalError) no such column: email_configurations.bank_id
[SQL: SELECT email_configurations.id AS email_configurations_id, email_configurations.user_id AS email_configurations_user_id, email_configurations.name AS email_configurations_name, email_configurations.email_host AS email_configurations_email_host, email_configurations.email_port AS email_configurations_email_port, email_configurations.email_username AS email_configurations_email_username, email_configurations.email_password AS email_configurations_email_password, email_configurations.email_use_ssl AS email_configurations_email_use_ssl, email_configurations.service_provider_id AS email_configurations_service_provider_id, email_configurations.bank_id AS email_configurations_bank_id, email_configurations.bank_email_addresses AS email_configurations_bank_email_addresses, email_configurations.bank_email_subjects AS email_configurations_bank_email_subjects, email_configurations.created_at AS email_configurations_created_at, email_configurations.updated_at AS email_configurations_updated_at 
FROM email_configurations 
WHERE email_configurations.user_id = ?]
[parameters: (1,)]
```

These errors occurred because the application was trying to query columns (`bank_id`) that didn't exist in the database tables. This happened because while the SQLAlchemy models had been updated to include these columns, the actual database schema hadn't been migrated to include them.

## Solution

The solution was to modify the `create_tables()` method in `database.py` to check for and add the missing columns to the existing tables. The following changes were made:

1. Added code to check if the `accounts` table has a `bank_id` column and add it if it doesn't exist.

The key SQL statement to add the column is:

```sql
ALTER TABLE accounts ADD COLUMN bank_id INTEGER REFERENCES banks(id)
```

If that fails (e.g., if the foreign key constraint can't be added), we fall back to:

```sql
ALTER TABLE accounts ADD COLUMN bank_id INTEGER
```

2. Added code to check if the `email_configurations` table has a `bank_id` column and add it if it doesn't exist.

The key SQL statement to add the column is:

```sql
ALTER TABLE email_configurations ADD COLUMN bank_id INTEGER REFERENCES banks(id)
```

If that fails, we fall back to:

```sql
ALTER TABLE email_configurations ADD COLUMN bank_id INTEGER
```

These changes were implemented in the `create_tables()` method in `database.py`, which is called when the application starts up. The method checks if the columns exist and adds them if they don't.

## Testing

To test the solution, we created two test scripts:

1. `test_migration.py`: This script initializes the database and runs the `create_tables()` method to trigger our migration code. The output confirmed that the columns were added successfully:

```
2025-07-29 16:40:19,717 - money_tracker.models.database - INFO - Added bank_id column to accounts table
2025-07-29 16:40:19,728 - money_tracker.models.database - INFO - Added bank_id column to email_configurations table
```

2. `test_queries.py`: This script tests the specific queries that were failing according to the error messages. The output confirmed that the queries now work correctly:

```
2025-07-29 16:42:38,588 - __main__ - INFO - Successfully queried accounts table. Found 2 accounts.
2025-07-29 16:42:38,608 - __main__ - INFO - Successfully queried email_configurations table. Found 1 configurations.
```

## Conclusion

The issue was resolved by adding migration code to check for and add the missing columns to the existing tables. This approach ensures that the database schema stays in sync with the SQLAlchemy models, even when new columns are added to the models.

The solution is backward compatible, as it makes the new columns nullable, so existing records can have NULL values for these columns. New records created after this migration will have the appropriate values set for these columns based on the application logic.

## Future Recommendations

1. Consider using a proper database migration tool like Alembic to manage database schema changes in a more structured way.
2. Add tests to verify that the database schema matches the SQLAlchemy models before deploying changes.
3. Document any changes to the database schema in a central location to help other developers understand the structure of the database.