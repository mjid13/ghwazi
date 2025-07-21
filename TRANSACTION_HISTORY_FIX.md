# Transaction History Filter Fix

## Issue Description

The application was experiencing an error when trying to filter transaction history by date:

```
{"message":"Error getting account details: TransactionRepository.get_account_transaction_history() got an unexpected keyword argument 'date_from'","success":false}
```

This error occurred because the `get_account_transaction_history()` method in the `TransactionRepository` class did not accept a `date_from` parameter, but this parameter was being passed to the method from the webapp.py file.

## Root Cause

In the webapp.py file, when filtering transactions by the "recent" filter type, a `date_from` parameter was added to the filter_params dictionary:

```python
if filter_type == 'recent':
    filter_params['date_from'] = datetime.now() - timedelta(days=30)
```

These filter parameters were then passed to the `get_account_transaction_history()` method using the `**filter_params` syntax, which unpacks the dictionary as keyword arguments:

```python
transactions_history = TransactionRepository.get_account_transaction_history(
    db_session, user_id, account_number, page=page, per_page=per_page, **filter_params
)
```

However, the `get_account_transaction_history()` method in models.py did not have a `date_from` parameter in its signature, causing the error.

## Solution

The solution involved two main changes:

1. **Updated Method Signature**: Added `date_from` and `transaction_type` parameters to the `get_account_transaction_history()` method signature:

```python
@staticmethod
def get_account_transaction_history(session: Session, user_id: int, account_number: str,
                                   page: int = 1, per_page: int = 200, date_from: datetime = None,
                                   transaction_type: str = None) -> Dict[str, Any]:
```

2. **Updated Method Implementation**: Modified the method to use these parameters in the query:

```python
# Apply date filter if provided
if date_from:
    query = query.filter(Transaction.value_date >= date_from)
    
# Apply transaction type filter if provided
if transaction_type:
    # Handle case difference between string values and enum values
    if transaction_type == 'INCOME':
        query = query.filter(Transaction.transaction_type == TransactionType.INCOME)
    elif transaction_type == 'EXPENSE':
        query = query.filter(Transaction.transaction_type == TransactionType.EXPENSE)
    elif transaction_type == 'TRANSFER':
        query = query.filter(Transaction.transaction_type == TransactionType.TRANSFER)
    else:
        logger.warning(f"Unknown transaction type: {transaction_type}")
```

The transaction_type filter implementation handles the case difference between the string values passed from webapp.py ('INCOME', 'EXPENSE', 'TRANSFER') and the enum values defined in models.py (TransactionType.INCOME, TransactionType.EXPENSE, TransactionType.TRANSFER).

## Benefits

This fix ensures that:

1. The "Recent" filter (last 30 days) works correctly on the account details page
2. Transaction type filters (Income, Expense, Transfer) work correctly
3. The application no longer throws an error when these filters are applied

The changes are minimal and focused on fixing the specific issue without changing the overall behavior of the application.