# Bank Model Implementation

## Overview

This document describes the implementation of a Bank model in the Money Tracker application. The Bank model centralizes bank information that was previously scattered across different models, making it easier to manage and maintain.

## Changes Made

1. **Created a new Bank model** in `models.py` with the following fields:
   - `name`: The name of the bank
   - `email_address`: The email address used by the bank for transaction notifications
   - `email_subjects`: Common subject keywords used in bank transaction emails
   - `currency`: The default currency used by the bank

2. **Modified the Account model** to reference the Bank model:
   - Added a `bank_id` foreign key to reference the Bank model
   - Added a relationship to the Bank model
   - Kept the existing `bank_name` and `currency` fields for backward compatibility

3. **Modified the EmailConfiguration model** to reference the Bank model:
   - Added a `bank_id` foreign key to reference the Bank model
   - Added a relationship to the Bank model
   - Kept the existing `bank_email_addresses` and `bank_email_subjects` fields for backward compatibility

4. **Updated database.py** to create the bank table and initialize default banks:
   - Added a `_initialize_banks` method to populate the bank table with default banks
   - Updated the `create_tables` method to call the `_initialize_banks` method

5. **Updated the account management forms and routes**:
   - Modified `add_account.html` and `edit_account.html` to show a dropdown of available banks
   - Added JavaScript to update the currency field based on the selected bank
   - Updated the corresponding routes in `app.py` to pass the banks data to the templates and handle the `bank_id` field

6. **Updated the email configuration forms and routes**:
   - Modified `add_email_config.html` and `edit_email_config.html` to show a dropdown of available banks
   - Added JavaScript to update the hidden fields based on the selected bank
   - Updated the corresponding routes in `app.py` to pass the banks data to the templates and handle the `bank_id` field

## Default Banks

The following default banks are initialized in the database:

1. **Bank Muscat**
   - Email Address: noreply@bankmuscat.com
   - Email Subjects: Account Transaction
   - Currency: OMR

2. **HSBC**
   - Email Address: alerts@hsbc.com
   - Email Subjects: Transaction Alert, Account Activity
   - Currency: USD

3. **Citibank**
   - Email Address: alerts@citibank.com
   - Email Subjects: Transaction Notification, Account Alert
   - Currency: USD

4. **Bank of America**
   - Email Address: alerts@bankofamerica.com
   - Email Subjects: Transaction Alert, Account Activity
   - Currency: USD

5. **Chase**
   - Email Address: no-reply@alertsp.chase.com
   - Email Subjects: Chase Alert, Transaction Notification
   - Currency: USD

## How to Use

### Adding a Bank Account

1. Go to the "Add Bank Account" page
2. Select a bank from the dropdown list
3. The currency field will be automatically populated based on the selected bank
4. Fill in the other required fields
5. Click "Add Account"

### Adding an Email Configuration

1. Go to the "Add Email Configuration" page
2. Fill in the email address and password
3. Select one or more banks from the dropdown list (hold Ctrl/Cmd to select multiple)
4. The bank email addresses and subject keywords will be automatically aggregated from all selected banks
5. Click "Add Configuration"

> **Note:** The ability to select multiple banks was added in a later update. See [MULTIPLE_BANK_SELECTION.md](MULTIPLE_BANK_SELECTION.md) for more details.

## Future Improvements

1. Add a page to manage banks (add, edit, delete)
2. Allow users to add custom banks
3. Improve the bank selection UI with search and filtering options