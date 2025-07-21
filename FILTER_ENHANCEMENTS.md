# Transaction Filter Enhancements

## Overview

This document describes the enhancements made to the transaction filtering capabilities in the Money Tracker application. The changes improve the UI/UX for data filtering and add new filtering options, including date range filtering and text search functionality.

## Changes Made

### 1. Enhanced Filter UI in account_details.html

The filter UI in the account details page has been completely redesigned to provide a better user experience:

- **Transaction Type Filter**: Replaced the dropdown menu with a dedicated dropdown select control
- **Date Range Filter**: Added date range picker with From and To date inputs
- **Search Text Filter**: Added a search text input for searching by counterparty name, amount, or description
- **Filter Controls**: Added Apply Filters and Clear Filters buttons
- **Active Filters Display**: Added a section to display active filters as badges with the ability to remove individual filters

### 2. Updated JavaScript in account_details.js

The JavaScript code has been updated to handle the new filter controls:

- **Filter Initialization**: Added code to initialize all filter controls and set initial values from URL parameters
- **Apply Filters**: Implemented function to apply filters and update the transaction list via AJAX
- **Clear Filters**: Implemented function to clear all filters and reset the transaction list
- **Active Filters Display**: Added functionality to display active filters as badges with remove buttons
- **Event Handling**: Added event listeners for filter controls, including Enter key support for the search input

### 3. Enhanced Backend Filtering in models.py

The `get_account_transaction_history` method in the `TransactionRepository` class has been enhanced to support new filter parameters:

- **Date Range Filtering**: Added support for both start date (`date_from`) and end date (`date_to`) parameters
- **Text Search Filtering**: Added support for searching by counterparty name, transaction details (description), or amount

### 4. Updated Routes in webapp.py

Both the `account_details` and `export_transactions` routes have been updated to handle the new filter parameters:

- **Date Range Handling**: Added code to parse date strings and convert them to datetime objects
- **Search Text Handling**: Added code to extract and pass the search text parameter
- **Error Handling**: Added validation and error logging for invalid date formats

## Benefits

These enhancements provide several benefits to users:

1. **More Precise Filtering**: Users can now filter transactions by specific date ranges instead of just predefined periods
2. **Text Search Capability**: Users can search for transactions by counterparty name, amount, or description
3. **Improved User Experience**: The new UI is more intuitive and provides better feedback about active filters
4. **Consistent Export Functionality**: The same filters applied to the transaction list can be used when exporting to CSV

## Usage

### Filtering by Transaction Type

1. Select the desired transaction type from the dropdown (Income, Expenses, Transfers)
2. Click "Apply Filters"

### Filtering by Date Range

1. Enter a start date in the "From" field
2. Enter an end date in the "To" field (optional)
3. Click "Apply Filters"

### Searching by Text

1. Enter search text in the search input field
2. Click the search button or press Enter
3. The system will search for matches in counterparty names, transaction descriptions, and amounts

### Clearing Filters

1. Click "Clear Filters" to remove all active filters
2. Alternatively, click the "x" button on individual filter badges to remove specific filters

## Technical Implementation

The filter parameters are passed as URL parameters:

- `filter`: Transaction type (income, expense, transfer)
- `date_from`: Start date in YYYY-MM-DD format
- `date_to`: End date in YYYY-MM-DD format
- `search`: Text to search for in counterparty, description, or amount

These parameters are processed by the backend and used to filter the database query before returning the results.