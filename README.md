# Bank Email Parser & Account Tracker Web Application

A web application that allows users to parse transaction data from bank emails and track their accounts. The application can extract transaction details from email content, display the parsed data, and optionally save it to a database for tracking.

## Features

- **Email Parsing**: Parse transaction data from bank emails
  - Paste email content directly
  - Upload email files
- **Transaction Display**: View parsed transaction data in a user-friendly format
- **Account Tracking**: Track accounts and their transactions
  - View account summaries
  - View transaction history for each account
- **Data Storage**: Save transactions to a database for future reference

## Supported Banks

- Bank Muscat

## Supported Transaction Types

- Income (money received)
- Expense (money spent)
- Transfer (money moved between accounts)

## Installation

1. Clone the repository:
   ```
   git clone <repository-url>
   cd money_tracker
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Set up environment variables (optional):
   Create a `.env` file in the project root with the following variables:
   ```
   SECRET_KEY=your_secret_key
   DATABASE_URL=sqlite:///transactions.db
   UPLOAD_FOLDER=uploads
   LOG_LEVEL=INFO
   ```

## Running the Application

1. Start the web application:
   ```
   python webapp.py
   ```

2. Open a web browser and navigate to:
   ```
   http://localhost:5000
   ```

## Usage

### Parsing Email Content

1. On the home page, choose one of the options:
   - **Paste Email Content**: Paste the full email content including headers and body
   - **Upload Email File**: Upload a text file containing the email content

2. Optionally, you can provide additional information:
   - Email subject (for pasted content)
   - Sender email address

3. Check the "Save transaction to database" option if you want to save the parsed transaction data

4. Click "Parse Email" to process the email content

### Viewing Results

After parsing an email, you'll be redirected to the results page, which displays:
- Transaction type (income, expense, or transfer)
- Account number and bank name
- Transaction amount and currency
- Date and time of the transaction
- Sender or receiver information
- Additional details like description and country

### Managing Accounts

1. Click on "Accounts" in the navigation bar to view all accounts
2. Each account card shows:
   - Account number and bank name
   - Current balance
   - Transaction summary (counts and totals for income, expense, and transfer transactions)
   - Last updated timestamp

3. Click "View Details" to see the transaction history for a specific account

## Development

### Project Structure

- `webapp.py`: Main entry point for the web application
- `money_tracker/`: Core package
  - `services/`: Service modules
    - `parser_service.py`: Email parsing logic
    - `email_service.py`: Email retrieval service
    - `transaction_service.py`: Transaction processing service
  - `models/`: Database models
    - `models.py`: Account and Transaction models
    - `database.py`: Database connection and session management
  - `config/`: Configuration settings
- `templates/`: HTML templates for the web interface
- `uploads/`: Temporary storage for uploaded files

## License

This project is licensed under the MIT License - see the LICENSE file for details.