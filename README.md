# Bank Email Parser & Account Tracker

A comprehensive Flask web application for parsing bank transaction emails and tracking financial accounts. This application automatically processes bank notification emails to extract transaction data and provides a user-friendly interface for managing personal finances.

## Features

### Core Functionality
- **Email Processing**: Automatically fetch and parse bank transaction emails
- **Transaction Management**: View, categorize, and manage financial transactions
- **Account Tracking**: Monitor multiple bank accounts and their balances
- **Category Management**: Organize transactions with custom categories
- **User Authentication**: Secure user registration and login system
- **Dashboard Analytics**: Visual charts and reports for financial insights

### Technical Features
- **Modular Architecture**: Clean separation of concerns with blueprints
- **Database Management**: SQLAlchemy ORM with migration support
- **Email Integration**: IMAP email fetching with configurable providers
- **PDF Processing**: Extract transaction data from PDF statements
- **RESTful API**: JSON API endpoints for frontend integration
- **Responsive Design**: Mobile-friendly web interface

## Project Structure

```
ghwawzi/
├── app/
│   ├── __init__.py              # Application factory
│   ├── models/
│   │   ├── __init__.py
│   │   ├── user.py
│   │   ├── category.py
│   │   └── transaction.py
│   ├── views/                   # or 'routes'
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── auth.py
│   │   ├── api.py
│   │   └── admin.py
│   ├── templates/
│   │   ├── base.html
│   │   ├── auth/
│   │   ├── main/
│   │   └── admin/
│   ├── static/
│   │   ├── css/
│   │   ├── js/
│   │   └── images/
│   ├── services/               # Business logic
│   │   ├── __init__.py
│   │   ├── user_service.py
│   │   ├── transaction_service.py
│   │   └── email_service.py
│   ├── utils/
│   │   ├── __init__.py
│   │   ├── helpers.py
│   │   └── validators.py
│   ├── config/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── development.py
│   │   ├── production.py
│   │   └── testing.py
│   └── extensions.py           # Initialize extensions
├── migrations/                 # Database migrations
├── tests/
│   ├── __init__.py
│   ├── test_models.py
│   ├── test_views.py
│   └── test_services.py
├── requirements/
│   ├── base.txt
│   ├── development.txt
│   ├── production.txt
│   └── testing.txt
├── .env
├── .env.example
├── .gitignore
├── README.md
├── run.py                      # Application entry point
└── requirements.txt
```

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)
- Virtual environment (recommended)

### Setup Instructions

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd ghwawzi
   ```

2. **Create and activate virtual environment**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   # For development
   pip install -r requirements/development.txt
   
   # For production
   pip install -r requirements/production.txt
   ```

4. **Configure environment variables**
   ```bash
   cp .env.example .env
   # Edit .env file with your configuration
   ```

5. **Initialize the database**
   ```bash
   flask db init
   flask db migrate -m "Initial migration"
   flask db upgrade
   ```

6. **Run the application**
   ```bash
   python run.py
   ```

The application will be available at `http://localhost:5000`

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure the following variables:

#### Flask Configuration
- `SECRET_KEY`: Secret key for session management
- `FLASK_ENV`: Environment (development/production)
- `FLASK_DEBUG`: Enable debug mode

#### Database Configuration
- `DATABASE_URL`: Database connection string
- `DEV_DATABASE_URL`: Development database URL

#### Email Configuration
- `EMAIL_HOST`: IMAP server hostname
- `EMAIL_PORT`: IMAP server port
- `EMAIL_USERNAME`: Email account username
- `EMAIL_PASSWORD`: Email account password
- `EMAIL_USE_SSL`: Use SSL connection

#### Bank Settings
- `BANK_EMAIL_ADDRESSES`: Comma-separated list of bank email addresses
- `BANK_EMAIL_SUBJECTS`: Keywords to identify transaction emails

## Usage

### User Registration and Login
1. Navigate to `/auth/register` to create a new account
2. Login at `/auth/login` with your credentials
3. Access the dashboard at `/dashboard`

### Email Configuration
1. Go to Admin → Email Configurations
2. Add your email account details
3. Configure bank email filters

### Transaction Management
1. View transactions in the Accounts section
2. Categorize transactions for better organization
3. Use the API endpoints for programmatic access

### Running Email Fetcher
The application can automatically fetch emails:
```bash
# Manual fetch
python -c "from app.services.email_service import EmailService; EmailService().fetch_emails()"
```

## API Endpoints

### Authentication
- `POST /auth/login` - User login
- `POST /auth/register` - User registration
- `GET /auth/logout` - User logout

### Transactions
- `GET /api/transactions` - List transactions
- `DELETE /api/transaction/<id>` - Delete transaction
- `PUT /api/transaction/<id>/category` - Update transaction category

### Charts and Analytics
- `GET /api/chart/data` - Get chart data for dashboard

## Development

### Running Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app

# Run specific test file
pytest tests/test_models.py
```

### Database Migrations
```bash
# Create migration
flask db migrate -m "Description of changes"

# Apply migration
flask db upgrade

# Downgrade migration
flask db downgrade
```

### Code Quality
```bash
# Format code
black app/ tests/

# Sort imports
isort app/ tests/

# Lint code
flake8 app/ tests/

# Type checking
mypy app/
```

## Deployment

### Production Setup
1. Set `FLASK_ENV=production` in environment
2. Configure production database
3. Set up proper logging
4. Use a WSGI server like Gunicorn:
   ```bash
   gunicorn -w 4 -b 0.0.0.0:8000 run:app
   ```

### Docker Deployment
```dockerfile
# Example Dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements/production.txt .
RUN pip install -r production.txt
COPY . .
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "run:app"]
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 style guidelines
- Write tests for new features
- Update documentation as needed
- Use meaningful commit messages

## Troubleshooting

### Common Issues

**Database Connection Error**
- Check `DATABASE_URL` in `.env` file
- Ensure database server is running
- Run database migrations

**Email Fetching Issues**
- Verify email credentials in `.env`
- Check IMAP server settings
- Enable "Less secure app access" for Gmail (or use App Passwords)

**Import Errors**
- Ensure virtual environment is activated
- Install all dependencies from requirements files
- Check Python path configuration

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue on GitHub
- Check the documentation
- Review the troubleshooting section

## Changelog

### Version 1.0.0
- Initial release
- Basic email parsing functionality
- User authentication system
- Transaction management
- Dashboard with charts
- Admin interface for categories and email configs