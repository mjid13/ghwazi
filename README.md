<div align="center">

# 🏦 Bank Email Parser & Account Tracker

*Transform your financial emails into actionable insights*

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.3.3-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/yourusername/ghwazi/graphs/commit-activity)

</div>

---

## 📋 Table of Contents

- [🎯 Overview](#-overview)
- [✨ Features](#-features)
- [🏗️ Architecture](#️-architecture)
- [🚀 Quick Start](#-quick-start)
- [📁 Project Structure](#-project-structure)
- [⚙️ Configuration](#️-configuration)
- [🎮 Usage Guide](#-usage-guide)
- [📊 Screenshots](#-screenshots)
- [🔧 API Reference](#-api-reference)
- [🧪 Development](#-development)
- [🚀 Deployment](#-deployment)
- [🐳 Docker](#-docker)
- [🔒 Security](#-security)
- [📈 Performance](#-performance)
- [❓ FAQ](#-faq)
- [🤝 Contributing](#-contributing)
- [🐛 Troubleshooting](#-troubleshooting)
- [📞 Support](#-support)

---

## 🎯 Overview

A comprehensive Flask web application that revolutionizes personal finance management by automatically parsing bank transaction emails and providing intelligent insights. Built with modern web technologies and designed for scalability, security, and ease of use.

### 🌟 Why Choose This Application?

- **🤖 Automated Processing**: No more manual transaction entry
- **📧 Multi-Bank Support**: Works with various bank email formats
- **📊 Rich Analytics**: Beautiful charts and financial insights
- **🔐 Secure**: Industry-standard security practices
- **📱 Responsive**: Works perfectly on all devices
- **🎯 Open Source**: Completely free and customizable

## ✨ Features

<table>
<tr>
<td width="50%">

### 💰 Financial Management
- 📧 **Smart Email Processing** - Automatically fetch and parse bank emails
- 💳 **Multi-Account Tracking** - Monitor all your bank accounts in one place
- 📊 **Transaction Categorization** - Organize expenses with smart categories
- 📈 **Visual Analytics** - Beautiful charts and spending insights
- 🎯 **Budget Tracking** - Set and monitor spending limits
- 📱 **Mobile Responsive** - Access your data anywhere, anytime

</td>
<td width="50%">

### 🔧 Technical Excellence
- 🏗️ **Modular Architecture** - Clean, maintainable codebase
- 🗄️ **Advanced Database** - PostgreSQL/MySQL with migrations
- 🔐 **Secure Authentication** - JWT tokens and password hashing
- 📄 **PDF Processing** - Extract data from bank statements
- 🚀 **RESTful API** - Full API for integrations
- ⚡ **High Performance** - Optimized queries and caching

</td>
</tr>
</table>

### 🌐 Supported Banks & Email Providers
- Gmail, Outlook, Yahoo Mail
- Chase, Bank of America, Wells Fargo
- And many more through configurable parsers!

## 🏗️ Architecture

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
   cd ghwazi
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
   # Navigate to the ghwazi directory
   cd ghwazi

   # For development
   pip install -r requirements/development.txt

   # For production
   pip install -r requirements/production.txt

   # Or install base requirements
   pip install -r requirements.txt
   ```

4. **Configure environment variables**
   ```bash
   # Copy example file from ghwazi directory
   cp ghwazi/.env.example .env
   # Edit .env file with your configuration
   ```

5. **Initialize the database**
   ```bash
   # Navigate to ghwazi directory if not already there
   cd ghwazi

   # Initialize database using the CLI commands
   python app.py init-db
   ```

6. **Run the application**
   ```bash
   # From the ghwazi directory
   python app.py
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

---

## 🐳 Docker

A production-ready Dockerfile and docker-compose.yml are included.

Quick start:
- Build: docker build -t money-tracker:latest .
- Run (compose): docker compose up -d --build

For full instructions, environment variables, and persistence details, see DOCKER.md.
