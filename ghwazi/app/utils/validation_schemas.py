"""
Validation schemas for common application forms and API endpoints.
These schemas define the validation rules for different types of input data.
"""

from datetime import datetime, timedelta
from decimal import Decimal
from typing import Dict, Any
from .validators import ValidationSchema


class UserRegistrationSchema(ValidationSchema):
    """Validation schema for user registration forms."""
    
    def get_fields(self) -> Dict[str, Dict[str, Any]]:
        return {
            'username': {
                'type': 'string',
                'min_length': 3,
                'max_length': 30,
                'pattern': 'username',
                'required': True
            },
            'email': {
                'type': 'email',
                'required': True
            },
            'password': {
                'type': 'string',
                'min_length': 8,
                'max_length': 128,
                'required': True
            },
            'confirm_password': {
                'type': 'string',
                'min_length': 8,
                'max_length': 128,
                'required': True
            },
            'first_name': {
                'type': 'string',
                'min_length': 1,
                'max_length': 50,
                'pattern': 'alpha_space',
                'required': False
            },
            'last_name': {
                'type': 'string',
                'min_length': 1,
                'max_length': 50,
                'pattern': 'alpha_space',
                'required': False
            }
        }
    
    def validate(self, data: Dict[str, Any]):
        """Override to add custom validation for password confirmation."""
        is_valid, errors, cleaned_data = super().validate(data)
        
        # Check password confirmation
        if 'password' in cleaned_data and 'confirm_password' in cleaned_data:
            if cleaned_data['password'] != cleaned_data['confirm_password']:
                if 'confirm_password' not in errors:
                    errors['confirm_password'] = []
                errors['confirm_password'].append('Passwords do not match')
                is_valid = False
        
        return is_valid, errors, cleaned_data


class UserLoginSchema(ValidationSchema):
    """Validation schema for user login forms."""
    
    def get_fields(self) -> Dict[str, Dict[str, Any]]:
        return {
            'email': {
                'type': 'email',
                'required': True
            },
            'password': {
                'type': 'string',
                'min_length': 1,
                'max_length': 128,
                'required': True
            },
            'remember_me': {
                'type': 'choice',
                'choices': ['on', 'true', '1'],
                'required': False
            }
        }


class TransactionSchema(ValidationSchema):
    """Validation schema for transaction forms."""
    
    def get_fields(self) -> Dict[str, Dict[str, Any]]:
        return {
            'description': {
                'type': 'string',
                'min_length': 1,
                'max_length': 200,
                'required': True
            },
            'amount': {
                'type': 'decimal',
                'min_value': Decimal('0.01'),
                'max_value': Decimal('999999.99'),
                'decimal_places': 2,
                'required': True
            },
            'transaction_type': {
                'type': 'choice',
                'choices': ['debit', 'credit'],
                'required': True,
                'case_sensitive': False
            },
            'category_id': {
                'type': 'integer',
                'min_value': 1,
                'required': False
            },
            'account_id': {
                'type': 'integer',
                'min_value': 1,
                'required': True
            },
            'transaction_date': {
                'type': 'date',
                'format': '%Y-%m-%d',
                'min_date': datetime.now() - timedelta(days=365*5),  # 5 years ago
                'max_date': datetime.now() + timedelta(days=1),  # Tomorrow
                'required': True
            },
            'counterparty': {
                'type': 'string',
                'min_length': 0,
                'max_length': 100,
                'required': False,
                'allow_empty': True
            }
        }


class AccountSchema(ValidationSchema):
    """Validation schema for bank account forms."""
    
    def get_fields(self) -> Dict[str, Dict[str, Any]]:
        return {
            'account_name': {
                'type': 'string',
                'min_length': 1,
                'max_length': 100,
                'required': True
            },
            'account_number': {
                'type': 'string',
                'min_length': 8,
                'max_length': 20,
                'pattern': 'numeric',
                'required': True
            },
            'bank_name': {
                'type': 'string',
                'min_length': 1,
                'max_length': 100,
                'required': True
            },
            'account_type': {
                'type': 'choice',
                'choices': ['checking', 'savings', 'credit', 'investment', 'other'],
                'required': True,
                'case_sensitive': False
            },
            'initial_balance': {
                'type': 'decimal',
                'min_value': Decimal('-999999.99'),
                'max_value': Decimal('999999.99'),
                'decimal_places': 2,
                'required': False
            },
            'description': {
                'type': 'string',
                'min_length': 0,
                'max_length': 500,
                'required': False,
                'allow_empty': True
            }
        }


class CategorySchema(ValidationSchema):
    """Validation schema for category forms."""
    
    def get_fields(self) -> Dict[str, Dict[str, Any]]:
        return {
            'name': {
                'type': 'string',
                'min_length': 1,
                'max_length': 50,
                'required': True
            },
            'description': {
                'type': 'string',
                'min_length': 0,
                'max_length': 200,
                'required': False,
                'allow_empty': True
            },
            'color': {
                'type': 'string',
                'pattern': 'hex_color',
                'required': False
            },
            'parent_category_id': {
                'type': 'integer',
                'min_value': 1,
                'required': False
            }
        }


class EmailConfigSchema(ValidationSchema):
    """Validation schema for email configuration forms."""
    
    def get_fields(self) -> Dict[str, Dict[str, Any]]:
        return {
            'email_address': {
                'type': 'email',
                'required': True
            },
            'email_provider': {
                'type': 'choice',
                'choices': ['gmail', 'outlook', 'yahoo', 'other'],
                'required': True,
                'case_sensitive': False
            },
            'imap_server': {
                'type': 'string',
                'min_length': 3,
                'max_length': 100,
                'required': False
            },
            'imap_port': {
                'type': 'integer',
                'min_value': 1,
                'max_value': 65535,
                'required': False
            },
            'use_ssl': {
                'type': 'choice',
                'choices': ['on', 'true', '1'],
                'required': False
            },
            'search_keywords': {
                'type': 'string',
                'min_length': 0,
                'max_length': 500,
                'required': False,
                'allow_empty': True
            }
        }


class PasswordResetSchema(ValidationSchema):
    """Validation schema for password reset forms."""
    
    def get_fields(self) -> Dict[str, Dict[str, Any]]:
        return {
            'email': {
                'type': 'email',
                'required': True
            }
        }


class PasswordChangeSchema(ValidationSchema):
    """Validation schema for password change forms."""
    
    def get_fields(self) -> Dict[str, Dict[str, Any]]:
        return {
            'current_password': {
                'type': 'string',
                'min_length': 1,
                'max_length': 128,
                'required': True
            },
            'new_password': {
                'type': 'string',
                'min_length': 8,
                'max_length': 128,
                'required': True
            },
            'confirm_password': {
                'type': 'string',
                'min_length': 8,
                'max_length': 128,
                'required': True
            }
        }
    
    def validate(self, data: Dict[str, Any]):
        """Override to add custom validation for password confirmation."""
        is_valid, errors, cleaned_data = super().validate(data)
        
        # Check password confirmation
        if 'new_password' in cleaned_data and 'confirm_password' in cleaned_data:
            if cleaned_data['new_password'] != cleaned_data['confirm_password']:
                if 'confirm_password' not in errors:
                    errors['confirm_password'] = []
                errors['confirm_password'].append('Passwords do not match')
                is_valid = False
        
        # Check that new password is different from current
        if 'current_password' in cleaned_data and 'new_password' in cleaned_data:
            if cleaned_data['current_password'] == cleaned_data['new_password']:
                if 'new_password' not in errors:
                    errors['new_password'] = []
                errors['new_password'].append('New password must be different from current password')
                is_valid = False
        
        return is_valid, errors, cleaned_data


class SearchSchema(ValidationSchema):
    """Validation schema for search forms."""
    
    def get_fields(self) -> Dict[str, Dict[str, Any]]:
        return {
            'query': {
                'type': 'string',
                'min_length': 1,
                'max_length': 100,
                'required': True
            },
            'category': {
                'type': 'choice',
                'choices': ['all', 'transactions', 'accounts', 'categories'],
                'required': False,
                'case_sensitive': False
            },
            'date_from': {
                'type': 'date',
                'format': '%Y-%m-%d',
                'required': False
            },
            'date_to': {
                'type': 'date',
                'format': '%Y-%m-%d',
                'required': False
            },
            'amount_min': {
                'type': 'decimal',
                'min_value': Decimal('0.00'),
                'decimal_places': 2,
                'required': False
            },
            'amount_max': {
                'type': 'decimal',
                'min_value': Decimal('0.00'),
                'decimal_places': 2,
                'required': False
            }
        }


class BulkImportSchema(ValidationSchema):
    """Validation schema for bulk import forms."""
    
    def get_fields(self) -> Dict[str, Dict[str, Any]]:
        return {
            'account_id': {
                'type': 'integer',
                'min_value': 1,
                'required': True
            },
            'file_format': {
                'type': 'choice',
                'choices': ['csv', 'xlsx', 'pdf'],
                'required': True,
                'case_sensitive': False
            },
            'has_header': {
                'type': 'choice',
                'choices': ['on', 'true', '1'],
                'required': False
            },
            'date_format': {
                'type': 'choice',
                'choices': ['%Y-%m-%d', '%m/%d/%Y', '%d/%m/%Y', '%Y%m%d'],
                'required': True
            },
            'currency_symbol': {
                'type': 'string',
                'min_length': 1,
                'max_length': 5,
                'required': False
            }
        }


# Validation schema registry for easy lookup
VALIDATION_SCHEMAS = {
    'user_registration': UserRegistrationSchema,
    'user_login': UserLoginSchema,
    'transaction': TransactionSchema,
    'account': AccountSchema,
    'category': CategorySchema,
    'email_config': EmailConfigSchema,
    'password_reset': PasswordResetSchema,
    'password_change': PasswordChangeSchema,
    'search': SearchSchema,
    'bulk_import': BulkImportSchema,
}


def get_validation_schema(schema_name: str) -> ValidationSchema:
    """
    Get a validation schema instance by name.
    
    Args:
        schema_name: Name of the schema to retrieve
        
    Returns:
        ValidationSchema instance
        
    Raises:
        ValueError: If schema name is not found
    """
    if schema_name not in VALIDATION_SCHEMAS:
        raise ValueError(f"Unknown validation schema: {schema_name}")
    
    schema_class = VALIDATION_SCHEMAS[schema_name]
    return schema_class()