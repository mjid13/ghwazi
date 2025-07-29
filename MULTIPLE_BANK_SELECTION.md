# Multiple Bank Selection Feature

## Overview

This document describes the implementation of the multiple bank selection feature in the Money Tracker application. This feature allows users to associate multiple banks with an email configuration, making it easier to process emails from different banks using a single email configuration.

## Changes Made

1. **Modified the database schema** to support a many-to-many relationship between EmailConfiguration and Bank:
   - Created a new junction table `email_config_banks` to store the many-to-many relationship
   - Updated the EmailConfiguration model to use the new relationship
   - Updated the Bank model to use the new relationship
   - Added migration code to ensure backward compatibility with existing data

2. **Updated the email configuration forms** to allow multiple bank selection:
   - Modified `add_email_config.html` and `edit_email_config.html` to use a multiple select dropdown for bank selection
   - Updated the JavaScript code to handle multiple selections and aggregate email addresses and subject keywords
   - Updated the templates to pre-select all associated banks when editing an email configuration

3. **Updated the controllers** to handle multiple bank selections:
   - Modified the `add_email_config` route to create the many-to-many relationships
   - Modified the `edit_email_config` route to update the many-to-many relationships
   - Ensured backward compatibility by maintaining the `bank_id` field in the EmailConfiguration model

## How to Use

### Adding an Email Configuration with Multiple Banks

1. Go to the "Add Email Configuration" page
2. Fill in the email address and password
3. Select one or more banks from the dropdown list (hold Ctrl/Cmd to select multiple)
4. The bank email addresses and subject keywords will be automatically aggregated from all selected banks
5. Click "Add Configuration"

### Editing an Email Configuration with Multiple Banks

1. Go to the "Email Configurations" page
2. Click "Edit" for the configuration you want to modify
3. Select one or more banks from the dropdown list (hold Ctrl/Cmd to select multiple)
4. The bank email addresses and subject keywords will be automatically aggregated from all selected banks
5. Click "Save Changes"

## Technical Details

### Database Schema

The many-to-many relationship between EmailConfiguration and Bank is implemented using a junction table:

```python
class EmailConfigBank(Base):
    """Junction table for many-to-many relationship between EmailConfiguration and Bank."""
    __tablename__ = 'email_config_banks'

    email_config_id = Column(Integer, ForeignKey('email_configurations.id'), primary_key=True)
    bank_id = Column(Integer, ForeignKey('banks.id'), primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    email_config = relationship("EmailConfiguration", back_populates="email_config_banks")
    bank = relationship("Bank", back_populates="email_config_banks")
```

The EmailConfiguration model has been updated to include relationships to the junction table and to the Bank model:

```python
class EmailConfiguration(Base):
    # ...
    bank_id = Column(Integer, ForeignKey('banks.id'), nullable=True)  # Kept for backward compatibility
    # ...
    bank = relationship("Bank", foreign_keys=[bank_id])  # Kept for backward compatibility
    email_config_banks = relationship("EmailConfigBank", back_populates="email_config", cascade="all, delete-orphan")
    banks = relationship("Bank", secondary="email_config_banks", viewonly=True)
```

The Bank model has been updated to include relationships to the junction table and to the EmailConfiguration model:

```python
class Bank(Base):
    # ...
    email_configs = relationship("EmailConfiguration", foreign_keys="EmailConfiguration.bank_id")  # Kept for backward compatibility
    email_config_banks = relationship("EmailConfigBank", back_populates="bank", cascade="all, delete-orphan")
    email_configurations = relationship("EmailConfiguration", secondary="email_config_banks", viewonly=True)
```

### Migration Code

The migration code in `database.py` ensures that the new junction table is created and that existing relationships are migrated:

```python
# Check if email_config_banks table exists and create it if it doesn't
if 'email_config_banks' not in inspector.get_table_names():
    try:
        # Create the email_config_banks table
        from money_tracker.models.models import EmailConfigBank
        Base.metadata.create_all(self.engine, tables=[EmailConfigBank.__table__])
        logger.info("Created email_config_banks table")
        
        # Migrate existing bank_id values from email_configurations to email_config_banks
        try:
            from sqlalchemy.sql import text
            with self.engine.connect() as connection:
                # Insert records into email_config_banks for existing relationships
                connection.execute(text("""
                    INSERT INTO email_config_banks (email_config_id, bank_id, created_at)
                    SELECT id, bank_id, CURRENT_TIMESTAMP
                    FROM email_configurations
                    WHERE bank_id IS NOT NULL
                """))
                connection.commit()
            logger.info("Migrated existing bank_id values to email_config_banks table")
        except Exception as e:
            logger.error(f"Error migrating bank_id values to email_config_banks table: {str(e)}")
    except Exception as e:
        logger.error(f"Error creating email_config_banks table: {str(e)}")
```

## Future Improvements

1. Add a visual indicator in the UI to show which banks are associated with each email configuration
2. Implement a more user-friendly interface for selecting multiple banks, such as checkboxes or a dual-list box
3. Add the ability to filter emails based on specific banks within a single email configuration
4. Provide more detailed statistics on which banks are sending the most emails