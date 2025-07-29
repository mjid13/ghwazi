# Email Service Provider Implementation

## Overview

This document describes the implementation of the email service provider detection and configuration system. The system allows users to simply enter their email address and password, and the application will automatically detect the email provider and configure the appropriate settings.

## Changes Made

### 1. Database Schema

1. Created a new `EmailServiceProvider` model in `models.py`:
   - Fields: provider_name, host, port, use_ssl, created_at, updated_at
   - Established a relationship with EmailConfiguration

2. Updated the `EmailConfiguration` model:
   - Added service_provider_id field (foreign key to email_service_providers.id)
   - Added service_provider relationship

### 2. Database Initialization

1. Added `_initialize_email_providers` method to the `Database` class:
   - Populates the email_service_providers table with common providers
   - Includes configurations for Gmail, Outlook, Yahoo, AOL, Zoho, iCloud, and ProtonMail
   - Called during application startup in the create_tables method

### 3. Email Service Detection

1. Added `extract_provider_from_email` method to the `EmailService` class:
   - Extracts the domain from the email address
   - Maps domains to provider names (e.g., gmail.com → gmail)
   - Returns the provider name or None if not recognized

2. Added `get_provider_config` method to the `EmailService` class:
   - Fetches the provider configuration from the database
   - Returns host, port, and SSL settings for the provider

### 4. Route Updates

1. Updated the `add_email_config` route:
   - Extracts the provider from the email address
   - Fetches the provider configuration from the database
   - Uses the provider settings if available, falls back to manual settings if not

2. Updated the `edit_email_config` route:
   - Similar changes to the add route
   - Maintains the relationship with the email service provider

### 5. Form Updates

1. Updated the `add_email_config.html` template:
   - Reordered fields to put email address first (after configuration name)
   - Added provider detection messages
   - Made host, port, and SSL settings optional and initially hidden
   - Added JavaScript to detect the provider and show/hide appropriate sections

2. Updated the `edit_email_config.html` template:
   - Similar changes to the add template
   - Maintains existing functionality (delete button, etc.)
   - Checks the provider on page load for existing configurations

## How It Works

1. When a user enters their email address in the form:
   - JavaScript detects the provider from the domain
   - If recognized, it shows a success message and hides the manual configuration fields
   - If not recognized, it shows a warning message and displays the manual configuration fields

2. When the form is submitted:
   - The server extracts the provider from the email address
   - It fetches the provider configuration from the database
   - If available, it uses those settings and sets the service_provider_id
   - If not available, it falls back to the manually entered values

3. The system supports the following email providers:
   - Gmail (gmail.com, googlemail.com)
   - Outlook (outlook.com, hotmail.com, live.com, msn.com)
   - Yahoo (yahoo.com, yahoo.co.uk, yahoo.fr)
   - AOL (aol.com)
   - Zoho (zoho.com)
   - iCloud (icloud.com, me.com, mac.com)
   - ProtonMail (protonmail.com, protonmail.ch, pm.me)

## Benefits

1. **Simplified User Experience**: Users only need to enter their email and password, not technical details.
2. **Reduced Errors**: Automatic configuration prevents misconfigurations.
3. **Flexibility**: Manual configuration is still available for unsupported providers.
4. **Maintainability**: Provider configurations are stored in the database, making them easy to update.

## Future Improvements

1. Add more email providers to the database.
2. Implement a way for administrators to add/edit provider configurations through the UI.
3. Add support for OAuth authentication for providers that support it.