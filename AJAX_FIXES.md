# AJAX Fixes for Upload Transaction Forms

## Issue Description
Fix the AJAX code for upload transactions forms (email form, file form)

## Changes Made

### 1. Added ID Attributes to Forms
Added unique ID attributes to both forms to make them easier to select in JavaScript:
- Added `id="email-form"` to the email transactions form
- Added `id="pdf-form"` to the PDF statement upload form

### 2. Added AJAX Handling Code
Added JavaScript code in the `extra_js` block of dashboard.html that:
- Includes the ajax.js file
- Selects the forms by their IDs
- Uses `Ajax.submitForm()` to handle form submission via AJAX
- Handles success and error responses
- Shows notifications to the user
- Redirects to the appropriate page after a successful submission

### 3. Removed Invalid Attribute
Removed an invalid `method="get"` attribute from an anchor tag.

## Benefits of These Changes
1. **Improved User Experience**: Forms are now submitted without page reloads, providing a smoother experience.
2. **Better Feedback**: Users receive immediate feedback through notifications.
3. **Consistent Error Handling**: Both forms now use the same error handling approach.
4. **Reduced Server Load**: AJAX requests are more efficient than full page reloads.

## Technical Details
The implementation leverages the existing `Ajax` utility module in ajax.js, which provides:
- Form validation
- CSRF token handling
- Loading state indicators
- Error handling

Both server-side handlers (`fetch_emails` and `upload_pdf`) were already set up to handle AJAX requests, so no changes were needed on the server side.

## Testing
The changes have been tested and verified to work correctly. Both forms now submit via AJAX and handle responses appropriately.