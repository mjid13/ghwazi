# Loading Spinner Fix

## Issue Description

The loading spinner was not being hidden after page navigation, causing it to remain visible indefinitely. The specific HTML for the loading spinner is:

```html
<div class="spinner-border text-primary mb-3" style="width: 3rem; height: 3rem;" role="status">
    <span class="visually-hidden">Loading...</span>
</div>
<p class="mb-0 fw-medium">Loading...</p>
```

This spinner is part of a full-screen overlay defined in `base.html`:

```html
<div class="loading-spinner position-fixed top-0 start-0 w-100 h-100 d-flex justify-content-center align-items-center" style="background-color: rgba(0,0,0,0.3); backdrop-filter: blur(2px); z-index: 9999;">
    <div class="bg-white p-4 rounded-4 shadow-lg d-flex flex-column align-items-center">
        <!-- Spinner HTML here -->
    </div>
</div>
```

## Root Cause

The loading spinner was being shown in two scenarios:

1. When clicking on links for page navigation (in `main.js`)
2. When making AJAX requests (in `ajax.js`)

While the spinner was properly hidden after AJAX requests completed (in `ajax.js`), there was no code to hide the spinner when a new page finished loading after regular navigation. This caused the spinner to remain visible indefinitely when navigating between pages.

## Solution

The following changes were made to fix the issue:

1. Added code to hide the spinner by default when the page initially loads:

```javascript
// Hide loading spinner by default when page loads
document.querySelector('.loading-spinner').style.display = 'none';
```

2. Added code to hide the spinner when the DOM content is loaded:

```javascript
document.addEventListener('DOMContentLoaded', () => {
    // ... existing code ...
    
    // Hide loading spinner when DOM is loaded
    document.querySelector('.loading-spinner').style.display = 'none';
});
```

3. Added code to hide the spinner when the entire page is fully loaded:

```javascript
// Hide loading spinner when page is fully loaded
window.addEventListener('load', () => {
    document.querySelector('.loading-spinner').style.display = 'none';
});
```

These changes ensure that the loading spinner is properly hidden in all scenarios:

- By default when the page first loads
- When the DOM content is loaded
- When the entire page and all resources are loaded
- After AJAX requests complete (already handled in `ajax.js`)

The spinner will still be shown when clicking on links for navigation and when making AJAX requests, but now it will be properly hidden when the page loads or when AJAX requests complete.

## Files Modified

- `/static/js/main.js`

## Testing

The solution was tested to ensure the loading spinner appears and disappears correctly in the following scenarios:

1. Initial page load
2. Navigation between pages
3. AJAX requests

The loading spinner now properly disappears after each of these actions, providing a better user experience.