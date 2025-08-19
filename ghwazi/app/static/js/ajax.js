/**
 * AJAX Utility Module
 * Provides functions for making AJAX requests and handling responses
 */

const Ajax = {
    /**
     * Send an AJAX request
     * @param {string} url - The URL to send the request to
     * @param {string} method - The HTTP method (GET, POST, PUT, DELETE)
     * @param {Object|FormData} data - The data to send with the request
     * @param {Function} successCallback - Function to call on success
     * @param {Function} errorCallback - Function to call on error
     * @param {boolean} processForm - Whether to process form data
     */
    request: function(url, method, data, successCallback, errorCallback, processForm = false) {
        // Show the global loading spinner if it exists
        const loadingSpinner = document.querySelector('.loading-spinner');
        if (loadingSpinner) {
            loadingSpinner.style.display = 'block';
        }
        
        // Create the fetch options
        const options = {
            method: method,
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin'
        };
        
        // Add CSRF token to headers for non-GET requests
        if (method !== 'GET') {
            const csrfToken = document.querySelector('input[name="csrf_token"]')?.value;
            if (csrfToken) {
                options.headers['X-CSRFToken'] = csrfToken;
            }
        }
        
        // Process the data based on type
        if (data) {
            if (data instanceof FormData) {
                // For FormData, don't set Content-Type header (browser will set it with boundary)
                options.body = data;
            } else if (processForm && data instanceof HTMLFormElement) {
                // For HTML Form element, convert to FormData
                options.body = new FormData(data);
            } else {
                // For regular objects, stringify to JSON
                options.headers['Content-Type'] = 'application/json';
                options.body = JSON.stringify(data);
            }
        }
        
        // Make the fetch request
        fetch(url, options)
            .then(response => {
                // Check if the response is JSON
                const contentType = response.headers.get('content-type');
                const isJson = contentType && contentType.includes('application/json');
                
                // Process the response based on status
                if (response.ok) {
                    return isJson ? response.json() : response.text();
                } else {
                    // For error responses, try to parse JSON first
                    return (isJson ? response.json() : response.text())
                        .then(errorData => {
                            throw {
                                status: response.status,
                                statusText: response.statusText,
                                data: errorData
                            };
                        });
                }
            })
            .then(data => {
                // Hide the loading spinner if it exists
                const loadingSpinner = document.querySelector('.loading-spinner');
                if (loadingSpinner) {
                    loadingSpinner.style.display = 'none';
                }
                
                // Call the success callback
                if (successCallback) {
                    successCallback(data);
                }
            })
            .catch(error => {
                // Hide the loading spinner if it exists
                const loadingSpinner = document.querySelector('.loading-spinner');
                if (loadingSpinner) {
                    loadingSpinner.style.display = 'none';
                }
                
                // Log the error
                console.error('AJAX Error:', error);
                
                // Call the error callback
                if (errorCallback) {
                    errorCallback(error);
                } else {
                    // Default error handling
                    Ajax.showNotification('An error occurred. Please try again.', 'error');
                }
            });
    },
    
    /**
     * Send a GET request
     * @param {string} url - The URL to send the request to
     * @param {Function} successCallback - Function to call on success
     * @param {Function} errorCallback - Function to call on error
     */
    get: function(url, successCallback, errorCallback) {
        this.request(url, 'GET', null, successCallback, errorCallback);
    },
    
    /**
     * Send a POST request
     * @param {string} url - The URL to send the request to
     * @param {Object|FormData} data - The data to send with the request
     * @param {Function} successCallback - Function to call on success
     * @param {Function} errorCallback - Function to call on error
     */
    post: function(url, data, successCallback, errorCallback) {
        this.request(url, 'POST', data, successCallback, errorCallback);
    },
    
    /**
     * Submit a form via AJAX
     * @param {HTMLFormElement} form - The form to submit
     * @param {Function} successCallback - Function to call on success
     * @param {Function} errorCallback - Function to call on error
     */
    submitForm: function(form, successCallback, errorCallback) {
        // Check if the form already has an AJAX event listener
        if (form.dataset.ajaxSubmitInitialized === 'true') {
            return;
        }
        
        // Mark the form as having an AJAX event listener
        form.dataset.ajaxSubmitInitialized = 'true';
        
        // Prevent default form submission
        form.addEventListener('submit', function(event) {
            event.preventDefault();
            
            // Check form validity
            if (!form.checkValidity()) {
                form.classList.add('was-validated');
                return;
            }
            
            // Show loading state on submit button
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn) {
                const spinner = submitBtn.querySelector('.spinner-border');
                if (spinner) {
                    spinner.classList.remove('d-none');
                } else {
                    submitBtn.dataset.originalText = submitBtn.innerHTML;
                    submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Processing...';
                }
                submitBtn.disabled = true;
            }
            
            // Create FormData from the form
            const formData = new FormData(form);
            
            // Send the AJAX request
            Ajax.request(
                form.action,
                form.method,
                formData,
                function(data) {
                    // Reset submit button
                    if (submitBtn) {
                        if (submitBtn.dataset.originalText) {
                            submitBtn.innerHTML = submitBtn.dataset.originalText;
                            delete submitBtn.dataset.originalText;
                        }
                        const spinner = submitBtn.querySelector('.spinner-border');
                        if (spinner) {
                            spinner.classList.add('d-none');
                        }
                        submitBtn.disabled = false;
                    }
                    
                    // Call the success callback
                    if (successCallback) {
                        successCallback(data);
                    }
                },
                function(error) {
                    // Reset submit button
                    if (submitBtn) {
                        if (submitBtn.dataset.originalText) {
                            submitBtn.innerHTML = submitBtn.dataset.originalText;
                            delete submitBtn.dataset.originalText;
                        }
                        const spinner = submitBtn.querySelector('.spinner-border');
                        if (spinner) {
                            spinner.classList.add('d-none');
                        }
                        submitBtn.disabled = false;
                    }
                    
                    // Call the error callback
                    if (errorCallback) {
                        errorCallback(error);
                    } else {
                        // Default error handling
                        Ajax.showNotification('An error occurred. Please try again.', 'error');
                    }
                }
            );
        });
    },
    
    /**
     * Load content into an element
     * @param {string} url - The URL to load content from
     * @param {string} targetSelector - The selector for the target element
     * @param {Function} callback - Function to call after content is loaded
     */
    loadContent: function(url, targetSelector, callback) {
        const targetElement = document.querySelector(targetSelector);
        if (!targetElement) {
            console.error('Target element not found:', targetSelector);
            return;
        }
        
        // Create a unique token to prevent out-of-order updates
        const token = `${Date.now()}:${Math.random()}`;
        targetElement.dataset.loadToken = token;
        
        // Show loading indicator in the target element
        const loadingHTML = '<div class="text-center py-4"><div class="spinner-border" role="status"><span class="visually-hidden">Loading...</span></div></div>';
        targetElement.innerHTML = loadingHTML;
        
        // Send the AJAX request
        this.get(
            url,
            function(data) {
                // If a newer request has been issued for this target, ignore this response
                if (targetElement.dataset.loadToken !== token) {
                    return;
                }
                
                // Update the target element with the response
                if (typeof data === 'string') {
                    targetElement.innerHTML = data;
                } else if (data.html) {
                    targetElement.innerHTML = data.html;
                } else {
                    targetElement.innerHTML = JSON.stringify(data);
                }
                
                // Call the callback function
                if (callback) {
                    callback(data);
                }
                
                // Initialize any new elements
                Ajax.initializeElements(targetElement);
            },
            function(error) {
                // If a newer request has been issued for this target, ignore this error update
                if (targetElement.dataset.loadToken !== token) {
                    return;
                }
                // Show error message in the target element
                targetElement.innerHTML = '<div class="alert alert-danger">Failed to load content. Please try again.</div>';
            }
        );
    },
    
    /**
     * Show a notification message
     * @param {string} message - The message to show
     * @param {string} type - The type of notification (success, error, warning, info)
     * @param {number} duration - The duration in milliseconds
     */
    showNotification: function(message, type = 'info', duration = 5000) {
        // Map type to Bootstrap alert class
        const alertClass = {
            'success': 'alert-success',
            'error': 'alert-danger',
            'warning': 'alert-warning',
            'info': 'alert-info'
        }[type] || 'alert-info';
        
        // Create the notification element
        const notification = document.createElement('div');
        notification.className = `alert ${alertClass} alert-dismissible fade show`;
        notification.role = 'alert';
        notification.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;
        
        // Add the notification to the flash-messages container
        const container = document.querySelector('.flash-messages');
        if (container) {
            container.appendChild(notification);
            
            // Initialize the Bootstrap alert
            const bsAlert = new bootstrap.Alert(notification);
            
            // Auto-dismiss after duration
            if (duration > 0) {
                setTimeout(() => {
                    bsAlert.close();
                }, duration);
            }
        }
    },
    
    /**
     * Initialize elements in a container
     * @param {HTMLElement} container - The container element
     */
    initializeElements: function(container) {
        // Initialize tooltips
        const tooltips = container.querySelectorAll('[data-bs-toggle="tooltip"]');
        tooltips.forEach(tooltip => new bootstrap.Tooltip(tooltip));
        
        // Initialize popovers
        const popovers = container.querySelectorAll('[data-bs-toggle="popover"]');
        popovers.forEach(popover => new bootstrap.Popover(popover));
        
        // Initialize form validation
        const forms = container.querySelectorAll('.needs-validation');
        forms.forEach(form => {
            // Check if the form already has a submit event listener
            if (!form.dataset.ajaxInitialized) {
                form.dataset.ajaxInitialized = 'true';
                
                // Add submit event listener for form validation
                form.addEventListener('submit', event => {
                    if (!form.checkValidity()) {
                        event.preventDefault();
                        event.stopPropagation();
                    }
                    form.classList.add('was-validated');
                }, false);
            }
        });
    }
};

// Initialize elements when the DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    Ajax.initializeElements(document);
});