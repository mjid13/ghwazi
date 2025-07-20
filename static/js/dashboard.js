/**
 * Dashboard-specific JavaScript functionality
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize email fetching form
    initEmailFetchForm();
    
    // Initialize PDF upload form
    initPdfUploadForm();
    
    // Initialize mode switching
    initModeSwitching();
    
    // Initialize email task status checking
    initEmailTaskStatusChecking();
});

/**
 * Initialize email fetching form with AJAX submission
 */
function initEmailFetchForm() {
    const emailFetchForm = document.querySelector('form[action*="fetch_emails"]');
    if (!emailFetchForm) return;
    
    // Add validation for disabled options
    emailFetchForm.addEventListener('submit', function(event) {
        const accountSelect = document.getElementById('email_account_number');
        if (accountSelect && accountSelect.value) {
            const selectedOption = accountSelect.options[accountSelect.selectedIndex];
            if (selectedOption.disabled) {
                event.preventDefault();
                Ajax.showNotification('This account is currently being scraped. Please wait for the process to complete.', 'warning');
                return;
            }
        }
    });
    
    // Add AJAX submission
    Ajax.submitForm(emailFetchForm, function(response) {
        if (response.success) {
            // Show success notification
            Ajax.showNotification('Email fetching started successfully. You can check the status in the dashboard.', 'success');
            
            // Start polling for status updates
            if (response.task_id) {
                pollEmailTaskStatus(response.task_id);
            }
            
            // Close any open modals
            const modal = bootstrap.Modal.getInstance(document.querySelector('.modal.show'));
            if (modal) {
                modal.hide();
            }
            
            // Redirect to dashboard if specified
            if (response.redirect) {
                window.location.href = response.redirect;
            }
        } else {
            // Show error notification
            Ajax.showNotification(response.message || 'Failed to start email fetching.', 'error');
        }
    });
}

/**
 * Initialize PDF upload form with AJAX submission
 */
function initPdfUploadForm() {
    const pdfUploadForm = document.querySelector('form[action*="upload_pdf"]');
    if (!pdfUploadForm) return;
    
    // Add AJAX submission
    pdfUploadForm.addEventListener('submit', function(event) {
        event.preventDefault();
        
        // Check form validity
        if (!pdfUploadForm.checkValidity()) {
            pdfUploadForm.classList.add('was-validated');
            return;
        }
        
        // Show loading state
        const submitBtn = pdfUploadForm.querySelector('button[type="submit"]');
        if (submitBtn) {
            submitBtn.disabled = true;
            submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Uploading...';
        }
        
        // Create FormData
        const formData = new FormData(pdfUploadForm);
        
        // Send AJAX request
        fetch(pdfUploadForm.action, {
            method: 'POST',
            body: formData,
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        })
        .then(response => response.json())
        .then(data => {
            // Reset button
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.innerHTML = 'Upload and Process';
            }
            
            if (data.success) {
                // Show success notification
                Ajax.showNotification(data.message || 'PDF uploaded and processed successfully.', 'success');
                
                // Close any open modals
                const modal = bootstrap.Modal.getInstance(document.querySelector('.modal.show'));
                if (modal) {
                    modal.hide();
                }
                
                // Redirect if specified
                if (data.redirect) {
                    window.location.href = data.redirect;
                }
            } else {
                // Show error notification
                Ajax.showNotification(data.message || 'Failed to upload PDF.', 'error');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            
            // Reset button
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.innerHTML = 'Upload and Process';
            }
            
            // Show error notification
            Ajax.showNotification('An error occurred while uploading the PDF.', 'error');
        });
    });
}

/**
 * Initialize mode switching with AJAX content loading
 */
function initModeSwitching() {
    const emailModeLink = document.querySelector('a[href*="dashboard?mode=email"]');
    const uploadModeLink = document.querySelector('a[href*="dashboard?mode=upload"]');
    
    if (!emailModeLink || !uploadModeLink) return;
    
    // Handle email mode link click
    emailModeLink.addEventListener('click', function(event) {
        event.preventDefault();
        
        // Update button styles
        emailModeLink.classList.add('btn-primary');
        emailModeLink.classList.remove('btn-outline-primary');
        uploadModeLink.classList.add('btn-outline-primary');
        uploadModeLink.classList.remove('btn-primary');
        
        // Load content via AJAX
        Ajax.loadContent(emailModeLink.href, '.manual-entry-form', function() {
            // Re-initialize email fetching form
            initEmailFetchForm();
            
            // Update URL without reloading
            history.pushState({}, '', emailModeLink.href);
        });
    });
    
    // Handle upload mode link click
    uploadModeLink.addEventListener('click', function(event) {
        event.preventDefault();
        
        // Update button styles
        uploadModeLink.classList.add('btn-primary');
        uploadModeLink.classList.remove('btn-outline-primary');
        emailModeLink.classList.add('btn-outline-primary');
        emailModeLink.classList.remove('btn-primary');
        
        // Load content via AJAX
        Ajax.loadContent(uploadModeLink.href, '.manual-entry-form', function() {
            // Re-initialize PDF upload form
            initPdfUploadForm();
            
            // Update URL without reloading
            history.pushState({}, '', uploadModeLink.href);
        });
    });
}

/**
 * Initialize email task status checking
 */
function initEmailTaskStatusChecking() {
    // Check if there are any active email tasks
    const scrapingElements = document.querySelectorAll('.spin');
    if (scrapingElements.length > 0) {
        // Start polling for all active tasks
        pollAllEmailTasks();
    }
}

/**
 * Poll for status updates for all email tasks
 */
function pollAllEmailTasks() {
    // Send AJAX request to get status of all tasks
    Ajax.get('/email_processing_status', function(response) {
        if (response.tasks && Object.keys(response.tasks).length > 0) {
            // Update UI for each task
            for (const [accountNumber, task] of Object.entries(response.tasks)) {
                updateTaskUI(accountNumber, task);
            }
            
            // Continue polling if there are active tasks
            if (Object.keys(response.tasks).length > 0) {
                setTimeout(pollAllEmailTasks, 5000);
            }
        }
    });
}

/**
 * Poll for status updates for a specific email task
 * @param {string} taskId - The ID of the task to poll
 */
function pollEmailTaskStatus(taskId) {
    Ajax.get(`/email_task_status/${taskId}`, function(response) {
        if (response.status && response.status !== 'completed' && response.status !== 'failed') {
            // Update UI
            if (response.account_number) {
                updateTaskUI(response.account_number, response);
            }
            
            // Continue polling
            setTimeout(() => pollEmailTaskStatus(taskId), 5000);
        } else {
            // Task completed or failed, show notification
            if (response.status === 'completed') {
                Ajax.showNotification('Email fetching completed successfully.', 'success');
            } else if (response.status === 'failed') {
                Ajax.showNotification(`Email fetching failed: ${response.message || 'Unknown error'}`, 'error');
            }
            
            // Reload the page to show updated data
            window.location.reload();
        }
    });
}

/**
 * Update the UI for a specific email task
 * @param {string} accountNumber - The account number
 * @param {Object} task - The task data
 */
function updateTaskUI(accountNumber, task) {
    // Find the account option in the dropdown
    const accountOption = document.querySelector(`option[value*="${accountNumber}"]`);
    if (accountOption) {
        // Update the option text with progress
        const progress = task.progress ? Math.round(task.progress * 100) : 0;
        accountOption.textContent = `${accountOption.textContent.split('(')[0]} (Scraping: ${progress}%)`;
        accountOption.disabled = true;
    }
    
    // Find any account items with this account number
    const accountItems = document.querySelectorAll(`.account-item[href*="${accountNumber}"]`);
    accountItems.forEach(item => {
        // Make sure the badge exists
        let badge = item.querySelector('.badge.bg-warning');
        if (!badge) {
            // Create the badge if it doesn't exist
            const accountName = item.querySelector('h5');
            if (accountName) {
                badge = document.createElement('span');
                badge.className = 'badge bg-warning text-dark ms-2';
                badge.innerHTML = '<i class="bi bi-arrow-repeat me-1 spin"></i>Scraping';
                accountName.appendChild(badge);
            }
        }
        
        // Update the badge text with progress
        if (badge && task.progress) {
            const progress = Math.round(task.progress * 100);
            badge.innerHTML = `<i class="bi bi-arrow-repeat me-1 spin"></i>Scraping: ${progress}%`;
        }
    });
}