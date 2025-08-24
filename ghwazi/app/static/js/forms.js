/**
 * Common form validation and handling functionality
 */

// Initialize form validation for Bootstrap forms with 'needs-validation' class
function initFormValidation() {
    const forms = document.querySelectorAll('.needs-validation');
    
    Array.from(forms).forEach(form => {
        form.addEventListener('submit', event => {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            } else {
                // If form is valid, show loading state on submit button if it exists
                const submitBtn = form.querySelector('button[type="submit"]');
                if (submitBtn) {
                    const spinner = submitBtn.querySelector('.spinner-border');
                    if (spinner) {
                        spinner.classList.remove('d-none');
                    } else {
                        // If no spinner exists, add loading text
                        submitBtn.dataset.originalText = submitBtn.innerHTML;
                        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>' + _('Processing...');
                    }
                    submitBtn.disabled = true;
                }
            }
            
            form.classList.add('was-validated');
        }, false);
    });
}

// Initialize tooltips
function initTooltips() {
    const tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltips.forEach(tooltip => new bootstrap.Tooltip(tooltip));
}

// Auto-focus first input in modal when opened
function initModalFocus() {
    const modals = document.querySelectorAll('.modal');
    
    modals.forEach(modal => {
        modal.addEventListener('shown.bs.modal', function() {
            // Focus the first input, select or textarea
            const firstInput = this.querySelector('input:not([type=hidden]), select, textarea');
            if (firstInput) {
                firstInput.focus();
            }
        });
    });
}

// Initialize all form-related functionality
document.addEventListener('DOMContentLoaded', function() {
    initFormValidation();
    initTooltips();
    initModalFocus();
});