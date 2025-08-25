// Hide loading spinner by default when page loads
const loadingSpinner = document.querySelector('.loading-spinner');
if (loadingSpinner) {
    loadingSpinner.style.display = 'none';
}

// Dark mode toggle function
function initThemeToggle() {
    const themeToggle = document.getElementById('theme-toggle');
    if (!themeToggle) return;
    
    const html = document.documentElement;
    const icon = themeToggle.querySelector('i');
    
    function updateThemeIcon(isDark) {
        if (icon) {
            icon.className = isDark ? 'bi bi-sun' : 'bi bi-moon-stars';
        }
    }
    
    // Check for saved theme preference
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        html.setAttribute('data-bs-theme', savedTheme);
        updateThemeIcon(savedTheme === 'dark');
    }
    
    themeToggle.addEventListener('click', () => {
        const isDark = html.getAttribute('data-bs-theme') === 'dark';
        const newTheme = isDark ? 'light' : 'dark';
        html.setAttribute('data-bs-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        updateThemeIcon(!isDark);
    });
}

// Show loading spinner on page navigation
document.addEventListener('click', (e) => {
    if (e.target.tagName === 'A' && e.target.href && !e.target.hasAttribute('data-bs-toggle')) {
        const spinner = document.querySelector('.loading-spinner');
        if (spinner) {
            spinner.style.display = 'block';
        }
    }
});

// Initialize tooltips
document.addEventListener('DOMContentLoaded', () => {
    // Initialize theme toggle
    initThemeToggle();
    
    const tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltips.forEach(tooltip => new bootstrap.Tooltip(tooltip));

    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 50000);
    });
    
    // Hide loading spinner when DOM is loaded
    const spinner = document.getElementById('loadingSpinner');
    if (spinner) {
        spinner.style.display = 'none';
    }
});

// Hide loading spinner when page is fully loaded
window.addEventListener('load', () => {
    const spinner = document.querySelector('.loading-spinner');
    if (spinner) {
        spinner.style.display = 'none';
    }
});

// Global confirmation handler for elements or forms with [data-confirm]
(function(){
  function shouldConfirm(el){
    if (!el) return null;
    const target = el.closest('[data-confirm]');
    return target;
  }

  // Intercept clicks on links/buttons with data-confirm
  document.addEventListener('click', function(e){
    const target = e.target.closest('[data-confirm]');
    if (!target) return;
    const message = target.getAttribute('data-confirm') || 'Are you sure?';
    if (!window.confirm(message)) {
      e.preventDefault();
      e.stopPropagation();
    }
  }, true);

  // Intercept form submissions if form has data-confirm (e.g., pressing Enter)
  document.addEventListener('submit', function(e){
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;

    // If submitter (clicked button) has data-confirm, use that; else check form
    let msg = null;
    const submitter = e.submitter || null;
    if (submitter && submitter.hasAttribute && submitter.hasAttribute('data-confirm')) {
      msg = submitter.getAttribute('data-confirm');
    } else if (form.hasAttribute('data-confirm')) {
      msg = form.getAttribute('data-confirm');
    }
    if (msg) {
      if (!window.confirm(msg || 'Are you sure?')) {
        e.preventDefault();
        e.stopPropagation();
      }
    }
  }, true);
})();

// Budget form enhancements
document.addEventListener('DOMContentLoaded', function() {
  // Add smooth animation for form submissions
  const budgetForms = document.querySelectorAll('.budget-form');
  budgetForms.forEach(form => {
    form.addEventListener('submit', function(e) {
      const submitBtn = form.querySelector('button[type="submit"]');
      if (submitBtn) {
        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Creating...';
        submitBtn.disabled = true;
        
        // Re-enable after 3 seconds in case of page redirect issues
        setTimeout(() => {
          submitBtn.innerHTML = originalText;
          submitBtn.disabled = false;
        }, 3000);
      }
    });

    // Add focus effects for better UX
    const inputs = form.querySelectorAll('input, select');
    inputs.forEach(input => {
      input.addEventListener('focus', function() {
        this.closest('.card')?.classList.add('border-primary');
      });
      input.addEventListener('blur', function() {
        this.closest('.card')?.classList.remove('border-primary');
      });
    });

    // Real-time validation feedback
    const amountInput = form.querySelector('input[name="amount"]');
    if (amountInput) {
      amountInput.addEventListener('input', function() {
        const value = parseFloat(this.value);
        if (value > 0) {
          this.classList.remove('is-invalid');
          this.classList.add('is-valid');
        } else {
          this.classList.remove('is-valid');
          if (this.value) this.classList.add('is-invalid');
        }
      });
    }
  });

  // Enhanced progress bars with animation
  const progressBars = document.querySelectorAll('.progress-bar');
  progressBars.forEach((bar, index) => {
    const targetWidth = bar.style.width;
    bar.style.width = '0%';
    
    setTimeout(() => {
      bar.style.transition = 'width 1s ease-in-out';
      bar.style.width = targetWidth;
    }, index * 200);
  });

  // Add hover effects to budget cards
  const budgetCards = document.querySelectorAll('.card');
  budgetCards.forEach(card => {
    card.addEventListener('mouseenter', function() {
      this.style.transform = 'translateY(-2px)';
      this.style.transition = 'transform 0.2s ease';
    });
    
    card.addEventListener('mouseleave', function() {
      this.style.transform = 'translateY(0)';
    });
  });
});