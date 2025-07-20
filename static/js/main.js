// Hide loading spinner by default when page loads
document.querySelector('.loading-spinner').style.display = 'none';

// Dark mode toggle
const themeToggle = document.getElementById('theme-toggle');
const html = document.documentElement;
const icon = themeToggle.querySelector('i');

function updateThemeIcon(isDark) {
    icon.className = isDark ? 'bi bi-sun' : 'bi bi-moon-stars';
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

// Show loading spinner on page navigation
document.addEventListener('click', (e) => {
    if (e.target.tagName === 'A' && e.target.href && !e.target.hasAttribute('data-bs-toggle')) {
        document.querySelector('.loading-spinner').style.display = 'block';
    }
});

// Initialize tooltips
document.addEventListener('DOMContentLoaded', () => {
    const tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltips.forEach(tooltip => new bootstrap.Tooltip(tooltip));

    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });
    
    // Hide loading spinner when DOM is loaded
    const spinner = document.getElementById('loadingSpinner');
    if (spinner) {
        spinner.style.display = 'none';
    }
});

// Hide loading spinner when page is fully loaded
window.addEventListener('load', () => {
    document.querySelector('.loading-spinner').style.display = 'none';
});