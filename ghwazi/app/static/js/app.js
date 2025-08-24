/**
 * Modern Money Tracker Application
 * ES6+ Module-based architecture
 */

// Import utility modules
import Utils, { DOM, Storage, HTTP, eventBus } from './modules/utils.js';
import UI, { themeManager, notificationManager, loadingManager, modalManager } from './modules/ui.js';

// Import feature modules
import './modules/dashboard.js';
import Realtime, { realtimeManager, ajaxFormHandler, dataTableManager } from './modules/realtime.js';

/**
 * Main Application Class
 */
class MoneyTrackerApp {
  constructor() {
    this.isInitialized = false;
    this.version = '2.0.0';
    this.debug = false;
    
    this.init();
  }

  async init() {
    if (this.isInitialized) return;

    try {
      // Initialize core services
      await this.initializeCore();
      
      // Initialize UI components
      this.initializeUI();
      
      // Initialize page-specific features
      this.initializePageFeatures();
      
      // Bind global events
      this.bindGlobalEvents();
      
      // Initialize service worker if available
      this.initializeServiceWorker();
      
      this.isInitialized = true;
      
      // Emit app ready event
      eventBus.emit('app:ready', { version: this.version });
      
      if (this.debug) {
        console.log(`Money Tracker App v${this.version} initialized successfully`);
      }
      
    } catch (error) {
      console.error('Failed to initialize Money Tracker App:', error);
      notificationManager.error(_('Application failed to initialize'), _('Startup Error'));
    }
  }

  async initializeCore() {
    // Set CSRF token for all AJAX requests
    const csrfToken = HTTP.getCSRFToken();
    if (csrfToken) {
      HTTP.defaults.headers['X-CSRFToken'] = csrfToken;
    }

    // Initialize error handling
    this.initializeErrorHandling();
    
    // Initialize performance monitoring
    this.initializePerformanceMonitoring();
  }

  initializeUI() {
    // Theme manager is auto-initialized
    
    // Initialize tooltips and popovers
    this.initializeBootstrapComponents();
    
    // Initialize custom form validation
    this.initializeFormValidation();
    
    // Initialize loading states
    this.initializeLoadingStates();
  }

  initializePageFeatures() {
    const currentPage = this.getCurrentPage();
    
    switch (currentPage) {
      case 'dashboard':
        // Dashboard is auto-initialized via its module
        break;
        
      case 'accounts':
        this.initializeAccountsPage();
        break;
        
      case 'login':
      case 'register':
        this.initializeAuthPages();
        break;
        
      case 'transactions':
        this.initializeTransactionsPage();
        break;
        
      default:
        // Initialize common features for all pages
        this.initializeCommonFeatures();
    }
  }

  initializeBootstrapComponents() {
    // Initialize tooltips
    const tooltipTriggerList = DOM.queryAll('[data-bs-toggle="tooltip"]');
    tooltipTriggerList.forEach(tooltipTriggerEl => {
      new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    const popoverTriggerList = DOM.queryAll('[data-bs-toggle="popover"]');
    popoverTriggerList.forEach(popoverTriggerEl => {
      new bootstrap.Popover(popoverTriggerEl);
    });
  }

  initializeFormValidation() {
    const forms = DOM.queryAll('.needs-validation');
    
    forms.forEach(form => {
      DOM.on(form, 'submit', (event) => {
        if (!form.checkValidity()) {
          event.preventDefault();
          event.stopPropagation();
          
          // Focus first invalid field
          const firstInvalid = DOM.query(':invalid', form);
          if (firstInvalid) {
            firstInvalid.focus();
          }
        } else {
          // Show loading state on submit button
          const submitBtn = DOM.query('button[type="submit"]', form);
          if (submitBtn) {
            this.setButtonLoading(submitBtn, true);
          }
        }
        
        form.classList.add('was-validated');
      });
    });
  }

  initializeLoadingStates() {
    // Show loading spinner immediately on navigation
    DOM.on(document, 'click', (e) => {
      const link = e.target.closest('a[href]');
      if (link && 
          !link.hasAttribute('data-bs-toggle') && 
          !link.href.startsWith('#') &&
          !link.href.startsWith('javascript:') &&
          !link.href.includes('mailto:') &&
          !link.href.includes('tel:') &&
          !link.target === '_blank') {
        
        // Show loading immediately for better perceived performance
        this.showPageLoading('Loading page...');
      }
    });

    // Show loading on form submissions
    DOM.on(document, 'submit', (e) => {
      const form = e.target;
      if (form && !form.hasAttribute('data-no-loading')) {
        this.showPageLoading('Processing...');
      }
    });

    // Hide loading on page load and when DOM is ready
    DOM.on(document, 'DOMContentLoaded', () => {
      this.hidePageLoading();
    });
    
    DOM.on(window, 'load', () => {
      this.hidePageLoading();
    });

    // Hide loading on beforeunload to prevent flicker
    DOM.on(window, 'beforeunload', () => {
      this.hidePageLoading();
    });
  }

  showPageLoading(message = 'Loading...') {
    const spinner = DOM.query('#loadingSpinner');
    const text = DOM.query('#loadingText');
    
    if (spinner) {
      if (text) text.textContent = message;
      DOM.removeClass(spinner, 'd-none');
      DOM.addClass(spinner, 'd-flex');
    }
  }

  hidePageLoading() {
    const spinner = DOM.query('#loadingSpinner');
    if (spinner) {
      DOM.addClass(spinner, 'd-none');
      DOM.removeClass(spinner, 'd-flex');
    }
  }

  initializeAccountsPage() {
    // Enhanced account interactions
    const accountCards = DOM.queryAll('.account-summary-card, .account-item');
    
    accountCards.forEach(card => {
      // Add hover effects
      DOM.on(card, 'mouseenter', () => {
        DOM.addClass(card, 'hover-elevation');
      });
      
      DOM.on(card, 'mouseleave', () => {
        DOM.removeClass(card, 'hover-elevation');
      });
    });
  }

  initializeAuthPages() {
    // Auto-focus first input
    const firstInput = DOM.query('input[type="text"], input[type="email"]');
    if (firstInput) {
      firstInput.focus();
    }

    // Enhanced form submission
    const authForms = DOM.queryAll('form');
    authForms.forEach(form => {
      DOM.on(form, 'submit', () => {
        loadingManager.showGlobal('Authenticating...');
      });
    });
  }

  async initializeTransactionsPage() {
    // Check if we have tables that need DataTables
    const tables = DOM.queryAll('.data-table');
    if (tables.length === 0) return;

    // Show loading for DataTables initialization
    this.showPageLoading('Loading table features...');
    
    try {
      // Lazy load jQuery and DataTables only when needed
      await this.loadDataTables();
      
      // Initialize DataTables
      tables.forEach(table => {
        if (window.$ && $.fn.DataTable) {
          $(table).DataTable({
            responsive: true,
            pageLength: 25,
            order: [[0, 'desc']], // Sort by date descending
            language: {
              search: "Search transactions:",
              lengthMenu: "Show _MENU_ transactions per page",
              info: "Showing _START_ to _END_ of _TOTAL_ transactions"
            },
            initComplete: () => {
              this.hidePageLoading();
            }
          });
        }
      });
    } catch (error) {
      console.error('Failed to load DataTables:', error);
      this.hidePageLoading();
    }
  }

  async loadDataTables() {
    // Check if already loaded
    if (window.$ && window.$.fn.DataTable) {
      return;
    }

    // Load jQuery first if needed
    if (!window.$) {
      await this.loadScript('https://code.jquery.com/jquery-3.7.0.min.js');
    }

    // Load DataTables
    await Promise.all([
      this.loadScript('https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js'),
      this.loadStylesheet('https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css')
    ]);

    // Load Bootstrap integration
    await Promise.all([
      this.loadScript('https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js'),
      this.loadScript('https://cdn.datatables.net/responsive/2.5.0/js/dataTables.responsive.min.js'),
      this.loadScript('https://cdn.datatables.net/responsive/2.5.0/js/responsive.bootstrap5.min.js'),
      this.loadStylesheet('https://cdn.datatables.net/responsive/2.5.0/css/responsive.bootstrap5.min.css')
    ]);
  }

  loadScript(src) {
    return new Promise((resolve, reject) => {
      // Check if already loaded
      if (DOM.query(`script[src="${src}"]`)) {
        resolve();
        return;
      }

      const script = DOM.create('script', {
        src,
        onload: resolve,
        onerror: reject
      });
      
      document.head.appendChild(script);
    });
  }

  loadStylesheet(href) {
    return new Promise((resolve, reject) => {
      // Check if already loaded
      if (DOM.query(`link[href="${href}"]`)) {
        resolve();
        return;
      }

      const link = DOM.create('link', {
        rel: 'stylesheet',
        href,
        onload: resolve,
        onerror: reject
      });
      
      document.head.appendChild(link);
    });
  }

  initializeCommonFeatures() {
    // Initialize confirmation dialogs
    this.initializeConfirmationDialogs();
    
    // Initialize auto-save forms
    this.initializeAutoSave();
    
    // Initialize keyboard shortcuts
    this.initializeKeyboardShortcuts();
  }

  initializeConfirmationDialogs() {
    const confirmButtons = DOM.queryAll('[data-confirm]');
    
    confirmButtons.forEach(button => {
      DOM.on(button, 'click', async (e) => {
        e.preventDefault();
        
        const message = button.dataset.confirm;
        const confirmed = await modalManager.confirm(message);
        
        if (confirmed) {
          // If it's a form button, submit the form
          if (button.type === 'submit') {
            const form = button.closest('form');
            if (form) {
              form.submit();
            }
          }
          // If it's a link, navigate to it
          else if (button.href) {
            window.location.href = button.href;
          }
        }
      });
    });
  }

  initializeAutoSave() {
    const autoSaveForms = DOM.queryAll('[data-auto-save]');
    
    autoSaveForms.forEach(form => {
      const inputs = DOM.queryAll('input, textarea, select', form);
      
      inputs.forEach(input => {
        DOM.on(input, 'input', this.debounce(async () => {
          await this.autoSaveForm(form);
        }, 2000));
      });
    });
  }

  async autoSaveForm(form) {
    try {
      const formData = new FormData(form);
      const saveUrl = form.dataset.autoSave;
      
      if (saveUrl) {
        await HTTP.post(saveUrl, formData);
        
        // Show subtle save indicator
        const saveIndicator = DOM.create('span', {
          className: 'text-success small ms-2',
          innerHTML: '<i class="bi bi-check-circle"></i> Saved'
        });
        
        const submitBtn = DOM.query('button[type="submit"]', form);
        if (submitBtn && !DOM.query('.save-indicator', submitBtn.parentNode)) {
          submitBtn.parentNode.appendChild(saveIndicator);
          
          setTimeout(() => {
            if (saveIndicator.parentNode) {
              saveIndicator.parentNode.removeChild(saveIndicator);
            }
          }, 3000);
        }
      }
    } catch (error) {
      console.error('Auto-save failed:', error);
    }
  }

  initializeKeyboardShortcuts() {
    DOM.on(document, 'keydown', (e) => {
      // Ctrl/Cmd + K for search
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        const searchInput = DOM.query('input[type="search"], .dataTables_filter input');
        if (searchInput) {
          searchInput.focus();
        }
      }
      
      // Escape to close modals/dropdowns
      if (e.key === 'Escape') {
        const activeModal = DOM.query('.modal.show');
        if (activeModal) {
          const modalInstance = bootstrap.Modal.getInstance(activeModal);
          if (modalInstance) {
            modalInstance.hide();
          }
        }
      }
    });
  }

  initializeErrorHandling() {
    // Global error handler
    window.addEventListener('error', (event) => {
      console.error('Global error:', event.error);
      
      if (this.debug) {
        notificationManager.error(
          `Script error: ${event.error.message}`,
          _('JavaScript Error')
        );
      }
    });

    // Unhandled promise rejection handler
    window.addEventListener('unhandledrejection', (event) => {
      console.error('Unhandled promise rejection:', event.reason);
      
      if (this.debug) {
        notificationManager.error(
          _('An unexpected error occurred'),
          _('System Error')
        );
      }
    });

    // AJAX error handler
    eventBus.on('http:error', (error) => {
      console.error('HTTP error:', error);
      
      if (error.status === 403) {
        notificationManager.error(_('Access denied'), _('Authorization Error'));
      } else if (error.status === 429) {
        notificationManager.warning(_('Too many requests. Please try again later.'), _('Rate Limited'));
      } else if (error.status >= 500) {
        notificationManager.error(_('Server error. Please try again.'), _('Server Error'));
      }
    });
  }

  initializePerformanceMonitoring() {
    // Monitor page load performance
    window.addEventListener('load', () => {
      if ('performance' in window) {
        const perfData = performance.getEntriesByType('navigation')[0];
        
        if (this.debug) {
          console.log('Page load performance:', {
            loadTime: perfData.loadEventEnd - perfData.loadEventStart,
            domContentLoaded: perfData.domContentLoadedEventEnd - perfData.domContentLoadedEventStart,
            totalTime: perfData.loadEventEnd - perfData.fetchStart
          });
        }
        
        // Report slow loads
        const totalTime = perfData.loadEventEnd - perfData.fetchStart;
        if (totalTime > 5000) { // 5 seconds
          eventBus.emit('performance:slow-load', { totalTime });
        }
      }
    });
  }

  async initializeServiceWorker() {
    if ('serviceWorker' in navigator) {
      try {
        const registration = await navigator.serviceWorker.register('/static/js/sw.js');
        
        if (this.debug) {
          console.log('Service Worker registered:', registration);
        }
        
        eventBus.emit('sw:registered', registration);
      } catch (error) {
        if (this.debug) {
          console.warn('Service Worker registration failed:', error);
        }
      }
    }
  }

  bindGlobalEvents() {
    // Theme change events
    eventBus.on('theme:changed', (data) => {
      // Update charts if they exist
      if (window.Chart) {
        Chart.defaults.color = data.theme === 'dark' ? '#ffffff' : '#666666';
        Chart.defaults.borderColor = data.theme === 'dark' ? '#444444' : '#e0e0e0';
        
        // Update existing charts
        Object.values(Chart.instances).forEach(chart => {
          chart.update('none');
        });
      }
    });

    // Visibility change events
    DOM.on(document, 'visibilitychange', () => {
      eventBus.emit('page:visibility-change', {
        hidden: document.hidden,
        visibilityState: document.visibilityState
      });
    });

    // Real-time connection events
    eventBus.on('realtime:connected', (data) => {
      if (this.debug) {
        console.log(`Real-time connection established via ${data.type}`);
      }
    });

    eventBus.on('realtime:unavailable', (data) => {
      if (this.debug) {
        console.log('Real-time features unavailable:', data.message);
      }
      // Application continues to work normally without real-time features
    });
  }

  getCurrentPage() {
    const path = window.location.pathname;
    
    if (path.includes('/dashboard')) return 'dashboard';
    if (path.includes('/accounts')) return 'accounts';
    if (path.includes('/login')) return 'login';
    if (path.includes('/register')) return 'register';
    if (path.includes('/transactions')) return 'transactions';
    
    return 'home';
  }

  setButtonLoading(button, loading = true) {
    if (loading) {
      button.dataset.originalText = button.innerHTML;
      button.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Loading...';
      button.disabled = true;
    } else {
      button.innerHTML = button.dataset.originalText || button.innerHTML;
      button.disabled = false;
      delete button.dataset.originalText;
    }
  }

  debounce(func, delay) {
    let timeoutId;
    return function (...args) {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(() => func.apply(this, args), delay);
    };
  }

  // Public API methods
  getVersion() {
    return this.version;
  }

  enableDebug() {
    this.debug = true;
    console.log('Debug mode enabled');
  }

  disableDebug() {
    this.debug = false;
  }

  restart() {
    window.location.reload();
  }
}

// Initialize the application
const app = new MoneyTrackerApp();

// Make utilities globally available
window.MoneyTracker = {
  app,
  Utils,
  UI,
  Realtime,
  DOM,
  Storage,
  HTTP,
  eventBus,
  themeManager,
  notificationManager,
  loadingManager,
  modalManager,
  realtimeManager,
  ajaxFormHandler,
  dataTableManager
};

// Export for ES6 modules
export default app;
export { 
  app, 
  Utils, 
  UI, 
  Realtime,
  DOM, 
  Storage, 
  HTTP, 
  eventBus,
  themeManager,
  notificationManager,
  loadingManager,
  modalManager,
  realtimeManager,
  ajaxFormHandler,
  dataTableManager
};