/**
 * Modern UI Components and Interactions
 * ES6+ classes for UI management
 */

import { DOM, Storage, Animation, eventBus } from './utils.js';

export class ThemeManager {
  constructor() {
    this.themeKey = 'app-theme';
    this.init();
  }

  init() {
    this.applyStoredTheme();
    this.bindToggleButton();
    this.watchSystemTheme();
  }

  applyStoredTheme() {
    const savedTheme = Storage.get(this.themeKey, 'light');
    this.setTheme(savedTheme);
  }

  setTheme(theme) {
    const html = document.documentElement;
    html.setAttribute('data-bs-theme', theme);
    Storage.set(this.themeKey, theme);
    this.updateToggleIcon(theme);
    eventBus.emit('theme:changed', { theme });
  }

  updateToggleIcon(theme) {
    const toggle = DOM.query('#theme-toggle');
    if (!toggle) return;

    const icon = DOM.query('i', toggle);
    if (icon) {
      icon.className = theme === 'dark' ? 'bi bi-sun' : 'bi bi-moon-stars';
    }
  }

  bindToggleButton() {
    const toggle = DOM.query('#theme-toggle');
    if (!toggle) return;

    DOM.on(toggle, 'click', () => {
      const currentTheme = document.documentElement.getAttribute('data-bs-theme');
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      this.setTheme(newTheme);
    });
  }

  watchSystemTheme() {
    if (window.matchMedia) {
      const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
      
      DOM.on(mediaQuery, 'change', (e) => {
        if (!Storage.has(this.themeKey)) {
          this.setTheme(e.matches ? 'dark' : 'light');
        }
      });
    }
  }

  getCurrentTheme() {
    return document.documentElement.getAttribute('data-bs-theme') || 'light';
  }
}

export class NotificationManager {
  constructor() {
    this.container = this.createContainer();
    this.notifications = new Map();
    this.defaultDuration = 5000;
  }

  createContainer() {
    let container = DOM.query('.notifications-container');
    if (!container) {
      container = DOM.create('div', {
        className: 'notifications-container position-fixed top-0 end-0 p-3',
        attributes: { style: 'z-index: 1055; max-width: 400px;' }
      });
      document.body.appendChild(container);
    }
    return container;
  }

  /**
   * Show notification
   * @param {Object} options - Notification options
   */
  show(options = {}) {
    const {
      type = 'info',
      title = '',
      message = '',
      duration = this.defaultDuration,
      persistent = false
    } = options;

    const id = this.generateId();
    const notification = this.createNotification(id, type, title, message, persistent);
    
    this.notifications.set(id, notification);
    this.container.appendChild(notification.element);
    
    // Animate in
    Animation.fadeIn(notification.element);
    
    // Auto-remove if not persistent
    if (!persistent && duration > 0) {
      setTimeout(() => this.remove(id), duration);
    }

    return id;
  }

  createNotification(id, type, title, message, persistent) {
    const alertClass = this.getAlertClass(type);
    const icon = this.getIcon(type);
    
    const element = DOM.create('div', {
      className: `alert ${alertClass} alert-dismissible fade show animate-slide-left`,
      attributes: { role: 'alert' },
      innerHTML: `
        <div class="d-flex align-items-start">
          <i class="bi ${icon} me-2 mt-1"></i>
          <div class="flex-grow-1">
            ${title ? `<h6 class="alert-heading mb-1">${title}</h6>` : ''}
            <div>${message}</div>
          </div>
          ${!persistent ? '<button type="button" class="btn-close" aria-label="Close"></button>' : ''}
        </div>
      `
    });

    if (!persistent) {
      const closeBtn = DOM.query('.btn-close', element);
      DOM.on(closeBtn, 'click', () => this.remove(id));
    }

    return { element, type, persistent };
  }

  getAlertClass(type) {
    const classes = {
      success: 'alert-success',
      error: 'alert-danger',
      warning: 'alert-warning',
      info: 'alert-info'
    };
    return classes[type] || classes.info;
  }

  getIcon(type) {
    const icons = {
      success: 'bi-check-circle',
      error: 'bi-exclamation-circle',
      warning: 'bi-exclamation-triangle',
      info: 'bi-info-circle'
    };
    return icons[type] || icons.info;
  }

  async remove(id) {
    const notification = this.notifications.get(id);
    if (!notification) return;

    // Animate out
    DOM.addClass(notification.element, 'animate-slide-right');
    
    setTimeout(() => {
      if (notification.element.parentNode) {
        notification.element.parentNode.removeChild(notification.element);
      }
      this.notifications.delete(id);
    }, 300);
  }

  generateId() {
    return `notification-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  success(message, title = 'Success') {
    return this.show({ type: 'success', title, message });
  }

  error(message, title = 'Error') {
    return this.show({ type: 'error', title, message, persistent: true });
  }

  warning(message, title = 'Warning') {
    return this.show({ type: 'warning', title, message });
  }

  info(message, title = 'Info') {
    return this.show({ type: 'info', title, message });
  }

  clearAll() {
    this.notifications.forEach((_, id) => this.remove(id));
  }
}

export class LoadingManager {
  constructor() {
    this.activeLoaders = new Set();
    this.overlay = null;
  }

  /**
   * Show loading spinner on element
   * @param {Element|string} target - Target element or selector
   * @param {Object} options - Loading options
   */
  show(target, options = {}) {
    const element = typeof target === 'string' ? DOM.query(target) : target;
    if (!element) return;

    const {
      text = 'Loading...',
      overlay = true,
      size = 'md'
    } = options;

    const loaderId = this.generateId();
    const loader = this.createLoader(loaderId, text, size);
    
    if (overlay) {
      element.style.position = 'relative';
      loader.classList.add('position-absolute', 'top-0', 'start-0', 'w-100', 'h-100');
      loader.style.backgroundColor = 'rgba(255, 255, 255, 0.9)';
      loader.style.backdropFilter = 'blur(2px)';
      loader.style.zIndex = '10';
    }

    element.appendChild(loader);
    this.activeLoaders.add({ element, loader, loaderId });
    
    Animation.fadeIn(loader);
    
    return loaderId;
  }

  createLoader(id, text, size) {
    const sizeClass = size === 'sm' ? 'spinner-border-sm' : '';
    
    return DOM.create('div', {
      className: 'd-flex flex-column justify-content-center align-items-center p-4',
      attributes: { 'data-loader-id': id },
      innerHTML: `
        <div class="spinner-border text-primary ${sizeClass}" role="status">
          <span class="visually-hidden">Loading...</span>
        </div>
        <div class="mt-2 text-muted small">${text}</div>
      `
    });
  }

  /**
   * Hide loading spinner
   * @param {string} loaderId - Loader ID
   */
  hide(loaderId) {
    const loader = Array.from(this.activeLoaders).find(l => l.loaderId === loaderId);
    if (!loader) return;

    Animation.animate(loader.loader, 'animate-fade-out', 300).then(() => {
      if (loader.loader.parentNode) {
        loader.loader.parentNode.removeChild(loader.loader);
      }
      this.activeLoaders.delete(loader);
    });
  }

  /**
   * Show global loading overlay
   */
  showGlobal(text = 'Loading...') {
    if (this.overlay) return;

    this.overlay = DOM.create('div', {
      className: 'position-fixed top-0 start-0 w-100 h-100 d-flex justify-content-center align-items-center',
      attributes: { style: 'z-index: 9999; background-color: rgba(0, 0, 0, 0.5); backdrop-filter: blur(3px);' },
      innerHTML: `
        <div class="bg-white rounded-4 p-4 shadow-lg text-center">
          <div class="spinner-border text-primary mb-3" role="status">
            <span class="visually-hidden">Loading...</span>
          </div>
          <div class="text-muted">${text}</div>
        </div>
      `
    });

    document.body.appendChild(this.overlay);
    Animation.fadeIn(this.overlay);
  }

  /**
   * Hide global loading overlay
   */
  hideGlobal() {
    if (!this.overlay) return;

    Animation.animate(this.overlay, 'animate-fade-out', 300).then(() => {
      if (this.overlay.parentNode) {
        this.overlay.parentNode.removeChild(this.overlay);
      }
      this.overlay = null;
    });
  }

  generateId() {
    return `loader-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
}

export class FormManager {
  constructor(form) {
    this.form = typeof form === 'string' ? DOM.query(form) : form;
    this.validators = new Map();
    this.init();
  }

  init() {
    if (!this.form) return;

    this.bindSubmitHandler();
    this.bindInputHandlers();
  }

  bindSubmitHandler() {
    DOM.on(this.form, 'submit', async (e) => {
      e.preventDefault();
      
      if (await this.validate()) {
        this.onSubmit(this.getFormData());
      }
    });
  }

  bindInputHandlers() {
    const inputs = DOM.queryAll('input, select, textarea', this.form);
    
    inputs.forEach(input => {
      DOM.on(input, 'blur', () => this.validateField(input));
      DOM.on(input, 'input', () => this.clearFieldError(input));
    });
  }

  async validate() {
    const inputs = DOM.queryAll('[data-validate]', this.form);
    let isValid = true;

    for (const input of inputs) {
      if (!await this.validateField(input)) {
        isValid = false;
      }
    }

    return isValid;
  }

  async validateField(input) {
    const rules = input.dataset.validate ? input.dataset.validate.split('|') : [];
    const value = input.value.trim();
    
    this.clearFieldError(input);

    for (const rule of rules) {
      const [ruleName, ...params] = rule.split(':');
      const validator = this.getValidator(ruleName);
      
      if (validator && !validator(value, ...params)) {
        this.showFieldError(input, this.getErrorMessage(ruleName, params));
        return false;
      }
    }

    this.showFieldSuccess(input);
    return true;
  }

  getValidator(ruleName) {
    const validators = {
      required: (value) => value !== '',
      email: (value) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value),
      min: (value, min) => value.length >= parseInt(min),
      max: (value, max) => value.length <= parseInt(max),
      numeric: (value) => /^\d+$/.test(value)
    };
    
    return validators[ruleName];
  }

  getErrorMessage(ruleName, params) {
    const messages = {
      required: 'This field is required',
      email: 'Please enter a valid email address',
      min: `Minimum ${params[0]} characters required`,
      max: `Maximum ${params[0]} characters allowed`,
      numeric: 'Please enter numbers only'
    };
    
    return messages[ruleName] || 'Invalid input';
  }

  showFieldError(input, message) {
    DOM.addClass(input, 'is-invalid');
    DOM.removeClass(input, 'is-valid');
    
    let feedback = input.parentNode.querySelector('.invalid-feedback');
    if (!feedback) {
      feedback = DOM.create('div', {
        className: 'invalid-feedback',
        textContent: message
      });
      input.parentNode.appendChild(feedback);
    } else {
      feedback.textContent = message;
    }
  }

  showFieldSuccess(input) {
    DOM.addClass(input, 'is-valid');
    DOM.removeClass(input, 'is-invalid');
  }

  clearFieldError(input) {
    DOM.removeClass(input, 'is-invalid', 'is-valid');
    
    const feedback = input.parentNode.querySelector('.invalid-feedback');
    if (feedback) {
      feedback.remove();
    }
  }

  getFormData() {
    const formData = new FormData(this.form);
    const data = {};
    
    for (const [key, value] of formData.entries()) {
      data[key] = value;
    }
    
    return data;
  }

  onSubmit(data) {
    // Override this method in subclasses
    console.log('Form submitted:', data);
  }

  reset() {
    this.form.reset();
    const inputs = DOM.queryAll('input, select, textarea', this.form);
    inputs.forEach(input => this.clearFieldError(input));
  }
}

export class ModalManager {
  constructor() {
    this.activeModals = new Map();
  }

  /**
   * Show modal
   * @param {Object} options - Modal options
   */
  show(options = {}) {
    const {
      title = '',
      content = '',
      size = 'md',
      backdrop = true,
      keyboard = true,
      footer = null
    } = options;

    const id = this.generateId();
    const modal = this.createModal(id, title, content, size, footer);
    
    document.body.appendChild(modal);
    this.activeModals.set(id, modal);
    
    // Show modal
    const bsModal = new bootstrap.Modal(modal, {
      backdrop,
      keyboard
    });
    
    bsModal.show();
    
    // Cleanup on hide
    DOM.on(modal, 'hidden.bs.modal', () => {
      modal.remove();
      this.activeModals.delete(id);
    });
    
    return { id, modal, bsModal };
  }

  createModal(id, title, content, size, footer) {
    const sizeClass = size !== 'md' ? `modal-${size}` : '';
    
    return DOM.create('div', {
      className: 'modal fade',
      attributes: {
        id,
        tabindex: '-1',
        'aria-labelledby': `${id}-label`,
        'aria-hidden': 'true'
      },
      innerHTML: `
        <div class="modal-dialog ${sizeClass}">
          <div class="modal-content">
            <div class="modal-header">
              <h5 class="modal-title" id="${id}-label">${title}</h5>
              <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
              ${content}
            </div>
            ${footer ? `<div class="modal-footer">${footer}</div>` : ''}
          </div>
        </div>
      `
    });
  }

  generateId() {
    return `modal-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  confirm(message, title = 'Confirm') {
    return new Promise((resolve) => {
      const footer = `
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
        <button type="button" class="btn btn-primary confirm-btn">Confirm</button>
      `;
      
      const { modal } = this.show({
        title,
        content: `<p>${message}</p>`,
        footer
      });
      
      const confirmBtn = DOM.query('.confirm-btn', modal);
      DOM.on(confirmBtn, 'click', () => {
        bootstrap.Modal.getInstance(modal).hide();
        resolve(true);
      });
      
      DOM.on(modal, 'hidden.bs.modal', () => {
        resolve(false);
      });
    });
  }
}

// Create global UI manager instances
export const themeManager = new ThemeManager();
export const notificationManager = new NotificationManager();
export const loadingManager = new LoadingManager();
export const modalManager = new ModalManager();

export default {
  ThemeManager,
  NotificationManager,
  LoadingManager,
  FormManager,
  ModalManager,
  themeManager,
  notificationManager,
  loadingManager,
  modalManager
};