/**
 * Modern JavaScript Utilities
 * ES6+ utility functions and helpers
 */

export class DOM {
  /**
   * Query selector with null safety
   * @param {string} selector - CSS selector
   * @param {Element} context - Optional context element
   * @returns {Element|null}
   */
  static query(selector, context = document) {
    return context.querySelector(selector);
  }

  /**
   * Query all elements with null safety
   * @param {string} selector - CSS selector
   * @param {Element} context - Optional context element
   * @returns {NodeList}
   */
  static queryAll(selector, context = document) {
    return context.querySelectorAll(selector);
  }

  /**
   * Create element with attributes and content
   * @param {string} tag - Element tag name
   * @param {Object} options - Element options
   * @returns {Element}
   */
  static create(tag, options = {}) {
    const element = document.createElement(tag);
    
    if (options.className) {
      element.className = options.className;
    }
    
    if (options.attributes) {
      Object.entries(options.attributes).forEach(([key, value]) => {
        element.setAttribute(key, value);
      });
    }
    
    if (options.innerHTML) {
      element.innerHTML = options.innerHTML;
    }
    
    if (options.textContent) {
      element.textContent = options.textContent;
    }
    
    return element;
  }

  /**
   * Add event listener with cleanup
   * @param {Element} element - Target element
   * @param {string} event - Event type
   * @param {Function} handler - Event handler
   * @param {Object} options - Event options
   * @returns {Function} Cleanup function
   */
  static on(element, event, handler, options = {}) {
    element.addEventListener(event, handler, options);
    return () => element.removeEventListener(event, handler, options);
  }

  /**
   * Toggle class on element
   * @param {Element} element - Target element
   * @param {string} className - Class name
   * @param {boolean} force - Force add/remove
   */
  static toggleClass(element, className, force) {
    element.classList.toggle(className, force);
  }

  /**
   * Add classes to element
   * @param {Element} element - Target element
   * @param {...string} classes - Class names
   */
  static addClass(element, ...classes) {
    element.classList.add(...classes);
  }

  /**
   * Remove classes from element
   * @param {Element} element - Target element
   * @param {...string} classes - Class names
   */
  static removeClass(element, ...classes) {
    element.classList.remove(...classes);
  }

  /**
   * Check if element has class
   * @param {Element} element - Target element
   * @param {string} className - Class name
   * @returns {boolean}
   */
  static hasClass(element, className) {
    return element.classList.contains(className);
  }
}

export class Storage {
  /**
   * Get item from localStorage with JSON parsing
   * @param {string} key - Storage key
   * @param {*} defaultValue - Default value if key doesn't exist
   * @returns {*}
   */
  static get(key, defaultValue = null) {
    try {
      const item = localStorage.getItem(key);
      return item ? JSON.parse(item) : defaultValue;
    } catch (error) {
      console.warn(`Error parsing localStorage item "${key}":`, error);
      return defaultValue;
    }
  }

  /**
   * Set item in localStorage with JSON stringification
   * @param {string} key - Storage key
   * @param {*} value - Value to store
   */
  static set(key, value) {
    try {
      localStorage.setItem(key, JSON.stringify(value));
    } catch (error) {
      console.warn(`Error setting localStorage item "${key}":`, error);
    }
  }

  /**
   * Remove item from localStorage
   * @param {string} key - Storage key
   */
  static remove(key) {
    localStorage.removeItem(key);
  }

  /**
   * Clear all localStorage
   */
  static clear() {
    localStorage.clear();
  }

  /**
   * Check if key exists in localStorage
   * @param {string} key - Storage key
   * @returns {boolean}
   */
  static has(key) {
    return localStorage.getItem(key) !== null;
  }
}

export class HTTP {
  /**
   * Default fetch options
   */
  static defaults = {
    headers: {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest'
    },
    credentials: 'same-origin'
  };

  /**
   * Get CSRF token from meta tag or form
   * @returns {string}
   */
  static getCSRFToken() {
    const metaToken = DOM.query('meta[name="csrf-token"]');
    if (metaToken) {
      return metaToken.getAttribute('content');
    }
    
    const formToken = DOM.query('input[name="csrf_token"]');
    if (formToken) {
      return formToken.value;
    }
    
    return '';
  }

  /**
   * Enhanced fetch with error handling
   * @param {string} url - Request URL
   * @param {Object} options - Fetch options
   * @returns {Promise}
   */
  static async request(url, options = {}) {
    const config = {
      ...this.defaults,
      ...options,
      headers: {
        ...this.defaults.headers,
        ...options.headers
      }
    };

    // Add CSRF token for non-GET requests
    if (config.method && config.method.toUpperCase() !== 'GET') {
      const csrfToken = this.getCSRFToken();
      if (csrfToken) {
        config.headers['X-CSRFToken'] = csrfToken;
      }
    }

    try {
      const response = await fetch(url, config);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        return await response.json();
      }
      
      return await response.text();
    } catch (error) {
      console.error('Fetch error:', error);
      throw error;
    }
  }

  /**
   * GET request
   * @param {string} url - Request URL
   * @param {Object} options - Fetch options
   * @returns {Promise}
   */
  static get(url, options = {}) {
    return this.request(url, { ...options, method: 'GET' });
  }

  /**
   * POST request
   * @param {string} url - Request URL
   * @param {*} data - Request data
   * @param {Object} options - Fetch options
   * @returns {Promise}
   */
  static post(url, data = null, options = {}) {
    const config = { ...options, method: 'POST' };
    
    if (data) {
      if (data instanceof FormData) {
        config.body = data;
        // Remove Content-Type header for FormData (browser will set it)
        delete config.headers['Content-Type'];
      } else {
        config.body = JSON.stringify(data);
      }
    }
    
    return this.request(url, config);
  }

  /**
   * PUT request
   * @param {string} url - Request URL
   * @param {*} data - Request data
   * @param {Object} options - Fetch options
   * @returns {Promise}
   */
  static put(url, data = null, options = {}) {
    const config = { ...options, method: 'PUT' };
    if (data) {
      config.body = JSON.stringify(data);
    }
    return this.request(url, config);
  }

  /**
   * DELETE request
   * @param {string} url - Request URL
   * @param {Object} options - Fetch options
   * @returns {Promise}
   */
  static delete(url, options = {}) {
    return this.request(url, { ...options, method: 'DELETE' });
  }
}

export class EventBus {
  constructor() {
    this.events = new Map();
  }

  /**
   * Subscribe to event
   * @param {string} event - Event name
   * @param {Function} callback - Event callback
   * @returns {Function} Unsubscribe function
   */
  on(event, callback) {
    if (!this.events.has(event)) {
      this.events.set(event, new Set());
    }
    
    this.events.get(event).add(callback);
    
    return () => this.off(event, callback);
  }

  /**
   * Unsubscribe from event
   * @param {string} event - Event name
   * @param {Function} callback - Event callback
   */
  off(event, callback) {
    if (this.events.has(event)) {
      this.events.get(event).delete(callback);
    }
  }

  /**
   * Emit event
   * @param {string} event - Event name
   * @param {*} data - Event data
   */
  emit(event, data = null) {
    if (this.events.has(event)) {
      this.events.get(event).forEach(callback => {
        try {
          callback(data);
        } catch (error) {
          console.error(`Error in event handler for "${event}":`, error);
        }
      });
    }
  }

  /**
   * Subscribe to event once
   * @param {string} event - Event name
   * @param {Function} callback - Event callback
   */
  once(event, callback) {
    const unsubscribe = this.on(event, (data) => {
      callback(data);
      unsubscribe();
    });
  }

  /**
   * Clear all event listeners
   */
  clear() {
    this.events.clear();
  }
}

export class Debouncer {
  /**
   * Debounce function execution
   * @param {Function} func - Function to debounce
   * @param {number} delay - Delay in milliseconds
   * @returns {Function}
   */
  static debounce(func, delay = 300) {
    let timeoutId;
    return function (...args) {
      clearTimeout(timeoutId);
      timeoutId = setTimeout(() => func.apply(this, args), delay);
    };
  }

  /**
   * Throttle function execution
   * @param {Function} func - Function to throttle
   * @param {number} delay - Delay in milliseconds
   * @returns {Function}
   */
  static throttle(func, delay = 300) {
    let lastCall = 0;
    return function (...args) {
      const now = Date.now();
      if (now - lastCall >= delay) {
        lastCall = now;
        return func.apply(this, args);
      }
    };
  }
}

export class Animation {
  /**
   * Animate element with CSS classes
   * @param {Element} element - Target element
   * @param {string} animationClass - Animation class name
   * @param {number} duration - Animation duration in ms
   * @returns {Promise}
   */
  static animate(element, animationClass, duration = 500) {
    return new Promise((resolve) => {
      DOM.addClass(element, animationClass);
      
      const cleanup = () => {
        DOM.removeClass(element, animationClass);
        element.removeEventListener('animationend', cleanup);
        resolve();
      };
      
      element.addEventListener('animationend', cleanup);
      
      // Fallback timeout
      setTimeout(cleanup, duration);
    });
  }

  /**
   * Fade in element
   * @param {Element} element - Target element
   * @returns {Promise}
   */
  static fadeIn(element) {
    return this.animate(element, 'animate-fade-in');
  }

  /**
   * Slide up element
   * @param {Element} element - Target element
   * @returns {Promise}
   */
  static slideUp(element) {
    return this.animate(element, 'animate-slide-up');
  }

  /**
   * Scale up element
   * @param {Element} element - Target element
   * @returns {Promise}
   */
  static scaleUp(element) {
    return this.animate(element, 'animate-scale-up');
  }
}

export class Validator {
  /**
   * Validation rules
   */
  static rules = {
    required: (value) => value !== null && value !== undefined && value !== '',
    email: (value) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value),
    minLength: (min) => (value) => value.length >= min,
    maxLength: (max) => (value) => value.length <= max,
    numeric: (value) => /^\d+$/.test(value),
    decimal: (value) => /^\d+(\.\d+)?$/.test(value),
    url: (value) => {
      try {
        new URL(value);
        return true;
      } catch {
        return false;
      }
    }
  };

  /**
   * Validate value against rules
   * @param {*} value - Value to validate
   * @param {Array} rules - Array of validation rules
   * @returns {Object} Validation result
   */
  static validate(value, rules = []) {
    const errors = [];
    
    for (const rule of rules) {
      if (typeof rule === 'function') {
        if (!rule(value)) {
          errors.push(_('Validation failed'));
        }
      } else if (typeof rule === 'object') {
        const { validator, message } = rule;
        if (typeof validator === 'function' && !validator(value)) {
          errors.push(message || _('Validation failed'));
        }
      }
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  }
}

// Create global event bus instance
export const eventBus = new EventBus();

// Export utilities for global access
export default {
  DOM,
  Storage,
  HTTP,
  EventBus,
  Debouncer,
  Animation,
  Validator,
  eventBus
};