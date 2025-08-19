/**
 * Real-time Updates and AJAX Interactivity
 * Modern WebSocket and SSE implementations
 */

import { DOM, HTTP, eventBus } from './utils.js';
import { notificationManager, loadingManager } from './ui.js';

export class RealtimeManager {
  constructor() {
    this.websocket = null;
    this.eventSource = null;
    this.isConnected = false;
    this.reconnectAttempts = 0;
    this.maxReconnectAttempts = 5;
    this.reconnectDelay = 1000;
    this.heartbeatInterval = null;
    this.heartbeatTimeout = 30000; // 30 seconds
    this.connectionMode = null; // 'websocket', 'sse', 'polling', 'disabled'
    this.initialConnectionAttempted = false;
    
    this.init();
  }

  async init() {
    if (this.initialConnectionAttempted) {
      return; // Prevent multiple initialization attempts
    }
    
    this.initialConnectionAttempted = true;
    
    // For development/testing - if running on localhost without real-time server
    // skip connection attempts and go straight to disabled mode
    if (this.isLocalDevelopment() && !this.hasRealtimeSupport()) {
      console.log('Development mode detected - real-time features disabled');
      this.connectionMode = 'disabled';
      eventBus.emit('realtime:unavailable', { message: 'Development mode - real-time features disabled' });
      return;
    }
    
    // Try WebSocket first, fallback to Server-Sent Events
    if (this.supportsWebSocket()) {
      await this.initWebSocket();
    } else if (this.supportsSSE()) {
      this.initServerSentEvents();
    } else {
      // Fallback to polling
      this.initPolling();
    }
  }

  isLocalDevelopment() {
    return window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
  }

  hasRealtimeSupport() {
    // Check if there's any indication that real-time features are supported
    // This could be a meta tag, config variable, etc.
    const metaTag = document.querySelector('meta[name="realtime-support"]');
    return metaTag && metaTag.content === 'true';
  }

  supportsWebSocket() {
    return 'WebSocket' in window;
  }

  supportsSSE() {
    return 'EventSource' in window;
  }

  async initWebSocket() {
    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws`;
      
      // Set a timeout for connection attempts
      const connectionTimeout = setTimeout(() => {
        if (this.websocket && this.websocket.readyState === WebSocket.CONNECTING) {
          console.log('WebSocket connection timeout, falling back to SSE/polling');
          this.websocket.close();
          this.fallbackToAlternative();
        }
      }, 3000); // 3 second timeout
      
      this.websocket = new WebSocket(wsUrl);
      
      this.websocket.onopen = () => {
        clearTimeout(connectionTimeout);
        this.isConnected = true;
        this.reconnectAttempts = 0;
        this.connectionMode = 'websocket';
        console.log('WebSocket connected');
        eventBus.emit('realtime:connected', { type: 'websocket' });
        this.startHeartbeat();
      };

      this.websocket.onmessage = (event) => {
        this.handleMessage(JSON.parse(event.data));
      };

      this.websocket.onclose = (event) => {
        clearTimeout(connectionTimeout);
        this.isConnected = false;
        this.stopHeartbeat();
        
        // Only log if it's not an initial connection failure
        if (this.reconnectAttempts > 0) {
          console.log('WebSocket disconnected:', event.code, event.reason);
        }
        
        eventBus.emit('realtime:disconnected', { type: 'websocket' });
        
        if (!event.wasClean && this.reconnectAttempts < this.maxReconnectAttempts && this.connectionMode === 'websocket') {
          this.scheduleReconnect();
        } else if (this.reconnectAttempts === 0) {
          // Initial connection failed, try fallback
          this.connectionMode = 'websocket-failed';
          this.fallbackToAlternative();
        }
      };

      this.websocket.onerror = (error) => {
        clearTimeout(connectionTimeout);
        
        // Only log detailed errors in debug mode
        if (window.MoneyTracker?.app?.debug) {
          console.error('WebSocket error:', error);
        } else {
          console.log('WebSocket not available, using fallback connection method');
        }
        
        eventBus.emit('realtime:error', { type: 'websocket', error });
        
        // If this is the first connection attempt, try fallback immediately
        if (this.reconnectAttempts === 0) {
          this.connectionMode = 'websocket-failed';
          this.fallbackToAlternative();
        }
      };

    } catch (error) {
      console.log('WebSocket not supported, using fallback connection method');
      this.fallbackToAlternative();
    }
  }

  fallbackToAlternative() {
    // Only attempt fallback if we haven't already established a connection mode
    if (this.connectionMode) {
      return; // Already have a working connection mode
    }
    
    // Try Server-Sent Events first
    if (this.supportsSSE() && this.connectionMode !== 'sse-failed') {
      console.log('Attempting Server-Sent Events connection...');
      this.connectionMode = 'sse-attempt';
      this.initServerSentEvents();
    } else {
      // Fall back to polling
      console.log('Falling back to polling for updates...');
      this.connectionMode = 'polling';
      this.initPolling();
    }
  }

  initServerSentEvents() {
    try {
      this.eventSource = new EventSource('/events');
      
      this.eventSource.onopen = () => {
        this.isConnected = true;
        this.reconnectAttempts = 0;
        this.connectionMode = 'sse';
        console.log('Server-Sent Events connected');
        eventBus.emit('realtime:connected', { type: 'sse' });
      };

      this.eventSource.onmessage = (event) => {
        this.handleMessage(JSON.parse(event.data));
      };

      this.eventSource.onerror = (error) => {
        this.isConnected = false;
        
        // Only log detailed errors in debug mode
        if (window.MoneyTracker?.app?.debug) {
          console.error('SSE error:', error);
        } else {
          console.log('Server-Sent Events not available, using polling fallback');
        }
        
        eventBus.emit('realtime:error', { type: 'sse', error });
        
        if (this.reconnectAttempts < this.maxReconnectAttempts && this.connectionMode === 'sse') {
          this.scheduleReconnect();
        } else if (this.reconnectAttempts === 0) {
          // Initial SSE connection failed, fallback to polling
          this.connectionMode = 'sse-failed';
          this.initPolling();
        }
      };

    } catch (error) {
      console.log('Server-Sent Events not supported, using polling fallback');
      // Fallback to polling
      this.initPolling();
    }
  }

  initPolling() {
    console.log('Real-time features disabled - no WebSocket or SSE support available');
    
    // Optional: Try polling for updates if the endpoint exists
    // First test if the endpoint is available
    HTTP.get('/api/updates')
      .then(() => {
        console.log('Polling enabled for background updates');
        // Poll every 30 seconds
        setInterval(async () => {
          try {
            const updates = await HTTP.get('/api/updates');
            if (updates && updates.length > 0) {
              updates.forEach(update => this.handleMessage(update));
            }
          } catch (error) {
            // Silently fail - polling is optional
            if (window.MoneyTracker?.app?.debug) {
              console.error('Polling error:', error);
            }
          }
        }, 30000);
        
        eventBus.emit('realtime:connected', { type: 'polling' });
      })
      .catch(() => {
        // No polling endpoint available - that's okay
        console.log('No polling endpoint available - real-time features disabled');
        eventBus.emit('realtime:unavailable', { message: 'Real-time features not supported' });
      });
  }

  handleMessage(message) {
    const { type, data, timestamp } = message;

    switch (type) {
      case 'account_sync_status':
        this.handleAccountSyncStatus(data);
        break;
        
      case 'transaction_update':
        this.handleTransactionUpdate(data);
        break;
        
      case 'balance_update':
        this.handleBalanceUpdate(data);
        break;
        
      case 'notification':
        this.handleNotification(data);
        break;
        
      case 'system_update':
        this.handleSystemUpdate(data);
        break;
        
      default:
        console.log('Unknown message type:', type, data);
    }

    eventBus.emit('realtime:message', { type, data, timestamp });
  }

  handleAccountSyncStatus(data) {
    const { account_number, status } = data;
    const badge = DOM.query(`[data-account-number="${account_number}"].account-sync-badge`);
    
    if (badge) {
      if (status === 'pending' || status === 'running') {
        DOM.removeClass(badge, 'd-none');
        const icon = DOM.query('i', badge);
        if (icon) {
          DOM.addClass(icon, 'animate-spin');
        }
      } else {
        DOM.addClass(badge, 'd-none');
        const icon = DOM.query('i', badge);
        if (icon) {
          DOM.removeClass(icon, 'animate-spin');
        }
        
        if (status === 'completed') {
          notificationManager.success(`Account sync completed for •••• ${account_number.slice(-4)}`);
          // Refresh dashboard data
          eventBus.emit('dashboard:refresh-data');
        } else if (status === 'failed') {
          notificationManager.error(`Account sync failed for •••• ${account_number.slice(-4)}`);
        }
      }
    }
  }

  handleTransactionUpdate(data) {
    const { count, account_number } = data;
    
    if (count > 0) {
      notificationManager.info(
        `${count} new transaction${count > 1 ? 's' : ''} added to account •••• ${account_number.slice(-4)}`,
        'Transactions Updated'
      );
      
      // Update transaction tables if visible
      eventBus.emit('transactions:refresh');
      
      // Update dashboard charts
      eventBus.emit('dashboard:refresh-charts');
    }
  }

  handleBalanceUpdate(data) {
    const { account_number, old_balance, new_balance, currency } = data;
    
    // Update balance displays
    const balanceElements = DOM.queryAll(`[data-account-number="${account_number}"] .balance-amount`);
    balanceElements.forEach(element => {
      element.textContent = new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: currency || 'USD'
      }).format(new_balance);
      
      // Add animation to highlight the change
      DOM.addClass(element, 'animate-pulse');
      setTimeout(() => {
        DOM.removeClass(element, 'animate-pulse');
      }, 2000);
    });

    const difference = new_balance - old_balance;
    const changeType = difference > 0 ? 'increased' : 'decreased';
    const changeAmount = Math.abs(difference);
    
    notificationManager.info(
      `Account balance ${changeType} by ${new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency: currency || 'USD'
      }).format(changeAmount)}`,
      'Balance Updated'
    );
  }

  handleNotification(data) {
    const { title, message, type, persistent } = data;
    
    notificationManager.show({
      type: type || 'info',
      title,
      message,
      persistent
    });
  }

  handleSystemUpdate(data) {
    const { message, action } = data;
    
    if (action === 'reload') {
      notificationManager.warning(
        'The application has been updated. Please refresh your browser.',
        'System Update',
        { persistent: true }
      );
    } else if (action === 'maintenance') {
      notificationManager.warning(
        message || 'System maintenance in progress.',
        'Maintenance Mode'
      );
    }
  }

  startHeartbeat() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }

    this.heartbeatInterval = setInterval(() => {
      if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
        this.websocket.send(JSON.stringify({ type: 'ping' }));
      }
    }, this.heartbeatTimeout);
  }

  stopHeartbeat() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  scheduleReconnect() {
    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
    
    console.log(`Scheduling reconnect attempt ${this.reconnectAttempts} in ${delay}ms`);
    
    setTimeout(() => {
      // Only reconnect using the same method that was working
      if (this.connectionMode === 'websocket') {
        this.initWebSocket();
      } else if (this.connectionMode === 'sse') {
        this.initServerSentEvents();
      }
      // Don't try to reconnect for polling or failed modes
    }, delay);
  }

  send(message) {
    if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
      this.websocket.send(JSON.stringify(message));
      return true;
    }
    return false;
  }

  disconnect() {
    this.stopHeartbeat();
    
    if (this.websocket) {
      this.websocket.close();
      this.websocket = null;
    }
    
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
    
    this.isConnected = false;
  }
}

export class AjaxFormHandler {
  constructor() {
    this.init();
  }

  init() {
    this.bindFormSubmissions();
    this.bindConfirmationForms();
    this.bindFileUploads();
  }

  bindFormSubmissions() {
    DOM.on(document, 'submit', async (e) => {
      const form = e.target;
      
      // Skip if form doesn't have ajax class or is already being processed
      if (!DOM.hasClass(form, 'ajax-form') || form.dataset.processing === 'true') {
        return;
      }

      e.preventDefault();
      form.dataset.processing = 'true';

      const submitBtn = DOM.query('button[type="submit"]', form);
      const originalText = submitBtn ? submitBtn.innerHTML : '';
      
      try {
        // Show loading state
        if (submitBtn) {
          submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Submitting...';
          submitBtn.disabled = true;
        }

        const formData = new FormData(form);
        const response = await HTTP.post(form.action, formData);

        if (response.success) {
          this.handleSuccessResponse(form, response);
        } else {
          this.handleErrorResponse(form, response);
        }

      } catch (error) {
        console.error('Form submission error:', error);
        this.handleErrorResponse(form, { 
          message: 'An error occurred while submitting the form.' 
        });
      } finally {
        // Reset form state
        form.dataset.processing = 'false';
        if (submitBtn) {
          submitBtn.innerHTML = originalText;
          submitBtn.disabled = false;
        }
      }
    });
  }

  bindConfirmationForms() {
    DOM.on(document, 'submit', async (e) => {
      const form = e.target;
      
      if (!form.dataset.confirm) return;

      e.preventDefault();
      
      const message = form.dataset.confirm;
      const confirmed = await this.showConfirmDialog(message);
      
      if (confirmed) {
        // Remove confirm attribute to avoid double confirmation
        delete form.dataset.confirm;
        form.submit();
      }
    });
  }

  bindFileUploads() {
    DOM.on(document, 'change', (e) => {
      const input = e.target;
      
      if (input.type !== 'file' || !DOM.hasClass(input, 'ajax-upload')) return;

      this.handleFileUpload(input);
    });
  }

  async handleFileUpload(input) {
    const files = Array.from(input.files);
    if (files.length === 0) return;

    const progressContainer = this.createProgressContainer(input);
    
    try {
      for (const file of files) {
        await this.uploadFile(file, input, progressContainer);
      }
    } catch (error) {
      console.error('File upload error:', error);
      notificationManager.error('File upload failed', 'Upload Error');
    }
  }

  async uploadFile(file, input, progressContainer) {
    const formData = new FormData();
    formData.append('file', file);
    formData.append('csrf_token', HTTP.getCSRFToken());

    const progressBar = this.createProgressBar(file.name, progressContainer);
    
    try {
      const response = await this.uploadWithProgress(
        input.dataset.uploadUrl || '/api/upload',
        formData,
        (progress) => {
          this.updateProgressBar(progressBar, progress);
        }
      );

      if (response.success) {
        this.updateProgressBar(progressBar, 100);
        DOM.addClass(progressBar.container, 'upload-success');
        
        // Emit file uploaded event
        eventBus.emit('file:uploaded', {
          file: file,
          response: response,
          input: input
        });
        
        notificationManager.success(`${file.name} uploaded successfully`);
      } else {
        DOM.addClass(progressBar.container, 'upload-error');
        notificationManager.error(response.message || 'Upload failed');
      }

    } catch (error) {
      DOM.addClass(progressBar.container, 'upload-error');
      throw error;
    }
  }

  createProgressContainer(input) {
    let container = DOM.query('.upload-progress', input.parentNode);
    
    if (!container) {
      container = DOM.create('div', {
        className: 'upload-progress mt-3'
      });
      input.parentNode.appendChild(container);
    }
    
    return container;
  }

  createProgressBar(filename, container) {
    const progressContainer = DOM.create('div', {
      className: 'progress-item mb-2 p-2 border rounded',
      innerHTML: `
        <div class="d-flex justify-content-between align-items-center mb-1">
          <span class="filename small">${filename}</span>
          <span class="percentage small text-muted">0%</span>
        </div>
        <div class="progress" style="height: 4px;">
          <div class="progress-bar" role="progressbar" style="width: 0%"></div>
        </div>
      `
    });

    container.appendChild(progressContainer);

    return {
      container: progressContainer,
      bar: DOM.query('.progress-bar', progressContainer),
      percentage: DOM.query('.percentage', progressContainer)
    };
  }

  updateProgressBar(progressBar, progress) {
    progressBar.bar.style.width = `${progress}%`;
    progressBar.percentage.textContent = `${Math.round(progress)}%`;
  }

  async uploadWithProgress(url, formData, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();

      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
          const progress = (e.loaded / e.total) * 100;
          onProgress(progress);
        }
      });

      xhr.addEventListener('load', () => {
        if (xhr.status >= 200 && xhr.status < 300) {
          try {
            const response = JSON.parse(xhr.responseText);
            resolve(response);
          } catch (error) {
            resolve({ success: true, data: xhr.responseText });
          }
        } else {
          reject(new Error(`HTTP ${xhr.status}: ${xhr.statusText}`));
        }
      });

      xhr.addEventListener('error', () => {
        reject(new Error('Network error'));
      });

      xhr.open('POST', url);
      xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
      xhr.send(formData);
    });
  }

  handleSuccessResponse(form, response) {
    const { message, redirect, reload, reset_form } = response;

    if (message) {
      notificationManager.success(message);
    }

    if (reset_form) {
      form.reset();
      // Clear validation classes
      const inputs = DOM.queryAll('input, select, textarea', form);
      inputs.forEach(input => {
        DOM.removeClass(input, 'is-valid', 'is-invalid');
      });
    }

    if (redirect) {
      setTimeout(() => {
        window.location.href = redirect;
      }, 1000);
    } else if (reload) {
      setTimeout(() => {
        window.location.reload();
      }, 1000);
    }

    eventBus.emit('form:success', { form, response });
  }

  handleErrorResponse(form, response) {
    const { message, errors } = response;

    if (message) {
      notificationManager.error(message);
    }

    if (errors) {
      this.displayFieldErrors(form, errors);
    }

    eventBus.emit('form:error', { form, response });
  }

  displayFieldErrors(form, errors) {
    // Clear existing errors
    const existingErrors = DOM.queryAll('.invalid-feedback', form);
    existingErrors.forEach(error => error.remove());

    const inputs = DOM.queryAll('input, select, textarea', form);
    inputs.forEach(input => {
      DOM.removeClass(input, 'is-invalid');
    });

    // Display new errors
    Object.entries(errors).forEach(([fieldName, fieldErrors]) => {
      const field = DOM.query(`[name="${fieldName}"]`, form);
      if (field) {
        DOM.addClass(field, 'is-invalid');
        
        const errorDiv = DOM.create('div', {
          className: 'invalid-feedback',
          textContent: Array.isArray(fieldErrors) ? fieldErrors[0] : fieldErrors
        });
        
        field.parentNode.appendChild(errorDiv);
      }
    });
  }

  async showConfirmDialog(message) {
    return new Promise((resolve) => {
      const modal = DOM.create('div', {
        className: 'modal fade',
        innerHTML: `
          <div class="modal-dialog">
            <div class="modal-content">
              <div class="modal-header">
                <h5 class="modal-title">Confirm Action</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
              </div>
              <div class="modal-body">
                <p>${message}</p>
              </div>
              <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                <button type="button" class="btn btn-danger confirm-btn">Confirm</button>
              </div>
            </div>
          </div>
        `
      });

      document.body.appendChild(modal);
      
      const bsModal = new bootstrap.Modal(modal);
      bsModal.show();

      const confirmBtn = DOM.query('.confirm-btn', modal);
      DOM.on(confirmBtn, 'click', () => {
        bsModal.hide();
        resolve(true);
      });

      DOM.on(modal, 'hidden.bs.modal', () => {
        modal.remove();
        resolve(false);
      });
    });
  }
}

export class DataTableManager {
  constructor() {
    this.tables = new Map();
    this.init();
  }

  init() {
    this.initializeExistingTables();
    this.bindTableEvents();
  }

  initializeExistingTables() {
    const tables = DOM.queryAll('.data-table');
    
    tables.forEach(table => {
      this.enhanceTable(table);
    });
  }

  enhanceTable(table) {
    if (!window.$ || !$.fn.DataTable) return;

    const config = this.getTableConfig(table);
    const dataTable = $(table).DataTable(config);
    
    this.tables.set(table, dataTable);
    
    // Add real-time update capability
    if (table.dataset.realtimeUrl) {
      this.enableRealtimeUpdates(table, dataTable);
    }
  }

  getTableConfig(table) {
    const defaultConfig = {
      responsive: true,
      pageLength: 25,
      lengthMenu: [[10, 25, 50, 100], [10, 25, 50, 100]],
      order: [[0, 'desc']],
      processing: true,
      language: {
        processing: '<div class="spinner-border text-primary"></div>',
        search: 'Search:',
        lengthMenu: 'Show _MENU_ entries',
        info: 'Showing _START_ to _END_ of _TOTAL_ entries',
        paginate: {
          first: 'First',
          last: 'Last',
          next: 'Next',
          previous: 'Previous'
        }
      },
      dom: '<"row"<"col-sm-12 col-md-6"l><"col-sm-12 col-md-6"f>>' +
           '<"row"<"col-sm-12"tr>>' +
           '<"row"<"col-sm-12 col-md-5"i><"col-sm-12 col-md-7"p>>'
    };

    // Merge with custom config from data attributes
    const customConfig = table.dataset.tableConfig ? 
      JSON.parse(table.dataset.tableConfig) : {};

    return { ...defaultConfig, ...customConfig };
  }

  enableRealtimeUpdates(table, dataTable) {
    const updateUrl = table.dataset.realtimeUrl;
    const updateInterval = parseInt(table.dataset.updateInterval) || 30000;

    setInterval(async () => {
      try {
        const response = await HTTP.get(updateUrl);
        
        if (response.success && response.data) {
          dataTable.clear();
          dataTable.rows.add(response.data);
          dataTable.draw();
        }
      } catch (error) {
        console.error('Table update error:', error);
      }
    }, updateInterval);
  }

  bindTableEvents() {
    // Handle table row actions
    DOM.on(document, 'click', async (e) => {
      const button = e.target.closest('[data-table-action]');
      if (!button) return;

      e.preventDefault();
      
      const action = button.dataset.tableAction;
      const row = button.closest('tr');
      const table = button.closest('table');
      
      await this.handleTableAction(action, button, row, table);
    });
  }

  async handleTableAction(action, button, row, table) {
    const loaderId = loadingManager.show(button, { size: 'sm' });

    try {
      switch (action) {
        case 'delete':
          await this.handleDeleteAction(button, row, table);
          break;
          
        case 'edit':
          await this.handleEditAction(button, row, table);
          break;
          
        case 'view':
          await this.handleViewAction(button, row, table);
          break;
          
        default:
          await this.handleCustomAction(action, button, row, table);
      }
    } catch (error) {
      console.error('Table action error:', error);
      notificationManager.error('Action failed', 'Error');
    } finally {
      loadingManager.hide(loaderId);
    }
  }

  async handleDeleteAction(button, row, table) {
    const confirmed = await this.showConfirmDialog(
      'Are you sure you want to delete this item?'
    );
    
    if (!confirmed) return;

    const deleteUrl = button.dataset.deleteUrl;
    if (!deleteUrl) return;

    const response = await HTTP.delete(deleteUrl);
    
    if (response.success) {
      // Remove row with animation
      DOM.addClass(row, 'animate-fade-out');
      
      setTimeout(() => {
        const dataTable = this.tables.get(table);
        if (dataTable) {
          dataTable.row(row).remove().draw();
        } else {
          row.remove();
        }
      }, 300);
      
      notificationManager.success('Item deleted successfully');
    } else {
      notificationManager.error(response.message || 'Delete failed');
    }
  }

  async handleEditAction(button, row, table) {
    const editUrl = button.dataset.editUrl;
    if (editUrl) {
      window.location.href = editUrl;
    }
  }

  async handleViewAction(button, row, table) {
    const viewUrl = button.dataset.viewUrl;
    if (viewUrl) {
      window.location.href = viewUrl;
    }
  }

  async handleCustomAction(action, button, row, table) {
    const actionUrl = button.dataset.actionUrl;
    if (!actionUrl) return;

    const response = await HTTP.post(actionUrl, {
      action: action,
      csrf_token: HTTP.getCSRFToken()
    });

    if (response.success) {
      notificationManager.success(response.message || 'Action completed');
      
      // Refresh table data
      const dataTable = this.tables.get(table);
      if (dataTable) {
        dataTable.ajax.reload();
      }
    } else {
      notificationManager.error(response.message || 'Action failed');
    }
  }

  refreshTable(tableElement) {
    const dataTable = this.tables.get(tableElement);
    if (dataTable && dataTable.ajax) {
      dataTable.ajax.reload();
    }
  }

  addRow(tableElement, rowData) {
    const dataTable = this.tables.get(tableElement);
    if (dataTable) {
      dataTable.row.add(rowData).draw();
    }
  }

  removeRow(tableElement, rowElement) {
    const dataTable = this.tables.get(tableElement);
    if (dataTable) {
      dataTable.row(rowElement).remove().draw();
    }
  }
}

// Initialize managers
export const realtimeManager = new RealtimeManager();
export const ajaxFormHandler = new AjaxFormHandler();
export const dataTableManager = new DataTableManager();

// Event listeners for page visibility
DOM.on(document, 'visibilitychange', () => {
  if (document.hidden) {
    // Page is hidden, reduce activity
    eventBus.emit('page:hidden');
  } else {
    // Page is visible, resume activity
    eventBus.emit('page:visible');
  }
});

export default {
  RealtimeManager,
  AjaxFormHandler,
  DataTableManager,
  realtimeManager,
  ajaxFormHandler,
  dataTableManager
};