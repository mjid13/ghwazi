/**
 * Modern Dashboard Module
 * ES6+ Dashboard functionality with real-time updates
 */

import { DOM, HTTP, eventBus, Debouncer } from './utils.js';
import { notificationManager, loadingManager } from './ui.js';

export class DashboardManager {
  constructor() {
    this.chartData = null;
    this.charts = new Map();
    this.updateInterval = null;
    this.isAutoRefreshEnabled = false;
    this.refreshRate = 30000; // 30 seconds
    this.init();
  }

  async init() {
    await this.loadChartData();
    this.initializeCharts();
    this.bindEvents();
    this.startAutoRefresh();
  }

  async loadChartData() {
    try {
      const dataHolder = DOM.query('#chart-data-holder');
      if (dataHolder) {
        const rawData = dataHolder.dataset.json;
        this.chartData = JSON.parse(rawData);
      } else {
        // Fallback: fetch data via API
        this.chartData = await HTTP.get('/api/dashboard/charts');
      }
    } catch (error) {
      console.error('Error loading chart data:', error);
      notificationManager.error('Failed to load dashboard data');
    }
  }

  initializeCharts() {
    if (!this.chartData || !window.Chart) return;

    this.initTrendChart();
    this.initCategoryChart();
    this.initBalanceChart();
    this.initIncomeExpenseChart();
  }

  initTrendChart() {
    const canvas = DOM.query('#trendChart');
    if (!canvas || !this.chartData.trend_data) return;

    const ctx = canvas.getContext('2d');
    const chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: this.chartData.trend_data.labels || [],
        datasets: [{
          label: 'Income',
          data: this.chartData.trend_data.income || [],
          borderColor: 'hsl(142, 70%, 45%)',
          backgroundColor: 'hsla(142, 70%, 45%, 0.1)',
          tension: 0.4,
          fill: true
        }, {
          label: 'Expenses',
          data: this.chartData.trend_data.expenses || [],
          borderColor: 'hsl(5, 85%, 55%)',
          backgroundColor: 'hsla(5, 85%, 55%, 0.1)',
          tension: 0.4,
          fill: true
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        interaction: {
          intersect: false,
          mode: 'index'
        },
        plugins: {
          legend: {
            position: 'top'
          },
          tooltip: {
            backgroundColor: 'rgba(0, 0, 0, 0.8)',
            titleColor: 'white',
            bodyColor: 'white',
            borderColor: 'rgba(255, 255, 255, 0.1)',
            borderWidth: 1
          }
        },
        scales: {
          x: {
            grid: {
              color: 'rgba(0, 0, 0, 0.05)'
            }
          },
          y: {
            grid: {
              color: 'rgba(0, 0, 0, 0.05)'
            },
            ticks: {
              callback: function(value) {
                return new Intl.NumberFormat('en-US', {
                  style: 'currency',
                  currency: 'USD',
                  minimumFractionDigits: 0
                }).format(value);
              }
            }
          }
        }
      }
    });

    this.charts.set('trend', chart);
  }

  initCategoryChart() {
    const canvas = DOM.query('#categoryChart');
    if (!canvas || !this.chartData.category_data) return;

    const ctx = canvas.getContext('2d');
    const chart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: this.chartData.category_data.labels || [],
        datasets: [{
          data: this.chartData.category_data.values || [],
          backgroundColor: [
            'hsl(5, 85%, 55%)',
            'hsl(142, 70%, 45%)',
            'hsl(220, 90%, 55%)',
            'hsl(35, 90%, 55%)',
            'hsl(280, 70%, 55%)',
            'hsl(200, 80%, 55%)',
            'hsl(160, 80%, 50%)',
            'hsl(320, 70%, 55%)'
          ],
          borderWidth: 2,
          borderColor: 'white'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              padding: 20,
              usePointStyle: true
            }
          },
          tooltip: {
            backgroundColor: 'rgba(0, 0, 0, 0.8)',
            titleColor: 'white',
            bodyColor: 'white',
            callbacks: {
              label: function(context) {
                const label = context.label || '';
                const value = context.parsed;
                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                const percentage = ((value / total) * 100).toFixed(1);
                return `${label}: ${percentage}%`;
              }
            }
          }
        }
      }
    });

    this.charts.set('category', chart);
  }

  initBalanceChart() {
    const canvas = DOM.query('#balanceChart');
    if (!canvas || !this.chartData.balance_data) return;

    const ctx = canvas.getContext('2d');
    const chart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: this.chartData.balance_data.labels || [],
        datasets: [{
          label: 'Account Balances',
          data: this.chartData.balance_data.values || [],
          backgroundColor: 'hsl(220, 90%, 55%)',
          borderColor: 'hsl(220, 90%, 45%)',
          borderWidth: 1,
          borderRadius: 6
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: false
          },
          tooltip: {
            backgroundColor: 'rgba(0, 0, 0, 0.8)',
            titleColor: 'white',
            bodyColor: 'white',
            callbacks: {
              label: function(context) {
                return new Intl.NumberFormat('en-US', {
                  style: 'currency',
                  currency: 'USD'
                }).format(context.parsed.y);
              }
            }
          }
        },
        scales: {
          x: {
            grid: {
              display: false
            }
          },
          y: {
            grid: {
              color: 'rgba(0, 0, 0, 0.05)'
            },
            ticks: {
              callback: function(value) {
                return new Intl.NumberFormat('en-US', {
                  style: 'currency',
                  currency: 'USD',
                  minimumFractionDigits: 0
                }).format(value);
              }
            }
          }
        }
      }
    });

    this.charts.set('balance', chart);
  }

  initIncomeExpenseChart() {
    const canvas = DOM.query('#incomeExpenseChart');
    if (!canvas || !this.chartData.income_expense_data) return;

    const ctx = canvas.getContext('2d');
    const chart = new Chart(ctx, {
      type: 'pie',
      data: {
        labels: ['Income', 'Expenses'],
        datasets: [{
          data: [
            this.chartData.income_expense_data.income || 0,
            this.chartData.income_expense_data.expenses || 0
          ],
          backgroundColor: [
            'hsl(142, 70%, 45%)',
            'hsl(5, 85%, 55%)'
          ],
          borderWidth: 2,
          borderColor: 'white'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              padding: 20,
              usePointStyle: true
            }
          },
          tooltip: {
            backgroundColor: 'rgba(0, 0, 0, 0.8)',
            titleColor: 'white',
            bodyColor: 'white',
            callbacks: {
              label: function(context) {
                const value = context.parsed;
                return new Intl.NumberFormat('en-US', {
                  style: 'currency',
                  currency: 'USD'
                }).format(value);
              }
            }
          }
        }
      }
    });

    this.charts.set('incomeExpense', chart);
  }

  bindEvents() {
    this.bindFilterEvents();
    this.bindRefreshButton();
    this.bindAutoCategorizeButton();
    this.bindSyncButton();
  }

  bindFilterEvents() {
    const accountFilter = DOM.query('#chart_account_filter');
    const dateFilter = DOM.query('#chart_date_filter');

    if (accountFilter) {
      DOM.on(accountFilter, 'change', Debouncer.debounce(() => {
        this.updateCharts();
      }, 500));
    }

    if (dateFilter) {
      DOM.on(dateFilter, 'change', Debouncer.debounce(() => {
        this.updateCharts();
      }, 500));
    }
  }

  bindRefreshButton() {
    const refreshButton = DOM.create('button', {
      className: 'btn btn-outline-primary btn-sm ms-2',
      innerHTML: '<i class="bi bi-arrow-clockwise me-1"></i>Refresh',
      attributes: { title: 'Refresh dashboard data' }
    });

    const chartsHeader = DOM.query('.charts-header');
    if (chartsHeader) {
      chartsHeader.appendChild(refreshButton);
      
      DOM.on(refreshButton, 'click', async () => {
        await this.refreshData();
      });
    }
  }

  bindAutoCategorizeButton() {
    const button = DOM.query('.auto-categorize-btn');
    if (!button) return;

    DOM.on(button, 'click', async (e) => {
      e.preventDefault();
      
      const form = button.closest('form');
      if (!form) return;

      const loaderId = loadingManager.show(button, { text: 'Processing...', overlay: false });
      
      try {
        const formData = new FormData(form);
        const response = await HTTP.post(form.action, formData);
        
        if (response.success) {
          notificationManager.success('Auto-categorization completed successfully');
          await this.refreshData();
        } else {
          notificationManager.error(response.message || 'Auto-categorization failed');
        }
      } catch (error) {
        console.error('Auto-categorize error:', error);
        notificationManager.error('Failed to auto-categorize transactions');
      } finally {
        loadingManager.hide(loaderId);
      }
    });
  }

  bindSyncButton() {
    const button = DOM.query('.sync-gmail-form button');
    if (!button) return;

    DOM.on(button, 'click', async (e) => {
      e.preventDefault();
      
      const form = button.closest('form');
      if (!form) return;

      const loaderId = loadingManager.show(button, { text: 'Syncing...', overlay: false });
      
      try {
        const formData = new FormData(form);
        const response = await HTTP.post(form.action, formData);
        
        if (response.success) {
          notificationManager.success('Gmail sync completed successfully');
          await this.refreshData();
        } else {
          notificationManager.error(response.message || 'Gmail sync failed');
        }
      } catch (error) {
        console.error('Gmail sync error:', error);
        notificationManager.error('Failed to sync Gmail');
      } finally {
        loadingManager.hide(loaderId);
      }
    });
  }

  async updateCharts() {
    const accountFilter = DOM.query('#chart_account_filter');
    const dateFilter = DOM.query('#chart_date_filter');
    
    const filters = {
      account: accountFilter?.value || 'all',
      date_range: dateFilter?.value || 'overall'
    };

    try {
      const response = await HTTP.post('/api/dashboard/charts/filter', filters);
      
      if (response.success) {
        this.chartData = response.data;
        this.updateAllCharts();
        notificationManager.success('Charts updated successfully');
      }
    } catch (error) {
      console.error('Error updating charts:', error);
      notificationManager.error('Failed to update charts');
    }
  }

  updateAllCharts() {
    this.charts.forEach((chart, name) => {
      this.updateChart(chart, name);
    });
  }

  updateChart(chart, name) {
    if (!this.chartData) return;

    switch (name) {
      case 'trend':
        if (this.chartData.trend_data) {
          chart.data.labels = this.chartData.trend_data.labels || [];
          chart.data.datasets[0].data = this.chartData.trend_data.income || [];
          chart.data.datasets[1].data = this.chartData.trend_data.expenses || [];
        }
        break;
        
      case 'category':
        if (this.chartData.category_data) {
          chart.data.labels = this.chartData.category_data.labels || [];
          chart.data.datasets[0].data = this.chartData.category_data.values || [];
        }
        break;
        
      case 'balance':
        if (this.chartData.balance_data) {
          chart.data.labels = this.chartData.balance_data.labels || [];
          chart.data.datasets[0].data = this.chartData.balance_data.values || [];
        }
        break;
        
      case 'incomeExpense':
        if (this.chartData.income_expense_data) {
          chart.data.datasets[0].data = [
            this.chartData.income_expense_data.income || 0,
            this.chartData.income_expense_data.expenses || 0
          ];
        }
        break;
    }

    chart.update('resize');
  }

  async refreshData() {
    const loaderId = loadingManager.show('.charts-header', { text: 'Refreshing...', size: 'sm' });
    
    try {
      await this.loadChartData();
      this.updateAllCharts();
      notificationManager.success('Dashboard data refreshed');
    } catch (error) {
      console.error('Error refreshing data:', error);
      notificationManager.error('Failed to refresh dashboard data');
    } finally {
      loadingManager.hide(loaderId);
    }
  }

  startAutoRefresh() {
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
    }

    this.updateInterval = setInterval(async () => {
      if (this.isAutoRefreshEnabled && document.visibilityState === 'visible') {
        await this.refreshData();
      }
    }, this.refreshRate);

    // Enable auto-refresh by default
    this.isAutoRefreshEnabled = true;
  }

  stopAutoRefresh() {
    if (this.updateInterval) {
      clearInterval(this.updateInterval);
      this.updateInterval = null;
    }
    this.isAutoRefreshEnabled = false;
  }

  toggleAutoRefresh() {
    this.isAutoRefreshEnabled = !this.isAutoRefreshEnabled;
    
    if (this.isAutoRefreshEnabled) {
      notificationManager.info('Auto-refresh enabled');
    } else {
      notificationManager.info('Auto-refresh disabled');
    }
  }

  destroy() {
    this.stopAutoRefresh();
    this.charts.forEach(chart => chart.destroy());
    this.charts.clear();
  }
}

export class AccountSyncMonitor {
  constructor() {
    this.pollingInterval = null;
    this.baseDelay = 5000; // 5 seconds
    this.maxDelay = 30000; // 30 seconds
    this.currentDelay = this.baseDelay;
    this.init();
  }

  init() {
    this.startPolling();
    
    // Stop polling when page becomes hidden
    DOM.on(document, 'visibilitychange', () => {
      if (document.hidden) {
        this.stopPolling();
      } else {
        this.startPolling();
      }
    });
  }

  startPolling() {
    if (this.pollingInterval) return;

    this.poll();
  }

  stopPolling() {
    if (this.pollingInterval) {
      clearTimeout(this.pollingInterval);
      this.pollingInterval = null;
    }
  }

  async poll() {
    const badges = DOM.queryAll('.account-sync-badge');
    if (badges.length === 0) {
      this.scheduleNext(this.maxDelay);
      return;
    }

    try {
      const promises = Array.from(badges).map(badge => 
        this.checkSyncStatus(badge.dataset.accountNumber)
      );
      
      const results = await Promise.allSettled(promises);
      let hasActive = false;

      results.forEach((result, index) => {
        if (result.status === 'fulfilled' && result.value) {
          const badge = badges[index];
          const { status } = result.value;
          
          if (status === 'pending' || status === 'running') {
            DOM.removeClass(badge, 'd-none');
            hasActive = true;
          } else {
            DOM.addClass(badge, 'd-none');
          }
        }
      });

      // Adjust polling frequency based on active syncs
      this.currentDelay = hasActive ? this.baseDelay : this.maxDelay;
      
    } catch (error) {
      console.error('Sync polling error:', error);
      this.currentDelay = Math.min(this.currentDelay * 2, this.maxDelay);
    }

    this.scheduleNext(this.currentDelay);
  }

  async checkSyncStatus(accountNumber) {
    try {
      const response = await HTTP.get(`/account/accounts/${encodeURIComponent(accountNumber)}/sync-status`);
      return response;
    } catch (error) {
      if (error.message.includes('429')) {
        // Rate limited - back off
        this.currentDelay = Math.min(this.currentDelay * 2, this.maxDelay);
      }
      throw error;
    }
  }

  scheduleNext(delay) {
    this.pollingInterval = setTimeout(() => {
      this.pollingInterval = null;
      this.poll();
    }, delay);
  }

  destroy() {
    this.stopPolling();
  }
}

// Initialize dashboard when DOM is ready
let dashboardManager = null;
let syncMonitor = null;

DOM.on(document, 'DOMContentLoaded', () => {
  // Only initialize on dashboard page
  if (DOM.query('#trendChart') || DOM.query('.account-sync-badge')) {
    dashboardManager = new DashboardManager();
    syncMonitor = new AccountSyncMonitor();
  }
});

// Cleanup on page unload
DOM.on(window, 'beforeunload', () => {
  if (dashboardManager) {
    dashboardManager.destroy();
  }
  if (syncMonitor) {
    syncMonitor.destroy();
  }
});

export { dashboardManager, syncMonitor };
export default { DashboardManager, AccountSyncMonitor };