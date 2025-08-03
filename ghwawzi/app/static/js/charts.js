/**
 * Chart initialization and configuration
 * Requires Chart.js to be loaded
 */

// Store chart instances so we can destroy and recreate them
let chartInstances = {
    incomeExpenseChart: null,
    categoryChart: null,
    trendChart: null,
    balanceChart: null
};

// Track ongoing requests to prevent race conditions
let pendingRequests = {
    allCharts: false,
    categoryChart: false
};

// Initialize dashboard charts
function initDashboardCharts(chartData) {
    // Only proceed if we have chart data
    if (!chartData || Object.keys(chartData).length === 0) {
        console.log('No chart data available');
        return;
    }

    // 1. Income vs Expense Chart
    if (chartData.income_expense && document.getElementById('incomeExpenseChart')) {
        // Destroy existing chart if it exists
        if (chartInstances.incomeExpenseChart) {
            chartInstances.incomeExpenseChart.destroy();
        }

        chartInstances.incomeExpenseChart = new Chart(document.getElementById('incomeExpenseChart'), {
            type: 'doughnut',
            data: chartData.income_expense,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }

    // 2. Category Distribution Chart with built-in filter
    if (chartData.category_distribution && document.getElementById('categoryChart')) {
        // Create filter buttons if they don't exist
        createCategoryFilter();

        // Only update category chart if there's no pending category-specific request
        if (!pendingRequests.categoryChart) {
            updateCategoryChartInstance(chartData);
        }
    }

    // 3. Monthly Trend Chart
    if (chartData.monthly_trend && document.getElementById('trendChart')) {
        // Destroy existing chart if it exists
        if (chartInstances.trendChart) {
            chartInstances.trendChart.destroy();
        }

        chartInstances.trendChart = new Chart(document.getElementById('trendChart'), {
            type: 'line',
            data: chartData.monthly_trend,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                },
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }

    // 4. Account Balance Chart
    if (chartData.account_balance && document.getElementById('balanceChart')) {
        // Destroy existing chart if it exists
        if (chartInstances.balanceChart) {
            chartInstances.balanceChart.destroy();
        }

        chartInstances.balanceChart = new Chart(document.getElementById('balanceChart'), {
            type: 'bar',
            data: chartData.account_balance,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    }
                }
            }
        });
    }
}

// Helper function to update category chart instance
function updateCategoryChartInstance(chartData) {
    // Destroy existing chart if it exists
    if (chartInstances.categoryChart) {
        chartInstances.categoryChart.destroy();
    }

    // Get the current category filter selection
    const activeFilter = document.querySelector('.category-filter-btn.active');
    const categoryType = activeFilter ? activeFilter.dataset.filter : 'expense';

    // Determine which data to use based on filter
    let categoryData;
    if (categoryType === 'income' && chartData.income_categories) {
        categoryData = chartData.income_categories;
    } else if (categoryType === 'expense' && chartData.expense_categories) {
        categoryData = chartData.expense_categories;
    } else {
        categoryData = chartData.category_distribution;
    }

    chartInstances.categoryChart = new Chart(document.getElementById('categoryChart'), {
        type: 'pie',
        data: categoryData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    display: true,
                    labels: {
                        usePointStyle: true,
                        padding: 20,
                        font: {
                            size: 12
                        }
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((value / total) * 100).toFixed(1);
                            return `${label}: ${value} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
}

// Function to create category filter buttons
function createCategoryFilter() {
    const categoryChartContainer = document.getElementById('categoryChart').closest('.chart-container');

    // Check if filter already exists
    if (categoryChartContainer.querySelector('.category-chart-filter')) {
        return;
    }

    // Create filter container
    const filterContainer = document.createElement('div');
    filterContainer.className = 'category-chart-filter d-flex justify-content-center mb-3';
    filterContainer.innerHTML = `
        <div class="btn-group" role="group" aria-label="Category filter">
            <button type="button" class="btn btn-outline-primary btn-sm category-filter-btn active" data-filter="expense">
                Expenses
            </button>
            <button type="button" class="btn btn-outline-success btn-sm category-filter-btn" data-filter="income">
                Income
            </button>
        </div>
    `;

    // Insert filter before the chart
    const chartElement = document.getElementById('categoryChart');
    chartElement.parentNode.insertBefore(filterContainer, chartElement);

    // Add event listeners to filter buttons
    filterContainer.querySelectorAll('.category-filter-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            // Prevent multiple simultaneous requests
            if (pendingRequests.categoryChart || pendingRequests.allCharts) {
                return;
            }

            // Remove active class from all buttons
            filterContainer.querySelectorAll('.category-filter-btn').forEach(b => {
                b.classList.remove('active');
                b.classList.add('btn-outline-primary');
                b.classList.remove('btn-primary', 'btn-success');
            });

            // Add active class to clicked button
            this.classList.add('active');
            this.classList.remove('btn-outline-primary', 'btn-outline-success');

            if (this.dataset.filter === 'income') {
                this.classList.add('btn-success');
            } else {
                this.classList.add('btn-primary');
            }

            // Update only the category chart
            updateCategoryChart();
        });
    });
}

// Function to update only the category chart based on its filter
function updateCategoryChart() {
    // Prevent race conditions
    if (pendingRequests.categoryChart || pendingRequests.allCharts) {
        console.log('Request already in progress, skipping category chart update');
        return;
    }

    const activeFilter = document.querySelector('.category-filter-btn.active');
    const categoryType = activeFilter ? activeFilter.dataset.filter : 'expense';

    // Get current global filter values
    const filters = getFilterValues();

    // Fetch data specifically for category chart
    fetchCategoryChartData(filters.accountNumber, filters.dateRange, categoryType);
}

// Function to fetch data specifically for category chart
function fetchCategoryChartData(accountNumber, dateRange, categoryType) {
    // Prevent multiple simultaneous requests
    if (pendingRequests.categoryChart || pendingRequests.allCharts) {
        console.log('Category chart request already in progress');
        return;
    }

    pendingRequests.categoryChart = true;

    const categoryChartContainer = document.getElementById('categoryChart').closest('.chart-container');

    // Show loading indicator only for category chart
    showLoadingForContainer(categoryChartContainer);

    // Fetch data from the server
    fetch(`/get_category_chart_data?account_number=${accountNumber}&date_range=${dateRange}&category_type=${categoryType}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            // Remove loading indicator
            hideLoadingForContainer(categoryChartContainer);

            // Update only the category chart
            if (chartInstances.categoryChart) {
                chartInstances.categoryChart.destroy();
            }

            chartInstances.categoryChart = new Chart(document.getElementById('categoryChart'), {
                type: 'pie',
                data: data,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                            display: true,
                            labels: {
                                usePointStyle: true,
                                padding: 20,
                                font: {
                                    size: 12
                                }
                            }
                        },
                        tooltip: {
                            callbacks: {
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.parsed;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = ((value / total) * 100).toFixed(1);
                                    return `${label}: ${value} (${percentage}%)`;
                                }
                            }
                        }
                    }
                }
            });
        })
        .catch(error => {
            console.error('Error fetching category chart data:', error);
            hideLoadingForContainer(categoryChartContainer);
            showErrorForContainer(categoryChartContainer, 'Error loading category data. Please try again.');
        })
        .finally(() => {
            pendingRequests.categoryChart = false;
        });
}

// Helper function to show loading for a specific container
function showLoadingForContainer(container) {
    container.classList.add('loading');

    // Remove existing loading indicator first
    const existingLoader = container.querySelector('.chart-loading');
    if (existingLoader) {
        existingLoader.remove();
    }

    const loadingDiv = document.createElement('div');
    loadingDiv.className = 'chart-loading';
    loadingDiv.innerHTML = '<div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div>';
    container.appendChild(loadingDiv);
}

// Helper function to hide loading for a specific container
function hideLoadingForContainer(container) {
    const loadingElement = container.querySelector('.chart-loading');
    if (loadingElement) {
        loadingElement.remove();
    }
    container.classList.remove('loading');
}

// Helper function to show error for a specific container
function showErrorForContainer(container, message) {
    const errorMessage = document.createElement('div');
    errorMessage.className = 'alert alert-danger alert-sm mt-2';
    errorMessage.textContent = message;
    container.appendChild(errorMessage);

    // Auto-remove error message after 3 seconds
    setTimeout(() => {
        if (errorMessage.parentNode) {
            errorMessage.remove();
        }
    }, 3000);
}

// Function to get current filter values
function getFilterValues() {
    const accountFilter = document.getElementById('chart_account_filter');
    const dateFilter = document.getElementById('chart_date_filter');

    return {
        accountNumber: accountFilter ? accountFilter.value : 'all',
        dateRange: dateFilter ? dateFilter.value : 'overall'
    };
}

// Function to fetch chart data based on filters
function fetchChartData(accountNumber, dateRange) {
    // Prevent multiple simultaneous requests
    if (pendingRequests.allCharts) {
        console.log('All charts request already in progress');
        return;
    }

    // Cancel any pending category chart request
    pendingRequests.categoryChart = false;
    pendingRequests.allCharts = true;

    // Show loading indicator
    document.querySelectorAll('.chart-container').forEach(container => {
        showLoadingForContainer(container);
    });

    // Fetch data from the server
    fetch(`/get_chart_data?account_number=${accountNumber}&date_range=${dateRange}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            // Remove loading indicators
            document.querySelectorAll('.chart-container').forEach(container => {
                hideLoadingForContainer(container);
            });

            // Update charts with new data
            initDashboardCharts(data);
        })
        .catch(error => {
            console.error('Error fetching chart data:', error);
            // Remove loading indicators
            document.querySelectorAll('.chart-container').forEach(container => {
                hideLoadingForContainer(container);
            });

            // Show error message
            const errorMessage = document.createElement('div');
            errorMessage.className = 'alert alert-danger';
            errorMessage.textContent = 'Error loading chart data. Please try again.';
            const firstContainer = document.querySelector('.chart-container');
            if (firstContainer) {
                firstContainer.parentNode.insertBefore(errorMessage, firstContainer);

                // Auto-remove error message after 5 seconds
                setTimeout(() => {
                    if (errorMessage.parentNode) {
                        errorMessage.remove();
                    }
                }, 5000);
            }
        })
        .finally(() => {
            pendingRequests.allCharts = false;
        });
}

// Function to update charts based on current filters
function updateCharts() {
    const filters = getFilterValues();
    fetchChartData(filters.accountNumber, filters.dateRange);
}

// Initialize charts when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Check if we're on the dashboard page by looking for chart containers
    const chartContainers = document.querySelectorAll('.chart-container');
    if (chartContainers.length === 0) {
        return; // Not on dashboard page, exit early
    }

    // Use the global chart data variable set in the dashboard template
    if (window.chartData) {
        initDashboardCharts(window.chartData);
    } else {
        console.log('No chart data available');
    }

    // Add event listener to account filter dropdown
    const accountFilter = document.getElementById('chart_account_filter');
    if (accountFilter) {
        accountFilter.addEventListener('change', updateCharts);
    }

    // Add event listener to date range filter dropdown
    const dateFilter = document.getElementById('chart_date_filter');
    if (dateFilter) {
        dateFilter.addEventListener('change', updateCharts);
    }
});