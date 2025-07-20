/**
 * Chart initialization and configuration
 * Requires Chart.js to be loaded
 */

// Initialize dashboard charts
function initDashboardCharts(chartData) {
    // Only proceed if we have chart data
    if (!chartData || Object.keys(chartData).length === 0) {
        console.log('No chart data available');
        return;
    }

    // 1. Income vs Expense Chart
    if (chartData.income_expense && document.getElementById('incomeExpenseChart')) {
        new Chart(document.getElementById('incomeExpenseChart'), {
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

    // 2. Category Distribution Chart
    if (chartData.category_distribution && document.getElementById('categoryChart')) {
        new Chart(document.getElementById('categoryChart'), {
            type: 'pie',
            data: chartData.category_distribution,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        display: false
                    }
                }
            }
        });
    }

    // 3. Monthly Trend Chart
    if (chartData.monthly_trend && document.getElementById('trendChart')) {
        new Chart(document.getElementById('trendChart'), {
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
        new Chart(document.getElementById('balanceChart'), {
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
});