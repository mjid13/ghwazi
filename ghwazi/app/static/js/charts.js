/**
 * Chart initialization and configuration with RTL support
 * Requires Chart.js to be loaded
 */

// Local translation helper resilient to script order
const t = (function(){
    try {
        if (window.__t && typeof window.__t === 'function') return window.__t;
        if (typeof window._ === 'function') return window._;
    } catch(_) {}
    return function(s){ return s; };
})();

// RTL configuration for charts
const isRTL = document.documentElement.getAttribute('dir') === 'rtl';

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

// Styles for the category filter toggle (injected once into <head>)
const CATEGORY_FILTER_STYLES = `
.category-chart-filter {
    margin: 0 0 20px 0;
    padding: 0;
    position: relative;
    z-index: 10;
    display: flex;
    align-items: center;
}
.filter-toggle-container { position: relative; display: flex; align-items: center; justify-content: center; margin: 0; padding: 8px 0; }
.filter-toggle-wrapper { position: relative; background: var(--bs-body-bg, #fff); border-radius: 20px; padding: 1px; box-shadow: 0 4px 20px rgba(0,0,0,0.08), inset 0 1px 0 rgba(255,255,255,0.6); border: 1px solid rgba(0,0,0,0.08); transition: all 0.4s cubic-bezier(0.25,0.46,0.45,0.94); }
.filter-toggle-wrapper:hover { box-shadow: 0 6px 25px rgba(0,0,0,0.12), inset 0 1px 0 rgba(255,255,255,0.8); transform: translateY(-1px); }
.filter-toggle-track { position: relative; display: flex; border-radius: 17px; overflow: hidden; background: rgba(0,0,0,0.02); }
.filter-toggle-slider { position: absolute; top: 0; left: 0; width: 50%; height: 100%; background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 50%, #dc3545 100%); border-radius: 17px; transition: all 0.5s cubic-bezier(0.34, 1.56, 0.64, 1); box-shadow: 0 3px 12px rgba(220, 53, 69, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.3); z-index: 2; display: flex; align-items: center; justify-content: center; }
.filter-toggle-label { position: relative; z-index: 3; width: 44px; height: 44px; display: flex; align-items: center; justify-content: center; cursor: pointer; transition: all 0.25s ease; color: #495057; font-size: 16px; }
.filter-toggle-label:first-of-type { border-radius: 16px 0 0 16px; }
.filter-toggle-label:last-of-type { border-radius: 0 16px 16px 0; }
.filter-toggle-label:hover { color: #212529; transform: scale(1.02); }
.filter-toggle-label:active { transform: scale(0.98); }
.filter-toggle-wrapper input[type="radio"] { display: none; }
#expense-filter:checked ~ .filter-toggle-track .filter-toggle-slider { left: 0; background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 50%, #dc3545 100%); box-shadow: 0 3px 12px rgba(220, 53, 69, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.4); }
#income-filter:checked ~ .filter-toggle-track .filter-toggle-slider { left: 50%; background: linear-gradient(135deg, #38b000 0%, #2ea44f 50%, #198754 100%); box-shadow: 0 3px 12px rgba(25, 135, 84, 0.35), inset 0 1px 0 rgba(255, 255, 255, 0.4); }
.slider-icon { position: absolute; width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; }
.butter-icon { position: absolute; width: 24px; height: 24px; transform: translateY(0); transition: transform 0.45s cubic-bezier(0.34,1.56,0.64,1), opacity 0.25s ease; opacity: 0; filter: drop-shadow(0 2px 4px rgba(0,0,0,0.1)); }
.icon-circle { width: 24px; height: 24px; border-radius: 12px; background: rgba(255,255,255,0.95); display: flex; align-items: center; justify-content: center; box-shadow: inset 0 1px 0 rgba(255,255,255,0.8), 0 2px 5px rgba(0,0,0,0.08); }
.arrow-down, .arrow-up { width: 0; height: 0; border-left: 6px solid transparent; border-right: 6px solid transparent; }
.arrow-down { border-top: 8px solid #dc3545; }
.arrow-up { border-bottom: 8px solid #198754; }
#expense-filter:checked ~ .filter-toggle-track .butter-icon.expense-icon { opacity: 1; transform: translateY(0); }
#income-filter:checked ~ .filter-toggle-track .butter-icon.income-icon { opacity: 1; transform: translateY(0); }
.label-icon { display: flex; align-items: center; justify-content: center; position: relative; width: 100%; height: 100%; }
.icon-ring { width: 24px; height: 24px; border-radius: 50%; background: rgba(0,0,0,0.03); display: flex; align-items: center; justify-content: center; position: relative; box-shadow: inset 0 1px 0 rgba(255,255,255,0.6); }
.minus-line { width: 10px; height: 2px; background: #dc3545; border-radius: 2px; box-shadow: 0 1px 0 rgba(0,0,0,0.05), inset 0 1px 0 rgba(255,255,255,0.8); }
.plus-lines { position: relative; width: 16px; height: 16px; display: flex; align-items: center; justify-content: center; }
.plus-horizontal, .plus-vertical { position: absolute; background: #198754; border-radius: 2px; box-shadow: 0 1px 0 rgba(0,0,0,0.05), inset 0 1px 0 rgba(255,255,255,0.8); }
.plus-horizontal { width: 12px; height: 2px; }
.plus-vertical { width: 2px; height: 12px; }
#expense-filter:checked ~ .filter-toggle-track .label-icon.expense-label .icon-ring { background: rgba(220,53,69,0.08); }
#income-filter:checked ~ .filter-toggle-track .label-icon.income-label .icon-ring { background: rgba(25,135,84,0.08); }
.filter-toggle-wrapper.active { transform: translateY(-1px); box-shadow: 0 8px 28px rgba(0,0,0,0.15), inset 0 1px 0 rgba(255,255,255,0.8); }
.filter-toggle-label:active .icon-ring { transform: scale(0.96); }
.filter-toggle-label:hover .icon-ring { transform: scale(1.02); }
.filter-toggle-slider::before { content: ""; position: absolute; inset: 0; background: radial-gradient(circle at 100% 50%, rgba(255,255,255,0.4), transparent 60%); opacity: 0.35; border-radius: 17px; z-index: -1; transition: opacity 0.3s ease; }
.filter-toggle-wrapper:hover .filter-toggle-slider::before { opacity: 0.5; }
@media (prefers-reduced-motion: reduce) { .filter-toggle-slider, .filter-toggle-label, .filter-toggle-wrapper, .slider-icon i { transition: none !important; } }
.category-chart-filter + canvas,
.category-chart-filter ~ canvas,
.category-chart-filter + div canvas { margin-top: 2px !important; }
#categoryChart { position: relative; z-index: 1; }
.chart-container { transition: all 0.3s ease; padding-top: 0 !important; }
.chart-container.loading { pointer-events: none; }
.chart-container canvas { max-height: none !important; }
@media (max-width: 576px) {
  .category-chart-filter { margin-bottom: 15px; }
  .filter-toggle-wrapper { padding: 2px; }
  .filter-toggle-label { width: 38px; height: 38px; font-size: 14px; }
  .slider-icon i { font-size: 10px; }
}`;

function ensureCategoryFilterStyles() {
    if (document.getElementById('category-filter-styles')) return;
    const style = document.createElement('style');
    style.id = 'category-filter-styles';
    style.type = 'text/css';
    try {
        const meta = document.querySelector('meta[name="csp-nonce"]');
        if (meta && meta.content) {
            style.nonce = meta.content;
        }
    } catch (e) {
        console.warn('Unable to set CSP nonce on style tag:', e);
    }
    style.appendChild(document.createTextNode(CATEGORY_FILTER_STYLES));
    document.head.appendChild(style);
}

// Initialize dashboard charts
function initDashboardCharts(chartData) {
    // Only proceed if we have chart data
    if (!chartData || Object.keys(chartData).length === 0) {
        console.warn('No chart data available - cannot initialize charts');
        return;
    }

    console.log('Initializing dashboard charts with data:', chartData);

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
                cutout: '70%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        rtl: isRTL,
                        labels: {
                            usePointStyle: true,
                            pointStyle: 'circle',
                            padding: 20,
                            font: {
                                size: 12,
                                weight: '600'
                            },
                            generateLabels: function(chart) {
                                const data = chart.data;
                                if (data.labels.length && data.datasets.length) {
                                    const dataset = data.datasets[0];
                                    return data.labels.map((label, i) => {
                                        const value = dataset.data[i];
                                        const total = dataset.data.reduce((a, b) => a + b, 0);
                                        const percentage = ((value / total) * 100).toFixed(1);
                                        return {
                                            text: `${label} (${percentage}%)`,
                                            fillStyle: dataset.backgroundColor[i],
                                            strokeStyle: dataset.borderColor ? dataset.borderColor[i] : dataset.backgroundColor[i],
                                            lineWidth: 0,
                                            pointStyle: 'circle',
                                            hidden: chart.getDatasetMeta(0).data[i].hidden,
                                            index: i
                                        };
                                    });
                                }
                                return [];
                            }
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(33, 37, 41, 0.95)',
                        titleColor: '#fff',
                        bodyColor: '#fff',
                        cornerRadius: 12,
                        padding: 16,
                        displayColors: true,
                        titleFont: {
                            size: 14,
                            weight: '700'
                        },
                        bodyFont: {
                            size: 13,
                            weight: '500'
                        },
                        callbacks: {
                            label: function(context) {
                                const label = context.label || '';
                                const value = context.parsed;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = ((value / total) * 100).toFixed(1);
                                return [`${label}: ${value}`, `${percentage}% of total`];
                            }
                        }
                    }
                },
                elements: {
                    arc: {
                        borderWidth: 3,
                        borderColor: '#fff',
                        hoverBorderWidth: 4,
                        hoverBackgroundColor: function(ctx) {
                            const color = ctx.element.options.backgroundColor;
                            return Chart.helpers.color(color).alpha(0.8).rgbString();
                        }
                    }
                },
                animation: {
                    animateRotate: true,
                    animateScale: true,
                    duration: 1000,
                    easing: 'easeOutCubic'
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
                interaction: {
                    mode: 'index',
                    intersect: false,
                },
                scales: {
                    x: {
                        display: true,
                        reverse: isRTL,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.05)',
                            lineWidth: 1
                        },
                        ticks: {
                            font: {
                                size: 11,
                                weight: '500'
                            },
                            color: '#6c757d'
                        }
                    },
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.05)',
                            lineWidth: 1
                        },
                        ticks: {
                            font: {
                                size: 11,
                                weight: '500'
                            },
                            color: '#6c757d',
                            callback: function(value) {
                                return value.toLocaleString();
                            }
                        }
                    }
                },
                plugins: {
                    legend: {
                        position: 'bottom',
                        rtl: isRTL,
                        labels: {
                            usePointStyle: true,
                            pointStyle: 'circle',
                            padding: 20,
                            font: {
                                size: 12,
                                weight: '600'
                            }
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(33, 37, 41, 0.95)',
                        titleColor: '#fff',
                        bodyColor: '#fff',
                        cornerRadius: 12,
                        padding: 16,
                        displayColors: true,
                        titleFont: {
                            size: 14,
                            weight: '700'
                        },
                        bodyFont: {
                            size: 13,
                            weight: '500'
                        }
                    }
                },
                elements: {
                    point: {
                        radius: 5,
                        hoverRadius: 8,
                        borderWidth: 2,
                        hoverBorderWidth: 3
                    },
                    line: {
                        borderWidth: 3,
                        tension: 0.4,
                        fill: false
                    }
                },
                animation: {
                    duration: 1200,
                    easing: 'easeOutCubic'
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
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        backgroundColor: 'rgba(33, 37, 41, 0.95)',
                        titleColor: '#fff',
                        bodyColor: '#fff',
                        cornerRadius: 12,
                        padding: 16,
                        displayColors: false,
                        titleFont: {
                            size: 14,
                            weight: '700'
                        },
                        bodyFont: {
                            size: 13,
                            weight: '500'
                        },
                        callbacks: {
                            label: function(context) {
                                const value = context.parsed.y;
                                return `Balance: ${value.toLocaleString()}`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        grid: {
                            display: false
                        },
                        ticks: {
                            font: {
                                size: 11,
                                weight: '500'
                            },
                            color: '#6c757d',
                            maxRotation: 45
                        }
                    },
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.05)',
                            lineWidth: 1
                        },
                        ticks: {
                            font: {
                                size: 11,
                                weight: '500'
                            },
                            color: '#6c757d',
                            callback: function(value) {
                                return value.toLocaleString();
                            }
                        }
                    }
                },
                elements: {
                    bar: {
                        borderRadius: 8,
                        borderSkipped: false,
                        borderWidth: 0,
                        hoverBorderWidth: 0
                    }
                },
                animation: {
                    duration: 1000,
                    easing: 'easeOutCubic',
                    delay: function(context) {
                        return context.type === 'data' && context.mode === 'default' 
                            ? context.dataIndex * 100 
                            : 0;
                    }
                },
                onHover: (event, activeElements, chart) => {
                    event.native.target.style.cursor = activeElements.length > 0 ? 'pointer' : 'default';
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

    // Get category type from radio inputs (new toggle) or old button structure (fallback)
    const radioInput = document.querySelector('input[name="category-filter"]:checked');
    const oldButton = document.querySelector('.category-filter-btn.active');

    let categoryType = 'expense'; // default
    if (radioInput) {
        categoryType = radioInput.value;
    } else if (oldButton) {
        categoryType = oldButton.dataset.filter;
    }

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
            layout: {
                padding: {
                    top: 5,
                    bottom: 60,
                    left: 10,
                    right: 10
                }
            },
            plugins: {
                legend: {
                    position: 'bottom',
                    display: true,
                    align: 'center',
                    maxWidth: 400,
                    fullSize: true,
                    rtl: isRTL,
                    labels: {
                        usePointStyle: true,
                        pointStyle: 'circle',
                        padding: 10,
                        boxWidth: 10,
                        boxHeight: 10,
                        font: {
                            size: 11,
                            family: 'system-ui, -apple-system, sans-serif',
                            weight: '500'
                        },
                        color: '#495057',
                        generateLabels: function(chart) {
                            const data = chart.data;
                            if (data.labels.length && data.datasets.length) {
                                const dataset = data.datasets[0];
                                return data.labels.map((label, i) => {
                                    const value = dataset.data[i];
                                    const total = dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = ((value / total) * 100).toFixed(1);

                                    // Truncate long labels
                                    let displayLabel = label;
                                    if (label.length > 15) {
                                        displayLabel = label.substring(0, 12) + '...';
                                    }

                                    return {
                                        text: `${displayLabel} (${percentage}%)`,
                                        fillStyle: dataset.backgroundColor[i],
                                        strokeStyle: dataset.borderColor ? dataset.borderColor[i] : dataset.backgroundColor[i],
                                        lineWidth: dataset.borderWidth || 0,
                                        pointStyle: 'circle',
                                        hidden: chart.getDatasetMeta(0).data[i].hidden,
                                        index: i
                                    };
                                });
                            }
                            return [];
                        }
                    },
                    onClick: function(e, legendItem, legend) {
                        const index = legendItem.index;
                        const chart = legend.chart;
                        const meta = chart.getDatasetMeta(0);

                        meta.data[index].hidden = !meta.data[index].hidden;
                        chart.update('active');
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    titleColor: '#fff',
                    bodyColor: '#fff',
                    cornerRadius: 8,
                    displayColors: true,
                    padding: 12,
                    titleFont: {
                        size: 13,
                        weight: '600'
                    },
                    bodyFont: {
                        size: 12
                    },
                    callbacks: {
                        title: function(context) {
                            return context[0].label;
                        },
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed;
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = ((value / total) * 100).toFixed(1);
                            return [`Amount: ${value}`, `Percentage: ${percentage}%`];
                        }
                    }
                }
            },
            elements: {
                arc: {
                    borderWidth: 2,
                    borderColor: '#fff',
                    hoverBorderWidth: 3,
                    hoverBorderColor: '#fff'
                }
            },
            interaction: {
                intersect: false,
                mode: 'point'
            },
            animation: {
                animateRotate: true,
                animateScale: true,
                duration: 1000,
                easing: 'easeOutCubic'
            }
        }
    });
}

// Function to create category filter buttons
function createCategoryFilter() {
    const categoryChartContainer = document.getElementById('categoryChart').closest('.chart-container');

    // Check if filter already exists either in the chart container (fallback placement)
    // or in the header toggle container (preferred placement). This prevents duplicates
    // when charts are re-initialized.
    const existingHeaderToggle = document.querySelector('#category-toggle-container .category-chart-filter');
    if (categoryChartContainer.querySelector('.category-chart-filter') || existingHeaderToggle) {
        return;
    }

    // Create filter container with enhanced styling
    const filterContainer = document.createElement('div');
    filterContainer.className = 'category-chart-filter d-flex justify-content-center mb-1';
    // Ensure styles for the toggle are available once
    ensureCategoryFilterStyles();

    // Re-assign clean HTML for the filter (styles are injected in <head>)
    filterContainer.innerHTML = `
        <div class="filter-toggle-container">
            <div class="filter-toggle-wrapper">
                <input type="radio" id="expense-filter" name="category-filter" value="expense" checked>
                <input type="radio" id="income-filter" name="category-filter" value="income">
                
                <div class="filter-toggle-track">
                    <div class="filter-toggle-slider">
                        <div class="slider-icon">
                            <div class="butter-icon expense-icon">
                                <div class="icon-circle">
                                    <div class="arrow-down"></div>
                                </div>
                            </div>
                            <div class="butter-icon income-icon">
                                <div class="icon-circle">
                                    <div class="arrow-up"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                    <label for="expense-filter" class="filter-toggle-label" data-filter="expense">
                        <div class="label-icon expense-label">
                            <div class="icon-ring">
                                <div class="minus-line"></div>
                            </div>
                        </div>
                    </label>
                    <label for="income-filter" class="filter-toggle-label" data-filter="income">
                        <div class="label-icon income-label">
                            <div class="icon-ring">
                                <div class="plus-lines">
                                    <div class="plus-horizontal"></div>
                                    <div class="plus-vertical"></div>
                                </div>
                            </div>
                        </div>
                    </label>
                </div>
            </div>
        </div>
    `;

    // Find the header toggle container and place the toggle there
    const toggleContainer = document.getElementById("category-toggle-container");
    
    if (toggleContainer) {
        console.log("Found header toggle container, placing toggle in header");
        // Ensure only one toggle exists in the header
        toggleContainer.innerHTML = '';
        toggleContainer.appendChild(filterContainer);
    } else {
        console.log("Header toggle container not found, using fallback positioning");
        // Fallback: add above chart
        const chartElement = document.getElementById("categoryChart");
        const fallbackDiv = document.createElement("div");
        fallbackDiv.style.cssText = "display: flex; justify-content: flex-end; margin-bottom: 1rem;";
        fallbackDiv.appendChild(filterContainer);
        chartElement.parentNode.insertBefore(fallbackDiv, chartElement);
    }

    // Add event listeners to radio inputs
    const radioInputs = filterContainer.querySelectorAll('input[type="radio"]');
    const wrapper = filterContainer.querySelector('.filter-toggle-wrapper');

    radioInputs.forEach(radio => {
        radio.addEventListener('change', function() {
            // Prevent multiple simultaneous requests
            if (pendingRequests.categoryChart || pendingRequests.allCharts) {
                return;
            }

            // Add active state with bounce effect
            wrapper.classList.add('active');

            setTimeout(() => {
                wrapper.classList.remove('active');
            }, 200);

            // Update chart after a brief delay for smooth animation
            setTimeout(() => {
                updateCategoryChart();
            }, 150);
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

    // Get category type from radio inputs (new toggle) or old button structure (fallback)
    const radioInput = document.querySelector('input[name="category-filter"]:checked');
    const oldButton = document.querySelector('.category-filter-btn.active');

    let categoryType = 'expense'; // default
    if (radioInput) {
        categoryType = radioInput.value;
    } else if (oldButton) {
        categoryType = oldButton.dataset.filter;
    }

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
    fetch(`/api/get_category_chart_data?account_number=${accountNumber}&date_range=${dateRange}&category_type=${categoryType}`)
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
                    layout: {
                        padding: {
                            top: 5,
                            bottom: 60,
                            left: 10,
                            right: 10
                        }
                    },
                    plugins: {
                        legend: {
                            position: 'bottom',
                            display: true,
                            align: 'center',
                            maxWidth: 400,
                            fullSize: true,
                            rtl: isRTL,
                            labels: {
                                usePointStyle: true,
                                pointStyle: 'circle',
                                padding: 10,
                                boxWidth: 10,
                                boxHeight: 10,
                                font: {
                                    size: 10,
                                    family: 'system-ui, -apple-system, sans-serif',
                                    weight: '500'
                                },
                                color: '#495057',
                                generateLabels: function(chart) {
                                    const data = chart.data;
                                    if (data.labels.length && data.datasets.length) {
                                        const dataset = data.datasets[0];
                                        return data.labels.map((label, i) => {
                                            const value = dataset.data[i];
                                            const total = dataset.data.reduce((a, b) => a + b, 0);
                                            const percentage = ((value / total) * 100).toFixed(1);

                                            // Truncate long labels
                                            let displayLabel = label;
                                            if (label.length > 15) {
                                                displayLabel = label.substring(0, 12) + '...';
                                            }

                                            return {
                                                text: `${displayLabel} (${percentage}%)`,
                                                fillStyle: dataset.backgroundColor[i],
                                                strokeStyle: dataset.borderColor ? dataset.borderColor[i] : dataset.backgroundColor[i],
                                                lineWidth: dataset.borderWidth || 0,
                                                pointStyle: 'circle',
                                                hidden: chart.getDatasetMeta(0).data[i].hidden,
                                                index: i
                                            };
                                        });
                                    }
                                    return [];
                                }
                            },
                            onClick: function(e, legendItem, legend) {
                                const index = legendItem.index;
                                const chart = legend.chart;
                                const meta = chart.getDatasetMeta(0);

                                meta.data[index].hidden = !meta.data[index].hidden;
                                chart.update('active');
                            }
                        },
                        tooltip: {
                            backgroundColor: 'rgba(0, 0, 0, 0.8)',
                            titleColor: '#fff',
                            bodyColor: '#fff',
                            cornerRadius: 8,
                            displayColors: true,
                            padding: 12,
                            titleFont: {
                                size: 13,
                                weight: '600'
                            },
                            bodyFont: {
                                size: 12
                            },
                            callbacks: {
                                title: function(context) {
                                    return context[0].label;
                                },
                                label: function(context) {
                                    const label = context.label || '';
                                    const value = context.parsed;
                                    const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                    const percentage = ((value / total) * 100).toFixed(1);
                                    return [`Amount: ${value}`, `Percentage: ${percentage}%`];
                                }
                            }
                        }
                    },
                    elements: {
                        arc: {
                            borderWidth: 2,
                            borderColor: '#fff',
                            hoverBorderWidth: 3,
                            hoverBorderColor: '#fff'
                        }
                    },
                    interaction: {
                        intersect: false,
                        mode: 'point'
                    },
                    animation: {
                        animateRotate: true,
                        animateScale: true,
                        duration: 1000,
                        easing: 'easeOutCubic'
                    }
                }
            });
        })
        .catch(error => {
            console.error('Error fetching category chart data:', error);
            hideLoadingForContainer(categoryChartContainer);
            showErrorForContainer(categoryChartContainer, t('Error loading category data. Please try again.'));
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
    loadingDiv.innerHTML = '<div class="spinner-border text-primary" role="status"><span class="visually-hidden">' + t('Loading...') + '</span></div>';
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
    // Prefer new quick buttons; fallback to defaults
    const activeAccountBtn = document.querySelector('.quick-account-btn.active');
    const activeRangeBtn = document.querySelector('.quick-range-btn.active');

    const accountNumber = activeAccountBtn && activeAccountBtn.dataset && activeAccountBtn.dataset.account
        ? activeAccountBtn.dataset.account
        : 'all';
    const dateRange = activeRangeBtn && activeRangeBtn.dataset && activeRangeBtn.dataset.range
        ? activeRangeBtn.dataset.range
        : 'overall';

    return { accountNumber, dateRange };
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
    fetch(`/api/get_chart_data?account_number=${accountNumber}&date_range=${dateRange}`)
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
            errorMessage.textContent = t('Error loading chart data. Please try again.');
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
        console.log('No chart containers found, not on dashboard page');
        return; // Not on dashboard page, exit early
    }

    console.log(`Found ${chartContainers.length} chart containers on dashboard page`);

    // Use the global chart data variable set in the dashboard template
    if (window.chartData) {
        console.log('Chart data available, initializing charts...');
        console.log('Chart data keys:', Object.keys(window.chartData));
        initDashboardCharts(window.chartData);
    } else {
        console.warn('No chart data available - charts will not be displayed');
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

    // Add enhanced chart interactions
    addChartInteractions();
});

// Utility function to add enhanced chart interactions
function addChartInteractions() {
    // Add resize listener for responsive charts
    window.addEventListener("resize", debounce(() => {
        Object.values(chartInstances).forEach(chart => {
            if (chart) {
                chart.resize();
            }
        });
    }, 250));
}

// Debounce utility
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}
