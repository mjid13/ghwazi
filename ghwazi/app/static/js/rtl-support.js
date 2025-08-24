// RTL Support for JavaScript components
document.addEventListener('DOMContentLoaded', function() {
    const isRTL = document.documentElement.getAttribute('dir') === 'rtl';

    if (isRTL) {
        // DataTables RTL configuration
        if (typeof $.fn.DataTable !== 'undefined') {
            $.extend(true, $.fn.dataTable.defaults, {
                language: {
                    url: 'https://cdn.datatables.net/plug-ins/1.13.6/i18n/ar.json'
                },
                columnDefs: [
                    {
                        targets: '_all',
                        className: 'dt-rtl'
                    }
                ]
            });
            
            // Apply RTL styling to existing DataTables
            $('.dataTable').each(function() {
                $(this).addClass('rtl-table');
            });
        }

        // Chart.js RTL support (v4-safe)
        if (typeof Chart !== 'undefined' && Chart.defaults) {
            try {
                if (Chart.defaults.plugins && Chart.defaults.plugins.legend) {
                    Chart.defaults.plugins.legend.rtl = true;
                }
                if (Chart.defaults.plugins && Chart.defaults.plugins.tooltip) {
                    Chart.defaults.plugins.tooltip.rtl = true;
                }
                // In v4, defaults are per scale type; set reverse on common types if present
                if (Chart.defaults.scales) {
                    if (Chart.defaults.scales.category) Chart.defaults.scales.category.reverse = true;
                    if (Chart.defaults.scales.time) Chart.defaults.scales.time.reverse = true;
                    if (Chart.defaults.scales.timeseries) Chart.defaults.scales.timeseries.reverse = true;
                }
            } catch(e) {
                // swallow to avoid breaking page if structure differs
            }
        }

        // Bootstrap components RTL adjustments
        const dropdowns = document.querySelectorAll('.dropdown-menu-end');
        dropdowns.forEach(dropdown => {
            dropdown.classList.remove('dropdown-menu-end');
            dropdown.classList.add('dropdown-menu-start');
        });

        // Fix navbar collapse for RTL
        const navbarToggler = document.querySelector('.navbar-toggler');
        const navbarCollapse = document.querySelector('.navbar-collapse');

        if (navbarToggler && navbarCollapse) {
            navbarToggler.addEventListener('click', function() {
                // Ensure proper RTL behavior for mobile menu
                setTimeout(() => {
                    if (navbarCollapse.classList.contains('show')) {
                        navbarCollapse.style.textAlign = 'right';
                    }
                }, 100);
            });
        }

        // Fix form validation messages position
        const invalidFeedbacks = document.querySelectorAll('.invalid-feedback');
        invalidFeedbacks.forEach(feedback => {
            feedback.style.textAlign = 'right';
        });

        // Fix tooltip positioning for RTL
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.forEach(function (tooltipTriggerEl) {
            const placement = tooltipTriggerEl.getAttribute('data-bs-placement') || 'top';
            if (placement === 'left') {
                tooltipTriggerEl.setAttribute('data-bs-placement', 'right');
            } else if (placement === 'right') {
                tooltipTriggerEl.setAttribute('data-bs-placement', 'left');
            }
        });

        // Fix select2 RTL if present
        if (typeof $.fn.select2 !== 'undefined') {
            $('.select2').select2({
                dir: 'rtl'
            });
        }

        // Fix date picker RTL if present
        if (typeof flatpickr !== 'undefined') {
            flatpickr.localize(flatpickr.l10ns.ar);
        }

        // Fix modal positioning for RTL
        const modals = document.querySelectorAll('.modal');
        modals.forEach(modal => {
            modal.addEventListener('shown.bs.modal', function() {
                const modalDialog = modal.querySelector('.modal-dialog');
                if (modalDialog) {
                    modalDialog.style.marginLeft = 'auto';
                    modalDialog.style.marginRight = 'auto';
                }
            });
        });

        // Fix offcanvas RTL
        const offcanvasElements = document.querySelectorAll('.offcanvas-start');
        offcanvasElements.forEach(offcanvas => {
            offcanvas.classList.remove('offcanvas-start');
            offcanvas.classList.add('offcanvas-end');
        });

        // Fix carousel controls RTL
        const carouselPrevs = document.querySelectorAll('.carousel-control-prev');
        const carouselNexts = document.querySelectorAll('.carousel-control-next');
        
        carouselPrevs.forEach(prev => {
            prev.classList.remove('carousel-control-prev');
            prev.classList.add('carousel-control-next');
        });
        
        carouselNexts.forEach(next => {
            next.classList.remove('carousel-control-next');
            next.classList.add('carousel-control-prev');
        });
    }

    // Language-specific number formatting
    function formatNumberForLocale(number) {
        const locale = document.documentElement.lang;
        if (locale === 'ar') {
            // Use Western Arabic numerals for better readability
            return number.toLocaleString('en-US');
        }
        return number.toLocaleString();
    }

    // Apply number formatting to elements with class 'locale-number'
    const numberElements = document.querySelectorAll('.locale-number');
    numberElements.forEach(element => {
        const value = parseFloat(element.textContent);
        if (!isNaN(value)) {
            element.textContent = formatNumberForLocale(value);
        }
    });
});

// Theme toggle RTL support
document.addEventListener('DOMContentLoaded', function() {
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', function() {
            const isRTL = document.documentElement.getAttribute('dir') === 'rtl';
            if (isRTL) {
                // Ensure RTL styles are maintained after theme change
                setTimeout(() => {
                    document.body.classList.add('rtl-layout');
                }, 100);
            }
        });
    }
});
