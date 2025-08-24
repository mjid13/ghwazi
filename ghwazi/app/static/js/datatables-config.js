/**
 * DataTables Configuration
 *
 * This file contains common configuration for DataTables used throughout the application.
 * It provides consistent pagination, filtering, and search functionality for all data tables.
 */

// Initialize DataTables with default configuration
function initDataTables() {
    // Basic DataTable initialization with common settings
    $('.datatable').DataTable({
        // Pagination settings
        pageLength: 25,
        lengthMenu: [[10, 25, 50, 100, -1], [10, 25, 50, 100, _('All')]],
        pagingType: 'simple_numbers', // clean previous/next with numbers

        // Responsive design
        responsive: true,

        // Default sorting (first column, ascending)
        order: [[0, 'asc']],

        // Accessibility-friendly language settings
        language: {
            search: _('Search:'),
            lengthMenu: _('Show _MENU_ per page'),
            info: _('Showing _START_ to _END_ of _TOTAL_ entries'),
            infoEmpty: _('Showing 0 to 0 of 0 entries'),
            infoFiltered: _('(filtered from _MAX_ total entries)'),
            zeroRecords: _('No matching records found'),
            paginate: {
                first: _('First'),
                last: _('Last'),
                next: _('Next'),
                previous: _('Previous')
            },
            aria: {
                paginate: {
                    first: _('First Page'),
                    previous: _('Previous Page'),
                    next: _('Next Page'),
                    last: _('Last Page')
                }
            }
        },

        // DOM positioning (Bootstrap-friendly layout with top and bottom controls)
        dom: '<"row align-items-center g-2 mb-3"<"col-sm-12 col-md-6"l><"col-sm-12 col-md-6 d-flex justify-content-md-end"f>>t<"row align-items-center g-2 mt-3"<"col-sm-12 col-md-5"i><"col-sm-12 col-md-7 d-flex justify-content-md-end"p>>',

        // Initialize with empty state
        stateSave: false
    });
}

// Initialize DataTables with server-side processing
function initServerSideDataTable(tableId, ajaxUrl) {
    $(tableId).DataTable({
        "processing": true,
        "serverSide": true,
        "ajax": ajaxUrl,
        
        // Pagination settings
        "pageLength": 25,
        "lengthMenu": [[10, 25, 50, 100], [10, 25, 50, 100]],
        
        // Responsive design
        "responsive": true,
        
        // Custom language settings
        "language": {
            "search": _('Search:'),
            "lengthMenu": _('Show _MENU_ entries per page'),
            "info": "Showing _START_ to _END_ of _TOTAL_ entries",
            "infoEmpty": "Showing 0 to 0 of 0 entries",
            "processing": _('Loading data...'),
            "zeroRecords": _('No matching records found'),
            "paginate": {
                "first": _('First'),
                "last": _('Last'),
                "next": _('Next'),
                "previous": _('Previous')
            }
        },
        
        // DOM positioning (layout)
        "dom": '<"top"lf>rt<"bottom"ip><"clear">'
    });
}

// Initialize DataTable with custom column filters
function initDataTableWithFilters(tableId, filterConfig) {
    const table = $(tableId).DataTable({
        // Pagination settings
        "pageLength": 25,
        "lengthMenu": [[10, 25, 50, 100, -1], [10, 25, 50, 100, _('All')]],
        
        // Responsive design
        "responsive": true,
        
        // Default sorting (first column, ascending)
        "order": [[0, "asc"]],
        
        // Custom language settings
        "language": {
            "search": _('Search:'),
            "lengthMenu": _('Show _MENU_ entries per page'),
            "info": "Showing _START_ to _END_ of _TOTAL_ entries",
            "infoEmpty": "Showing 0 to 0 of 0 entries",
            "infoFiltered": "(filtered from _MAX_ total entries)",
            "zeroRecords": _('No matching records found'),
            "paginate": {
                "first": _('First'),
                "last": _('Last'),
                "next": _('Next'),
                "previous": _('Previous')
            }
        },
        
        // DOM positioning with filter container
        "dom": '<"top"lf><"filter-container">rt<"bottom"ip><"clear">'
    });
    
    // Add custom filter elements if provided
    if (filterConfig && filterConfig.length > 0) {
        let filterHtml = '<div class="datatable-filters mb-3">';
        
        filterConfig.forEach(filter => {
            filterHtml += `
                <div class="filter-group">
                    <label for="filter-${filter.column}">${filter.label}:</label>
                    <select id="filter-${filter.column}" class="form-select form-select-sm custom-column-filter" data-column="${filter.column}">
                        <option value="">All</option>
                        ${filter.options.map(option => `<option value="${option.value}">${option.label}</option>`).join('')}
                    </select>
                </div>
            `;
        });
        
        filterHtml += '</div>';
        
        $(tableId + '_wrapper .filter-container').html(filterHtml);
        
        // Add event listeners for custom filters
        $('.custom-column-filter').on('change', function() {
            const column = table.column($(this).data('column'));
            column.search($(this).val()).draw();
        });
    }
    
    return table;
}

// Document ready function to initialize all datatables
document.addEventListener('DOMContentLoaded', function() {
    // Initialize all tables with the 'datatable' class
    initDataTables();
});