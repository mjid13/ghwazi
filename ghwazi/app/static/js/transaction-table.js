/**
 * Transaction Table JavaScript
 * Initializes DataTables for the transaction table with responsive features
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize the transaction table with DataTables
    initTransactionTable();
});

/**
 * Initialize the transaction table with DataTables
 */
function initTransactionTable() {
    // Get the transaction table
    const table = document.querySelector('.table-responsive table');
    
    if (!table) return;
    
    // Add the datatable class to the table
    table.classList.add('datatable');
    
    // Add an ID to the table if it doesn't have one
    if (!table.id) {
        table.id = 'transaction-table';
    }
    
    // Add data-priority attributes to the table headers
    const headers = table.querySelectorAll('thead th');
    if (headers.length > 0) {
        // Date column (priority 1 - always visible)
        if (headers[0]) headers[0].setAttribute('data-priority', '1');
        
        // Type column (priority 1 - always visible)
        if (headers[1]) headers[1].setAttribute('data-priority', '1');
        
        // Amount column (priority 1 - always visible)
        if (headers[2]) headers[2].setAttribute('data-priority', '1');
        
        // Description column (priority 3 - hidden on small screens)
        if (headers[3]) headers[3].setAttribute('data-priority', '3');
        
        // Category column (priority 2 - visible on medium screens)
        if (headers[4]) headers[4].setAttribute('data-priority', '2');
        
        // Sender/Receiver column (priority 4 - hidden on most screens)
        if (headers[5]) headers[5].setAttribute('data-priority', '4');
        
        // Actions column (priority 1 - always visible)
        if (headers[6]) headers[6].setAttribute('data-priority', '1');
    }
    
    // Add data-label attributes to the table cells
    const rows = table.querySelectorAll('tbody tr');
    rows.forEach(row => {
        const cells = row.querySelectorAll('td');
        
        // Date column
        if (cells[0]) cells[0].setAttribute('data-label', _('Date'));
        
        // Type column
        if (cells[1]) cells[1].setAttribute('data-label', _('Type'));
        
        // Amount column
        if (cells[2]) cells[2].setAttribute('data-label', _('Amount'));
        
        // Description column
        if (cells[3]) cells[3].setAttribute('data-label', _('Description'));
        
        // Category column
        if (cells[4]) cells[4].setAttribute('data-label', _('Category'));
        
        // Sender/Receiver column
        if (cells[5]) cells[5].setAttribute('data-label', _('Sender/Receiver'));
        
        // Actions column
        if (cells[6]) cells[6].setAttribute('data-label', _('Actions'));
    });
    
    // Initialize DataTables with responsive features
    $(table).DataTable({
        // Disable DataTables pagination since we're using our own
        "paging": false,
        
        // Disable DataTables info display since we're using our own
        "info": false,
        
        // Disable DataTables searching since we're using our own
        "searching": false,
        
        // Enable responsive features
        "responsive": {
            details: {
                display: $.fn.dataTable.Responsive.display.childRowImmediate,
                type: 'column',
                renderer: function(api, rowIdx, columns) {
                    const data = $.map(columns, function(col, i) {
                        // Only show hidden columns in the responsive view
                        return col.hidden ?
                            '<tr data-dt-row="'+col.rowIndex+'" data-dt-column="'+col.columnIndex+'">' +
                                '<td class="responsive-label">' + col.title + ':</td> ' +
                                '<td class="responsive-data">' + col.data + '</td>' +
                            '</tr>' :
                            '';
                    }).join('');
                    
                    return data ?
                        $('<table class="responsive-details"/>').append(data) :
                        false;
                }
            }
        },
        
        // Disable initial sorting
        "order": [],
        
        // Disable automatic width calculation
        "autoWidth": false,
        
        // Custom language settings
        "language": {
            "emptyTable": _('No transactions found'),
            "zeroRecords": _('No matching transactions found')
        }
    });
}

/**
 * Reinitialize the transaction table after AJAX content is loaded
 */
function reinitTransactionTable() {
    // Destroy existing DataTable instance if it exists
    const table = $('#transaction-table').DataTable();
    if (table) {
        table.destroy();
    }
    
    // Initialize the transaction table again
    initTransactionTable();
}