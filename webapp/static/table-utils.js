/* Table utilities — search/filter and CSV export */

/**
 * Filter table rows by text content.
 * Hides rows whose text doesn't match the input value (case-insensitive).
 *
 * @param {HTMLInputElement} input - The search input element
 * @param {string} tableId - ID of the <table> to filter
 */
function filterTable(input, tableId) {
    const query = input.value.toLowerCase();
    const table = document.getElementById(tableId);
    if (!table) return;
    const rows = table.querySelectorAll('tbody tr');
    rows.forEach(row => {
        // Skip hidden drill-down rows (port expansion rows in switches table)
        if (row.id && row.id.startsWith('ports-row-')) return;
        if (row.id && row.id.startsWith('oui-edit-')) return;
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(query) ? '' : 'none';
    });
}

/**
 * Export a table to CSV and trigger download.
 *
 * @param {string} tableId - ID of the <table> to export
 * @param {string} filename - Download filename
 */
function exportTableCSV(tableId, filename) {
    const table = document.getElementById(tableId);
    if (!table) return;
    const rows = [];
    // Header
    const headers = [];
    table.querySelectorAll('thead th').forEach(th => {
        headers.push('"' + th.textContent.trim().replace(/"/g, '""') + '"');
    });
    rows.push(headers.join(','));
    // Body — only visible rows
    table.querySelectorAll('tbody tr').forEach(tr => {
        if (tr.style.display === 'none') return;
        if (tr.id && tr.id.startsWith('ports-row-')) return;
        if (tr.id && tr.id.startsWith('oui-edit-')) return;
        const cells = [];
        tr.querySelectorAll('td').forEach(td => {
            cells.push('"' + td.textContent.trim().replace(/"/g, '""') + '"');
        });
        rows.push(cells.join(','));
    });
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename || 'export.csv';
    a.click();
    URL.revokeObjectURL(url);
}
