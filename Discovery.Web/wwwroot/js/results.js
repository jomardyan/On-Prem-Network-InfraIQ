// Results Page JavaScript

class ResultsManager {
    constructor() {
        this.allResults = [];
        this.filteredResults = [];
        this.currentPage = 1;
        this.pageSize = 20;
        this.sortColumn = 'time';
        this.sortDirection = 'desc';
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadResults();
    }

    bindEvents() {
        // Filter controls
        document.getElementById('filterIp')?.addEventListener('input', () => this.applyFilters());
        document.getElementById('filterService')?.addEventListener('change', () => this.applyFilters());
        document.getElementById('filterPort')?.addEventListener('change', () => this.applyFilters());
        document.getElementById('clearFilters')?.addEventListener('click', () => this.clearFilters());

        // Data management
        document.getElementById('loadSampleData')?.addEventListener('click', () => this.loadSampleData());
        document.getElementById('exportAllResults')?.addEventListener('click', () => this.exportResults());

        // Sorting
        document.querySelectorAll('[data-sort]').forEach(button => {
            button.addEventListener('click', (e) => {
                const column = e.target.closest('[data-sort]').getAttribute('data-sort');
                this.sort(column);
            });
        });

        // Pagination
        document.getElementById('prevPage')?.addEventListener('click', (e) => {
            e.preventDefault();
            if (this.currentPage > 1) {
                this.currentPage--;
                this.displayResults();
            }
        });

        document.getElementById('nextPage')?.addEventListener('click', (e) => {
            e.preventDefault();
            const totalPages = Math.ceil(this.filteredResults.length / this.pageSize);
            if (this.currentPage < totalPages) {
                this.currentPage++;
                this.displayResults();
            }
        });
    }

    loadResults() {
        // Load from localStorage
        try {
            const stored = localStorage.getItem('networkScanResults');
            if (stored) {
                this.allResults = JSON.parse(stored);
                this.filteredResults = [...this.allResults];
                this.displayResults();
                this.updateStatistics();
            } else {
                this.showNoResults();
            }
        } catch (error) {
            console.error('Error loading results:', error);
            this.showNoResults();
        }
    }

    loadSampleData() {
        const sampleResults = [
            {
                ipAddress: '192.168.1.1',
                port: 22,
                isOpen: true,
                service: 'SSH',
                discoveredAt: new Date(Date.now() - 3600000).toISOString(),
                scanId: 'sample-1'
            },
            {
                ipAddress: '192.168.1.1',
                port: 80,
                isOpen: true,
                service: 'HTTP',
                discoveredAt: new Date(Date.now() - 3600000).toISOString(),
                scanId: 'sample-2'
            },
            {
                ipAddress: '192.168.1.5',
                port: 443,
                isOpen: true,
                service: 'HTTPS',
                discoveredAt: new Date(Date.now() - 1800000).toISOString(),
                scanId: 'sample-3'
            },
            {
                ipAddress: '192.168.1.10',
                port: 21,
                isOpen: true,
                service: 'FTP',
                discoveredAt: new Date(Date.now() - 900000).toISOString(),
                scanId: 'sample-4'
            },
            {
                ipAddress: '192.168.1.15',
                port: 23,
                isOpen: true,
                service: 'Telnet',
                discoveredAt: new Date(Date.now() - 300000).toISOString(),
                scanId: 'sample-5'
            }
        ];

        this.allResults = [...this.allResults, ...sampleResults];
        this.saveResults();
        this.applyFilters();
        Dashboard.showSuccess('Sample data loaded successfully.');
    }

    applyFilters() {
        const ipFilter = document.getElementById('filterIp')?.value.toLowerCase() || '';
        const serviceFilter = document.getElementById('filterService')?.value || '';
        const portFilter = document.getElementById('filterPort')?.value || '';

        this.filteredResults = this.allResults.filter(result => {
            const matchesIp = !ipFilter || result.ipAddress.toLowerCase().includes(ipFilter);
            const matchesService = !serviceFilter || result.service === serviceFilter;
            const matchesPort = !portFilter || result.port.toString() === portFilter;

            return matchesIp && matchesService && matchesPort;
        });

        this.currentPage = 1; // Reset to first page
        this.displayResults();
        this.updateStatistics();
    }

    clearFilters() {
        document.getElementById('filterIp').value = '';
        document.getElementById('filterService').value = '';
        document.getElementById('filterPort').value = '';
        this.applyFilters();
    }

    sort(column) {
        if (this.sortColumn === column) {
            this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            this.sortColumn = column;
            this.sortDirection = 'asc';
        }

        this.filteredResults.sort((a, b) => {
            let valueA, valueB;

            switch (column) {
                case 'ip':
                    valueA = this.ipToNumber(a.ipAddress);
                    valueB = this.ipToNumber(b.ipAddress);
                    break;
                case 'port':
                    valueA = a.port;
                    valueB = b.port;
                    break;
                case 'service':
                    valueA = a.service || '';
                    valueB = b.service || '';
                    break;
                case 'time':
                    valueA = new Date(a.discoveredAt);
                    valueB = new Date(b.discoveredAt);
                    break;
                default:
                    return 0;
            }

            if (valueA < valueB) return this.sortDirection === 'asc' ? -1 : 1;
            if (valueA > valueB) return this.sortDirection === 'asc' ? 1 : -1;
            return 0;
        });

        this.displayResults();
        this.updateSortIndicators();
    }

    updateSortIndicators() {
        // Update sort button indicators
        document.querySelectorAll('[data-sort] i').forEach(icon => {
            icon.className = 'fas fa-sort';
        });

        const currentSortButton = document.querySelector(`[data-sort="${this.sortColumn}"] i`);
        if (currentSortButton) {
            currentSortButton.className = this.sortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down';
        }
    }

    displayResults() {
        const noResultsMessage = document.getElementById('noResultsMessage');
        const resultsTable = document.getElementById('resultsTable');
        const tableBody = document.getElementById('resultsTableBody');
        const resultCount = document.getElementById('resultCount');

        if (this.filteredResults.length === 0) {
            noResultsMessage.style.display = 'block';
            resultsTable.style.display = 'none';
            resultCount.textContent = '0 results';
            return;
        }

        noResultsMessage.style.display = 'none';
        resultsTable.style.display = 'block';

        // Calculate pagination
        const startIndex = (this.currentPage - 1) * this.pageSize;
        const endIndex = Math.min(startIndex + this.pageSize, this.filteredResults.length);
        const pageResults = this.filteredResults.slice(startIndex, endIndex);

        // Clear table
        tableBody.innerHTML = '';

        // Add rows
        pageResults.forEach(result => {
            const row = this.createResultRow(result);
            tableBody.appendChild(row);
        });

        // Update result count
        resultCount.textContent = `${this.filteredResults.length} result${this.filteredResults.length !== 1 ? 's' : ''}`;

        // Update pagination
        this.updatePagination();
    }

    createResultRow(result) {
        const row = document.createElement('tr');
        
        const serviceIcon = Dashboard.getServiceIcon(result.service);
        const serviceColor = Dashboard.getServiceColor(result.service);
        const timestamp = new Date(result.discoveredAt).toLocaleString();
        const isVulnerable = this.isServiceVulnerable(result.service, result.port);

        row.innerHTML = `
            <td>
                <i class="fas fa-circle text-success me-2" title="Host is active"></i>
                ${result.ipAddress}
            </td>
            <td>
                <span class="badge bg-info">${result.port}</span>
            </td>
            <td>
                <i class="${serviceIcon} ${serviceColor} me-2"></i>
                ${result.service || 'Unknown'}
            </td>
            <td>
                <small class="text-muted">${timestamp}</small>
            </td>
            <td>
                ${isVulnerable 
                    ? '<span class="badge bg-warning text-dark">Needs Review</span>'
                    : '<span class="badge bg-success">Normal</span>'
                }
            </td>
            <td>
                <button class="btn btn-sm btn-outline-info" onclick="resultManager.showResultDetail('${result.scanId || result.ipAddress + ':' + result.port}')">
                    <i class="fas fa-info-circle"></i>
                </button>
            </td>
        `;

        return row;
    }

    showResultDetail(resultId) {
        const result = this.allResults.find(r => 
            (r.scanId && r.scanId === resultId) || 
            (r.ipAddress + ':' + r.port === resultId)
        );

        if (!result) return;

        const modal = new bootstrap.Modal(document.getElementById('resultDetailModal'));
        const modalContent = document.getElementById('modalContent');

        const isVulnerable = this.isServiceVulnerable(result.service, result.port);
        const serviceIcon = Dashboard.getServiceIcon(result.service);

        modalContent.innerHTML = `
            <div class="row">
                <div class="col-md-6">
                    <h6><i class="fas fa-globe me-2"></i>Network Information</h6>
                    <table class="table table-dark table-sm">
                        <tr><td>IP Address:</td><td><strong>${result.ipAddress}</strong></td></tr>
                        <tr><td>Port:</td><td><strong>${result.port}</strong></td></tr>
                        <tr><td>Status:</td><td><span class="badge bg-success">Open</span></td></tr>
                        <tr><td>Discovered:</td><td>${new Date(result.discoveredAt).toLocaleString()}</td></tr>
                    </table>
                </div>
                <div class="col-md-6">
                    <h6><i class="${serviceIcon} me-2"></i>Service Information</h6>
                    <table class="table table-dark table-sm">
                        <tr><td>Service:</td><td><strong>${result.service || 'Unknown'}</strong></td></tr>
                        <tr><td>Security:</td><td>${isVulnerable 
                            ? '<span class="badge bg-warning text-dark">Needs Review</span>'
                            : '<span class="badge bg-success">Normal</span>'
                        }</td></tr>
                        <tr><td>Common Use:</td><td>${this.getServiceDescription(result.service)}</td></tr>
                    </table>
                </div>
            </div>
            
            ${isVulnerable ? `
                <div class="alert alert-warning mt-3">
                    <h6><i class="fas fa-exclamation-triangle me-2"></i>Security Considerations</h6>
                    <p>${this.getSecurityRecommendation(result.service, result.port)}</p>
                </div>
            ` : ''}
        `;

        modal.show();
    }

    updatePagination() {
        const totalPages = Math.ceil(this.filteredResults.length / this.pageSize);
        const pagination = document.getElementById('pagination');
        const prevBtn = document.getElementById('prevPage');
        const nextBtn = document.getElementById('nextPage');

        if (totalPages <= 1) {
            pagination.style.display = 'none';
            return;
        }

        pagination.style.display = 'block';
        
        // Update button states
        prevBtn.parentElement.classList.toggle('disabled', this.currentPage === 1);
        nextBtn.parentElement.classList.toggle('disabled', this.currentPage === totalPages);

        // Update current page indicator
        const pageIndicator = pagination.querySelector('.page-item.active .page-link');
        if (pageIndicator) {
            pageIndicator.textContent = `${this.currentPage} of ${totalPages}`;
        }
    }

    updateStatistics() {
        const uniqueHosts = new Set(this.filteredResults.map(r => r.ipAddress)).size;
        const openPorts = this.filteredResults.length;
        const uniqueServices = new Set(this.filteredResults.map(r => r.service).filter(s => s)).size;
        const vulnerableServices = this.filteredResults.filter(r => this.isServiceVulnerable(r.service, r.port)).length;

        document.getElementById('statsHosts').textContent = uniqueHosts;
        document.getElementById('statsOpenPorts').textContent = openPorts;
        document.getElementById('statsServices').textContent = uniqueServices;
        document.getElementById('statsVulnerable').textContent = vulnerableServices;
    }

    exportResults() {
        if (this.allResults.length === 0) {
            Dashboard.showError('No results to export.');
            return;
        }

        const exportData = {
            exportedAt: new Date().toISOString(),
            version: '1.1.0',
            totalResults: this.allResults.length,
            filteredResults: this.filteredResults.length,
            results: this.allResults,
            statistics: {
                uniqueHosts: new Set(this.allResults.map(r => r.ipAddress)).size,
                totalPorts: this.allResults.length,
                uniqueServices: new Set(this.allResults.map(r => r.service).filter(s => s)).size,
                vulnerableServices: this.allResults.filter(r => this.isServiceVulnerable(r.service, r.port)).length
            }
        };

        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        
        a.href = url;
        a.download = `all-scan-results-${new Date().toISOString().split('T')[0]}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        Dashboard.showSuccess('All results exported successfully.');
    }

    saveResults() {
        try {
            localStorage.setItem('networkScanResults', JSON.stringify(this.allResults));
        } catch (error) {
            console.warn('Could not save results to localStorage:', error);
        }
    }

    showNoResults() {
        document.getElementById('noResultsMessage').style.display = 'block';
        document.getElementById('resultsTable').style.display = 'none';
    }

    // Utility methods
    ipToNumber(ip) {
        return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0);
    }

    isServiceVulnerable(service, port) {
        const vulnerableServices = ['FTP', 'Telnet'];
        const commonPorts = [21, 23, 135, 139, 445];
        
        return vulnerableServices.includes(service) || commonPorts.includes(port);
    }

    getServiceDescription(service) {
        const descriptions = {
            'HTTP': 'Web server (unencrypted)',
            'HTTPS': 'Secure web server',
            'SSH': 'Secure shell remote access',
            'FTP': 'File transfer protocol',
            'Telnet': 'Remote terminal access (unencrypted)',
            'DNS': 'Domain name resolution',
            'SMTP': 'Email server',
            'POP3': 'Email retrieval',
            'IMAP': 'Email access protocol'
        };
        
        return descriptions[service] || 'Unknown service type';
    }

    getSecurityRecommendation(service, port) {
        if (service === 'FTP') {
            return 'FTP transmits data in plain text. Consider using SFTP or FTPS for secure file transfers.';
        }
        if (service === 'Telnet') {
            return 'Telnet sends credentials and data unencrypted. Replace with SSH for secure remote access.';
        }
        if (port === 135 || port === 139 || port === 445) {
            return 'Windows networking ports should be restricted to internal networks only to prevent unauthorized access.';
        }
        return 'Review this service to ensure it follows security best practices.';
    }
}

// Initialize results manager when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('resultsTableBody')) {
        window.resultManager = new ResultsManager();
    }
});