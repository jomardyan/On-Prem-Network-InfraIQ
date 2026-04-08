/**
 * Enhanced Scan Results Manager
 * Provides advanced result management, filtering, and analysis
 */
class ScanResultsManager {
    constructor() {
        this.results = [];
        this.filteredResults = [];
        this.sortConfig = { column: null, direction: 'asc' };
        this.filters = {};
        this.analysisCache = new Map();
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.initializeFilters();
        this.setupExportHandlers();
    }

    setupEventListeners() {
        // Filter inputs
        document.addEventListener('input', (e) => {
            if (e.target.classList.contains('result-filter')) {
                this.updateFilter(e.target.name, e.target.value);
            }
        });

        // Sort headers
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('sort-header')) {
                this.toggleSort(e.target.dataset.column);
            }
        });

        // Export buttons
        document.addEventListener('click', (e) => {
            if (e.target.classList.contains('export-btn')) {
                this.exportResults(e.target.dataset.format);
            }
        });

        // Result selection
        document.addEventListener('change', (e) => {
            if (e.target.classList.contains('result-checkbox')) {
                this.updateSelection();
            }
        });
    }

    initializeFilters() {
        this.filters = {
            search: '',
            status: '',
            service: '',
            vulnerability: '',
            ipRange: '',
            portRange: ''
        };
    }

    updateResults(newResults) {
        this.results = Array.isArray(newResults) ? newResults : [];
        this.analysisCache.clear();
        this.applyFiltersAndSort();
        this.updateUI();
        this.updateStatistics();
    }

    updateFilter(filterName, value) {
        this.filters[filterName] = value;
        this.applyFiltersAndSort();
        this.updateUI();
    }

    applyFiltersAndSort() {
        let filtered = [...this.results];

        // Apply search filter
        if (this.filters.search) {
            const searchTerm = this.filters.search.toLowerCase();
            filtered = filtered.filter(result => 
                result.ipAddress?.toLowerCase().includes(searchTerm) ||
                result.service?.toLowerCase().includes(searchTerm) ||
                result.hostname?.toLowerCase().includes(searchTerm) ||
                result.serverInfo?.toLowerCase().includes(searchTerm)
            );
        }

        // Apply status filter
        if (this.filters.status) {
            filtered = filtered.filter(result => {
                switch (this.filters.status) {
                    case 'open': return result.isOpen;
                    case 'closed': return !result.isOpen;
                    case 'vulnerable': return result.isVulnerable;
                    case 'secure': return !result.isVulnerable;
                    default: return true;
                }
            });
        }

        // Apply service filter
        if (this.filters.service && this.filters.service !== 'all') {
            filtered = filtered.filter(result => 
                result.service?.toLowerCase().includes(this.filters.service.toLowerCase())
            );
        }

        // Apply vulnerability filter
        if (this.filters.vulnerability) {
            const hasVuln = this.filters.vulnerability === 'true';
            filtered = filtered.filter(result => result.isVulnerable === hasVuln);
        }

        // Apply IP range filter
        if (this.filters.ipRange) {
            filtered = filtered.filter(result => 
                this.isIPInRange(result.ipAddress, this.filters.ipRange)
            );
        }

        // Apply port range filter
        if (this.filters.portRange) {
            const [minPort, maxPort] = this.parsePortRange(this.filters.portRange);
            filtered = filtered.filter(result => 
                result.port >= minPort && result.port <= maxPort
            );
        }

        // Apply sorting
        if (this.sortConfig.column) {
            filtered.sort((a, b) => this.compareResults(a, b));
        }

        this.filteredResults = filtered;
    }

    isIPInRange(ip, range) {
        // Simple IP range checking - can be enhanced for CIDR notation
        if (range.includes('-')) {
            const [start, end] = range.split('-');
            return this.compareIPs(ip, start) >= 0 && this.compareIPs(ip, end) <= 0;
        }
        return ip.includes(range);
    }

    parsePortRange(range) {
        if (range.includes('-')) {
            const [min, max] = range.split('-').map(p => parseInt(p.trim()));
            return [min || 1, max || 65535];
        }
        const port = parseInt(range);
        return [port, port];
    }

    compareIPs(ip1, ip2) {
        const parts1 = ip1.split('.').map(Number);
        const parts2 = ip2.split('.').map(Number);
        
        for (let i = 0; i < 4; i++) {
            if (parts1[i] !== parts2[i]) {
                return parts1[i] - parts2[i];
            }
        }
        return 0;
    }

    toggleSort(column) {
        if (this.sortConfig.column === column) {
            this.sortConfig.direction = this.sortConfig.direction === 'asc' ? 'desc' : 'asc';
        } else {
            this.sortConfig.column = column;
            this.sortConfig.direction = 'asc';
        }
        
        this.applyFiltersAndSort();
        this.updateUI();
        this.updateSortHeaders();
    }

    compareResults(a, b) {
        const column = this.sortConfig.column;
        const direction = this.sortConfig.direction === 'asc' ? 1 : -1;

        let valueA = a[column];
        let valueB = b[column];

        // Handle special cases
        if (column === 'port') {
            valueA = parseInt(valueA) || 0;
            valueB = parseInt(valueB) || 0;
        } else if (column === 'pingTime') {
            valueA = parseFloat(valueA) || 0;
            valueB = parseFloat(valueB) || 0;
        } else if (column === 'ipAddress') {
            return this.compareIPs(valueA || '', valueB || '') * direction;
        } else {
            valueA = (valueA || '').toString().toLowerCase();
            valueB = (valueB || '').toString().toLowerCase();
        }

        if (valueA < valueB) return -1 * direction;
        if (valueA > valueB) return 1 * direction;
        return 0;
    }

    updateUI() {
        this.renderResultsTable();
        this.updateFilterCounts();
        this.updatePagination();
    }

    renderResultsTable() {
        const tbody = document.querySelector('#resultsTable tbody');
        if (!tbody) return;

        if (this.filteredResults.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="8" class="text-center py-4">
                        <i class="fas fa-search fa-2x text-muted mb-2"></i>
                        <p class="text-muted">No results found matching your criteria</p>
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = this.filteredResults.map((result, index) => `
            <tr class="result-row ${result.isVulnerable ? 'table-warning' : ''}" data-index="${index}">
                <td>
                    <input type="checkbox" class="form-check-input result-checkbox" 
                           data-ip="${result.ipAddress}" data-port="${result.port}">
                </td>
                <td>
                    <span class="badge ${result.isOpen ? 'bg-success' : 'bg-secondary'}">
                        ${result.isOpen ? 'Open' : 'Closed'}
                    </span>
                </td>
                <td>
                    <span class="fw-bold">${result.ipAddress}</span>
                    ${result.hostname ? `<br><small class="text-muted">${result.hostname}</small>` : ''}
                </td>
                <td>
                    <span class="badge bg-primary">${result.port}</span>
                </td>
                <td>
                    <span class="service-name">${result.service || 'Unknown'}</span>
                    ${result.serviceVersion ? `<br><small class="text-muted">v${result.serviceVersion}</small>` : ''}
                </td>
                <td>
                    ${result.isVulnerable ? 
                        `<span class="badge bg-danger">
                            <i class="fas fa-exclamation-triangle me-1"></i>Vulnerable
                        </span>` : 
                        `<span class="badge bg-success">
                            <i class="fas fa-shield-alt me-1"></i>Secure
                        </span>`
                    }
                    ${result.vulnerabilityInfo ? 
                        `<br><small class="text-muted">${result.vulnerabilityInfo}</small>` : ''
                    }
                </td>
                <td>
                    <small class="text-muted">${result.pingTime}ms</small>
                    ${result.country ? `<br><small class="text-muted">${result.country}</small>` : ''}
                </td>
                <td>
                    <div class="btn-group btn-group-sm">
                        <button class="btn btn-outline-primary btn-sm" onclick="resultManager.showDetails('${result.ipAddress}', ${result.port})">
                            <i class="fas fa-info-circle"></i>
                        </button>
                        <button class="btn btn-outline-secondary btn-sm" onclick="resultManager.rescanHost('${result.ipAddress}', ${result.port})">
                            <i class="fas fa-redo"></i>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
    }

    updateStatistics() {
        const stats = this.calculateStatistics();
        this.renderStatistics(stats);
    }

    calculateStatistics() {
        if (this.analysisCache.has('statistics')) {
            return this.analysisCache.get('statistics');
        }

        const stats = {
            total: this.results.length,
            open: this.results.filter(r => r.isOpen).length,
            closed: this.results.filter(r => !r.isOpen).length,
            vulnerable: this.results.filter(r => r.isVulnerable).length,
            uniqueHosts: new Set(this.results.map(r => r.ipAddress)).size,
            uniqueServices: new Set(this.results.filter(r => r.isOpen).map(r => r.service)).size,
            averageResponseTime: this.calculateAverageResponseTime(),
            topServices: this.getTopServices(),
            topVulnerabilities: this.getTopVulnerabilities(),
            riskScore: this.calculateRiskScore()
        };

        this.analysisCache.set('statistics', stats);
        return stats;
    }

    calculateAverageResponseTime() {
        const openPorts = this.results.filter(r => r.isOpen && r.pingTime > 0);
        if (openPorts.length === 0) return 0;
        
        const totalTime = openPorts.reduce((sum, r) => sum + r.pingTime, 0);
        return Math.round(totalTime / openPorts.length);
    }

    getTopServices() {
        const serviceCounts = {};
        this.results
            .filter(r => r.isOpen && r.service)
            .forEach(r => {
                serviceCounts[r.service] = (serviceCounts[r.service] || 0) + 1;
            });

        return Object.entries(serviceCounts)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 5)
            .map(([service, count]) => ({ service, count }));
    }

    getTopVulnerabilities() {
        const vulnCounts = {};
        this.results
            .filter(r => r.isVulnerable && r.vulnerabilityInfo)
            .forEach(r => {
                vulnCounts[r.vulnerabilityInfo] = (vulnCounts[r.vulnerabilityInfo] || 0) + 1;
            });

        return Object.entries(vulnCounts)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 5)
            .map(([vulnerability, count]) => ({ vulnerability, count }));
    }

    calculateRiskScore() {
        const weights = {
            openPorts: 1,
            vulnerabilities: 5,
            criticalServices: 3
        };

        const openPorts = this.results.filter(r => r.isOpen).length;
        const vulnerabilities = this.results.filter(r => r.isVulnerable).length;
        const criticalServices = this.results.filter(r => 
            r.isOpen && ['ssh', 'telnet', 'ftp', 'rdp'].includes(r.service?.toLowerCase())
        ).length;

        const rawScore = (openPorts * weights.openPorts) + 
                        (vulnerabilities * weights.vulnerabilities) + 
                        (criticalServices * weights.criticalServices);

        // Normalize to 0-100 scale
        return Math.min(100, Math.round(rawScore / Math.max(1, this.results.length) * 10));
    }

    renderStatistics(stats) {
        const container = document.querySelector('#statisticsContainer');
        if (!container) return;

        container.innerHTML = `
            <div class="row g-3">
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h3 class="text-primary">${stats.total}</h3>
                            <p class="card-text">Total Ports</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h3 class="text-success">${stats.open}</h3>
                            <p class="card-text">Open Ports</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h3 class="text-warning">${stats.vulnerable}</h3>
                            <p class="card-text">Vulnerabilities</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h3 class="text-info">${stats.uniqueHosts}</h3>
                            <p class="card-text">Unique Hosts</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="row mt-3">
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h6 class="mb-0">Top Services</h6>
                        </div>
                        <div class="card-body">
                            ${stats.topServices.map(s => `
                                <div class="d-flex justify-content-between">
                                    <span>${s.service}</span>
                                    <span class="badge bg-secondary">${s.count}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="card">
                        <div class="card-header">
                            <h6 class="mb-0">Risk Assessment</h6>
                        </div>
                        <div class="card-body">
                            <div class="d-flex justify-content-between mb-2">
                                <span>Risk Score</span>
                                <span class="badge ${this.getRiskBadgeClass(stats.riskScore)}">${stats.riskScore}/100</span>
                            </div>
                            <div class="progress">
                                <div class="progress-bar ${this.getRiskProgressClass(stats.riskScore)}" 
                                     style="width: ${stats.riskScore}%"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    getRiskBadgeClass(score) {
        if (score < 30) return 'bg-success';
        if (score < 60) return 'bg-warning';
        return 'bg-danger';
    }

    getRiskProgressClass(score) {
        if (score < 30) return 'bg-success';
        if (score < 60) return 'bg-warning';
        return 'bg-danger';
    }

    exportResults(format) {
        const data = this.filteredResults;
        let content = '';
        let filename = `scan_results_${new Date().toISOString().split('T')[0]}`;

        switch (format) {
            case 'json':
                content = JSON.stringify(data, null, 2);
                filename += '.json';
                break;
            case 'csv':
                content = this.convertToCSV(data);
                filename += '.csv';
                break;
            case 'xml':
                content = this.convertToXML(data);
                filename += '.xml';
                break;
            default:
                console.error('Unsupported export format:', format);
                return;
        }

        this.downloadFile(content, filename);
    }

    convertToCSV(data) {
        const headers = ['IP Address', 'Port', 'Service', 'Status', 'Vulnerable', 'Response Time', 'Hostname', 'Country'];
        const rows = data.map(result => [
            result.ipAddress,
            result.port,
            result.service || '',
            result.isOpen ? 'Open' : 'Closed',
            result.isVulnerable ? 'Yes' : 'No',
            result.pingTime,
            result.hostname || '',
            result.country || ''
        ]);

        return [headers, ...rows].map(row => 
            row.map(cell => `"${cell}"`).join(',')
        ).join('\n');
    }

    convertToXML(data) {
        let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<scanResults>\n';
        
        data.forEach(result => {
            xml += '  <result>\n';
            xml += `    <ipAddress>${result.ipAddress}</ipAddress>\n`;
            xml += `    <port>${result.port}</port>\n`;
            xml += `    <service>${result.service || ''}</service>\n`;
            xml += `    <isOpen>${result.isOpen}</isOpen>\n`;
            xml += `    <isVulnerable>${result.isVulnerable}</isVulnerable>\n`;
            xml += `    <responseTime>${result.pingTime}</responseTime>\n`;
            xml += `    <hostname>${result.hostname || ''}</hostname>\n`;
            xml += `    <country>${result.country || ''}</country>\n`;
            xml += '  </result>\n';
        });
        
        xml += '</scanResults>';
        return xml;
    }

    downloadFile(content, filename) {
        const blob = new Blob([content], { type: 'text/plain' });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        window.URL.revokeObjectURL(url);
    }

    showDetails(ipAddress, port) {
        const result = this.results.find(r => r.ipAddress === ipAddress && r.port === port);
        if (!result) return;

        // Create modal with detailed information
        const modal = this.createDetailsModal(result);
        document.body.appendChild(modal);
        
        const bootstrapModal = new bootstrap.Modal(modal);
        bootstrapModal.show();
        
        modal.addEventListener('hidden.bs.modal', () => {
            modal.remove();
        });
    }

    createDetailsModal(result) {
        const modal = document.createElement('div');
        modal.className = 'modal fade';
        modal.innerHTML = `
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">
                            <i class="fas fa-info-circle me-2"></i>
                            Host Details: ${result.ipAddress}:${result.port}
                        </h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row">
                            <div class="col-md-6">
                                <h6>Connection Details</h6>
                                <table class="table table-sm">
                                    <tr><td>IP Address</td><td>${result.ipAddress}</td></tr>
                                    <tr><td>Port</td><td>${result.port}</td></tr>
                                    <tr><td>Status</td><td>
                                        <span class="badge ${result.isOpen ? 'bg-success' : 'bg-secondary'}">
                                            ${result.isOpen ? 'Open' : 'Closed'}
                                        </span>
                                    </td></tr>
                                    <tr><td>Response Time</td><td>${result.pingTime}ms</td></tr>
                                    <tr><td>Hostname</td><td>${result.hostname || 'N/A'}</td></tr>
                                    <tr><td>Country</td><td>${result.country || 'N/A'}</td></tr>
                                </table>
                            </div>
                            <div class="col-md-6">
                                <h6>Service Information</h6>
                                <table class="table table-sm">
                                    <tr><td>Service</td><td>${result.service || 'Unknown'}</td></tr>
                                    <tr><td>Version</td><td>${result.serviceVersion || 'N/A'}</td></tr>
                                    <tr><td>Server Info</td><td>${result.serverInfo || 'N/A'}</td></tr>
                                    <tr><td>Operating System</td><td>${result.operatingSystem || 'N/A'}</td></tr>
                                </table>
                            </div>
                        </div>
                        ${result.isVulnerable ? `
                            <div class="alert alert-warning mt-3">
                                <h6><i class="fas fa-exclamation-triangle me-2"></i>Security Alert</h6>
                                <p class="mb-0">${result.vulnerabilityInfo}</p>
                            </div>
                        ` : ''}
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        <button type="button" class="btn btn-primary" onclick="resultManager.rescanHost('${result.ipAddress}', ${result.port})">
                            <i class="fas fa-redo me-1"></i>Rescan
                        </button>
                    </div>
                </div>
            </div>
        `;

        return modal;
    }

    async rescanHost(ipAddress, port) {
        // Implement rescan functionality
        console.log(`Rescanning ${ipAddress}:${port}`);
        // This would trigger a new scan for the specific host/port
    }
}

// Initialize the results manager
const resultManager = new ScanResultsManager();
window.resultManager = resultManager;