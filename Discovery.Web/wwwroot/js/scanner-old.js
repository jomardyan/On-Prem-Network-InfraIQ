// Enhanced Network Scanner JavaScript - Modern UI/UX

class NetworkScanner {
    constructor() {
        this.scanResults = [];
        this.isScanning = false;
        this.scanStartTime = null;
        this.currentScan = null;
        this.progressInterval = null;
        this.sortColumn = null;
        this.sortDirection = 'asc';
        this.filters = {
            search: '',
            service: '',
            status: ''
        };
        this.init();
    }

    init() {
        this.bindEvents();
        this.loadStoredResults();
        this.initializeEnhancements();
    }

    initializeEnhancements() {
        // Add progress tracking
        this.initProgressTracking();
        
        // Add keyboard shortcuts
        this.initKeyboardShortcuts();
        
        // Add real-time filtering
        this.initFiltering();
        
        // Add table sorting
        this.initTableSorting();
        
        // Add auto-save
        this.initAutoSave();
        
        // Add offline detection
        this.initOfflineDetection();
    }

    initProgressTracking() {
        // Enhanced progress tracking with detailed metrics
        this.progress = {
            hostsScanned: 0,
            portsChecked: 0,
            openPorts: 0,
            totalHosts: 0,
            totalPorts: 0,
            startTime: null,
            responses: []
        };
    }

    initKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                switch (e.key) {
                    case 's':
                        e.preventDefault();
                        this.triggerQuickScan();
                        break;
                    case 'r':
                        e.preventDefault();
                        this.refreshResults();
                        break;
                    case 'e':
                        e.preventDefault();
                        this.exportResults();
                        break;
                }
            }
            
            if (e.key === 'Escape' && this.isScanning) {
                this.stopScan();
            }
        });
    }

    initFiltering() {
        // Real-time search and filtering
        const searchFilter = document.getElementById('searchFilter');
        if (searchFilter) {
            searchFilter.addEventListener('input', (e) => {
                this.filters.search = e.target.value.toLowerCase();
                this.applyFilters();
            });
        }

        const serviceFilter = document.getElementById('serviceFilter');
        if (serviceFilter) {
            serviceFilter.addEventListener('change', (e) => {
                this.filters.service = e.target.value;
                this.applyFilters();
            });
        }

        const statusFilter = document.getElementById('statusFilter');
        if (statusFilter) {
            statusFilter.addEventListener('change', (e) => {
                this.filters.status = e.target.value;
                this.applyFilters();
            });
        }

        const resetFilters = document.getElementById('resetFilters');
        if (resetFilters) {
            resetFilters.addEventListener('click', () => this.resetFilters());
        }
    }

    initTableSorting() {
        // Add sortable table headers
        const sortableHeaders = document.querySelectorAll('.sortable');
        sortableHeaders.forEach(header => {
            header.addEventListener('click', () => {
                const column = header.dataset.sort;
                this.sortTable(column);
            });
            header.style.cursor = 'pointer';
        });
    }

    initAutoSave() {
        // Auto-save results to localStorage
        setInterval(() => {
            if (this.scanResults.length > 0) {
                this.saveResults();
            }
        }, 30000); // Save every 30 seconds
    }

    initOfflineDetection() {
        // Handle offline/online status
        window.addEventListener('online', () => {
            dashboard.showNotification('Connection restored. You can continue scanning.', 'success');
            this.updateConnectionStatus(true);
        });

        window.addEventListener('offline', () => {
            dashboard.showNotification('Connection lost. Scanning will be paused.', 'warning');
            this.updateConnectionStatus(false);
            if (this.isScanning) {
                this.pauseScan();
            }
        });
    }

    bindEvents() {
        // Enhanced event binding with better error handling
        this.bindFormEvents();
        this.bindButtonEvents();
        this.bindExportEvents();
        this.bindProgressEvents();
    }

    bindFormEvents() {
        const singleIpForm = document.getElementById('singleIpForm');
        if (singleIpForm) {
            singleIpForm.addEventListener('submit', (e) => this.handleSingleIpScan(e));
            
            // Add real-time validation
            const ipInput = document.getElementById('ipAddress');
            if (ipInput) {
                ipInput.addEventListener('input', (e) => this.validateIpInput(e.target));
                ipInput.addEventListener('paste', (e) => {
                    setTimeout(() => this.validateIpInput(e.target), 50);
                });
            }
        }

        const networkRangeForm = document.getElementById('networkRangeForm');
        if (networkRangeForm) {
            networkRangeForm.addEventListener('submit', (e) => this.handleNetworkRangeScan(e));
            
            // Add CIDR validation
            const cidrInput = document.getElementById('networkRange');
            if (cidrInput) {
                cidrInput.addEventListener('input', (e) => this.validateCidrInput(e.target));
            }
        }
    }

    bindButtonEvents() {
        const clearBtn = document.getElementById('clearResults');
        if (clearBtn) {
            clearBtn.addEventListener('click', () => this.clearResults());
        }

        const stopBtn = document.getElementById('stopScan');
        if (stopBtn) {
            stopBtn.addEventListener('click', () => this.stopScan());
        }

        const shareBtn = document.getElementById('shareResults');
        if (shareBtn) {
            shareBtn.addEventListener('click', () => this.shareResults());
        }
    }

    bindExportEvents() {
        const exportJsonBtn = document.getElementById('exportJson');
        if (exportJsonBtn) {
            exportJsonBtn.addEventListener('click', () => this.exportResults('json'));
        }

        const exportCsvBtn = document.getElementById('exportCsv');
        if (exportCsvBtn) {
            exportCsvBtn.addEventListener('click', () => this.exportResults('csv'));
        }
    }

    bindProgressEvents() {
        // Progress card events
        const progressCard = document.getElementById('progressCard');
        if (progressCard) {
            progressCard.addEventListener('click', () => {
                if (this.isScanning) {
                    this.showProgressDetails();
                }
            });
        }
    }

    validateIpInput(input) {
        const value = input.value.trim();
        const isValid = this.isValidIP(value);
        
        this.updateInputValidation(input, isValid, isValid ? '' : 'Please enter a valid IP address');
        return isValid;
    }

    validateCidrInput(input) {
        const value = input.value.trim();
        const isValid = this.isValidCIDR(value);
        
        this.updateInputValidation(input, isValid, isValid ? '' : 'Please enter valid CIDR notation (e.g., 192.168.1.0/24)');
        return isValid;
    }

    updateInputValidation(input, isValid, message) {
        const feedback = input.parentElement.querySelector('.invalid-feedback, .valid-feedback');
        if (feedback) {
            feedback.remove();
        }

        input.classList.remove('is-valid', 'is-invalid');
        
        if (input.value && input.value.trim() !== '') {
            if (isValid) {
                input.classList.add('is-valid');
                const validFeedback = document.createElement('div');
                validFeedback.className = 'valid-feedback';
                validFeedback.textContent = 'Looks good!';
                input.parentElement.appendChild(validFeedback);
            } else {
                input.classList.add('is-invalid');
                const invalidFeedback = document.createElement('div');
                invalidFeedback.className = 'invalid-feedback';
                invalidFeedback.textContent = message;
                input.parentElement.appendChild(invalidFeedback);
            }
        }
    }

    isValidIP(ip) {
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        return ipv4Regex.test(ip) || ipv6Regex.test(ip);
    }

    isValidCIDR(cidr) {
        const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$/;
        return cidrRegex.test(cidr);
    }

    async handleSingleIpScan(event) {
        event.preventDefault();
        
        if (this.isScanning) {
            dashboard.showNotification('A scan is already in progress. Please wait for it to complete.', 'warning');
            return;
        }

        const ipAddress = document.getElementById('ipAddress').value.trim();
        const ports = document.getElementById('singlePorts').value.trim();
        const timeout = parseInt(document.getElementById('singleTimeout').value);

        // Enhanced validation
        if (!this.validateIpInput(document.getElementById('ipAddress'))) {
            dashboard.showNotification('Please enter a valid IP address', 'danger');
            return;
        }

        const scanParams = {
            ipAddress,
            ports: this.parsePorts(ports),
            timeout
        };

        await this.performScan('single', scanParams);
    }

    async handleNetworkRangeScan(event) {
        event.preventDefault();
        
        if (this.isScanning) {
            dashboard.showNotification('A scan is already in progress. Please wait for it to complete.', 'warning');
            return;
        }

        const networkRange = document.getElementById('networkRange').value.trim();
        const ports = document.getElementById('networkPorts').value.trim();
        const timeout = parseInt(document.getElementById('networkTimeout').value);
        const maxConcurrency = parseInt(document.getElementById('maxConcurrency')?.value || 100);

        // Enhanced validation
        if (!this.validateCidrInput(document.getElementById('networkRange'))) {
            dashboard.showNotification('Please enter a valid CIDR notation', 'danger');
            return;
        }

        const scanParams = {
            networkRange,
            ports: this.parsePorts(ports),
            timeout,
            maxConcurrency
        };

        await this.performScan('network', scanParams);
    }

    async performScan(type, params) {
        try {
            this.startScan(type, params);
            
            const endpoint = type === 'single' ? '/api/NetworkScan/scan-ip' : '/api/NetworkScan/scan-network';
            const payload = type === 'single' 
                ? { ipAddress: params.ipAddress, ports: params.ports, timeout: params.timeout }
                : { networkRange: params.networkRange, ports: params.ports, timeout: params.timeout };

            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload)
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const results = await response.json();
            this.processScanResults(results);
            
        } catch (error) {
            console.error('Scan failed:', error);
            dashboard.showNotification(`Scan failed: ${error.message}`, 'danger');
        } finally {
            this.completeScan();
        }
    }

    startScan(type, params) {
        this.isScanning = true;
        this.scanStartTime = Date.now();
        this.progress.startTime = this.scanStartTime;
        
        // Calculate totals for progress tracking
        if (type === 'network') {
            this.calculateNetworkTotals(params.networkRange, params.ports);
        } else {
            this.progress.totalHosts = 1;
            this.progress.totalPorts = params.ports.length;
        }

        // Show progress UI
        this.showProgressCard();
        this.startProgressTracking();
        
        // Update UI states
        this.updateScanningState(true);
        
        dashboard.showNotification(`Starting ${type} scan...`, 'info');
    }

    calculateNetworkTotals(cidr, ports) {
        const [network, prefix] = cidr.split('/');
        const hostBits = 32 - parseInt(prefix);
        this.progress.totalHosts = Math.pow(2, hostBits) - 2; // Exclude network and broadcast
        this.progress.totalPorts = ports.length * this.progress.totalHosts;
    }

    showProgressCard() {
        const progressCard = document.getElementById('progressCard');
        if (progressCard) {
            progressCard.style.display = 'block';
            progressCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }
    }

    startProgressTracking() {
        this.progressInterval = setInterval(() => {
            this.updateProgressDisplay();
        }, 1000);
    }

    updateProgressDisplay() {
        const elapsedTime = Math.floor((Date.now() - this.progress.startTime) / 1000);
        
        // Update progress metrics
        document.getElementById('progressHosts').textContent = this.progress.hostsScanned;
        document.getElementById('progressPorts').textContent = this.progress.portsChecked;
        document.getElementById('progressOpen').textContent = this.progress.openPorts;
        document.getElementById('progressTime').textContent = `${elapsedTime}s`;
        
        // Update progress bar
        const progressPercent = this.progress.totalPorts > 0 
            ? (this.progress.portsChecked / this.progress.totalPorts) * 100 
            : 0;
        
        const progressBar = document.getElementById('progressBar');
        if (progressBar) {
            progressBar.style.width = `${Math.min(progressPercent, 100)}%`;
        }
        
        // Update progress text
        const progressText = document.getElementById('progressText');
        if (progressText) {
            if (this.progress.totalPorts > 0) {
                progressText.textContent = `Scanning... ${this.progress.portsChecked}/${this.progress.totalPorts} ports (${progressPercent.toFixed(1)}%)`;
            } else {
                progressText.textContent = 'Scanning in progress...';
            }
        }
    }

    processScanResults(results) {
        if (!Array.isArray(results)) {
            console.warn('Expected array of results, got:', typeof results);
            return;
        }

        // Process each result with enhanced data
        results.forEach(result => {
            const enhancedResult = {
                ...result,
                id: this.generateResultId(),
                discoveredAt: new Date().toISOString(),
                scanType: this.getCurrentScanType(),
                responseTime: result.PingTime || 0,
                security: this.assessSecurity(result),
                tags: this.generateTags(result)
            };
            
            this.scanResults.push(enhancedResult);
            this.progress.openPorts += result.IsOpen ? 1 : 0;
        });

        // Update displays
        this.updateResultsDisplay();
        this.updateStatistics();
        this.updateServiceFilter();
        
        // Save results
        this.saveResults();
        
        dashboard.showNotification(`Found ${results.length} results`, 'success');
    }

    generateResultId() {
        return 'result_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }

    getCurrentScanType() {
        // Determine scan type based on current form
        const singleForm = document.getElementById('singleIpForm');
        const networkForm = document.getElementById('networkRangeForm');
        
        if (singleForm && singleForm.contains(document.activeElement)) {
            return 'single';
        } else if (networkForm && networkForm.contains(document.activeElement)) {
            return 'network';
        }
        return 'unknown';
    }

    assessSecurity(result) {
        const port = result.Port;
        const service = result.ServiceName;
        
        // Enhanced security assessment
        if (!result.IsOpen) return { level: 'closed', score: 0 };
        
        const insecurePorts = [21, 23, 25, 53, 80, 110, 135, 139, 143, 445];
        const securePorts = [22, 443, 993, 995];
        
        if (securePorts.includes(port) || service?.includes('HTTPS') || service?.includes('SSH')) {
            return { level: 'secure', score: 8 };
        } else if (insecurePorts.includes(port)) {
            return { level: 'insecure', score: 3 };
        } else {
            return { level: 'unknown', score: 5 };
        }
    }

    generateTags(result) {
        const tags = [];
        
        if (result.IsOpen) tags.push('open');
        if (result.ServiceName) tags.push('identified');
        if (result.PingTime < 100) tags.push('fast');
        if (result.PingTime > 5000) tags.push('slow');
        
        return tags;
    }

    updateResultsDisplay() {
        this.renderResultsTable();
        this.showResultsSection();
    }

    renderResultsTable() {
        const tableBody = document.getElementById('resultsTableBody');
        if (!tableBody) return;

        // Apply filters and sorting
        let filteredResults = this.applyFiltersToResults(this.scanResults);
        filteredResults = this.applySortingToResults(filteredResults);

        tableBody.innerHTML = '';
        
        filteredResults.forEach(result => {
            const row = this.createResultRow(result);
            tableBody.appendChild(row);
        });
        
        // Update result count
        const resultCount = document.getElementById('resultCount');
        if (resultCount) {
            resultCount.textContent = filteredResults.length;
        }
    }

    createResultRow(result) {
        const row = document.createElement('tr');
        row.className = 'result-row';
        row.dataset.resultId = result.id;
        
        const securityClass = this.getSecurityClass(result.security?.level);
        const serviceIcon = Dashboard.getServiceIcon(result.ServiceName);
        const serviceColor = Dashboard.getServiceColor(result.ServiceName);
        
        row.innerHTML = `
            <td>
                <div class="d-flex align-items-center">
                    <span class="me-2">${Dashboard.formatIpAddress(result.IpAddress)}</span>
                    ${result.Hostname && result.Hostname !== result.IpAddress ? 
                        `<small class="text-muted">(${result.Hostname})</small>` : ''}
                </div>
            </td>
            <td>
                <span class="badge ${result.IsOpen ? 'bg-success' : 'bg-secondary'}">${result.Port}</span>
            </td>
            <td>
                <div class="d-flex align-items-center">
                    <i class="${serviceIcon} ${serviceColor} me-2"></i>
                    <span>${result.ServiceName || 'Unknown'}</span>
                    ${result.ServiceVersion ? `<small class="text-muted ms-1">v${result.ServiceVersion}</small>` : ''}
                </div>
            </td>
            <td>
                <span class="status-indicator ${result.IsOpen ? 'status-open' : 'status-closed'}">
                    <i class="fas fa-${result.IsOpen ? 'check-circle' : 'times-circle'}"></i>
                    ${result.IsOpen ? 'Open' : 'Closed'}
                </span>
                ${result.security ? `<div class="mt-1"><span class="security-level security-${result.security.level}">${result.security.level}</span></div>` : ''}
            </td>
            <td>
                <div class="text-end">
                    <div>${result.responseTime || result.PingTime || 0}ms</div>
                    <small class="text-muted">${Dashboard.formatTimestamp(result.discoveredAt || result.DiscoveredAt)}</small>
                </div>
            </td>
            <td>
                <div class="btn-group btn-group-sm">
                    <button class="btn btn-outline-light btn-sm" onclick="scanner.showResultDetails('${result.id}')" data-bs-toggle="tooltip" title="View details">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn btn-outline-primary btn-sm" onclick="scanner.rescanTarget('${result.IpAddress}', ${result.Port})" data-bs-toggle="tooltip" title="Rescan">
                        <i class="fas fa-redo"></i>
                    </button>
                    <button class="btn btn-outline-danger btn-sm" onclick="scanner.removeResult('${result.id}')" data-bs-toggle="tooltip" title="Remove">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </td>
        `;
        
        // Add highlight animation for new results
        if (result.isNew) {
            row.classList.add('result-highlight');
            setTimeout(() => {
                row.classList.remove('result-highlight');
                result.isNew = false;
            }, 2000);
        }
        
        return row;
    }

    getSecurityClass(level) {
        const classes = {
            'secure': 'text-success',
            'insecure': 'text-danger',
            'unknown': 'text-warning',
            'closed': 'text-muted'
        };
        return classes[level] || 'text-muted';
    }

    showResultsSection() {
        const emptyState = document.getElementById('emptyState');
        const scanResults = document.getElementById('scanResults');
        const filterControls = document.getElementById('filterControls');
        
        if (this.scanResults.length > 0) {
            if (emptyState) emptyState.style.display = 'none';
            if (scanResults) scanResults.style.display = 'block';
            if (filterControls) filterControls.style.display = 'block';
        } else {
            if (emptyState) emptyState.style.display = 'block';
            if (scanResults) scanResults.style.display = 'none';
            if (filterControls) filterControls.style.display = 'none';
        }
    }

    updateStatistics() {
        const stats = this.calculateStatistics();
        
        document.getElementById('totalHosts').textContent = stats.totalHosts;
        document.getElementById('openPorts').textContent = stats.openPorts;
        document.getElementById('uniqueServices').textContent = stats.uniqueServices;
        document.getElementById('scanDuration').textContent = stats.duration;
        document.getElementById('avgResponse').textContent = stats.avgResponse;
        document.getElementById('vulnerabilities').textContent = stats.vulnerabilities;
    }

    calculateStatistics() {
        const uniqueHosts = new Set(this.scanResults.map(r => r.IpAddress)).size;
        const openPorts = this.scanResults.filter(r => r.IsOpen).length;
        const uniqueServices = new Set(this.scanResults.filter(r => r.ServiceName).map(r => r.ServiceName)).size;
        const vulnerabilities = this.scanResults.filter(r => r.security?.level === 'insecure').length;
        
        const responseTimes = this.scanResults
            .map(r => r.responseTime || r.PingTime || 0)
            .filter(t => t > 0);
        const avgResponse = responseTimes.length > 0 
            ? Math.round(responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length) + 'ms'
            : 'N/A';
        
        const duration = this.scanStartTime 
            ? Math.round((Date.now() - this.scanStartTime) / 1000) + 's'
            : 'N/A';
        
        return {
            totalHosts: uniqueHosts,
            openPorts,
            uniqueServices,
            duration,
            avgResponse,
            vulnerabilities
        };
    }

    updateServiceFilter() {
        const serviceFilter = document.getElementById('serviceFilter');
        if (!serviceFilter) return;
        
        const services = [...new Set(this.scanResults
            .filter(r => r.ServiceName)
            .map(r => r.ServiceName)
        )].sort();
        
        // Clear existing options except the first one
        while (serviceFilter.children.length > 1) {
            serviceFilter.removeChild(serviceFilter.lastChild);
        }
        
        services.forEach(service => {
            const option = document.createElement('option');
            option.value = service;
            option.textContent = service;
            serviceFilter.appendChild(option);
        });
    }

    completeScan() {
        this.isScanning = false;
        this.updateScanningState(false);
        this.stopProgressTracking();
        
        const duration = this.scanStartTime ? Date.now() - this.scanStartTime : 0;
        dashboard.showNotification(`Scan completed in ${Math.round(duration / 1000)}s`, 'success');
        
        // Hide progress card after a delay
        setTimeout(() => {
            const progressCard = document.getElementById('progressCard');
            if (progressCard) {
                progressCard.style.display = 'none';
            }
        }, 5000);
    }

    stopProgressTracking() {
        if (this.progressInterval) {
            clearInterval(this.progressInterval);
            this.progressInterval = null;
        }
    }

    updateScanningState(isScanning) {
        const forms = document.querySelectorAll('#singleIpForm, #networkRangeForm');
        const submitButtons = document.querySelectorAll('#singleIpForm button[type="submit"], #networkRangeForm button[type="submit"]');
        
        forms.forEach(form => {
            if (isScanning) {
                form.classList.add('loading');
            } else {
                form.classList.remove('loading');
            }
        });
        
        submitButtons.forEach(button => {
            button.disabled = isScanning;
            if (isScanning) {
                button.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Scanning...';
            } else {
                const originalText = button.dataset.originalText || 'Start Scan';
                button.innerHTML = `<i class="fas fa-play me-2"></i>${originalText}`;
            }
        });
    }

    // Enhanced filtering and sorting methods
    applyFilters() {
        this.renderResultsTable();
    }

    applyFiltersToResults(results) {
        return results.filter(result => {
            // Search filter
            if (this.filters.search) {
                const searchText = this.filters.search;
                const searchableFields = [
                    result.IpAddress,
                    result.Port?.toString(),
                    result.ServiceName,
                    result.Hostname
                ].filter(Boolean).join(' ').toLowerCase();
                
                if (!searchableFields.includes(searchText)) {
                    return false;
                }
            }
            
            // Service filter
            if (this.filters.service && result.ServiceName !== this.filters.service) {
                return false;
            }
            
            // Status filter
            if (this.filters.status) {
                if (this.filters.status === 'open' && !result.IsOpen) return false;
                if (this.filters.status === 'closed' && result.IsOpen) return false;
                if (this.filters.status === 'filtered' && result.IsOpen !== undefined) return false;
            }
            
            return true;
        });
    }

    applySortingToResults(results) {
        if (!this.sortColumn) return results;
        
        return results.sort((a, b) => {
            let aVal, bVal;
            
            switch (this.sortColumn) {
                case 'ip':
                    aVal = this.ipToNumber(a.IpAddress);
                    bVal = this.ipToNumber(b.IpAddress);
                    break;
                case 'port':
                    aVal = a.Port || 0;
                    bVal = b.Port || 0;
                    break;
                case 'service':
                    aVal = a.ServiceName || '';
                    bVal = b.ServiceName || '';
                    break;
                case 'status':
                    aVal = a.IsOpen ? 1 : 0;
                    bVal = b.IsOpen ? 1 : 0;
                    break;
                case 'time':
                    aVal = a.responseTime || a.PingTime || 0;
                    bVal = b.responseTime || b.PingTime || 0;
                    break;
                default:
                    return 0;
            }
            
            if (aVal < bVal) return this.sortDirection === 'asc' ? -1 : 1;
            if (aVal > bVal) return this.sortDirection === 'asc' ? 1 : -1;
            return 0;
        });
    }

    sortTable(column) {
        if (this.sortColumn === column) {
            this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            this.sortColumn = column;
            this.sortDirection = 'asc';
        }
        
        this.updateSortIndicators();
        this.renderResultsTable();
    }

    updateSortIndicators() {
        document.querySelectorAll('.sortable i.fa-sort, .sortable i.fa-sort-up, .sortable i.fa-sort-down')
            .forEach(icon => {
                icon.className = 'fas fa-sort ms-1';
            });
        
        const currentHeader = document.querySelector(`[data-sort="${this.sortColumn}"] i`);
        if (currentHeader) {
            currentHeader.className = `fas fa-sort-${this.sortDirection === 'asc' ? 'up' : 'down'} ms-1`;
        }
    }

    resetFilters() {
        this.filters = { search: '', service: '', status: '' };
        
        document.getElementById('searchFilter').value = '';
        document.getElementById('serviceFilter').value = '';
        document.getElementById('statusFilter').value = '';
        
        this.applyFilters();
        dashboard.showNotification('Filters reset', 'info', 2000);
    }

    ipToNumber(ip) {
        return ip.split('.').reduce((num, octet) => (num << 8) + parseInt(octet), 0);
    }

    // Enhanced utility methods
    parsePorts(portsString) {
        if (!portsString || portsString.trim() === '') {
            return [22, 80, 443, 21, 23, 25, 53, 110, 143, 993, 995]; // Default common ports
        }
        
        return portsString.split(',')
            .map(p => parseInt(p.trim()))
            .filter(p => p > 0 && p <= 65535);
    }

    triggerQuickScan() {
        const ipInput = document.getElementById('ipAddress');
        if (ipInput && ipInput.value.trim()) {
            document.getElementById('singleIpForm').dispatchEvent(new Event('submit'));
        } else {
            dashboard.showNotification('Enter an IP address for quick scan', 'info');
            ipInput?.focus();
        }
    }

    refreshResults() {
        this.renderResultsTable();
        this.updateStatistics();
        dashboard.showNotification('Results refreshed', 'success', 2000);
    }

    stopScan() {
        if (this.isScanning) {
            this.isScanning = false;
            this.updateScanningState(false);
            this.stopProgressTracking();
            dashboard.showNotification('Scan stopped by user', 'warning');
        }
    }

    pauseScan() {
        // Implement pause functionality for offline scenarios
        if (this.isScanning) {
            dashboard.showNotification('Scan paused due to connection loss', 'warning');
        }
    }

    updateConnectionStatus(isOnline) {
        const indicator = document.getElementById('connection-indicator');
        if (indicator) {
            indicator.className = `position-fixed bottom-0 end-0 m-3 badge ${isOnline ? 'bg-success' : 'bg-danger'}`;
            indicator.innerHTML = `<i class="fas fa-${isOnline ? 'wifi' : 'wifi-slash'}"></i> ${isOnline ? 'Online' : 'Offline'}`;
        }
    }

    // Advanced features
    showResultDetails(resultId) {
        const result = this.scanResults.find(r => r.id === resultId);
        if (!result) return;
        
        const detailsHtml = `
            <div class="modal fade" id="resultDetailsModal" tabindex="-1">
                <div class="modal-dialog modal-lg">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">
                                <i class="fas fa-info-circle me-2"></i>
                                Scan Result Details
                            </h5>
                            <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body">
                            <div class="row">
                                <div class="col-md-6">
                                    <h6>Network Information</h6>
                                    <table class="table table-sm table-dark">
                                        <tr><td>IP Address</td><td>${result.IpAddress}</td></tr>
                                        <tr><td>Port</td><td>${result.Port}</td></tr>
                                        <tr><td>Status</td><td>${result.IsOpen ? 'Open' : 'Closed'}</td></tr>
                                        <tr><td>Service</td><td>${result.ServiceName || 'Unknown'}</td></tr>
                                        <tr><td>Response Time</td><td>${result.responseTime || result.PingTime || 0}ms</td></tr>
                                    </table>
                                </div>
                                <div class="col-md-6">
                                    <h6>Security Assessment</h6>
                                    <table class="table table-sm table-dark">
                                        <tr><td>Security Level</td><td><span class="security-level security-${result.security?.level || 'unknown'}">${result.security?.level || 'Unknown'}</span></td></tr>
                                        <tr><td>Risk Score</td><td>${result.security?.score || 'N/A'}/10</td></tr>
                                        <tr><td>Discovered</td><td>${Dashboard.formatTimestamp(result.discoveredAt || result.DiscoveredAt)}</td></tr>
                                        <tr><td>Scan Type</td><td>${result.scanType || 'Unknown'}</td></tr>
                                    </table>
                                </div>
                            </div>
                            ${result.tags && result.tags.length > 0 ? `
                                <div class="mt-3">
                                    <h6>Tags</h6>
                                    ${result.tags.map(tag => `<span class="badge bg-secondary me-1">${tag}</span>`).join('')}
                                </div>
                            ` : ''}
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-primary" onclick="scanner.rescanTarget('${result.IpAddress}', ${result.Port})">
                                <i class="fas fa-redo me-1"></i>Rescan
                            </button>
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Remove existing modal
        const existingModal = document.getElementById('resultDetailsModal');
        if (existingModal) {
            existingModal.remove();
        }
        
        document.body.insertAdjacentHTML('beforeend', detailsHtml);
        const modal = new bootstrap.Modal(document.getElementById('resultDetailsModal'));
        modal.show();
    }

    async rescanTarget(ipAddress, port) {
        dashboard.showNotification(`Rescanning ${ipAddress}:${port}...`, 'info');
        
        try {
            const response = await fetch('/api/NetworkScan/scan-ip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ipAddress: ipAddress,
                    ports: [port],
                    timeout: 5000
                })
            });
            
            if (response.ok) {
                const results = await response.json();
                dashboard.showNotification('Rescan completed', 'success');
                // Update existing result or add new one
                this.updateExistingResult(ipAddress, port, results[0]);
            }
        } catch (error) {
            dashboard.showNotification(`Rescan failed: ${error.message}`, 'danger');
        }
    }

    updateExistingResult(ipAddress, port, newResult) {
        const existingIndex = this.scanResults.findIndex(r => 
            r.IpAddress === ipAddress && r.Port === port
        );
        
        if (existingIndex !== -1) {
            this.scanResults[existingIndex] = {
                ...this.scanResults[existingIndex],
                ...newResult,
                discoveredAt: new Date().toISOString(),
                isNew: true
            };
        } else {
            this.scanResults.push({
                ...newResult,
                id: this.generateResultId(),
                discoveredAt: new Date().toISOString(),
                isNew: true
            });
        }
        
        this.updateResultsDisplay();
        this.updateStatistics();
    }

    removeResult(resultId) {
        const index = this.scanResults.findIndex(r => r.id === resultId);
        if (index !== -1) {
            this.scanResults.splice(index, 1);
            this.updateResultsDisplay();
            this.updateStatistics();
            this.saveResults();
            dashboard.showNotification('Result removed', 'info', 2000);
        }
    }

    clearResults() {
        if (this.scanResults.length === 0) {
            dashboard.showNotification('No results to clear', 'info', 2000);
            return;
        }
        
        if (confirm(`Are you sure you want to clear all ${this.scanResults.length} results?`)) {
            this.scanResults = [];
            this.updateResultsDisplay();
            this.updateStatistics();
            this.saveResults();
            dashboard.showNotification('All results cleared', 'success');
        }
    }

    exportResults(format = 'json') {
        if (this.scanResults.length === 0) {
            dashboard.showNotification('No results to export', 'warning');
            return;
        }
        
        const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
        const filename = `network-scan-results-${timestamp}`;
        
        let content, mimeType;
        
        if (format === 'csv') {
            content = this.generateCSV();
            mimeType = 'text/csv';
        } else {
            content = JSON.stringify(this.scanResults, null, 2);
            mimeType = 'application/json';
        }
        
        this.downloadFile(content, `${filename}.${format}`, mimeType);
        dashboard.showNotification(`Results exported as ${format.toUpperCase()}`, 'success');
    }

    generateCSV() {
        const headers = ['IP Address', 'Port', 'Status', 'Service', 'Response Time', 'Discovered At', 'Security Level'];
        const rows = [headers.join(',')];
        
        this.scanResults.forEach(result => {
            const row = [
                result.IpAddress,
                result.Port,
                result.IsOpen ? 'Open' : 'Closed',
                result.ServiceName || 'Unknown',
                result.responseTime || result.PingTime || 0,
                result.discoveredAt || result.DiscoveredAt,
                result.security?.level || 'Unknown'
            ].map(field => `"${field}"`);
            rows.push(row.join(','));
        });
        
        return rows.join('\n');
    }

    downloadFile(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    shareResults() {
        if (navigator.share && this.scanResults.length > 0) {
            const stats = this.calculateStatistics();
            navigator.share({
                title: 'Network Scan Results',
                text: `Found ${stats.openPorts} open ports on ${stats.totalHosts} hosts. ${stats.uniqueServices} unique services detected.`,
                url: window.location.href
            }).catch(err => console.log('Share failed:', err));
        } else {
            // Fallback: copy summary to clipboard
            const stats = this.calculateStatistics();
            const summary = `Network Scan Results: ${stats.openPorts} open ports on ${stats.totalHosts} hosts. ${stats.uniqueServices} unique services detected. Completed in ${stats.duration}.`;
            
            navigator.clipboard.writeText(summary).then(() => {
                dashboard.showNotification('Summary copied to clipboard', 'success');
            }).catch(() => {
                dashboard.showNotification('Share not available', 'info');
            });
        }
    }

    showProgressDetails() {
        // Show detailed progress information
        const details = `
            Scan Progress Details:
            • Hosts Scanned: ${this.progress.hostsScanned}/${this.progress.totalHosts}
            • Ports Checked: ${this.progress.portsChecked}/${this.progress.totalPorts}
            • Open Ports Found: ${this.progress.openPorts}
            • Elapsed Time: ${Math.floor((Date.now() - this.progress.startTime) / 1000)}s
        `;
        
        dashboard.showNotification(details, 'info', 8000);
    }

    // Storage methods
    saveResults() {
        try {
            localStorage.setItem('networkScanResults', JSON.stringify(this.scanResults));
        } catch (error) {
            console.warn('Failed to save results to localStorage:', error);
        }
    }

    loadStoredResults() {
        try {
            const stored = localStorage.getItem('networkScanResults');
            if (stored) {
                this.scanResults = JSON.parse(stored);
                this.updateResultsDisplay();
                this.updateStatistics();
                this.updateServiceFilter();
            }
        } catch (error) {
            console.warn('Failed to load stored results:', error);
        }
    }
}

// Initialize scanner when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.scanner = new NetworkScanner();
});

// Export for global access
window.NetworkScanner = NetworkScanner;