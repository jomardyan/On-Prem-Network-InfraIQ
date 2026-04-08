// Network Scanner JavaScript - Enhanced Version with SignalR Real-time Updates

class NetworkScanner {
    constructor() {
        this.scanResults = [];
        this.isScanning = false;
        this.scanStartTime = null;
        this.progressInterval = null;
        this.progressUpdater = null;
        this.sortColumn = null;
        this.sortDirection = 'asc';
        this.connection = null; // SignalR connection
        this.currentScanId = null;
        this.vulnerabilityAlerts = [];
        this.filters = {
            search: '',
            service: '',
            status: ''
        };
        this.progress = {
            hostsScanned: 0,
            portsChecked: 0,
            openPorts: 0,
            totalHosts: 0,
            totalPorts: 0,
            startTime: null
        };
        this.init();
    }

    async init() {
        this.bindEvents();
        this.loadStoredResults();
        this.initEnhancements();
        await this.initSignalR();
    }

    async initSignalR() {
        try {
            this.connection = new signalR.HubConnectionBuilder()
                .withUrl("/scanHub")
                .withAutomaticReconnect()
                .build();

            // Handle scan updates
            this.connection.on("ReceiveScanUpdate", (update) => {
                this.handleRealTimeScanUpdate(update);
            });

            // Handle scan progress
            this.connection.on("ReceiveScanProgress", (progress) => {
                this.updateRealTimeProgress(progress);
            });

            // Handle vulnerability alerts
            this.connection.on("ReceiveVulnerabilityAlert", (alert) => {
                this.showVulnerabilityAlert(alert);
            });

            await this.connection.start();
            console.log("SignalR Connected for real-time updates");
            this.showNotification("Connected to real-time updates", "success");

        } catch (err) {
            console.error("SignalR Connection failed:", err);
            this.showNotification("Real-time updates unavailable", "warning");
        }
    }

    handleRealTimeScanUpdate(update) {
        // Add to results
        this.scanResults.push(update);
        this.addRowToTable(update);
        this.updateProgress();
        this.saveResults();
        
        // Play notification sound if enabled
        this.playNotificationSound('result');
    }

    updateRealTimeProgress(progress) {
        // Update progress display
        this.updateProgressDisplay(progress);
        
        // Update statistics
        this.updateStatistics(progress);
    }

    showVulnerabilityAlert(alert) {
        this.vulnerabilityAlerts.push(alert);
        this.displayVulnerabilityAlert(alert);
        this.playNotificationSound('vulnerability');
    }

    displayVulnerabilityAlert(alert) {
        const alertsContainer = this.getOrCreateAlertsContainer();
        const alertElement = document.createElement('div');
        alertElement.className = `alert alert-${this.getSeverityClass(alert.Severity)} vulnerability-alert`;
        alertElement.innerHTML = `
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <h6 class="alert-heading mb-1">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        ${alert.Title}
                    </h6>
                    <p class="mb-1"><strong>${alert.Host}:${alert.Port || 'N/A'}</strong></p>
                    <small>${alert.Description}</small>
                    ${alert.CveId ? `<br><small class="badge bg-danger">CVE: ${alert.CveId}</small>` : ''}
                    ${alert.CvssScore ? `<small class="badge bg-warning ms-1">CVSS: ${alert.CvssScore}</small>` : ''}
                </div>
                <button type="button" class="btn-close" onclick="this.parentElement.parentElement.remove()"></button>
            </div>
        `;
        
        alertsContainer.appendChild(alertElement);
        
        // Auto-remove after 15 seconds
        setTimeout(() => {
            if (alertElement.parentNode) {
                alertElement.remove();
            }
        }, 15000);
    }

    getOrCreateAlertsContainer() {
        let container = document.getElementById('vulnerabilityAlerts');
        if (!container) {
            container = document.createElement('div');
            container.id = 'vulnerabilityAlerts';
            container.className = 'vulnerability-alerts-container';
            container.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 1050;
                max-width: 400px;
            `;
            document.body.appendChild(container);
        }
        return container;
    }

    getSeverityClass(severity) {
        const severityMap = {
            0: 'info',    // Info
            1: 'warning', // Low
            2: 'warning', // Medium
            3: 'danger',  // High
            4: 'danger'   // Critical
        };
        return severityMap[severity] || 'info';
    }

    playNotificationSound(type) {
        const settings = this.loadSettings();
        if (!settings.soundEffects) return;

        try {
            if (!this.audioContext) {
                this.audioContext = new (window.AudioContext || window.webkitAudioContext)();
            }

            const frequencies = {
                'result': 800,
                'vulnerability': 400,
                'complete': 600,
                'error': 300
            };

            const frequency = frequencies[type] || 600;
            this.playBeep(frequency, 0.1, 150);
        } catch (error) {
            console.warn('Audio not available:', error);
        }
    }

    playBeep(frequency, volume, duration) {
        if (!this.audioContext) return;

        const oscillator = this.audioContext.createOscillator();
        const gainNode = this.audioContext.createGain();

        oscillator.connect(gainNode);
        gainNode.connect(this.audioContext.destination);

        gainNode.gain.value = volume;
        oscillator.frequency.value = frequency;
        oscillator.type = 'sine';

        oscillator.start();
        oscillator.stop(this.audioContext.currentTime + duration / 1000);
    }

    loadSettings() {
        const defaultSettings = {
            soundEffects: true,
            autoExport: false,
            darkMode: true,
            maxResults: 1000
        };

        try {
            const saved = localStorage.getItem('scannerSettings');
            return saved ? { ...defaultSettings, ...JSON.parse(saved) } : defaultSettings;
        } catch {
            return defaultSettings;
        }
    }

    showNotification(message, type = 'info', duration = 4000) {
        // Create toast notification
        const toast = document.createElement('div');
        toast.className = `toast align-items-center text-white bg-${type} border-0`;
        toast.setAttribute('role', 'alert');
        toast.innerHTML = `
            <div class="d-flex">
                <div class="toast-body">
                    <i class="fas fa-${this.getNotificationIcon(type)} me-2"></i>
                    ${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        `;

        // Add to toast container
        let toastContainer = document.getElementById('toast-container');
        if (!toastContainer) {
            toastContainer = document.createElement('div');
            toastContainer.id = 'toast-container';
            toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
            toastContainer.style.zIndex = '1080';
            document.body.appendChild(toastContainer);
        }

        toastContainer.appendChild(toast);
        const bsToast = new bootstrap.Toast(toast, { delay: duration });
        bsToast.show();

        toast.addEventListener('hidden.bs.toast', () => {
            toast.remove();
        });
    }

    getNotificationIcon(type) {
        const icons = {
            'success': 'check-circle',
            'error': 'exclamation-circle',
            'warning': 'exclamation-triangle',
            'info': 'info-circle'
        };
        return icons[type] || 'info-circle';
    }

    updateProgressDisplay(progress) {
        // Update progress bar
        const progressBar = document.getElementById('progressBar');
        if (progressBar) {
            progressBar.style.width = `${progress.PercentComplete}%`;
            progressBar.setAttribute('aria-valuenow', progress.PercentComplete);
        }

        // Update status text
        const statusElement = document.getElementById('scanStatus');
        if (statusElement) {
            statusElement.textContent = progress.StatusMessage || progress.CurrentStage;
        }
    }

    updateStatistics(progress) {
        // Update real-time statistics
        const elements = {
            'hostsScanned': progress.HostsScanned,
            'hostsDiscovered': progress.HostsDiscovered,
            'openPorts': progress.OpenPorts,
            'vulnerabilities': progress.VulnerabilitiesFound,
            'scanSpeed': progress.ScanSpeed ? progress.ScanSpeed.toFixed(1) : '0'
        };

        Object.entries(elements).forEach(([id, value]) => {
            const element = document.getElementById(id);
            if (element) {
                element.textContent = value || '0';
            }
        });

        // Update time remaining
        if (progress.EstimatedTimeRemaining) {
            const timeElement = document.getElementById('timeRemaining');
            if (timeElement) {
                timeElement.textContent = `ETA: ${this.formatTimeSpan(progress.EstimatedTimeRemaining)}`;
            }
        }
    }

    formatTimeSpan(timeSpan) {
        if (typeof timeSpan === 'string') {
            return timeSpan;
        }
        
        const hours = Math.floor(timeSpan / 3600);
        const minutes = Math.floor((timeSpan % 3600) / 60);
        const seconds = Math.floor(timeSpan % 60);
        
        if (hours > 0) {
            return `${hours}h ${minutes}m`;
        } else if (minutes > 0) {
            return `${minutes}m ${seconds}s`;
        } else {
            return `${seconds}s`;
        }
    }

    generateScanId() {
        return 'scan_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }

    initEnhancements() {
        this.initKeyboardShortcuts();
        this.initFiltering();
        this.initTableSorting();
        this.initAutoSave();
        this.initConnectionMonitoring();
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
        setInterval(() => {
            if (this.scanResults.length > 0) {
                this.saveResults();
            }
        }, 30000);
    }

    initConnectionMonitoring() {
        window.addEventListener('online', () => {
            this.showNotification('Connection restored. You can continue scanning.', 'success');
        });

        window.addEventListener('offline', () => {
            this.showNotification('Connection lost. Scanning will be paused.', 'warning');
            if (this.isScanning) {
                this.pauseScan();
            }
        });
    }

    bindEvents() {
        this.bindFormEvents();
        this.bindButtonEvents();
    }

    bindFormEvents() {
        const singleIpForm = document.getElementById('singleIpForm');
        if (singleIpForm) {
            singleIpForm.addEventListener('submit', (e) => this.handleSingleIpScan(e));
            
            const ipInput = document.getElementById('ipAddress');
            if (ipInput) {
                ipInput.addEventListener('input', (e) => this.validateIpInput(e.target));
            }
        }

        const networkRangeForm = document.getElementById('networkRangeForm');
        if (networkRangeForm) {
            networkRangeForm.addEventListener('submit', (e) => this.handleNetworkRangeScan(e));
            
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

        const exportJsonBtn = document.getElementById('exportJson');
        if (exportJsonBtn) {
            exportJsonBtn.addEventListener('click', () => this.exportResults('json'));
        }

        const exportCsvBtn = document.getElementById('exportCsv');
        if (exportCsvBtn) {
            exportCsvBtn.addEventListener('click', () => this.exportResults('csv'));
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
            this.showNotification('A scan is already in progress. Please wait for it to complete.', 'warning');
            return;
        }

        const ipAddress = document.getElementById('ipAddress').value.trim();
        const ports = document.getElementById('singlePorts').value.trim();
        const timeout = parseInt(document.getElementById('singleTimeout').value);

        if (!this.validateIpInput(document.getElementById('ipAddress'))) {
            this.showNotification('Please enter a valid IP address', 'danger');
            return;
        }

        const scanParams = {
            ipAddress,
            ports: this.parsePorts(ports),
            timeoutMs: timeout
        };

        await this.performScan('single', scanParams);
    }

    async handleNetworkRangeScan(event) {
        event.preventDefault();
        
        if (this.isScanning) {
            this.showNotification('A scan is already in progress. Please wait for it to complete.', 'warning');
            return;
        }

        const networkRange = document.getElementById('networkRange').value.trim();
        const ports = document.getElementById('networkPorts').value.trim();
        const timeout = parseInt(document.getElementById('networkTimeout').value);

        if (!this.validateCidrInput(document.getElementById('networkRange'))) {
            this.showNotification('Please enter a valid CIDR notation', 'danger');
            return;
        }

        const scanParams = {
            networkRange,
            ports: this.parsePorts(ports),
            timeoutMs: timeout
        };

        await this.performScan('network', scanParams);
    }

    async performScan(type, params) {
        try {
            this.startScan(type, params);
            
            const endpoint = type === 'single' ? '/api/NetworkScan/scan-ip' : '/api/NetworkScan/scan-network';
            const payload = type === 'single' 
                ? { ipAddress: params.ipAddress, ports: params.ports, timeoutMs: params.timeoutMs }
                : { networkRange: params.networkRange, ports: params.ports, timeoutMs: params.timeoutMs };

            console.log('Making API request to:', endpoint);
            console.log('Payload:', payload);

            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(payload)
            });

            console.log('Response status:', response.status);

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`HTTP ${response.status}: ${errorText}`);
            }

            const results = await response.json();
            console.log('Scan results:', results);
            
            this.processScanResults(results, type);
            
        } catch (error) {
            console.error('Scan failed:', error);
            this.showNotification(`Scan failed: ${error.message}`, 'danger');
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
        
        this.showNotification(`Starting ${type} scan...`, 'info');
    }

    calculateNetworkTotals(cidr, ports) {
        const [network, prefix] = cidr.split('/');
        const hostBits = 32 - parseInt(prefix);
        this.progress.totalHosts = Math.pow(2, hostBits) - 2;
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
        // Start progress updates every second
        this.progressInterval = setInterval(() => {
            this.updateProgressDisplay();
        }, 1000);

        // Start simulated progress updates every 5 seconds for better user feedback
        this.progressUpdater = setInterval(() => {
            this.updateSimulatedProgress();
        }, 5000);
    }

    updateProgressDisplay() {
        const elapsedTime = Math.floor((Date.now() - this.progress.startTime) / 1000);
        
        // Update progress metrics
        const progressHosts = document.getElementById('progressHosts');
        const progressPorts = document.getElementById('progressPorts');
        const progressOpen = document.getElementById('progressOpen');
        const progressTime = document.getElementById('progressTime');
        
        if (progressHosts) progressHosts.textContent = this.progress.hostsScanned;
        if (progressPorts) progressPorts.textContent = this.progress.portsChecked;
        if (progressOpen) progressOpen.textContent = this.progress.openPorts;
        if (progressTime) progressTime.textContent = `${elapsedTime}s`;
        
        // Update progress bar
        const progressPercent = this.progress.totalPorts > 0 
            ? (this.progress.portsChecked / this.progress.totalPorts) * 100 
            : Math.min(elapsedTime * 2, 95); // Fallback for indeterminate progress
        
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
                progressText.textContent = `Scanning in progress... (${elapsedTime}s elapsed)`;
            }
        }
    }

    updateSimulatedProgress() {
        // Simulate progress for better user feedback when actual progress isn't available
        if (this.isScanning && this.progress.totalPorts > 0) {
            const increment = Math.floor(this.progress.totalPorts * 0.1);
            this.progress.portsChecked = Math.min(
                this.progress.portsChecked + increment, 
                this.progress.totalPorts * 0.9 // Don't go to 100% until scan completes
            );
            
            // Simulate host scanning progress
            const hostIncrement = Math.floor(this.progress.totalHosts * 0.15);
            this.progress.hostsScanned = Math.min(
                this.progress.hostsScanned + hostIncrement,
                this.progress.totalHosts * 0.9
            );
        }
    }

    processScanResults(results, scanType) {
        console.log('Processing scan results:', results);
        
        // Handle different response formats
        let scanData = [];
        
        if (Array.isArray(results)) {
            scanData = results;
        } else if (results.scanResults && Array.isArray(results.scanResults)) {
            scanData = results.scanResults;
        } else if (results.ScanResults && Array.isArray(results.ScanResults)) {
            scanData = results.ScanResults;
        } else {
            console.warn('Unexpected results format:', results);
            scanData = [];
        }

        if (scanData.length === 0) {
            this.showNotification('Scan completed. No open ports found.', 'info');
            return;
        }

        // Process each result with enhanced data
        scanData.forEach(result => {
            const enhancedResult = {
                ...result,
                id: this.generateResultId(),
                discoveredAt: new Date().toISOString(),
                scanType: scanType,
                responseTime: result.PingTime || result.pingTime || 0,
                security: this.assessSecurity(result),
                tags: this.generateTags(result)
            };
            
            this.scanResults.push(enhancedResult);
            this.progress.openPorts += (result.IsOpen || result.isOpen) ? 1 : 0;
        });

        // Update displays
        this.updateResultsDisplay();
        this.updateStatistics();
        this.updateServiceFilter();
        
        // Save results
        this.saveResults();
        
        this.showNotification(`Found ${scanData.length} results`, 'success');
    }

    generateResultId() {
        return 'result_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }

    assessSecurity(result) {
        const port = result.Port || result.port;
        const service = result.ServiceName || result.serviceName || result.service;
        
        if (!(result.IsOpen || result.isOpen)) return { level: 'closed', score: 0 };
        
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
        const isOpen = result.IsOpen || result.isOpen;
        const pingTime = result.PingTime || result.pingTime || 0;
        const serviceName = result.ServiceName || result.serviceName || result.service;
        
        if (isOpen) tags.push('open');
        if (serviceName) tags.push('identified');
        if (pingTime < 100) tags.push('fast');
        if (pingTime > 5000) tags.push('slow');
        
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
        
        const ipAddress = result.IpAddress || result.ipAddress;
        const port = result.Port || result.port;
        const serviceName = result.ServiceName || result.serviceName || result.service || 'Unknown';
        const isOpen = result.IsOpen || result.isOpen;
        const responseTime = result.responseTime || result.PingTime || result.pingTime || 0;
        const hostname = result.Hostname || result.hostname;
        
        row.innerHTML = `
            <td>
                <div class="d-flex align-items-center">
                    <span class="me-2">${ipAddress}</span>
                    ${hostname && hostname !== ipAddress ? 
                        `<small class="text-muted">(${hostname})</small>` : ''}
                </div>
            </td>
            <td>
                <span class="badge ${isOpen ? 'bg-success' : 'bg-secondary'}">${port}</span>
            </td>
            <td>
                <div class="d-flex align-items-center">
                    <i class="fas fa-cog me-2"></i>
                    <span>${serviceName}</span>
                </div>
            </td>
            <td>
                <span class="status-indicator ${isOpen ? 'status-open' : 'status-closed'}">
                    <i class="fas fa-${isOpen ? 'check-circle' : 'times-circle'}"></i>
                    ${isOpen ? 'Open' : 'Closed'}
                </span>
                ${result.security ? `<div class="mt-1"><span class="security-level security-${result.security.level}">${result.security.level}</span></div>` : ''}
            </td>
            <td>
                <div class="text-end">
                    <div>${responseTime}ms</div>
                    <small class="text-muted">${this.formatTimestamp(result.discoveredAt)}</small>
                </div>
            </td>
            <td>
                <div class="btn-group btn-group-sm">
                    <button class="btn btn-outline-light btn-sm" onclick="scanner.showResultDetails('${result.id}')" data-bs-toggle="tooltip" title="View details">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn btn-outline-primary btn-sm" onclick="scanner.rescanTarget('${ipAddress}', ${port})" data-bs-toggle="tooltip" title="Rescan">
                        <i class="fas fa-redo"></i>
                    </button>
                    <button class="btn btn-outline-danger btn-sm" onclick="scanner.removeResult('${result.id}')" data-bs-toggle="tooltip" title="Remove">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </td>
        `;
        
        return row;
    }

    formatTimestamp(timestamp) {
        if (!timestamp) return 'Unknown';
        try {
            return new Date(timestamp).toLocaleString();
        } catch (e) {
            return 'Invalid date';
        }
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
        
        const elements = {
            totalHosts: document.getElementById('totalHosts'),
            openPorts: document.getElementById('openPorts'),
            uniqueServices: document.getElementById('uniqueServices'),
            scanDuration: document.getElementById('scanDuration'),
            avgResponse: document.getElementById('avgResponse'),
            vulnerabilities: document.getElementById('vulnerabilities')
        };

        Object.keys(elements).forEach(key => {
            if (elements[key]) {
                elements[key].textContent = stats[key];
            }
        });
    }

    calculateStatistics() {
        const uniqueHosts = new Set(this.scanResults.map(r => r.IpAddress || r.ipAddress)).size;
        const openPorts = this.scanResults.filter(r => r.IsOpen || r.isOpen).length;
        const uniqueServices = new Set(this.scanResults
            .filter(r => r.ServiceName || r.serviceName || r.service)
            .map(r => r.ServiceName || r.serviceName || r.service)).size;
        const vulnerabilities = this.scanResults.filter(r => r.security?.level === 'insecure').length;
        
        const responseTimes = this.scanResults
            .map(r => r.responseTime || r.PingTime || r.pingTime || 0)
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
            scanDuration: duration,
            avgResponse,
            vulnerabilities
        };
    }

    updateServiceFilter() {
        const serviceFilter = document.getElementById('serviceFilter');
        if (!serviceFilter) return;
        
        const services = [...new Set(this.scanResults
            .filter(r => r.ServiceName || r.serviceName || r.service)
            .map(r => r.ServiceName || r.serviceName || r.service)
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
        
        // Complete the progress bar
        this.progress.portsChecked = this.progress.totalPorts;
        this.progress.hostsScanned = this.progress.totalHosts;
        this.updateProgressDisplay();
        
        this.updateScanningState(false);
        this.stopProgressTracking();
        
        const duration = this.scanStartTime ? Date.now() - this.scanStartTime : 0;
        this.showNotification(`Scan completed in ${Math.round(duration / 1000)}s`, 'success');
        
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
        if (this.progressUpdater) {
            clearInterval(this.progressUpdater);
            this.progressUpdater = null;
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
                if (!button.dataset.originalText) {
                    button.dataset.originalText = button.textContent;
                }
                button.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Scanning...';
            } else {
                const originalText = button.dataset.originalText || 'Start Scan';
                button.innerHTML = `<i class="fas fa-play me-2"></i>${originalText}`;
            }
        });
    }

    // Utility methods
    parsePorts(portsString) {
        if (!portsString || portsString.trim() === '') {
            return [22, 80, 443, 21, 23, 25, 53, 110, 143, 993, 995]; // Default common ports
        }
        
        return portsString.split(',')
            .map(p => parseInt(p.trim()))
            .filter(p => p > 0 && p <= 65535);
    }

    showNotification(message, type = 'info', duration = 5000) {
        // Try to use dashboard notification if available
        if (window.dashboard && window.dashboard.showNotification) {
            window.dashboard.showNotification(message, type, duration);
        } else {
            // Fallback to console and alert for critical messages
            console.log(`[${type.toUpperCase()}] ${message}`);
            if (type === 'danger' || type === 'error') {
                alert(message);
            }
        }
    }

    // Filtering and sorting methods
    applyFilters() {
        this.renderResultsTable();
    }

    applyFiltersToResults(results) {
        return results.filter(result => {
            const ipAddress = result.IpAddress || result.ipAddress || '';
            const port = (result.Port || result.port || '').toString();
            const serviceName = result.ServiceName || result.serviceName || result.service || '';
            const hostname = result.Hostname || result.hostname || '';
            const isOpen = result.IsOpen || result.isOpen;

            // Search filter
            if (this.filters.search) {
                const searchableFields = [ipAddress, port, serviceName, hostname].join(' ').toLowerCase();
                if (!searchableFields.includes(this.filters.search)) {
                    return false;
                }
            }
            
            // Service filter
            if (this.filters.service && serviceName !== this.filters.service) {
                return false;
            }
            
            // Status filter
            if (this.filters.status) {
                if (this.filters.status === 'open' && !isOpen) return false;
                if (this.filters.status === 'closed' && isOpen) return false;
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
                    aVal = this.ipToNumber(a.IpAddress || a.ipAddress);
                    bVal = this.ipToNumber(b.IpAddress || b.ipAddress);
                    break;
                case 'port':
                    aVal = a.Port || a.port || 0;
                    bVal = b.Port || b.port || 0;
                    break;
                case 'service':
                    aVal = a.ServiceName || a.serviceName || a.service || '';
                    bVal = b.ServiceName || b.serviceName || b.service || '';
                    break;
                case 'status':
                    aVal = (a.IsOpen || a.isOpen) ? 1 : 0;
                    bVal = (b.IsOpen || b.isOpen) ? 1 : 0;
                    break;
                case 'time':
                    aVal = a.responseTime || a.PingTime || a.pingTime || 0;
                    bVal = b.responseTime || b.PingTime || b.pingTime || 0;
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
        
        const searchFilter = document.getElementById('searchFilter');
        const serviceFilter = document.getElementById('serviceFilter');
        const statusFilter = document.getElementById('statusFilter');
        
        if (searchFilter) searchFilter.value = '';
        if (serviceFilter) serviceFilter.value = '';
        if (statusFilter) statusFilter.value = '';
        
        this.applyFilters();
        this.showNotification('Filters reset', 'info', 2000);
    }

    ipToNumber(ip) {
        if (!ip) return 0;
        return ip.split('.').reduce((num, octet) => (num << 8) + parseInt(octet), 0);
    }

    // Action methods
    triggerQuickScan() {
        const ipInput = document.getElementById('ipAddress');
        if (ipInput && ipInput.value.trim()) {
            document.getElementById('singleIpForm').dispatchEvent(new Event('submit'));
        } else {
            this.showNotification('Enter an IP address for quick scan', 'info');
            if (ipInput) ipInput.focus();
        }
    }

    refreshResults() {
        this.renderResultsTable();
        this.updateStatistics();
        this.showNotification('Results refreshed', 'success', 2000);
    }

    stopScan() {
        if (this.isScanning) {
            this.isScanning = false;
            this.updateScanningState(false);
            this.stopProgressTracking();
            this.showNotification('Scan stopped by user', 'warning');
        }
    }

    pauseScan() {
        if (this.isScanning) {
            this.showNotification('Scan paused due to connection loss', 'warning');
        }
    }

    clearResults() {
        if (this.scanResults.length === 0) {
            this.showNotification('No results to clear', 'info', 2000);
            return;
        }
        
        if (confirm(`Are you sure you want to clear all ${this.scanResults.length} results?`)) {
            this.scanResults = [];
            this.updateResultsDisplay();
            this.updateStatistics();
            this.saveResults();
            this.showNotification('All results cleared', 'success');
        }
    }

    exportResults(format = 'json') {
        if (this.scanResults.length === 0) {
            this.showNotification('No results to export', 'warning');
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
        this.showNotification(`Results exported as ${format.toUpperCase()}`, 'success');
    }

    generateCSV() {
        const headers = ['IP Address', 'Port', 'Status', 'Service', 'Response Time', 'Discovered At', 'Security Level'];
        const rows = [headers.join(',')];
        
        this.scanResults.forEach(result => {
            const row = [
                result.IpAddress || result.ipAddress,
                result.Port || result.port,
                (result.IsOpen || result.isOpen) ? 'Open' : 'Closed',
                result.ServiceName || result.serviceName || result.service || 'Unknown',
                result.responseTime || result.PingTime || result.pingTime || 0,
                result.discoveredAt,
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
        const stats = this.calculateStatistics();
        const summary = `Network Scan Results: ${stats.openPorts} open ports on ${stats.totalHosts} hosts. ${stats.uniqueServices} unique services detected. Completed in ${stats.scanDuration}.`;
        
        if (navigator.clipboard) {
            navigator.clipboard.writeText(summary).then(() => {
                this.showNotification('Summary copied to clipboard', 'success');
            }).catch(() => {
                this.showNotification('Share not available', 'info');
            });
        } else {
            this.showNotification('Share not available', 'info');
        }
    }

    // Result detail methods
    showResultDetails(resultId) {
        const result = this.scanResults.find(r => r.id === resultId);
        if (!result) return;
        
        // Implementation for showing detailed result modal would go here
        this.showNotification(`Details for result ${resultId}`, 'info');
    }

    async rescanTarget(ipAddress, port) {
        this.showNotification(`Rescanning ${ipAddress}:${port}...`, 'info');
        
        try {
            const response = await fetch('/api/NetworkScan/scan-ip', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ipAddress: ipAddress,
                    ports: [port],
                    timeoutMs: 5000
                })
            });
            
            if (response.ok) {
                const results = await response.json();
                this.showNotification('Rescan completed', 'success');
                // Update existing result or add new one
                this.updateExistingResult(ipAddress, port, results[0] || results.scanResults?.[0]);
            }
        } catch (error) {
            this.showNotification(`Rescan failed: ${error.message}`, 'danger');
        }
    }

    updateExistingResult(ipAddress, port, newResult) {
        if (!newResult) return;
        
        const existingIndex = this.scanResults.findIndex(r => 
            (r.IpAddress || r.ipAddress) === ipAddress && (r.Port || r.port) === port
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
            this.showNotification('Result removed', 'info', 2000);
        }
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
    console.log('DOM loaded, initializing NetworkScanner...');
    window.scanner = new NetworkScanner();
    console.log('NetworkScanner initialized:', window.scanner);
});

// Export for global access
window.NetworkScanner = NetworkScanner;