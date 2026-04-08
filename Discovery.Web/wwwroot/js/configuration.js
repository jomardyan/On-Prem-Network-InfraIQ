/**
 * Enhanced Configuration Manager
 * Provides advanced configuration management for the network scanner
 */
class ConfigurationManager {
    constructor() {
        this.defaultSettings = null;
        this.portPresets = null;
        this.init();
    }

    async init() {
        await this.loadDefaultSettings();
        await this.loadPortPresets();
        this.setupEventListeners();
    }

    async loadDefaultSettings() {
        try {
            const response = await fetch('/api/Configuration/defaults');
            this.defaultSettings = await response.json();
        } catch (error) {
            console.error('Failed to load default settings:', error);
        }
    }

    async loadPortPresets() {
        try {
            const response = await fetch('/api/Configuration/port-presets');
            this.portPresets = await response.json();
            this.populatePortPresets();
        } catch (error) {
            console.error('Failed to load port presets:', error);
        }
    }

    populatePortPresets() {
        if (!this.portPresets) return;

        const presetSelects = document.querySelectorAll('.port-preset-select');
        presetSelects.forEach(select => {
            select.innerHTML = '<option value="">Select a preset...</option>';
            
            Object.entries(this.portPresets.presets).forEach(([key, preset]) => {
                const option = document.createElement('option');
                option.value = key;
                option.textContent = `${preset.name} (${preset.ports.length} ports)`;
                option.title = preset.description;
                select.appendChild(option);
            });
        });
    }

    setupEventListeners() {
        // Port preset selection
        document.addEventListener('change', (e) => {
            if (e.target.classList.contains('port-preset-select')) {
                this.applyPortPreset(e.target.value, e.target);
            }
        });

        // Auto-suggestion for IP addresses
        document.addEventListener('input', (e) => {
            if (e.target.classList.contains('ip-input')) {
                this.showIPSuggestions(e.target);
            }
        });

        // Configuration validation
        document.addEventListener('blur', (e) => {
            if (e.target.classList.contains('validate-config')) {
                this.validateConfiguration(e.target);
            }
        });
    }

    applyPortPreset(presetKey, selectElement) {
        if (!presetKey || !this.portPresets) return;

        const preset = this.portPresets.presets[presetKey];
        if (!preset) return;

        // Find the associated port input field
        const form = selectElement.closest('form');
        const portInput = form.querySelector('.port-input');
        
        if (portInput) {
            portInput.value = preset.ports.join(',');
            
            // Show preset info
            this.showPresetInfo(selectElement, preset);
            
            // Trigger validation
            portInput.dispatchEvent(new Event('input'));
        }
    }

    showPresetInfo(selectElement, preset) {
        // Remove existing info
        const existingInfo = selectElement.parentNode.querySelector('.preset-info');
        if (existingInfo) {
            existingInfo.remove();
        }

        // Create new info element
        const infoDiv = document.createElement('div');
        infoDiv.className = 'preset-info mt-2 p-2 bg-light rounded';
        infoDiv.innerHTML = `
            <small class="text-muted">
                <strong>${preset.name}</strong><br>
                ${preset.description}<br>
                <strong>Ports:</strong> ${preset.ports.length} ports selected
            </small>
        `;

        selectElement.parentNode.appendChild(infoDiv);
    }

    showIPSuggestions(input) {
        const value = input.value.toLowerCase();
        const suggestions = [
            { value: '127.0.0.1', label: 'Localhost (127.0.0.1)' },
            { value: '192.168.1.1', label: 'Common Router (192.168.1.1)' },
            { value: '192.168.1.0/24', label: 'Local Network (192.168.1.0/24)' },
            { value: '10.0.0.0/24', label: 'Private Network (10.0.0.0/24)' },
            { value: '172.16.0.0/24', label: 'Private Network (172.16.0.0/24)' },
            { value: '::1', label: 'IPv6 Localhost (::1)' },
            { value: '2001:db8::/64', label: 'IPv6 Network (2001:db8::/64)' }
        ];

        const filteredSuggestions = suggestions.filter(s => 
            s.value.includes(value) || s.label.toLowerCase().includes(value)
        );

        this.showSuggestionDropdown(input, filteredSuggestions);
    }

    showSuggestionDropdown(input, suggestions) {
        // Remove existing dropdown
        const existingDropdown = document.querySelector('.ip-suggestions');
        if (existingDropdown) {
            existingDropdown.remove();
        }

        if (suggestions.length === 0 || input.value.length < 2) return;

        // Create dropdown
        const dropdown = document.createElement('div');
        dropdown.className = 'ip-suggestions list-group position-absolute w-100';
        dropdown.style.zIndex = '1000';
        dropdown.style.maxHeight = '200px';
        dropdown.style.overflowY = 'auto';

        suggestions.forEach(suggestion => {
            const item = document.createElement('button');
            item.className = 'list-group-item list-group-item-action';
            item.type = 'button';
            item.innerHTML = `
                <div class="d-flex justify-content-between">
                    <span>${suggestion.value}</span>
                    <small class="text-muted">${suggestion.label}</small>
                </div>
            `;
            
            item.addEventListener('click', () => {
                input.value = suggestion.value;
                dropdown.remove();
                input.dispatchEvent(new Event('input'));
            });

            dropdown.appendChild(item);
        });

        // Position dropdown
        const inputRect = input.getBoundingClientRect();
        dropdown.style.top = `${input.offsetTop + input.offsetHeight}px`;
        dropdown.style.left = `${input.offsetLeft}px`;
        dropdown.style.width = `${input.offsetWidth}px`;

        input.parentNode.style.position = 'relative';
        input.parentNode.appendChild(dropdown);

        // Close dropdown when clicking outside
        setTimeout(() => {
            document.addEventListener('click', (e) => {
                if (!dropdown.contains(e.target) && e.target !== input) {
                    dropdown.remove();
                }
            }, { once: true });
        }, 100);
    }

    async validateConfiguration(input) {
        const form = input.closest('form');
        if (!form) return;

        const formData = new FormData(form);
        const config = {
            target: formData.get('target') || input.value,
            ports: this.parsePortString(formData.get('ports') || ''),
            timeoutMs: parseInt(formData.get('timeout')) || 3000,
            concurrency: parseInt(formData.get('concurrency')) || 50
        };

        try {
            const response = await fetch('/api/Configuration/validate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(config)
            });

            const result = await response.json();
            this.showValidationResult(form, result);
        } catch (error) {
            console.error('Validation failed:', error);
        }
    }

    parsePortString(portString) {
        if (!portString) return [];
        
        return portString.split(',')
            .map(p => parseInt(p.trim()))
            .filter(p => !isNaN(p) && p > 0 && p <= 65535);
    }

    showValidationResult(form, result) {
        // Remove existing validation messages
        form.querySelectorAll('.validation-message').forEach(msg => msg.remove());

        // Create validation message container
        const messageContainer = document.createElement('div');
        messageContainer.className = 'validation-message mt-3';

        if (!result.isValid) {
            // Show errors
            result.errors.forEach(error => {
                const errorDiv = document.createElement('div');
                errorDiv.className = 'alert alert-danger alert-sm';
                errorDiv.innerHTML = `<i class="fas fa-exclamation-triangle me-2"></i>${error}`;
                messageContainer.appendChild(errorDiv);
            });
        }

        // Show warnings
        if (result.warnings && result.warnings.length > 0) {
            result.warnings.forEach(warning => {
                const warningDiv = document.createElement('div');
                warningDiv.className = 'alert alert-warning alert-sm';
                warningDiv.innerHTML = `<i class="fas fa-exclamation-circle me-2"></i>${warning}`;
                messageContainer.appendChild(warningDiv);
            });
        }

        // Show estimated duration
        if (result.estimatedDuration) {
            const durationDiv = document.createElement('div');
            durationDiv.className = 'alert alert-info alert-sm';
            durationDiv.innerHTML = `
                <i class="fas fa-clock me-2"></i>
                Estimated scan time: <strong>${result.estimatedDuration}</strong>
            `;
            messageContainer.appendChild(durationDiv);
        }

        // Show recommendations
        if (result.recommendations && result.recommendations.length > 0) {
            const recDiv = document.createElement('div');
            recDiv.className = 'alert alert-light alert-sm';
            recDiv.innerHTML = `
                <i class="fas fa-lightbulb me-2"></i>
                <strong>Recommendations:</strong>
                <ul class="mb-0 mt-1">
                    ${result.recommendations.map(rec => `<li>${rec}</li>`).join('')}
                </ul>
            `;
            messageContainer.appendChild(recDiv);
        }

        // Add to form
        form.appendChild(messageContainer);
    }

    // Utility method to get default settings
    getDefaultSettings() {
        return this.defaultSettings;
    }

    // Utility method to get port presets
    getPortPresets() {
        return this.portPresets;
    }
}

/**
 * Scan History Manager
 * Manages scan history and results in local storage
 */
class ScanHistoryManager {
    constructor() {
        this.storageKey = 'networkScanHistory';
        this.maxHistoryItems = 50;
    }

    addScanResult(scanConfig, results) {
        const history = this.getHistory();
        const newEntry = {
            id: Date.now().toString(),
            timestamp: new Date().toISOString(),
            config: scanConfig,
            results: results,
            summary: this.generateSummary(results)
        };

        history.unshift(newEntry);
        
        // Limit history size
        if (history.length > this.maxHistoryItems) {
            history.splice(this.maxHistoryItems);
        }

        localStorage.setItem(this.storageKey, JSON.stringify(history));
        return newEntry.id;
    }

    getHistory() {
        try {
            const stored = localStorage.getItem(this.storageKey);
            return stored ? JSON.parse(stored) : [];
        } catch (error) {
            console.error('Failed to load scan history:', error);
            return [];
        }
    }

    getScanById(id) {
        const history = this.getHistory();
        return history.find(entry => entry.id === id);
    }

    deleteScan(id) {
        const history = this.getHistory();
        const filtered = history.filter(entry => entry.id !== id);
        localStorage.setItem(this.storageKey, JSON.stringify(filtered));
    }

    clearHistory() {
        localStorage.removeItem(this.storageKey);
    }

    generateSummary(results) {
        if (!results || !Array.isArray(results)) {
            return { totalHosts: 0, openPorts: 0, vulnerabilities: 0 };
        }

        const openPorts = results.filter(r => r.isOpen).length;
        const vulnerabilities = results.filter(r => r.isVulnerable).length;
        const uniqueHosts = new Set(results.map(r => r.ipAddress)).size;

        return {
            totalHosts: uniqueHosts,
            openPorts: openPorts,
            vulnerabilities: vulnerabilities
        };
    }

    exportHistory(format = 'json') {
        const history = this.getHistory();
        
        switch (format.toLowerCase()) {
            case 'csv':
                return this.exportToCSV(history);
            case 'xml':
                return this.exportToXML(history);
            default:
                return JSON.stringify(history, null, 2);
        }
    }

    exportToCSV(history) {
        const headers = ['ID', 'Timestamp', 'Target', 'Total Hosts', 'Open Ports', 'Vulnerabilities'];
        const rows = history.map(entry => [
            entry.id,
            entry.timestamp,
            entry.config.target || 'Unknown',
            entry.summary.totalHosts,
            entry.summary.openPorts,
            entry.summary.vulnerabilities
        ]);

        return [headers, ...rows].map(row => row.join(',')).join('\n');
    }

    exportToXML(history) {
        let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<scanHistory>\n';
        
        history.forEach(entry => {
            xml += `  <scan id="${entry.id}" timestamp="${entry.timestamp}">\n`;
            xml += `    <target>${entry.config.target || 'Unknown'}</target>\n`;
            xml += `    <summary>\n`;
            xml += `      <totalHosts>${entry.summary.totalHosts}</totalHosts>\n`;
            xml += `      <openPorts>${entry.summary.openPorts}</openPorts>\n`;
            xml += `      <vulnerabilities>${entry.summary.vulnerabilities}</vulnerabilities>\n`;
            xml += `    </summary>\n`;
            xml += `  </scan>\n`;
        });
        
        xml += '</scanHistory>';
        return xml;
    }
}

// Initialize global instances
const configManager = new ConfigurationManager();
const historyManager = new ScanHistoryManager();

// Export for use in other modules
window.configManager = configManager;
window.historyManager = historyManager;