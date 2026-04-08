// On-Prem Network InfraIQ Dashboard JavaScript - Enhanced UI/UX

class Dashboard {
    constructor() {
        this.apiStatus = null;
        this.notifications = [];
        this.init();
    }

    init() {
        // Initialize enhanced UI components
        this.initTooltips();
        this.initProgressiveEnhancement();
        this.checkApiStatus();
        this.initTheme();
        this.initAnimations();
        this.initKeyboardShortcuts();
        this.initNotificationSystem();
        this.initPerformanceMonitoring();
    }

    initTooltips() {
        // Initialize Bootstrap tooltips with enhanced options
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl, {
                delay: { show: 300, hide: 100 },
                animation: true,
                html: true
            });
        });
    }

    initProgressiveEnhancement() {
        // Add progressive enhancement features
        this.enhanceCards();
        this.enhanceButtons();
        this.enhanceForms();
        this.addLoadingStates();
    }

    enhanceCards() {
        // Add interactive enhancements to cards
        const cards = document.querySelectorAll('.card');
        cards.forEach(card => {
            card.classList.add('interactive-card');
            
            // Add hover sound effect (subtle)
            card.addEventListener('mouseenter', () => {
                this.playInteractionSound('hover');
            });

            // Add click animation
            card.addEventListener('click', (e) => {
                if (!e.target.closest('a, button, input')) {
                    this.addRippleEffect(card, e);
                }
            });
        });
    }

    enhanceButtons() {
        // Enhance button interactions
        const buttons = document.querySelectorAll('.btn');
        buttons.forEach(button => {
            button.addEventListener('click', (e) => {
                this.addRippleEffect(button, e);
                this.playInteractionSound('click');
            });

            // Add loading state capability
            if (!button.dataset.originalText) {
                button.dataset.originalText = button.textContent;
            }
        });
    }

    enhanceForms() {
        // Add form enhancements
        const formControls = document.querySelectorAll('.form-control');
        formControls.forEach(control => {
            // Add floating label effect
            control.addEventListener('focus', () => {
                control.parentElement.classList.add('focused');
            });

            control.addEventListener('blur', () => {
                if (!control.value) {
                    control.parentElement.classList.remove('focused');
                }
            });

            // Add input validation feedback
            control.addEventListener('input', () => {
                this.validateInput(control);
            });
        });
    }

    addLoadingStates() {
        // Initialize loading state management
        this.loadingStates = new Map();
    }

    initAnimations() {
        // Initialize scroll animations
        this.observeElements();
        
        // Add entrance animations
        const elements = document.querySelectorAll('.card, .jumbotron');
        elements.forEach((element, index) => {
            element.style.opacity = '0';
            element.style.transform = 'translateY(30px)';
            
            setTimeout(() => {
                element.style.transition = 'all 0.6s cubic-bezier(0.4, 0, 0.2, 1)';
                element.style.opacity = '1';
                element.style.transform = 'translateY(0)';
            }, index * 100);
        });
    }

    observeElements() {
        // Intersection Observer for scroll animations
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('animate-in');
                }
            });
        }, {
            threshold: 0.1,
            rootMargin: '0px 0px -50px 0px'
        });

        const animatedElements = document.querySelectorAll('.animate-on-scroll');
        animatedElements.forEach(el => observer.observe(el));
    }

    initKeyboardShortcuts() {
        // Add keyboard shortcuts for power users
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                switch (e.key) {
                    case 's':
                        e.preventDefault();
                        this.triggerScan();
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
        });
    }

    initNotificationSystem() {
        // Create notification container
        const notificationContainer = document.createElement('div');
        notificationContainer.id = 'notification-container';
        notificationContainer.className = 'position-fixed top-0 end-0 p-3';
        notificationContainer.style.zIndex = '9999';
        document.body.appendChild(notificationContainer);
    }

    initPerformanceMonitoring() {
        // Monitor performance and show indicators
        if ('connection' in navigator) {
            this.updateConnectionStatus(navigator.connection);
            navigator.connection.addEventListener('change', () => {
                this.updateConnectionStatus(navigator.connection);
            });
        }
    }

    async checkApiStatus() {
        try {
            Dashboard.showLoading(document.querySelector('.api-status-container'), 'Checking API...');
            
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000);
            
            const response = await fetch('/api/NetworkScan/status', {
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            if (response.ok) {
                const status = await response.json();
                this.apiStatus = status;
                this.updateApiStatus(status);
                this.showNotification('API Status: Connected', 'success');
            } else {
                throw new Error(`HTTP ${response.status}`);
            }
        } catch (error) {
            console.error('Failed to check API status:', error);
            this.showApiError(error);
            this.showNotification('API Status: Connection Failed', 'danger');
        }
    }

    updateApiStatus(status) {
        const statusElements = document.querySelectorAll('.api-status');
        statusElements.forEach(element => {
            element.innerHTML = `
                <div class="d-flex align-items-center">
                    <div class="status-indicator status-open me-2">
                        <i class="fas fa-check-circle"></i>
                        Online
                    </div>
                    <small class="text-muted">v${status.Version || '1.0.0'}</small>
                </div>
            `;
        });

        // Update connection indicator
        this.updateConnectionIndicator('connected');
    }

    showApiError(error) {
        const statusElements = document.querySelectorAll('.api-status');
        statusElements.forEach(element => {
            element.innerHTML = `
                <div class="d-flex align-items-center">
                    <div class="status-indicator status-closed me-2">
                        <i class="fas fa-exclamation-circle"></i>
                        Offline
                    </div>
                    <small class="text-muted">${error.message || 'Connection failed'}</small>
                </div>
            `;
        });

        this.updateConnectionIndicator('disconnected');
    }

    updateConnectionIndicator(status) {
        let indicator = document.getElementById('connection-indicator');
        if (!indicator) {
            indicator = document.createElement('div');
            indicator.id = 'connection-indicator';
            indicator.className = 'position-fixed bottom-0 end-0 m-3';
            document.body.appendChild(indicator);
        }

        const statusConfig = {
            connected: {
                class: 'badge bg-success',
                icon: 'fas fa-wifi',
                text: 'Connected'
            },
            disconnected: {
                class: 'badge bg-danger',
                icon: 'fas fa-wifi-slash',
                text: 'Disconnected'
            },
            slow: {
                class: 'badge bg-warning',
                icon: 'fas fa-exclamation-triangle',
                text: 'Slow Connection'
            }
        };

        const config = statusConfig[status] || statusConfig.disconnected;
        indicator.innerHTML = `
            <div class="${config.class} d-flex align-items-center gap-1">
                <i class="${config.icon}"></i>
                ${config.text}
            </div>
        `;
    }

    updateConnectionStatus(connection) {
        const effectiveType = connection.effectiveType;
        if (effectiveType === 'slow-2g' || effectiveType === '2g') {
            this.updateConnectionIndicator('slow');
            this.showNotification('Slow connection detected. Some features may be limited.', 'warning');
        } else {
            this.updateConnectionIndicator('connected');
        }
    }

    initTheme() {
        // Enhanced theme management - avoid conflicts with _Layout.cshtml
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'dark';
        this.updateTheme(currentTheme);
        
        // Listen for system theme changes
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)');
        prefersDark.addEventListener('change', (e) => {
            if (!localStorage.getItem('theme')) {
                this.updateTheme(e.matches ? 'dark' : 'light');
            }
        });
    }

    updateTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        document.body.setAttribute('data-bs-theme', theme);
        localStorage.setItem('theme', theme);
        
        // Update theme toggle icon
        const themeToggle = document.getElementById('theme-toggle');
        if (themeToggle) {
            const icon = themeToggle.querySelector('i');
            if (icon) {
                icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
                themeToggle.setAttribute('title', `Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`);
            }
        }
        
        // Update body classes for Bootstrap compatibility
        if (theme === 'dark') {
            document.body.classList.remove('bg-light', 'text-dark');
            document.body.classList.add('bg-dark', 'text-light');
        } else {
            document.body.classList.remove('bg-dark', 'text-light');
            document.body.classList.add('bg-light', 'text-dark');
        }
        
        // Trigger custom event for theme change
        window.dispatchEvent(new CustomEvent('themeChanged', { detail: { theme } }));
        
        // Show notification
        this.showNotification(`Switched to ${theme} theme`, 'success', 2000);
    }

    // Enhanced utility methods
    addRippleEffect(element, event) {
        const ripple = document.createElement('span');
        const rect = element.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        const x = event.clientX - rect.left - size / 2;
        const y = event.clientY - rect.top - size / 2;
        
        ripple.style.cssText = `
            position: absolute;
            width: ${size}px;
            height: ${size}px;
            left: ${x}px;
            top: ${y}px;
            background: rgba(255, 255, 255, 0.5);
            border-radius: 50%;
            transform: scale(0);
            animation: ripple 0.6s ease-out;
            pointer-events: none;
        `;
        
        element.style.position = 'relative';
        element.style.overflow = 'hidden';
        element.appendChild(ripple);
        
        setTimeout(() => ripple.remove(), 600);
    }

    playInteractionSound(type) {
        // Subtle audio feedback (only if user preference allows)
        if (this.audioEnabled && 'AudioContext' in window) {
            // Implementation would go here for subtle audio feedback
        }
    }

    validateInput(input) {
        const value = input.value;
        const type = input.type;
        const pattern = input.pattern;
        
        let isValid = true;
        let message = '';

        // Custom validation logic
        if (input.id === 'ipAddress') {
            isValid = this.validateIP(value);
            message = isValid ? '' : 'Please enter a valid IP address';
        } else if (input.id === 'networkRange') {
            isValid = this.validateCIDR(value);
            message = isValid ? '' : 'Please enter a valid CIDR notation (e.g., 192.168.1.0/24)';
        }

        this.showInputFeedback(input, isValid, message);
        return isValid;
    }

    validateIP(ip) {
        const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
        return ipv4Regex.test(ip) || ipv6Regex.test(ip);
    }

    validateCIDR(cidr) {
        const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$/;
        return cidrRegex.test(cidr);
    }

    showInputFeedback(input, isValid, message) {
        // Remove existing feedback
        const existingFeedback = input.parentElement.querySelector('.invalid-feedback, .valid-feedback');
        if (existingFeedback) {
            existingFeedback.remove();
        }

        // Update input classes
        input.classList.remove('is-valid', 'is-invalid');
        if (input.value) {
            input.classList.add(isValid ? 'is-valid' : 'is-invalid');
        }

        // Add feedback message
        if (message) {
            const feedback = document.createElement('div');
            feedback.className = isValid ? 'valid-feedback' : 'invalid-feedback';
            feedback.textContent = message;
            input.parentElement.appendChild(feedback);
        }
    }

    showNotification(message, type = 'info', duration = 4000) {
        // Ensure notification container exists
        let container = document.getElementById('notification-container');
        if (!container) {
            this.initNotificationSystem();
            container = document.getElementById('notification-container');
        }
        
        if (!container) {
            console.error('Failed to create notification container');
            // Fallback to console
            console.log(`${type.toUpperCase()}: ${message}`);
            return null;
        }

        const notification = document.createElement('div');
        notification.className = `alert alert-${type} alert-dismissible fade show notification-toast`;
        notification.style.cssText = `
            margin-bottom: 0.5rem;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            backdrop-filter: blur(10px);
            animation: slideInRight 0.3s ease-out;
        `;
        
        notification.innerHTML = `
            <i class="fas fa-${this.getNotificationIcon(type)} me-2"></i>
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        `;

        container.appendChild(notification);

        // Auto dismiss
        setTimeout(() => {
            if (notification.parentElement) {
                notification.classList.remove('show');
                setTimeout(() => notification.remove(), 300);
            }
        }, duration);

        return notification;
    }

    getNotificationIcon(type) {
        const icons = {
            success: 'check-circle',
            danger: 'exclamation-circle',
            warning: 'exclamation-triangle',
            info: 'info-circle'
        };
        return icons[type] || icons.info;
    }

    // Enhanced loading states
    static showLoading(element, message = 'Loading...') {
        if (!element) return;
        
        element.classList.add('loading');
        
        const overlay = document.createElement('div');
        overlay.className = 'loading-overlay';
        overlay.innerHTML = `
            <div class="text-center">
                <div class="loading-spinner mb-3"></div>
                <div class="text-white">${message}</div>
            </div>
        `;
        
        element.appendChild(overlay);
    }

    static hideLoading(element) {
        if (!element) return;
        
        element.classList.remove('loading');
        const overlay = element.querySelector('.loading-overlay');
        if (overlay) {
            overlay.remove();
        }
    }

    // Enhanced error handling
    static showError(message, container = null, details = null) {
        const errorId = 'error-' + Date.now();
        const errorHtml = `
            <div class="alert alert-danger alert-dismissible fade show" role="alert" id="${errorId}">
                <div class="d-flex align-items-start">
                    <i class="fas fa-exclamation-triangle me-3 mt-1"></i>
                    <div class="flex-grow-1">
                        <strong>Error:</strong> ${message}
                        ${details ? `<div class="mt-2"><small class="text-muted">${details}</small></div>` : ''}
                    </div>
                </div>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        `;
        
        if (container) {
            container.insertAdjacentHTML('afterbegin', errorHtml);
        } else {
            const main = document.querySelector('main');
            if (main) {
                main.insertAdjacentHTML('afterbegin', errorHtml);
            }
        }

        // Auto-scroll to error
        const errorElement = document.getElementById(errorId);
        if (errorElement) {
            errorElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    }

    // Enhanced success messages
    static showSuccess(message, container = null, actions = null) {
        const successId = 'success-' + Date.now();
        const actionsHtml = actions ? `
            <div class="mt-2">
                ${actions.map(action => `
                    <button type="button" class="btn btn-sm btn-outline-success me-2" onclick="${action.onclick}">
                        <i class="${action.icon} me-1"></i>${action.text}
                    </button>
                `).join('')}
            </div>
        ` : '';
        
        const successHtml = `
            <div class="alert alert-success alert-dismissible fade show" role="alert" id="${successId}">
                <div class="d-flex align-items-start">
                    <i class="fas fa-check-circle me-3 mt-1"></i>
                    <div class="flex-grow-1">
                        ${message}
                        ${actionsHtml}
                    </div>
                </div>
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        `;
        
        if (container) {
            container.insertAdjacentHTML('afterbegin', successHtml);
        } else {
            const main = document.querySelector('main');
            if (main) {
                main.insertAdjacentHTML('afterbegin', successHtml);
            }
        }
    }

    // Utility methods for other components
    triggerScan() {
        // Trigger scan functionality (would be implemented in scanner.js)
        console.log('Scan triggered via keyboard shortcut');
    }

    refreshResults() {
        // Refresh results functionality
        console.log('Results refreshed via keyboard shortcut');
    }

    exportResults() {
        // Export results functionality
        console.log('Export triggered via keyboard shortcut');
    }

    // Static utility methods that match the original API
    static formatTimestamp(timestamp) {
        const date = new Date(timestamp);
        return new Intl.DateTimeFormat('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        }).format(date);
    }

    static formatIpAddress(ip) {
        // Enhanced IP formatting with validation
        if (!ip) return 'Unknown';
        
        // IPv4 formatting
        if (ip.includes('.')) {
            return ip;
        }
        
        // IPv6 formatting
        if (ip.includes(':')) {
            return ip.toLowerCase();
        }
        
        return ip;
    }

    static getServiceIcon(service) {
        const icons = {
            'HTTP': 'fas fa-globe',
            'HTTPS': 'fas fa-lock',
            'SSH': 'fas fa-terminal',
            'FTP': 'fas fa-folder-open',
            'FTPS': 'fas fa-folder-open',
            'Telnet': 'fas fa-terminal',
            'DNS': 'fas fa-server',
            'SMTP': 'fas fa-envelope',
            'SMTPS': 'fas fa-envelope',
            'POP3': 'fas fa-inbox',
            'POP3S': 'fas fa-inbox',
            'IMAP': 'fas fa-mail-bulk',
            'IMAPS': 'fas fa-mail-bulk',
            'SNMP': 'fas fa-network-wired',
            'RDP': 'fas fa-desktop',
            'VNC': 'fas fa-desktop',
            'MySQL': 'fas fa-database',
            'PostgreSQL': 'fas fa-database',
            'MongoDB': 'fas fa-database',
            'Redis': 'fas fa-database',
            'Unknown': 'fas fa-question-circle'
        };
        
        return icons[service] || icons['Unknown'];
    }

    static getServiceColor(service) {
        const colors = {
            'HTTP': 'service-web',
            'HTTPS': 'service-secure',
            'SSH': 'service-secure',
            'FTPS': 'service-secure',
            'SMTPS': 'service-secure',
            'POP3S': 'service-secure',
            'IMAPS': 'service-secure',
            'FTP': 'service-insecure',
            'Telnet': 'service-insecure',
            'SMTP': 'service-insecure',
            'POP3': 'service-insecure',
            'IMAP': 'service-insecure',
            'DNS': 'service-web',
            'Unknown': 'service-unknown'
        };
        
        return colors[service] || colors['Unknown'];
    }

    static getSecurityLevel(port, service) {
        // Determine security level based on port and service
        const insecurePorts = [21, 23, 25, 53, 80, 110, 143];
        const securePorts = [22, 443, 993, 995];
        
        if (securePorts.includes(port) || service?.includes('S')) {
            return 'secure';
        } else if (insecurePorts.includes(port)) {
            return 'insecure';
        } else {
            return 'unknown';
        }
    }
}

// Add CSS animations via JavaScript
const styleSheet = document.createElement('style');
styleSheet.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes ripple {
        to {
            transform: scale(2);
            opacity: 0;
        }
    }
    
    .notification-toast {
        max-width: 400px;
        word-wrap: break-word;
    }
    
    .animate-on-scroll {
        opacity: 0;
        transform: translateY(30px);
        transition: all 0.6s cubic-bezier(0.4, 0, 0.2, 1);
    }
    
    .animate-in {
        opacity: 1;
        transform: translateY(0);
    }
`;
document.head.appendChild(styleSheet);

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.dashboard = new Dashboard();
});

// Export for use in other modules
window.Dashboard = Dashboard;