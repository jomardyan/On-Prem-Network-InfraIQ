# 📖 On-Prem Network InfraIQ - Help Guide

## Table of Contents
1. [Getting Started](#getting-started)
2. [Menu Navigation](#menu-navigation)
3. [Scanning Features](#scanning-features)
4. [Live Display Controls](#live-display-controls)
5. [Security Tools](#security-tools)
6. [Command Line Usage](#command-line-usage)
7. [Export and Reports](#export-and-reports)
8. [Troubleshooting](#troubleshooting)
9. [Best Practices](#best-practices)

## Getting Started

### First Launch
When you first run On-Prem Network InfraIQ, you'll see a beautiful ASCII art banner and an interactive menu system. The interface is designed to be intuitive and user-friendly.

### Menu Structure
The main menu is organized into logical categories:
- 🔍 **Port Scanning Tools** - Core scanning functionality
- 🔎 **Network Discovery** - Host and service discovery
- 🛠️ **Network Utilities** - Diagnostic and analysis tools
- 🔐 **Security Tools** - Security assessment features
- ⚙️ **System** - Configuration and help options

## Menu Navigation

### Using the Interface
- **Arrow Keys** - Navigate up and down through options
- **Enter** - Select the highlighted option
- **Tab** - Quick navigation between sections
- **Escape** - Return to previous menu (where applicable)

### Visual Indicators
- **Icons** - Each tool has a descriptive emoji for quick identification
- **Colors** - Different categories use distinct color schemes
- **Grouping** - Related tools are grouped together logically

## Scanning Features

### 🌐 Local Network Range Scanning
- **Purpose**: Scan your local network to discover devices and services
- **Use Case**: Network inventory, security audit of internal network
- **Input**: Automatically detects your network interfaces
- **Output**: Live display of discovered hosts and open ports

**Example Workflow:**
1. Select "🌐 Scan local network range"
2. Choose your network interface (if multiple available)
3. Set IP range (default: 1-254)
4. Choose ports to scan (popular or custom)
5. Watch live results as they appear

### 🖥️ Single IP Scanning
- **Purpose**: Deep scan of a specific host
- **Use Case**: Detailed analysis of a particular server or device
- **Input**: IP address or hostname
- **Output**: Complete port listing with service identification

**Best For:**
- Troubleshooting specific server issues
- Security assessment of individual hosts
- Service verification after configuration changes

### 🎯 CIDR Network Scanning
- **Purpose**: Scan networks using CIDR notation
- **Use Case**: Scanning specific subnets or network segments
- **Input**: CIDR format (e.g., 192.168.1.0/24)
- **Output**: Comprehensive network map with all discovered services

**CIDR Examples:**
- `192.168.1.0/24` - 254 hosts in 192.168.1.x
- `10.0.0.0/16` - 65,534 hosts in 10.0.x.x
- `172.16.0.0/12` - 1,048,574 hosts in 172.16-31.x.x

### ⚡ Quick Port Scan
- **Purpose**: Fast scan of the most common ports
- **Use Case**: Quick security check or service discovery
- **Ports Scanned**: 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5900, 8080
- **Speed**: Optimized for rapid results

## Live Display Controls

### Real-Time Updates
The live display system shows results as they're discovered, providing immediate feedback during scanning operations.

### Interactive Controls
- **TAB Key** - Cycle through display modes:
  1. **Recent Results** - Latest discoveries (default)
  2. **All Hosts** - Grouped by IP address
  3. **Summary** - Statistics and analysis
- **F1 Key** - Toggle help instructions on/off
- **ESC Key** - Clear any active filters
- **Ctrl+C** - Gracefully stop the current scan

### Display Modes Explained

#### Recent Results Mode
- Shows the 12 most recently discovered services
- Color-coded by discovery time:
  - 🟢 **Green** - Discovered within last 5 seconds
  - 🟡 **Yellow** - Discovered 5-30 seconds ago
  - ⚪ **White** - Discovered over 30 seconds ago
- Perfect for monitoring active scans

#### All Hosts Mode
- Groups results by IP address
- Shows all open ports for each host
- Displays service summaries and OS detection
- Ideal for network inventory and host analysis

#### Summary Mode
- Service distribution statistics
- Operating system breakdown
- Port range analysis:
  - Well-known ports (1-1023)
  - Registered ports (1024-49151)
  - Dynamic ports (49152-65535)

## Enhanced Network Utilities

### 📡 Optimized Ping Sweep
- **Purpose**: Fast discovery of live hosts with enhanced performance
- **Features**:
  - **Adaptive Concurrency**: Automatic optimization based on network size (50-100 concurrent pings)
  - **Live Host Discovery**: Real-time notifications as alive hosts are found
  - **TTL Analysis**: Operating system detection based on TTL values
  - **Progress Statistics**: Live rate calculation and elapsed time tracking
  - **Enhanced Output**: Detailed table with response times and TTL information

**Example Output:**
```
💡 Alive host found: 192.168.1.1 (5ms TTL:64)
💡 Alive host found: 192.168.1.105 (12ms TTL:128)
📊 Progress: 8 hosts found in 01:23 (rate: 5.8/min)
```

### 🔗 Enhanced ARP Table Scanning
- **Purpose**: Comprehensive network neighbor discovery with multiple fallback methods
- **Features**:
  - **Multi-Method Approach**: `/proc/net/arp`, `ip neigh show`, `arp -a` commands
  - **Async Processing**: Concurrent execution of all methods for faster results
  - **Live Discovery**: Real-time ARP entry notifications
  - **Cross-Platform**: Works on Linux, Unix, and other systems
  - **Detailed Information**: Device interface, MAC addresses, and connection states

**Example Output:**
```
📍 Found: 192.168.1.1 → aa:bb:cc:dd:ee:ff (wlan0 - REACHABLE)
📍 Found: 192.168.1.105 → 11:22:33:44:55:66 (eth0 - STALE)
```

### 🛤️ Enhanced Traceroute
- **Purpose**: Multi-method route tracing with live hop discovery
- **Features**:
  - **Multiple Methods**: `traceroute`, `tracepath`, and .NET ping-based fallbacks
  - **Live Hop Display**: Real-time route discovery as hops are found
  - **Cross-Platform**: Automatic method selection based on availability
  - **Progressive Fallback**: Tries system commands first, then .NET implementation
  - **Detailed Analysis**: Response times and hop-by-hop progression

**Example Output:**
```
🔗 Hop 1: 192.168.1.1 - 2ms
🔗 Hop 2: 10.0.0.1 - 15ms
🔗 Hop 3: 203.0.113.1 - 45ms
```

### 🌐 Enhanced DNS Lookup
- **Purpose**: Comprehensive DNS resolution with parallel processing
- **Features**:
  - **Concurrent Queries**: Parallel A, AAAA, and reverse DNS lookups
  - **Service Detection**: Automatic identification of mail, web, FTP, DNS, and CDN services
  - **Live Results**: Real-time DNS record discovery
  - **Enhanced Reporting**: Detailed table with record types and values
  - **Error Handling**: Graceful fallbacks for failed lookups

**Example Output:**
```
✅ Hostname: example.com
🌐 IPv4: 93.184.216.34
🔄 Reverse DNS: 93.184.216.34 → example.com
🏷️ Detected Type: Web Server
```

## Security Tools

### 🛡️ Vulnerability Scanning
- **Purpose**: Enhanced security assessment with real-time vulnerability discovery
- **Input**: Single IP address or CIDR network (e.g., 192.168.1.1 or 192.168.1.0/24)
- **Scope**: Supports both single host and network-wide vulnerability scanning
- **Methodology**: Concurrent vulnerability checking with live result streaming
- **Risk Levels**: High, Medium, Low with color-coded severity indicators
- **Output**: Real-time vulnerability notifications and comprehensive final report

**Enhanced Features:**
- **Live Results Display**: Vulnerabilities appear immediately as they're discovered
- **Real-time Notifications**: Instant alerts for high-risk findings
- **Adaptive Concurrency**: Optimized scanning speed based on network size
- **Progress Tracking**: Live statistics and completion rates
- **Severity Color Coding**: Visual risk assessment (Red=High, Yellow=Medium, Blue=Low)

**Example Live Output:**
```
🚨 Found: High - 192.168.1.5:Telnet - Unencrypted remote access protocol
🚨 Found: Medium - 192.168.1.10:SMB - Windows file sharing (check for SMBv1)
🚨 Found: Low - 192.168.1.15:DNS - Potential DNS amplification attacks
```

**Common Checks:**
- Unencrypted protocols (Telnet, FTP, HTTP)
- Default service ports
- Legacy protocols (NetBIOS, RPC)
- Database exposure
- Remote access services (RDP, SSH)

**Network Scanning Features:**
- CIDR notation support (e.g., 192.168.1.0/24)
- Concurrent scanning for improved performance
- Progress tracking for large network ranges
- Risk prioritization and summary statistics
- Warning prompts for large scan ranges

### 🔓 SSL/TLS Certificate Check
- **Purpose**: Validate SSL certificates and security
- **Input**: Hostname and port (default: 443)
- **Analysis**:
  - Certificate validity period
  - Issuer information
  - Subject details
  - Expiration warnings
  - Security recommendations

### 📊 Port Security Audit
- **Purpose**: Comprehensive security analysis of open ports
- **Assessment**: Risk evaluation for each discovered service
- **Recommendations**: Specific security improvement suggestions
- **Reporting**: Color-coded risk levels with actionable advice

### 🏛️ DORA Compliance Assessment
- **Purpose**: Comprehensive assessment against EU's Digital Operational Resilience Act (DORA) requirements
- **Input**: Single IP address or hostname for compliance evaluation
- **Scope**: Evaluates compliance across all five key DORA pillars
- **Output**: Detailed compliance report with scores, issues, and remediation guidance

**DORA Assessment Pillars:**

**1. ICT Risk Management (Article 5)**
- Evaluates security controls and risk management framework implementation
- Checks for access controls, security monitoring, and encryption usage
- Assesses overall security posture and control effectiveness
- Score: 0-100 based on security control presence and vulnerability assessment

**2. Digital Operational Resilience Testing (Article 11)**
- Assesses business continuity and disaster recovery capabilities
- Checks for backup systems, redundancy mechanisms, and recovery procedures
- Evaluates operational resilience and system fault tolerance
- Score: 0-100 based on resilience control presence

**3. Third-party ICT Risk Management (Article 28-44)**
- Identifies external dependencies and cloud service usage
- Evaluates third-party monitoring and risk management capabilities
- Assesses vendor risk management and service provider oversight
- Score: 0-100 with penalties for high-risk external dependencies

**4. Incident Reporting (Article 17-23)**
- Checks for incident logging and security event monitoring
- Evaluates automated alerting and response capabilities
- Assesses incident detection and reporting readiness
- Score: 0-100 based on monitoring and logging infrastructure

**5. Information Sharing (Article 24)**
- Evaluates secure communication channel availability
- Checks for threat intelligence sharing capabilities
- Assesses information sharing protocol implementation
- Score: 0-100 based on communication and sharing infrastructure

**Compliance Scoring:**
- **90-100**: Excellent compliance posture
- **75-89**: Good compliance with minor improvements needed
- **60-74**: Adequate compliance with notable gaps
- **40-59**: Poor compliance requiring significant improvement
- **0-39**: Critical compliance deficiencies requiring immediate attention

**Example Assessment Output:**
```
🏛️ DORA Compliance Assessment Results
Target: 192.168.1.100 | Assessment Date: 2024-01-15 14:30:25

Overall Compliance Score: 72/100

📊 Detailed Assessment Results
┌─────────────────────────────────────────────────────────────┐
│ DORA Category              │ Score  │ Status        │ Findings │
├─────────────────────────────────────────────────────────────┤
│ 🔐 ICT Risk Management     │ 85/100 │ ✅ Compliant  │ Framework detected │
│ 🛡️ Digital Resilience      │ 50/100 │ ⚠️ Partial    │ Backup: No, Redundancy: No │
│ 🌐 Third-party Risk        │ 90/100 │ ✅ Managed    │ 2 dependencies identified │
│ 📊 Incident Reporting      │ 75/100 │ ✅ Ready      │ Logging: Yes, Monitoring: Yes │
│ 🔄 Information Sharing     │ 60/100 │ ⚠️ Partial    │ Secure Comm: Yes │
└─────────────────────────────────────────────────────────────┘

🚨 Compliance Issues
┌─────────────────────────────────────────────────────────────┐
│ ID           │ Severity │ Issue                    │ Reference │
├─────────────────────────────────────────────────────────────┤
│ DORA-RES-001 │ High     │ Insufficient Digital     │ Article 11 │
│              │          │ Operational Resilience   │           │
└─────────────────────────────────────────────────────────────┘

💡 Recommendations:
• Enhance business continuity and disaster recovery capabilities
• Implement redundancy and backup systems for critical services
• Establish comprehensive incident logging, monitoring, and automated alerting systems
```

**Report Export:**
- JSON format export for integration with compliance management systems
- Detailed technical findings with DORA article references
- Remediation guidance with specific implementation recommendations
- Executive summary suitable for regulatory reporting

## Command Line Usage

### Basic Syntax
```bash
dotnet run -- [IP_ADDRESS] [OPTIONS]
```

### Options
- `--ip, -i <address>` - Target IP address or network
- `--single, -s` - Scan single IP only
- `--cidr, -c` - Use CIDR notation
- `--ports, -p <ports>` - Custom port specification
- `--help, -h` - Show help information

### Examples

#### Single Host Scan
```bash
dotnet run -- 192.168.1.1 --single
```

#### Network Range with Custom Ports
```bash
dotnet run -- 192.168.1.0/24 --cidr --ports 22,80,443,3389
```

#### Port Ranges
```bash
dotnet run -- 10.0.0.1 --single --ports 8080-8090,3000-3100
```

### Non-Interactive Mode
Command line usage runs in non-interactive mode, providing:
- Progress indicators
- Structured output
- No live display (for scripting)
- Results summary at completion

## Export and Reports

### Export Formats
- **JSON** - Structured data with complete details
- **CSV** - Spreadsheet-compatible format
- **Text Reports** - Human-readable summaries

### Export Options
1. **Scan Results** - Raw discovery data with timestamps
2. **Network Configuration** - System network settings
3. **Security Reports** - Vulnerability assessment summaries

### Automated Reporting
- Network interface inventory
- Service distribution analysis
- Security risk assessment
- Historical comparison (when available)

## Troubleshooting

### Common Issues

#### "No Network Interfaces Found"
- **Cause**: No active network connections
- **Solution**: Check network connectivity, enable network adapter

#### "Permission Denied" Errors
- **Cause**: Insufficient privileges for network operations
- **Solution**: Run with administrator/root privileges

#### Slow Scanning Performance
- **Causes**: Network congestion, high latency, firewall delays
- **Solutions**:
  - Reduce concurrent connections
  - Increase timeout values
  - Scan smaller IP ranges
  - Use specific port lists instead of full ranges

#### "Cannot Resolve Hostname"
- **Cause**: DNS resolution failure
- **Solution**: Use IP address directly or check DNS settings

### Performance Optimization

#### For Large Networks
- Use CIDR scanning for efficient network traversal
- Scan during off-peak hours
- Consider scanning in smaller segments
- Use quick scan for initial discovery

#### For Slow Networks
- Increase timeout values
- Reduce concurrent connections
- Use ping sweep before port scanning
- Focus on essential ports only

## Best Practices

### Ethical Scanning
1. **Only scan networks you own or have permission to test**
2. **Respect rate limits to avoid overwhelming targets**
3. **Document and report findings responsibly**
4. **Follow legal and organizational policies**

### Security Assessment Workflow
1. **Discovery Phase**
   - Start with ping sweep
   - Identify live hosts
   - Basic service enumeration

2. **Analysis Phase**
   - Detailed port scanning
   - Service version detection
   - Vulnerability assessment

3. **Reporting Phase**
   - Document all findings
   - Prioritize security issues
   - Provide remediation recommendations

### Network Troubleshooting Workflow
1. **Connectivity Check**
   - Ping sweep to verify reachability
   - Check network interface status
   - Verify routing table

2. **Service Analysis**
   - Port scanning for expected services
   - DNS resolution testing
   - Bandwidth performance testing

3. **Path Analysis**
   - Traceroute for routing issues
   - Network latency measurement
   - Connection quality assessment

### Regular Monitoring
- Schedule periodic security scans
- Monitor for unauthorized services
- Track network inventory changes
- Maintain baseline configurations

## Advanced Features

### Custom Port Specifications
- **Single Ports**: `80,443,8080`
- **Port Ranges**: `8000-8100`
- **Mixed Specification**: `22,80,443,8080-8090,3000-3100`

### CIDR Network Calculations
The scanner automatically calculates:
- Network address
- Broadcast address
- Number of hosts
- IP range boundaries

### Performance Tuning
- **Concurrent Connections**: Default 200, adjustable
- **Timeout Values**: Default 1000ms, configurable
- **Refresh Rates**: Live display updates every 300ms
- **Memory Management**: Efficient handling of large result sets

---

**💡 Pro Tip**: Start with ping sweeps and quick scans to get an overview, then use detailed scans on interesting targets. Always use the security tools responsibly and only on networks you're authorized to test.

**🆘 Need More Help?**: Use the built-in help system (❓ Help menu) or check the README.md file for additional information and examples.
