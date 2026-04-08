# On-Prem Network InfraIQ - Python Port

[![PyPI version](https://badge.fury.io/py/onprem-network-infraiq.svg)](https://badge.fury.io/py/onprem-network-infraiq)
[![Python versions](https://img.shields.io/pypi/pyversions/onprem-network-infraiq.svg)](https://pypi.org/project/onprem-network-infraiq/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Enterprise-grade network discovery and security assessment platform, now available in Python!

## Features

- 🔍 **Network Discovery**: Comprehensive network scanning and service detection
- 🛡️ **Security Assessment**: Vulnerability scanning with 30+ security checks
- 🌐 **Protocol Support**: TCP, UDP, ICMP with IPv4/IPv6 support
- 🎯 **Smart Detection**: Advanced service fingerprinting and OS detection
- 📊 **Rich Output**: Beautiful console output with progress tracking
- 🔧 **Extensible**: Plugin-based architecture for custom modules
- 🚀 **High Performance**: Async/await based scanning with concurrent execution

## Installation

### From PyPI (Recommended)

```bash
pip install onprem-network-infraiq
```

### From Source

```bash
git clone https://github.com/jomardyan/On-Prem-Network-InfraIQ.git
cd On-Prem-Network-InfraIQ
pip install -e .
```

## Quick Start

### Command Line Interface

```bash
# Basic network scan
onprem-infraiq scan network 192.168.1.0/24

# Single host scan
onprem-infraiq scan host 192.168.1.1

# Vulnerability assessment
onprem-infraiq vuln scan 192.168.1.1

# Interactive mode
onprem-infraiq interactive
```

### Python Library

```python
import asyncio
from onprem_network_infraiq import NetworkScanner, VulnerabilityScanner

async def main():
    # Network scanning
    scanner = NetworkScanner()
    results = await scanner.scan_network("192.168.1.0/24")
    
    for result in results:
        print(f"Host: {result.ip} - Port: {result.port} - Service: {result.service}")
    
    # Vulnerability assessment
    vuln_scanner = VulnerabilityScanner()
    vulnerabilities = await vuln_scanner.scan_host("192.168.1.1")
    
    for vuln in vulnerabilities:
        print(f"Vulnerability: {vuln.title} - Severity: {vuln.severity}")

asyncio.run(main())
```

## Documentation

For comprehensive documentation, visit: [Documentation](https://github.com/jomardyan/On-Prem-Network-InfraIQ/blob/main/HELP.md)

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security Notice

⚠️ **Important**: This tool is designed for authorized security testing only. Always ensure you have explicit permission before scanning any networks or systems.

## Support

- 🐛 [Report Issues](https://github.com/jomardyan/On-Prem-Network-InfraIQ/issues)
- 💬 [Discussions](https://github.com/jomardyan/On-Prem-Network-InfraIQ/discussions)
- 📧 [Contact Us](mailto:info@onprem-infraiq.com)