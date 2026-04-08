#!/usr/bin/env python3
"""
Demo script showing the Python port functionality.
"""

import asyncio
import sys
import time
from datetime import datetime

# Add the current directory to path for imports
sys.path.insert(0, '/home/runner/work/On-Prem-Network-InfraIQ/On-Prem-Network-InfraIQ')

from onprem_network_infraiq import (
    NetworkScanner,
    VulnerabilityScanner,
    PortScanner,
    NetworkUtils,
    ScanConfiguration,
    ScanResult,
    VulnerabilityResult,
    SeverityLevel,
    ScanType,
    COMMON_PORTS,
    __version__,
)

async def main():
    """Demonstrate the Python port functionality."""
    print("🔍 On-Prem Network InfraIQ - Python Port Demo")
    print("=" * 60)
    print(f"Version: {__version__}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()
    
    # 1. Demonstrate Network Utilities
    print("📡 1. Network Utilities Demo")
    print("-" * 30)
    
    # IP validation
    test_ips = ["192.168.1.1", "10.0.0.1", "invalid-ip", "2001:db8::1"]
    for ip in test_ips:
        is_valid = NetworkUtils.validate_ip_address(ip)
        print(f"  {ip:<15} - {'✓ Valid' if is_valid else '✗ Invalid'}")
    
    # Subnet calculation
    network = "192.168.1.0/24"
    subnet_info = NetworkUtils.calculate_subnet_info(network)
    print(f"\n  Network: {network}")
    print(f"  Hosts: {subnet_info['num_hosts']}")
    print(f"  First host: {subnet_info['first_host']}")
    print(f"  Last host: {subnet_info['last_host']}")
    print()
    
    # 2. Demonstrate Data Models
    print("📊 2. Data Models Demo")
    print("-" * 30)
    
    # Create sample scan result
    scan_result = ScanResult(
        ip_address="192.168.1.1",
        port=80,
        is_open=True,
        service_name="HTTP",
        ping_time=12.5,
        operating_system="Linux",
        server_info="Apache/2.4.41",
        hostname="webserver.local",
        service_version="Apache 2.4.41"
    )
    
    print(f"  Scan Result: {scan_result.ip_address}:{scan_result.port}")
    print(f"  Service: {scan_result.service_name} ({scan_result.service_version})")
    print(f"  Response time: {scan_result.ping_time}ms")
    print(f"  OS: {scan_result.operating_system}")
    print(f"  Hostname: {scan_result.hostname}")
    
    # Create sample vulnerability result
    vuln_result = VulnerabilityResult(
        host="192.168.1.1",
        port=22,
        service="SSH",
        vulnerability="Weak SSH Version",
        severity=SeverityLevel.HIGH,
        title="SSH Server Vulnerable Version",
        description="SSH server is running OpenSSH 6.0 which has known vulnerabilities",
        recommendation="Update SSH server to OpenSSH 8.0 or later",
        cve_id="CVE-2020-15778"
    )
    
    print(f"\n  Vulnerability: {vuln_result.title}")
    print(f"  Severity: {vuln_result.severity}")
    print(f"  Service: {vuln_result.service} on port {vuln_result.port}")
    print(f"  CVE: {vuln_result.cve_id}")
    print()
    
    # 3. Demonstrate Scanner Configuration
    print("⚙️ 3. Scanner Configuration Demo")
    print("-" * 30)
    
    config = ScanConfiguration(
        timeout=5,
        max_threads=50,
        ports=[22, 80, 443, 3389, 5432],
        scan_type=ScanType.COMPREHENSIVE,
        include_vulnerability_scan=True,
        stealth_mode=False,
        user_agent="OnPrem-InfraIQ-Demo/2.1.0"
    )
    
    print(f"  Timeout: {config.timeout}s")
    print(f"  Max threads: {config.max_threads}")
    print(f"  Ports to scan: {config.ports}")
    print(f"  Scan type: {config.scan_type}")
    print(f"  Vulnerability scan: {config.include_vulnerability_scan}")
    print(f"  Stealth mode: {config.stealth_mode}")
    print()
    
    # 4. Demonstrate Scanner Creation
    print("🔧 4. Scanner Creation Demo")
    print("-" * 30)
    
    # Create scanners
    network_scanner = NetworkScanner(config)
    port_scanner = PortScanner(config)
    vuln_scanner = VulnerabilityScanner(config)
    
    print(f"  NetworkScanner: ✓ Created (timeout={network_scanner.config.timeout}s)")
    print(f"  PortScanner: ✓ Created (threads={port_scanner.config.max_threads})")
    print(f"  VulnerabilityScanner: ✓ Created (DB={len(vuln_scanner.vulnerability_db)} vulns)")
    print()
    
    # 5. Demonstrate Statistics Calculation
    print("📈 5. Statistics Calculation Demo")
    print("-" * 30)
    
    # Create sample results
    sample_results = [
        ScanResult(
            ip_address="192.168.1.1",
            port=22,
            is_open=True,
            service_name="SSH",
            ping_time=8.5,
            operating_system="Linux",
            is_vulnerable=True
        ),
        ScanResult(
            ip_address="192.168.1.1",
            port=80,
            is_open=True,
            service_name="HTTP",
            ping_time=12.0,
            operating_system="Linux"
        ),
        ScanResult(
            ip_address="192.168.1.2",
            port=443,
            is_open=True,
            service_name="HTTPS",
            ping_time=15.5,
            operating_system="Windows"
        ),
        ScanResult(
            ip_address="192.168.1.3",
            port=3389,
            is_open=True,
            service_name="RDP",
            ping_time=22.0,
            operating_system="Windows"
        ),
    ]
    
    stats = await network_scanner.get_scan_statistics(sample_results)
    
    print(f"  Total hosts: {stats.total_hosts}")
    print(f"  Active hosts: {stats.active_hosts}")
    print(f"  Open ports: {stats.open_ports}")
    print(f"  Vulnerabilities: {stats.vulnerabilities_found}")
    print(f"  Avg response time: {stats.avg_response_time:.1f}ms")
    print(f"  Services detected: {', '.join(stats.services_detected)}")
    print(f"  OS detected: {', '.join(stats.os_detected)}")
    print()
    
    # 6. Demonstrate Vulnerability Database
    print("🛡️ 6. Vulnerability Database Demo")
    print("-" * 30)
    
    print(f"  Total vulnerabilities in DB: {len(vuln_scanner.vulnerability_db)}")
    print("  Sample vulnerabilities:")
    
    for i, (vuln_id, vuln_info) in enumerate(list(vuln_scanner.vulnerability_db.items())[:5]):
        print(f"    {i+1}. {vuln_info['title']} ({vuln_info['severity']})")
        print(f"       Ports: {vuln_info['ports']}")
        print(f"       Method: {vuln_info['test_method']}")
    
    print()
    
    # 7. Demonstrate Network Expansion
    print("🌐 7. Network Expansion Demo")
    print("-" * 30)
    
    # Small network expansion
    small_network = "192.168.1.0/30"
    hosts = NetworkUtils.expand_cidr(small_network)
    print(f"  Network: {small_network}")
    print(f"  Hosts: {', '.join(hosts)}")
    
    # Large network (limited)
    large_network = "10.0.0.0/16"
    hosts_large = NetworkUtils.expand_cidr(large_network, max_hosts=5)
    print(f"\n  Network: {large_network}")
    print(f"  First 5 hosts: {', '.join(hosts_large)}")
    print()
    
    # 8. Performance Test
    print("🚀 8. Performance Test")
    print("-" * 30)
    
    start_time = time.time()
    
    # Create many objects
    results = []
    for i in range(5000):
        result = ScanResult(
            ip_address=f"192.168.{i//254 + 1}.{i%254 + 1}",
            port=80 + (i % 100),
            is_open=i % 3 == 0,
            service_name="HTTP",
            ping_time=float(i % 50 + 5),
            operating_system="Linux" if i % 2 == 0 else "Windows"
        )
        results.append(result)
    
    end_time = time.time()
    
    print(f"  Created {len(results)} objects in {end_time - start_time:.3f}s")
    print(f"  Performance: {len(results) / (end_time - start_time):.0f} objects/second")
    print()
    
    # Clean up
    network_scanner.close()
    port_scanner.close()
    vuln_scanner.close()
    
    print("=" * 60)
    print("✅ Demo completed successfully!")
    print("🎉 Python port is fully functional and ready for use!")
    print()
    print("📝 Next steps:")
    print("  - Install: pip install onprem-network-infraiq")
    print("  - CLI: onprem-infraiq --help")
    print("  - Library: from onprem_network_infraiq import NetworkScanner")
    print("  - Publish to PyPI when ready!")


if __name__ == "__main__":
    asyncio.run(main())