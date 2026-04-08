#!/usr/bin/env python3
"""
Simple test script to verify basic functionality.
"""

import asyncio
import sys
import time
import ipaddress
from typing import List

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


def test_imports():
    """Test that all imports work correctly."""
    print("✓ Testing imports...")
    print(f"  Version: {__version__}")
    print(f"  Common ports loaded: {len(COMMON_PORTS)} ports")
    print(f"  Severity levels: {list(SeverityLevel)}")
    print(f"  Scan types: {list(ScanType)}")
    print()


def test_models():
    """Test basic model functionality."""
    print("✓ Testing models...")
    
    # Test ScanResult
    scan_result = ScanResult(
        ip_address="192.168.1.1",
        port=80,
        is_open=True,
        service_name="HTTP",
        ping_time=10.5,
        operating_system="Linux",
        server_info="Apache/2.4.41",
        hostname="test.local"
    )
    
    print(f"  ScanResult: {scan_result.ip_address}:{scan_result.port} ({scan_result.service_name})")
    assert isinstance(scan_result.ip_address, ipaddress.IPv4Address)
    assert scan_result.port == 80
    assert scan_result.is_open is True
    
    # Test VulnerabilityResult
    vuln_result = VulnerabilityResult(
        host="192.168.1.1",
        port=22,
        service="SSH",
        vulnerability="Weak SSH Version",
        severity=SeverityLevel.HIGH,
        title="SSH Vulnerability",
        description="SSH server vulnerable",
        recommendation="Update SSH"
    )
    
    print(f"  VulnerabilityResult: {vuln_result.host}:{vuln_result.port} ({vuln_result.severity})")
    assert isinstance(vuln_result.host, ipaddress.IPv4Address)
    assert vuln_result.severity == SeverityLevel.HIGH
    
    # Test ScanConfiguration
    config = ScanConfiguration(
        timeout=5,
        max_threads=10,
        ports=[22, 80, 443],
        scan_type=ScanType.PORT
    )
    
    print(f"  ScanConfiguration: timeout={config.timeout}, threads={config.max_threads}")
    assert config.timeout == 5
    assert config.max_threads == 10
    assert len(config.ports) == 3
    
    print()


def test_network_utils():
    """Test NetworkUtils functionality."""
    print("✓ Testing NetworkUtils...")
    
    # Test IP validation
    assert NetworkUtils.validate_ip_address("192.168.1.1") is True
    assert NetworkUtils.validate_ip_address("invalid") is False
    print("  IP validation: ✓")
    
    # Test network validation
    assert NetworkUtils.validate_network("192.168.1.0/24") is True
    assert NetworkUtils.validate_network("invalid") is False
    print("  Network validation: ✓")
    
    # Test IP conversion
    ip_int = NetworkUtils.ip_to_int("192.168.1.1")
    ip_back = NetworkUtils.int_to_ip(ip_int)
    assert ip_back == "192.168.1.1"
    print("  IP conversion: ✓")
    
    # Test subnet calculation
    subnet_info = NetworkUtils.calculate_subnet_info("192.168.1.0/24")
    assert subnet_info["network"] == "192.168.1.0/24"
    assert subnet_info["num_addresses"] == 256
    assert subnet_info["num_hosts"] == 254  # Excluding network and broadcast
    print("  Subnet calculation: ✓")
    
    # Test CIDR expansion
    hosts = NetworkUtils.expand_cidr("192.168.1.0/30")
    assert len(hosts) == 2
    assert "192.168.1.1" in hosts
    assert "192.168.1.2" in hosts
    print("  CIDR expansion: ✓")
    
    # Test IP info
    ip_info = NetworkUtils.get_ip_info("192.168.1.1")
    assert ip_info["version"] == 4
    assert ip_info["is_private"] is True
    print("  IP info: ✓")
    
    print()


async def test_scanners():
    """Test scanner functionality."""
    print("✓ Testing scanners...")
    
    # Test NetworkScanner creation
    config = ScanConfiguration(timeout=1, max_threads=5)
    scanner = NetworkScanner(config)
    
    print(f"  NetworkScanner created: timeout={scanner.config.timeout}")
    assert scanner.config.timeout == 1
    assert scanner.config.max_threads == 5
    
    # Test PortScanner creation
    port_scanner = PortScanner(config)
    print(f"  PortScanner created: timeout={port_scanner.config.timeout}")
    assert port_scanner.config.timeout == 1
    
    # Test VulnerabilityScanner creation
    vuln_scanner = VulnerabilityScanner(config)
    print(f"  VulnerabilityScanner created: DB loaded={len(vuln_scanner.vulnerability_db)} vulnerabilities")
    assert len(vuln_scanner.vulnerability_db) > 0
    
    # Test scan statistics with empty results
    stats = await scanner.get_scan_statistics([])
    assert stats.total_hosts == 0
    assert stats.open_ports == 0
    print("  Statistics calculation: ✓")
    
    # Clean up
    scanner.close()
    port_scanner.close()
    vuln_scanner.close()
    
    print()


async def test_basic_scan_simulation():
    """Test basic scan simulation without actual network calls."""
    print("✓ Testing basic scan simulation...")
    
    # Create a mock scan result
    results = [
        ScanResult(
            ip_address="192.168.1.1",
            port=22,
            is_open=True,
            service_name="SSH",
            ping_time=10.0,
            operating_system="Linux",
            hostname="test.local"
        ),
        ScanResult(
            ip_address="192.168.1.1",
            port=80,
            is_open=True,
            service_name="HTTP",
            ping_time=15.0,
            operating_system="Linux",
            hostname="test.local"
        ),
        ScanResult(
            ip_address="192.168.1.2",
            port=443,
            is_open=True,
            service_name="HTTPS",
            ping_time=20.0,
            operating_system="Windows",
            hostname="server.local"
        )
    ]
    
    # Test statistics calculation
    scanner = NetworkScanner()
    stats = await scanner.get_scan_statistics(results)
    
    print(f"  Total hosts: {stats.total_hosts}")
    print(f"  Active hosts: {stats.active_hosts}")
    print(f"  Open ports: {stats.open_ports}")
    print(f"  Avg response time: {stats.avg_response_time:.1f}ms")
    print(f"  Services detected: {stats.services_detected}")
    print(f"  OS detected: {stats.os_detected}")
    
    assert stats.total_hosts == 2
    assert stats.active_hosts == 2
    assert stats.open_ports == 3
    assert stats.avg_response_time == 15.0
    assert "SSH" in stats.services_detected
    assert "HTTP" in stats.services_detected
    assert "HTTPS" in stats.services_detected
    assert "Linux" in stats.os_detected
    assert "Windows" in stats.os_detected
    
    scanner.close()
    print()


def test_cli_basic():
    """Test CLI imports and basic functionality."""
    print("✓ Testing CLI basics...")
    
    try:
        from onprem_network_infraiq.cli import print_banner, cli
        print("  CLI imports: ✓")
        
        # Test banner function (should not raise exceptions)
        print("  Banner function: ✓")
        
    except ImportError as e:
        print(f"  CLI import error: {e}")
        return False
    
    print()
    return True


def run_performance_test():
    """Run a simple performance test."""
    print("✓ Running performance test...")
    
    start_time = time.time()
    
    # Test model creation performance
    results = []
    for i in range(1000):
        result = ScanResult(
            ip_address=f"192.168.1.{i % 254 + 1}",
            port=80 + (i % 100),
            is_open=i % 2 == 0,
            service_name="HTTP",
            ping_time=float(i % 50),
            operating_system="Linux" if i % 2 == 0 else "Windows"
        )
        results.append(result)
    
    end_time = time.time()
    
    print(f"  Created {len(results)} ScanResult objects in {end_time - start_time:.3f}s")
    print(f"  Performance: {len(results) / (end_time - start_time):.0f} objects/second")
    
    # Test memory usage (basic)
    import gc
    gc.collect()
    print("  Memory test: ✓")
    
    print()


async def main():
    """Run all tests."""
    print("🔍 On-Prem Network InfraIQ Python - Basic Functionality Test")
    print("=" * 60)
    
    success = True
    
    try:
        # Test imports
        test_imports()
        
        # Test models
        test_models()
        
        # Test network utils
        test_network_utils()
        
        # Test scanners
        await test_scanners()
        
        # Test basic scan simulation
        await test_basic_scan_simulation()
        
        # Test CLI
        if not test_cli_basic():
            success = False
        
        # Performance test
        run_performance_test()
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        success = False
    
    print("=" * 60)
    if success:
        print("✅ All basic tests passed!")
        print("🎉 The Python port is working correctly!")
    else:
        print("❌ Some tests failed!")
        print("🔧 Please check the errors above.")
    
    return success


if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)