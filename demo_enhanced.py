#!/usr/bin/env python3
"""
Enhanced Python Library Demonstration Script

This script demonstrates the enhanced capabilities of the OnPrem Network InfraIQ Python library.
"""

import asyncio
import sys
import os
from datetime import datetime

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def print_banner():
    """Print the demo banner."""
    print("=" * 80)
    print("🚀 On-Prem Network InfraIQ - Enhanced Python Library Demo")
    print("=" * 80)
    print()


def check_module_availability():
    """Check which enhanced modules are available."""
    print("📋 Checking module availability:")
    print("-" * 40)
    
    available_modules = []
    
    try:
        import onprem_network_infraiq
        print("✅ Core library imported successfully")
        available_modules.append("core")
    except ImportError as e:
        print(f"❌ Core library import failed: {e}")
        return []
    
    # Check core modules
    core_modules = [
        ("NetworkScanner", "Basic network scanning"),
        ("NetworkUtils", "Network utility functions"),
        ("ScanResult", "Data model for scan results"),
        ("HostInfo", "Data model for host information"),
    ]
    
    for module_name, description in core_modules:
        try:
            getattr(onprem_network_infraiq, module_name)
            print(f"✅ {module_name} - {description}")
            available_modules.append(module_name)
        except AttributeError:
            print(f"❌ {module_name} - Not available")
    
    # Check enhanced modules
    enhanced_modules = [
        ("VulnerabilityScanner", "Vulnerability assessment"),
        ("PortScanner", "Advanced port scanning"),
        ("IPv6Scanner", "IPv6 network discovery"),
        ("SSLCertificateAnalyzer", "SSL/TLS certificate analysis"),
        ("WebApplicationScanner", "Web vulnerability scanning"),
        ("NetworkAnomalyDetector", "ML-based anomaly detection"),
        ("DatabaseManager", "Persistent data storage"),
    ]
    
    print()
    print("🔧 Enhanced modules:")
    for module_name, description in enhanced_modules:
        try:
            module = getattr(onprem_network_infraiq, module_name)
            if module is not None:
                print(f"✅ {module_name} - {description}")
                available_modules.append(module_name)
            else:
                print(f"⚠️  {module_name} - Disabled (missing dependencies)")
        except AttributeError:
            print(f"❌ {module_name} - Not available")
    
    print()
    print(f"📊 Total available modules: {len(available_modules)}")
    print(f"🔢 Library version: {onprem_network_infraiq.__version__}")
    print()
    
    return available_modules


async def demo_basic_scanning():
    """Demonstrate basic network scanning capabilities."""
    print("🔍 Basic Network Scanning Demo")
    print("-" * 40)
    
    try:
        from onprem_network_infraiq import NetworkScanner
        
        # Create scanner instance
        scanner = NetworkScanner()
        print("✅ NetworkScanner instantiated")
        
        # Demo: scan localhost
        print("🎯 Scanning localhost...")
        results = await scanner.scan_host("127.0.0.1", [22, 80, 443, 8080])
        
        print(f"📊 Found {len(results)} results:")
        for result in results[:3]:  # Show first 3 results
            status = "🟢 OPEN" if result.is_open else "🔴 CLOSED"
            print(f"  {status} {result.ip_address}:{result.port} - {result.service_name}")
        
        if len(results) > 3:
            print(f"  ... and {len(results) - 3} more")
            
    except Exception as e:
        print(f"❌ Basic scanning demo failed: {e}")
    
    print()


async def demo_host_discovery():
    """Demonstrate host discovery capabilities."""
    print("🌐 Host Discovery Demo")
    print("-" * 40)
    
    try:
        from onprem_network_infraiq import NetworkScanner
        
        scanner = NetworkScanner()
        
        # Demo: discover hosts in local network
        print("🔍 Discovering hosts in local network...")
        hosts = await scanner.discover_hosts("127.0.0.0/30")  # Small range for demo
        
        print(f"📊 Discovered {len(hosts)} hosts:")
        for host in hosts[:5]:  # Show first 5 hosts
            status = "🟢 UP" if host.is_reachable else "🔴 DOWN"
            print(f"  {status} {host.ip_address} - {host.hostname or 'Unknown'}")
        
        if len(hosts) > 5:
            print(f"  ... and {len(hosts) - 5} more")
            
    except Exception as e:
        print(f"❌ Host discovery demo failed: {e}")
    
    print()


async def demo_vulnerability_scanning():
    """Demonstrate vulnerability scanning capabilities."""
    print("🔐 Vulnerability Scanning Demo")
    print("-" * 40)
    
    try:
        from onprem_network_infraiq import VulnerabilityScanner
        
        if VulnerabilityScanner is None:
            print("⚠️  VulnerabilityScanner not available (missing dependencies)")
            return
        
        vuln_scanner = VulnerabilityScanner()
        print("✅ VulnerabilityScanner instantiated")
        
        # Demo: scan localhost for vulnerabilities
        print("🔍 Scanning localhost for vulnerabilities...")
        vulnerabilities = await vuln_scanner.scan_host("127.0.0.1")
        
        print(f"📊 Found {len(vulnerabilities)} potential vulnerabilities:")
        for vuln in vulnerabilities[:3]:  # Show first 3 vulnerabilities
            severity_icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(vuln.severity, "ℹ️")
            print(f"  {severity_icon} {vuln.severity} - {vuln.title}")
        
        if len(vulnerabilities) > 3:
            print(f"  ... and {len(vulnerabilities) - 3} more")
            
    except Exception as e:
        print(f"❌ Vulnerability scanning demo failed: {e}")
    
    print()


async def demo_ipv6_scanning():
    """Demonstrate IPv6 scanning capabilities."""
    print("🔗 IPv6 Scanning Demo")
    print("-" * 40)
    
    try:
        from onprem_network_infraiq import IPv6Scanner
        
        if IPv6Scanner is None:
            print("⚠️  IPv6Scanner not available (missing dependencies)")
            return
        
        ipv6_scanner = IPv6Scanner()
        print("✅ IPv6Scanner instantiated")
        
        # Demo: IPv6 neighbor discovery
        print("🔍 Performing IPv6 neighbor discovery...")
        hosts = []
        async for host in ipv6_scanner.discover_link_local_hosts():
            hosts.append(host)
            if len(hosts) >= 5:  # Limit for demo
                break
        
        print(f"📊 Discovered {len(hosts)} IPv6 hosts:")
        for host in hosts:
            print(f"  🔗 {host.ip_address} - {host.hostname or 'Unknown'}")
        
        if len(hosts) == 0:
            print("  ℹ️  No IPv6 hosts discovered in link-local network")
            
    except Exception as e:
        print(f"❌ IPv6 scanning demo failed: {e}")
    
    print()


async def demo_ssl_analysis():
    """Demonstrate SSL certificate analysis capabilities."""
    print("🔒 SSL Certificate Analysis Demo")
    print("-" * 40)
    
    try:
        from onprem_network_infraiq import SSLCertificateAnalyzer
        
        if SSLCertificateAnalyzer is None:
            print("⚠️  SSLCertificateAnalyzer not available (missing dependencies)")
            return
        
        ssl_analyzer = SSLCertificateAnalyzer()
        print("✅ SSLCertificateAnalyzer instantiated")
        
        # Demo: analyze a certificate (using a common public site)
        print("🔍 Analyzing SSL certificate...")
        cert_info = await ssl_analyzer.analyze_certificate("httpbin.org", 443)
        
        if cert_info:
            print(f"📊 Certificate analysis results:")
            print(f"  🏷️  Subject: {cert_info.subject.get('commonName', 'Unknown')}")
            print(f"  🏢 Issuer: {cert_info.issuer.get('organizationName', 'Unknown')}")
            print(f"  🔐 Security Level: {cert_info.security_level}")
            print(f"  📅 Expires: {cert_info.not_after.strftime('%Y-%m-%d')}")
            print(f"  ⚠️  Vulnerabilities: {len(cert_info.vulnerabilities)}")
        else:
            print("  ℹ️  Could not analyze certificate (network unreachable)")
            
    except Exception as e:
        print(f"❌ SSL analysis demo failed: {e}")
    
    print()


async def demo_anomaly_detection():
    """Demonstrate anomaly detection capabilities."""
    print("🤖 Anomaly Detection Demo")
    print("-" * 40)
    
    try:
        from onprem_network_infraiq import NetworkAnomalyDetector
        
        if NetworkAnomalyDetector is None:
            print("⚠️  NetworkAnomalyDetector not available (missing dependencies)")
            return
        
        anomaly_detector = NetworkAnomalyDetector()
        print("✅ NetworkAnomalyDetector instantiated")
        
        # Demo: analyze some mock scan results
        print("🔍 Analyzing network data for anomalies...")
        
        # Create mock scan results for demonstration
        from onprem_network_infraiq import ScanResult
        import ipaddress
        
        mock_results = [
            ScanResult(
                ip_address=ipaddress.IPv4Address("127.0.0.1"),
                port=22,
                is_open=True,
                service_name="ssh",
                ping_time=5.0
            ),
            ScanResult(
                ip_address=ipaddress.IPv4Address("127.0.0.1"),
                port=80,
                is_open=True,
                service_name="http",
                ping_time=2.0
            ),
            ScanResult(
                ip_address=ipaddress.IPv4Address("127.0.0.1"),
                port=443,
                is_open=True,
                service_name="https",
                ping_time=3.0
            )
        ]
        
        anomalies = await anomaly_detector.analyze_network_data(mock_results)
        
        print(f"📊 Detected {len(anomalies)} anomalies:")
        for anomaly in anomalies[:3]:  # Show first 3 anomalies
            severity_icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(anomaly.severity, "ℹ️")
            print(f"  {severity_icon} {anomaly.severity} - {anomaly.description}")
        
        if len(anomalies) > 3:
            print(f"  ... and {len(anomalies) - 3} more")
        elif len(anomalies) == 0:
            print("  ✅ No anomalies detected in network data")
            
    except Exception as e:
        print(f"❌ Anomaly detection demo failed: {e}")
    
    print()


async def demo_database_integration():
    """Demonstrate database integration capabilities."""
    print("💾 Database Integration Demo")
    print("-" * 40)
    
    try:
        from onprem_network_infraiq import DatabaseManager
        
        if DatabaseManager is None:
            print("⚠️  DatabaseManager not available (missing dependencies)")
            return
        
        # Use in-memory SQLite for demo
        db_manager = DatabaseManager("sqlite:///:memory:")
        print("✅ DatabaseManager instantiated")
        
        # Demo: initialize database
        print("🔍 Initializing database...")
        await db_manager.initialize()
        
        # Demo: save some mock scan results
        from onprem_network_infraiq import ScanResult
        import ipaddress
        
        mock_results = [
            ScanResult(
                ip_address=ipaddress.IPv4Address("127.0.0.1"),
                port=22,
                is_open=True,
                service_name="ssh"
            ),
            ScanResult(
                ip_address=ipaddress.IPv4Address("127.0.0.1"),
                port=80,
                is_open=True,
                service_name="http"
            )
        ]
        
        session_id = "demo_session_123"
        await db_manager.save_scan_results(session_id, mock_results)
        
        # Demo: retrieve results
        saved_results = await db_manager.get_scan_results(session_id)
        
        print(f"📊 Saved and retrieved {len(saved_results)} scan results:")
        for result in saved_results:
            print(f"  🔍 {result['ip_address']}:{result['port']} - {result['service_name']}")
        
        await db_manager.close()
        
    except Exception as e:
        print(f"❌ Database integration demo failed: {e}")
    
    print()


def print_enhancement_summary():
    """Print summary of library enhancements."""
    print("📈 Library Enhancement Summary")
    print("-" * 40)
    
    enhancements = [
        "🔧 Robust import system with optional dependencies",
        "🔗 Advanced IPv6 scanning with neighbor discovery",
        "🔒 SSL/TLS certificate analysis and security assessment",
        "🌐 Web application vulnerability scanning (OWASP Top 10)",
        "🤖 Machine learning-based anomaly detection",
        "💾 Database integration with SQLite/PostgreSQL support",
        "⚡ High-performance async/await implementation",
        "🛡️ Enterprise-grade security assessment tools",
        "📊 Comprehensive reporting and statistics",
        "🔄 Fallback mechanisms for missing dependencies",
    ]
    
    print("Key enhancements added to the Python library:")
    for enhancement in enhancements:
        print(f"  {enhancement}")
    
    print()
    print("🎯 The enhanced library provides:")
    print("  • Feature parity with the C# version")
    print("  • Additional Python-specific optimizations")
    print("  • Modern async/await patterns")
    print("  • Optional dependencies for flexible deployment")
    print("  • PyPI-ready package structure")
    print("  • Comprehensive documentation and examples")
    print()


async def main():
    """Main demo function."""
    print_banner()
    
    # Check module availability
    available_modules = check_module_availability()
    
    if not available_modules:
        print("❌ No modules available, cannot continue demo")
        return
    
    # Run basic demos
    await demo_basic_scanning()
    await demo_host_discovery()
    
    # Run enhanced demos if modules are available
    if "VulnerabilityScanner" in available_modules:
        await demo_vulnerability_scanning()
    
    if "IPv6Scanner" in available_modules:
        await demo_ipv6_scanning()
    
    if "SSLCertificateAnalyzer" in available_modules:
        await demo_ssl_analysis()
    
    if "NetworkAnomalyDetector" in available_modules:
        await demo_anomaly_detection()
    
    if "DatabaseManager" in available_modules:
        await demo_database_integration()
    
    # Print enhancement summary
    print_enhancement_summary()
    
    print("🎉 Enhanced Python Library Demo Complete!")
    print("=" * 80)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⏹️  Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()