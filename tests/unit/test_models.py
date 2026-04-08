"""
Unit tests for core models.
"""

import pytest
import ipaddress
from datetime import datetime
from onprem_network_infraiq.core.models import (
    ScanResult,
    VulnerabilityResult,
    NetworkRange,
    ScanConfiguration,
    ScanType,
    SeverityLevel,
    COMMON_PORTS,
    VULNERABILITY_PATTERNS,
)


class TestScanResult:
    """Test ScanResult model."""
    
    def test_scan_result_creation(self):
        """Test creating a ScanResult."""
        result = ScanResult(
            ip_address="192.168.1.1",
            port=80,
            is_open=True,
            service_name="HTTP"
        )
        
        assert str(result.ip_address) == "192.168.1.1"
        assert result.port == 80
        assert result.is_open is True
        assert result.service_name == "HTTP"
        assert isinstance(result.discovered_at, datetime)
    
    def test_scan_result_ip_conversion(self):
        """Test IP address conversion in ScanResult."""
        result = ScanResult(
            ip_address="192.168.1.1",
            port=80,
            is_open=True,
            service_name="HTTP"
        )
        
        assert isinstance(result.ip_address, ipaddress.IPv4Address)
        assert str(result.ip_address) == "192.168.1.1"
    
    def test_scan_result_ipv6(self):
        """Test IPv6 address in ScanResult."""
        result = ScanResult(
            ip_address="2001:db8::1",
            port=80,
            is_open=True,
            service_name="HTTP"
        )
        
        assert isinstance(result.ip_address, ipaddress.IPv6Address)
        assert str(result.ip_address) == "2001:db8::1"
    
    def test_scan_result_invalid_ip(self):
        """Test invalid IP address raises error."""
        with pytest.raises(ValueError):
            ScanResult(
                ip_address="invalid-ip",
                port=80,
                is_open=True,
                service_name="HTTP"
            )


class TestVulnerabilityResult:
    """Test VulnerabilityResult model."""
    
    def test_vulnerability_result_creation(self):
        """Test creating a VulnerabilityResult."""
        result = VulnerabilityResult(
            host="192.168.1.1",
            port=22,
            service="SSH",
            vulnerability="Weak SSH Version",
            severity=SeverityLevel.HIGH
        )
        
        assert str(result.host) == "192.168.1.1"
        assert result.port == 22
        assert result.service == "SSH"
        assert result.vulnerability == "Weak SSH Version"
        assert result.severity == SeverityLevel.HIGH
        assert isinstance(result.discovered_at, datetime)
    
    def test_vulnerability_result_ip_conversion(self):
        """Test IP address conversion in VulnerabilityResult."""
        result = VulnerabilityResult(
            host="192.168.1.1",
            port=22,
            service="SSH",
            vulnerability="Weak SSH Version",
            severity=SeverityLevel.HIGH
        )
        
        assert isinstance(result.host, ipaddress.IPv4Address)
        assert str(result.host) == "192.168.1.1"


class TestNetworkRange:
    """Test NetworkRange model."""
    
    def test_network_range_creation(self):
        """Test creating a NetworkRange."""
        network_range = NetworkRange(
            network="192.168.1.0/24",
            description="Test network"
        )
        
        assert str(network_range.network) == "192.168.1.0/24"
        assert network_range.description == "Test network"
        assert isinstance(network_range.network, ipaddress.IPv4Network)
    
    def test_network_range_hosts(self):
        """Test getting hosts from NetworkRange."""
        network_range = NetworkRange(network="192.168.1.0/30")
        
        hosts = network_range.hosts
        assert len(hosts) == 2
        assert str(hosts[0]) == "192.168.1.1"
        assert str(hosts[1]) == "192.168.1.2"
    
    def test_network_range_num_hosts(self):
        """Test getting number of hosts from NetworkRange."""
        network_range = NetworkRange(network="192.168.1.0/24")
        
        assert network_range.num_hosts == 256
    
    def test_network_range_invalid_network(self):
        """Test invalid network raises error."""
        with pytest.raises(ValueError):
            NetworkRange(network="invalid-network")


class TestScanConfiguration:
    """Test ScanConfiguration model."""
    
    def test_scan_configuration_defaults(self):
        """Test ScanConfiguration with default values."""
        config = ScanConfiguration()
        
        assert config.timeout == 5
        assert config.max_threads == 100
        assert config.ports == [22, 80, 443, 3389]
        assert config.scan_type == ScanType.PORT
        assert config.include_vulnerability_scan is False
        assert config.stealth_mode is False
        assert config.user_agent == "OnPrem-InfraIQ/2.1.0"
    
    def test_scan_configuration_custom_values(self):
        """Test ScanConfiguration with custom values."""
        config = ScanConfiguration(
            timeout=10,
            max_threads=50,
            ports=[80, 443],
            scan_type=ScanType.VULNERABILITY,
            include_vulnerability_scan=True,
            stealth_mode=True,
            user_agent="CustomAgent/1.0"
        )
        
        assert config.timeout == 10
        assert config.max_threads == 50
        assert config.ports == [80, 443]
        assert config.scan_type == ScanType.VULNERABILITY
        assert config.include_vulnerability_scan is True
        assert config.stealth_mode is True
        assert config.user_agent == "CustomAgent/1.0"
    
    def test_scan_configuration_invalid_timeout(self):
        """Test invalid timeout raises error."""
        with pytest.raises(ValueError):
            ScanConfiguration(timeout=0)
    
    def test_scan_configuration_invalid_threads(self):
        """Test invalid max_threads raises error."""
        with pytest.raises(ValueError):
            ScanConfiguration(max_threads=0)
    
    def test_scan_configuration_invalid_ports(self):
        """Test invalid ports raise error."""
        with pytest.raises(ValueError):
            ScanConfiguration(ports=[0, 65536])


class TestSeverityLevel:
    """Test SeverityLevel enum."""
    
    def test_severity_levels(self):
        """Test all severity levels."""
        assert SeverityLevel.CRITICAL == "Critical"
        assert SeverityLevel.HIGH == "High"
        assert SeverityLevel.MEDIUM == "Medium"
        assert SeverityLevel.LOW == "Low"
        assert SeverityLevel.INFO == "Info"


class TestScanType:
    """Test ScanType enum."""
    
    def test_scan_types(self):
        """Test all scan types."""
        assert ScanType.PORT == "port"
        assert ScanType.VULNERABILITY == "vulnerability"
        assert ScanType.COMPREHENSIVE == "comprehensive"
        assert ScanType.QUICK == "quick"
        assert ScanType.STEALTH == "stealth"


class TestConstants:
    """Test constants."""
    
    def test_common_ports(self):
        """Test COMMON_PORTS constant."""
        assert isinstance(COMMON_PORTS, dict)
        assert 22 in COMMON_PORTS
        assert COMMON_PORTS[22] == "SSH"
        assert 80 in COMMON_PORTS
        assert COMMON_PORTS[80] == "HTTP"
        assert 443 in COMMON_PORTS
        assert COMMON_PORTS[443] == "HTTPS"
    
    def test_vulnerability_patterns(self):
        """Test VULNERABILITY_PATTERNS constant."""
        assert isinstance(VULNERABILITY_PATTERNS, dict)
        assert "anonymous_ftp" in VULNERABILITY_PATTERNS
        assert "weak_ssh" in VULNERABILITY_PATTERNS
        assert "open_telnet" in VULNERABILITY_PATTERNS
        
        # Test structure of vulnerability patterns
        for pattern_name, pattern_data in VULNERABILITY_PATTERNS.items():
            assert "ports" in pattern_data
            assert "pattern" in pattern_data
            assert "severity" in pattern_data
            assert "description" in pattern_data
            assert isinstance(pattern_data["ports"], list)
            assert isinstance(pattern_data["severity"], SeverityLevel)