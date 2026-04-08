"""
Test configuration and fixtures.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch
import ipaddress
from datetime import datetime

from onprem_network_infraiq.core.models import (
    ScanResult,
    VulnerabilityResult,
    NetworkRange,
    ScanConfiguration,
    SeverityLevel,
    ScanType,
)


@pytest.fixture
def sample_scan_result():
    """Sample scan result for testing."""
    return ScanResult(
        ip_address="192.168.1.1",
        port=80,
        is_open=True,
        service_name="HTTP",
        ping_time=12.5,
        operating_system="Linux",
        server_info="Apache/2.4.41",
        hostname="test.local",
        is_vulnerable=False,
        vulnerability_info="",
        service_version="Apache 2.4.41"
    )


@pytest.fixture
def sample_vulnerability_result():
    """Sample vulnerability result for testing."""
    return VulnerabilityResult(
        host="192.168.1.1",
        port=22,
        service="SSH",
        vulnerability="Weak SSH Version",
        severity=SeverityLevel.HIGH,
        title="SSH Server Vulnerable Version",
        description="SSH server is running a vulnerable version",
        recommendation="Update SSH server to latest version",
        cve_id="CVE-2020-15778",
        cvss_score=7.5
    )


@pytest.fixture
def sample_network_range():
    """Sample network range for testing."""
    return NetworkRange(
        network="192.168.1.0/24",
        description="Test network"
    )


@pytest.fixture
def sample_scan_config():
    """Sample scan configuration for testing."""
    return ScanConfiguration(
        timeout=5,
        max_threads=10,
        ports=[22, 80, 443],
        scan_type=ScanType.PORT,
        include_vulnerability_scan=False
    )


@pytest.fixture
def mock_socket():
    """Mock socket for testing."""
    with patch('socket.socket') as mock_sock:
        mock_sock.return_value.connect_ex.return_value = 0
        mock_sock.return_value.recv.return_value = b"SSH-2.0-OpenSSH_8.0"
        yield mock_sock


@pytest.fixture
def mock_dns_resolver():
    """Mock DNS resolver for testing."""
    with patch('dns.resolver.resolve') as mock_resolve:
        mock_resolve.return_value = ['192.168.1.1']
        yield mock_resolve


# Test data
SAMPLE_HOSTS = [
    "192.168.1.1",
    "192.168.1.2",
    "192.168.1.3",
    "10.0.0.1",
    "172.16.0.1"
]

SAMPLE_PORTS = [22, 80, 443, 3389, 5432]

SAMPLE_NETWORKS = [
    "192.168.1.0/24",
    "10.0.0.0/8",
    "172.16.0.0/12"
]

SAMPLE_VULNERABILITIES = [
    {
        "id": "weak_ssh",
        "title": "Weak SSH Version",
        "severity": SeverityLevel.HIGH,
        "ports": [22],
        "description": "SSH server running vulnerable version"
    },
    {
        "id": "anonymous_ftp",
        "title": "Anonymous FTP Access",
        "severity": SeverityLevel.MEDIUM,
        "ports": [21],
        "description": "FTP server allows anonymous access"
    }
]