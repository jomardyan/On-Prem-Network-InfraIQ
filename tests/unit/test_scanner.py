"""
Unit tests for network scanner.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
import ipaddress

from onprem_network_infraiq.core.scanner import NetworkScanner
from onprem_network_infraiq.core.models import (
    ScanResult,
    ScanConfiguration,
    NetworkRange,
    ScanType,
)


class TestNetworkScanner:
    """Test NetworkScanner class."""
    
    def test_scanner_initialization(self):
        """Test scanner initialization."""
        scanner = NetworkScanner()
        
        assert scanner.config is not None
        assert isinstance(scanner.config, ScanConfiguration)
        assert scanner.session_id == ""
    
    def test_scanner_initialization_with_config(self):
        """Test scanner initialization with custom config."""
        config = ScanConfiguration(timeout=10, max_threads=50)
        scanner = NetworkScanner(config)
        
        assert scanner.config == config
        assert scanner.config.timeout == 10
        assert scanner.config.max_threads == 50
    
    @pytest.mark.asyncio
    async def test_ping_host_success(self):
        """Test successful host ping."""
        scanner = NetworkScanner()
        
        with patch('socket.socket') as mock_socket:
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            mock_sock.connect_ex.return_value = 0
            
            result = await scanner._ping_host("192.168.1.1")
            
            assert result is True
            mock_sock.connect_ex.assert_called()
            mock_sock.close.assert_called()
    
    @pytest.mark.asyncio
    async def test_ping_host_failure(self):
        """Test failed host ping."""
        scanner = NetworkScanner()
        
        with patch('socket.socket') as mock_socket:
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            mock_sock.connect_ex.return_value = 1  # Connection refused
            
            result = await scanner._ping_host("192.168.1.1")
            
            assert result is True  # Still returns True as host is reachable
    
    @pytest.mark.asyncio
    async def test_detect_os_windows(self):
        """Test OS detection for Windows."""
        scanner = NetworkScanner()
        
        with patch('socket.socket') as mock_socket:
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            mock_sock.connect_ex.side_effect = [0, 1, 1, 1]  # First port (135) is open
            
            result = await scanner._detect_os("192.168.1.1")
            
            assert result == "Windows"
    
    @pytest.mark.asyncio
    async def test_detect_os_linux(self):
        """Test OS detection for Linux."""
        scanner = NetworkScanner()
        
        with patch('socket.socket') as mock_socket:
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            mock_sock.connect_ex.side_effect = [1, 1, 1, 1, 0, 1]  # SSH port (22) is open
            
            result = await scanner._detect_os("192.168.1.1")
            
            assert result == "Linux/Unix"
    
    @pytest.mark.asyncio
    async def test_detect_os_unknown(self):
        """Test OS detection when unknown."""
        scanner = NetworkScanner()
        
        with patch('socket.socket') as mock_socket:
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            mock_sock.connect_ex.return_value = 1  # All ports closed
            
            result = await scanner._detect_os("192.168.1.1")
            
            assert result == "Unknown"
    
    @pytest.mark.asyncio
    async def test_get_hostname_success(self):
        """Test successful hostname resolution."""
        scanner = NetworkScanner()
        
        with patch('socket.gethostbyaddr') as mock_gethostbyaddr:
            mock_gethostbyaddr.return_value = ("test.local", [], ["192.168.1.1"])
            
            result = await scanner._get_hostname("192.168.1.1")
            
            assert result == "test.local"
    
    @pytest.mark.asyncio
    async def test_get_hostname_failure(self):
        """Test failed hostname resolution."""
        scanner = NetworkScanner()
        
        with patch('socket.gethostbyaddr') as mock_gethostbyaddr:
            mock_gethostbyaddr.side_effect = Exception("Host not found")
            
            result = await scanner._get_hostname("192.168.1.1")
            
            assert result == ""
    
    @pytest.mark.asyncio
    async def test_scan_port_open(self):
        """Test scanning an open port."""
        scanner = NetworkScanner()
        
        with patch('socket.socket') as mock_socket:
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            mock_sock.connect_ex.return_value = 0
            mock_sock.recv.return_value = b"Apache/2.4.41"
            
            result = await scanner._scan_port("192.168.1.1", 80, "Linux", "test.local")
            
            assert result is not None
            assert result.ip_address == ipaddress.ip_address("192.168.1.1")
            assert result.port == 80
            assert result.is_open is True
            assert result.service_name == "HTTP"
            assert result.operating_system == "Linux"
            assert result.hostname == "test.local"
    
    @pytest.mark.asyncio
    async def test_scan_port_closed(self):
        """Test scanning a closed port."""
        scanner = NetworkScanner()
        
        with patch('socket.socket') as mock_socket:
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            mock_sock.connect_ex.return_value = 1  # Connection refused
            
            result = await scanner._scan_port("192.168.1.1", 80, "Linux", "test.local")
            
            assert result is None
    
    @pytest.mark.asyncio
    async def test_scan_port_timeout(self):
        """Test scanning a port with timeout."""
        scanner = NetworkScanner()
        
        with patch('socket.socket') as mock_socket:
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            mock_sock.connect_ex.side_effect = Exception("timeout")
            
            result = await scanner._scan_port("192.168.1.1", 80, "Linux", "test.local")
            
            assert result is None
    
    @pytest.mark.asyncio
    async def test_scan_host_success(self):
        """Test successful host scan."""
        scanner = NetworkScanner()
        
        with patch.object(scanner, '_ping_host', return_value=True), \
             patch.object(scanner, '_detect_os', return_value="Linux"), \
             patch.object(scanner, '_get_hostname', return_value="test.local"), \
             patch.object(scanner, '_scan_port') as mock_scan_port:
            
            mock_scan_port.return_value = ScanResult(
                ip_address="192.168.1.1",
                port=80,
                is_open=True,
                service_name="HTTP",
                operating_system="Linux",
                hostname="test.local"
            )
            
            results = await scanner.scan_host("192.168.1.1", [80])
            
            assert len(results) == 1
            assert results[0].ip_address == ipaddress.ip_address("192.168.1.1")
            assert results[0].port == 80
            assert results[0].is_open is True
    
    @pytest.mark.asyncio
    async def test_scan_host_unreachable(self):
        """Test scan of unreachable host."""
        scanner = NetworkScanner()
        
        with patch.object(scanner, '_ping_host', return_value=False):
            results = await scanner.scan_host("192.168.1.1", [80])
            
            assert len(results) == 0
    
    @pytest.mark.asyncio
    async def test_scan_network_small(self):
        """Test scanning a small network."""
        scanner = NetworkScanner()
        
        with patch.object(scanner, '_scan_host') as mock_scan_host:
            mock_scan_host.return_value = [
                ScanResult(
                    ip_address="192.168.1.1",
                    port=80,
                    is_open=True,
                    service_name="HTTP"
                )
            ]
            
            results = await scanner.scan_network("192.168.1.0/30")
            
            assert len(results) == 2  # 2 hosts in /30 network
            assert all(isinstance(r, ScanResult) for r in results)
    
    @pytest.mark.asyncio
    async def test_scan_network_large_limited(self):
        """Test scanning a large network (should be limited)."""
        scanner = NetworkScanner()
        
        with patch.object(scanner, '_scan_host') as mock_scan_host:
            mock_scan_host.return_value = []
            
            results = await scanner.scan_network("10.0.0.0/8")
            
            # Should be limited to 1000 hosts
            assert mock_scan_host.call_count == 1000
    
    @pytest.mark.asyncio
    async def test_get_scan_statistics(self):
        """Test getting scan statistics."""
        scanner = NetworkScanner()
        
        results = [
            ScanResult(
                ip_address="192.168.1.1",
                port=80,
                is_open=True,
                service_name="HTTP",
                ping_time=10.0,
                operating_system="Linux"
            ),
            ScanResult(
                ip_address="192.168.1.1",
                port=443,
                is_open=True,
                service_name="HTTPS",
                ping_time=15.0,
                operating_system="Linux"
            ),
            ScanResult(
                ip_address="192.168.1.2",
                port=22,
                is_open=True,
                service_name="SSH",
                ping_time=8.0,
                operating_system="Linux",
                is_vulnerable=True
            )
        ]
        
        stats = await scanner.get_scan_statistics(results)
        
        assert stats.total_hosts == 2
        assert stats.active_hosts == 2
        assert stats.open_ports == 3
        assert stats.vulnerabilities_found == 1
        assert stats.avg_response_time == 11.0
        assert "HTTP" in stats.services_detected
        assert "HTTPS" in stats.services_detected
        assert "SSH" in stats.services_detected
        assert "Linux" in stats.os_detected
    
    @pytest.mark.asyncio
    async def test_get_scan_statistics_empty(self):
        """Test getting scan statistics with no results."""
        scanner = NetworkScanner()
        
        stats = await scanner.get_scan_statistics([])
        
        assert stats.total_hosts == 0
        assert stats.active_hosts == 0
        assert stats.open_ports == 0
        assert stats.vulnerabilities_found == 0
        assert stats.avg_response_time == 0.0
        assert len(stats.services_detected) == 0
        assert len(stats.os_detected) == 0
    
    def test_context_manager(self):
        """Test scanner as context manager."""
        config = ScanConfiguration(timeout=10)
        
        with NetworkScanner(config) as scanner:
            assert scanner.config.timeout == 10
        
        # Scanner should be closed after context
        # (We can't easily test the actual closure, but ensure no exceptions)
    
    def test_close_method(self):
        """Test scanner close method."""
        scanner = NetworkScanner()
        
        # Should not raise any exceptions
        scanner.close()
    
    @pytest.mark.asyncio
    async def test_get_service_info_http(self):
        """Test getting service info for HTTP."""
        scanner = NetworkScanner()
        
        with patch('socket.socket') as mock_socket:
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n"
            
            result = await scanner._get_service_info("192.168.1.1", 80, mock_sock)
            
            assert "Server: Apache/2.4.41" in result
    
    @pytest.mark.asyncio
    async def test_get_service_info_ssh(self):
        """Test getting service info for SSH."""
        scanner = NetworkScanner()
        
        with patch('socket.socket') as mock_socket:
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.0"
            
            result = await scanner._get_service_info("192.168.1.1", 22, mock_sock)
            
            assert "SSH-2.0-OpenSSH_8.0" in result
    
    @pytest.mark.asyncio
    async def test_get_service_info_https(self):
        """Test getting service info for HTTPS."""
        scanner = NetworkScanner()
        
        with patch('socket.socket') as mock_socket:
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            
            result = await scanner._get_service_info("192.168.1.1", 443, mock_sock)
            
            assert result == "HTTPS"
    
    @pytest.mark.asyncio
    async def test_get_service_info_exception(self):
        """Test getting service info with exception."""
        scanner = NetworkScanner()
        
        with patch('socket.socket') as mock_socket:
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            mock_sock.recv.side_effect = Exception("Connection error")
            
            result = await scanner._get_service_info("192.168.1.1", 80, mock_sock)
            
            assert result == ""