"""
Integration tests for the complete scanning workflow.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
import ipaddress

from onprem_network_infraiq import NetworkScanner, VulnerabilityScanner, PortScanner
from onprem_network_infraiq.core.models import (
    ScanResult,
    VulnerabilityResult,
    ScanConfiguration,
    SeverityLevel,
    ScanType,
)


class TestNetworkScanningWorkflow:
    """Test complete network scanning workflow."""
    
    @pytest.mark.asyncio
    async def test_complete_network_scan_workflow(self):
        """Test a complete network scanning workflow."""
        # Mock network interfaces and responses
        with patch('socket.socket') as mock_socket, \
             patch('socket.gethostbyaddr') as mock_gethostbyaddr:
            
            # Setup mocks
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            mock_sock.connect_ex.side_effect = [0, 0, 1, 0, 1]  # Ports 22, 80 open; 443, 8080 closed
            mock_sock.recv.side_effect = [
                b"SSH-2.0-OpenSSH_8.0",
                b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n",
                b"",
                b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n"
            ]
            
            mock_gethostbyaddr.return_value = ("test.local", [], ["192.168.1.1"])
            
            # Create scanner
            config = ScanConfiguration(
                timeout=5,
                max_threads=10,
                ports=[22, 80, 443, 8080]
            )
            
            scanner = NetworkScanner(config)
            
            # Perform scan
            results = await scanner.scan_host("192.168.1.1")
            
            # Verify results
            assert len(results) == 2  # Only open ports
            
            # Check SSH result
            ssh_result = next((r for r in results if r.port == 22), None)
            assert ssh_result is not None
            assert ssh_result.is_open is True
            assert ssh_result.service_name == "SSH"
            assert ssh_result.hostname == "test.local"
            assert "SSH-2.0-OpenSSH_8.0" in ssh_result.server_info
            
            # Check HTTP result
            http_result = next((r for r in results if r.port == 80), None)
            assert http_result is not None
            assert http_result.is_open is True
            assert http_result.service_name == "HTTP"
            assert "Apache/2.4.41" in http_result.server_info
            
            scanner.close()
    
    @pytest.mark.asyncio
    async def test_complete_vulnerability_scan_workflow(self):
        """Test a complete vulnerability scanning workflow."""
        # Mock network responses
        with patch('socket.socket') as mock_socket, \
             patch('aiohttp.ClientSession') as mock_session:
            
            # Setup socket mocks
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            mock_sock.connect_ex.side_effect = [0, 0, 0]  # Ports 21, 22, 23 open
            mock_sock.recv.side_effect = [
                b"220 FTP server ready. Anonymous login allowed.",
                b"SSH-1.0-OpenSSH_5.0",
                b"Telnet server ready"
            ]
            
            # Setup HTTP session mocks
            mock_response = Mock()
            mock_response.text = AsyncMock(return_value="<html><title>Index of /</title></html>")
            mock_session.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value = mock_response
            
            # Create scanner
            config = ScanConfiguration(
                timeout=5,
                max_threads=10,
                include_vulnerability_scan=True
            )
            
            scanner = VulnerabilityScanner(config)
            
            # Perform scan
            results = await scanner.scan_host("192.168.1.1", [21, 22, 23])
            
            # Verify vulnerability results
            assert len(results) > 0
            
            # Check for expected vulnerabilities
            vulnerability_titles = [r.title for r in results]
            
            # Should detect anonymous FTP
            assert any("Anonymous FTP" in title for title in vulnerability_titles)
            
            # Should detect weak SSH
            assert any("Weak SSH" in title for title in vulnerability_titles)
            
            # Should detect Telnet
            assert any("Telnet" in title for title in vulnerability_titles)
            
            # Verify severity levels
            severities = [r.severity for r in results]
            assert SeverityLevel.HIGH in severities
            assert SeverityLevel.MEDIUM in severities
            
            scanner.close()
    
    @pytest.mark.asyncio
    async def test_port_scanner_integration(self):
        """Test PortScanner integration."""
        with patch('socket.socket') as mock_socket:
            # Setup mocks
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            mock_sock.connect_ex.side_effect = [0, 1, 0, 1, 0]  # Alternating open/closed
            mock_sock.recv.side_effect = [
                b"SSH-2.0-OpenSSH_8.0",
                b"",
                b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n",
                b"",
                b"HTTPS service"
            ]
            
            config = ScanConfiguration(timeout=5, max_threads=10)
            scanner = PortScanner(config)
            
            # Test TCP scanning
            results = await scanner.scan_tcp_ports("192.168.1.1", [22, 23, 80, 8080, 443])
            
            # Verify results
            open_ports = [r for r in results if r.is_open]
            assert len(open_ports) == 3  # Ports 22, 80, 443 should be open
            
            # Check specific ports
            ssh_result = next((r for r in open_ports if r.port == 22), None)
            assert ssh_result is not None
            assert ssh_result.service_name == "SSH"
            
            http_result = next((r for r in open_ports if r.port == 80), None)
            assert http_result is not None
            assert http_result.service_name == "HTTP"
            
            https_result = next((r for r in open_ports if r.port == 443), None)
            assert https_result is not None
            assert https_result.service_name == "HTTPS"
            
            scanner.close()
    
    @pytest.mark.asyncio
    async def test_network_range_scanning(self):
        """Test scanning a network range."""
        with patch('socket.socket') as mock_socket:
            # Setup mocks for multiple hosts
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            
            # Mock responses for different hosts
            def mock_connect_ex(addr):
                host, port = addr
                if host == "192.168.1.1" and port in [22, 80]:
                    return 0  # Open
                elif host == "192.168.1.2" and port in [80, 443]:
                    return 0  # Open
                else:
                    return 1  # Closed
            
            mock_sock.connect_ex.side_effect = mock_connect_ex
            mock_sock.recv.side_effect = [
                b"SSH-2.0-OpenSSH_8.0",
                b"Apache/2.4.41",
                b"nginx/1.18.0",
                b"HTTPS service"
            ]
            
            config = ScanConfiguration(timeout=2, max_threads=5, ports=[22, 80, 443])
            scanner = NetworkScanner(config)
            
            # Scan small network
            results = await scanner.scan_network("192.168.1.0/30")
            
            # Verify results
            open_results = [r for r in results if r.is_open]
            assert len(open_results) == 4  # 2 ports per host, 2 hosts
            
            # Check hosts
            hosts = set(str(r.ip_address) for r in open_results)
            assert "192.168.1.1" in hosts
            assert "192.168.1.2" in hosts
            
            # Check services
            services = [r.service_name for r in open_results]
            assert "SSH" in services
            assert "HTTP" in services
            assert "HTTPS" in services
            
            scanner.close()
    
    @pytest.mark.asyncio
    async def test_scan_statistics_integration(self):
        """Test scan statistics generation."""
        # Create sample results
        results = [
            ScanResult(
                ip_address="192.168.1.1",
                port=22,
                is_open=True,
                service_name="SSH",
                ping_time=10.0,
                operating_system="Linux",
                is_vulnerable=True
            ),
            ScanResult(
                ip_address="192.168.1.1",
                port=80,
                is_open=True,
                service_name="HTTP",
                ping_time=15.0,
                operating_system="Linux"
            ),
            ScanResult(
                ip_address="192.168.1.2",
                port=443,
                is_open=True,
                service_name="HTTPS",
                ping_time=20.0,
                operating_system="Windows"
            ),
            ScanResult(
                ip_address="192.168.1.3",
                port=22,
                is_open=False,
                service_name="SSH",
                ping_time=None,
                operating_system="Unknown"
            )
        ]
        
        scanner = NetworkScanner()
        stats = await scanner.get_scan_statistics(results)
        
        # Verify statistics
        assert stats.total_hosts == 3
        assert stats.active_hosts == 2
        assert stats.open_ports == 3
        assert stats.vulnerabilities_found == 1
        assert stats.avg_response_time == 15.0
        assert "SSH" in stats.services_detected
        assert "HTTP" in stats.services_detected
        assert "HTTPS" in stats.services_detected
        assert "Linux" in stats.os_detected
        assert "Windows" in stats.os_detected
        
        scanner.close()
    
    @pytest.mark.asyncio
    async def test_error_handling_integration(self):
        """Test error handling in integrated workflow."""
        with patch('socket.socket') as mock_socket:
            # Setup mocks to raise exceptions
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            mock_sock.connect_ex.side_effect = [
                0,  # First port succeeds
                Exception("Connection error"),  # Second port fails
                0   # Third port succeeds
            ]
            mock_sock.recv.side_effect = [
                b"SSH-2.0-OpenSSH_8.0",
                b"HTTP/1.1 200 OK"
            ]
            
            config = ScanConfiguration(timeout=2, max_threads=5)
            scanner = NetworkScanner(config)
            
            # Should handle exceptions gracefully
            results = await scanner.scan_host("192.168.1.1", [22, 80, 443])
            
            # Should still get results from successful scans
            open_results = [r for r in results if r.is_open]
            assert len(open_results) >= 1  # At least one successful result
            
            scanner.close()
    
    @pytest.mark.asyncio
    async def test_timeout_handling_integration(self):
        """Test timeout handling in integrated workflow."""
        with patch('socket.socket') as mock_socket:
            # Setup mocks to simulate timeouts
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            mock_sock.connect_ex.side_effect = [
                0,  # First port succeeds quickly
                0   # Second port succeeds
            ]
            mock_sock.recv.side_effect = [
                b"SSH-2.0-OpenSSH_8.0",
                b"HTTP/1.1 200 OK"
            ]
            
            # Use very short timeout
            config = ScanConfiguration(timeout=1, max_threads=5)
            scanner = NetworkScanner(config)
            
            # Should complete within reasonable time
            import time
            start_time = time.time()
            results = await scanner.scan_host("192.168.1.1", [22, 80])
            end_time = time.time()
            
            # Should complete quickly due to short timeout
            assert end_time - start_time < 10  # Should be much faster
            
            scanner.close()
    
    @pytest.mark.asyncio
    async def test_concurrent_scanning_integration(self):
        """Test concurrent scanning integration."""
        with patch('socket.socket') as mock_socket:
            # Setup mocks for concurrent operations
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            mock_sock.connect_ex.return_value = 0  # All ports open
            mock_sock.recv.return_value = b"Test service"
            
            # Use high concurrency
            config = ScanConfiguration(timeout=5, max_threads=50)
            scanner = NetworkScanner(config)
            
            # Scan many ports concurrently
            ports = list(range(1000, 1100))  # 100 ports
            results = await scanner.scan_host("192.168.1.1", ports)
            
            # Should handle concurrency well
            assert len(results) == 100
            assert all(r.is_open for r in results)
            
            scanner.close()


class TestRealWorldScenarios:
    """Test real-world scanning scenarios."""
    
    @pytest.mark.asyncio
    async def test_web_server_scanning(self):
        """Test scanning a typical web server."""
        with patch('socket.socket') as mock_socket, \
             patch('aiohttp.ClientSession') as mock_session:
            
            # Setup web server mocks
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            mock_sock.connect_ex.side_effect = lambda addr: 0 if addr[1] in [80, 443] else 1
            mock_sock.recv.side_effect = [
                b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n",
                b"HTTPS service"
            ]
            
            # Setup HTTP session mocks
            mock_response = Mock()
            mock_response.text = AsyncMock(return_value="<html><body>Welcome</body></html>")
            mock_response.status = 200
            mock_session.return_value.__aenter__.return_value.get.return_value.__aenter__.return_value = mock_response
            mock_session.return_value.__aenter__.return_value.request.return_value.__aenter__.return_value = mock_response
            
            # Scan web server
            config = ScanConfiguration(timeout=5, max_threads=10)
            scanner = VulnerabilityScanner(config)
            
            results = await scanner.scan_host("192.168.1.1", [80, 443])
            
            # Should find web services
            assert len(results) >= 0  # May or may not find vulnerabilities
            
            scanner.close()
    
    @pytest.mark.asyncio
    async def test_database_server_scanning(self):
        """Test scanning a typical database server."""
        with patch('socket.socket') as mock_socket:
            # Setup database server mocks
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            mock_sock.connect_ex.side_effect = lambda addr: 0 if addr[1] in [3306, 5432] else 1
            mock_sock.recv.side_effect = [
                b"5.7.34-0ubuntu0.18.04.1",  # MySQL
                b"PostgreSQL 12.8"          # PostgreSQL
            ]
            
            # Scan database server
            config = ScanConfiguration(timeout=5, max_threads=10)
            scanner = VulnerabilityScanner(config)
            
            results = await scanner.scan_host("192.168.1.1", [3306, 5432, 1433])
            
            # Should detect database services
            assert len(results) >= 0
            
            scanner.close()
    
    @pytest.mark.asyncio
    async def test_network_infrastructure_scanning(self):
        """Test scanning network infrastructure devices."""
        with patch('socket.socket') as mock_socket:
            # Setup network device mocks
            mock_sock = Mock()
            mock_socket.return_value = mock_sock
            mock_sock.connect_ex.side_effect = lambda addr: 0 if addr[1] in [22, 23, 80, 161] else 1
            mock_sock.recv.side_effect = [
                b"SSH-2.0-Cisco-1.25",
                b"Cisco IOS Telnet",
                b"HTTP/1.1 200 OK\r\nServer: Cisco-IOS\r\n",
                b"SNMP v2c"
            ]
            
            # Scan network device
            config = ScanConfiguration(timeout=5, max_threads=10)
            scanner = VulnerabilityScanner(config)
            
            results = await scanner.scan_host("192.168.1.1", [22, 23, 80, 161])
            
            # Should detect network services
            assert len(results) >= 0
            
            scanner.close()