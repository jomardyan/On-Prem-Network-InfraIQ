"""
Core network scanner implementation.
"""

import asyncio
import socket
import time
import ipaddress
from typing import List, Dict, Optional, Union, AsyncGenerator
from datetime import datetime, timezone
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from .models import (
    ScanResult,
    ScanConfiguration,
    NetworkRange,
    ServiceFingerprint,
    HostInfo,
    ScanSession,
    ScanStatistics,
    ScanType,
    COMMON_PORTS,
)


logger = logging.getLogger(__name__)


class NetworkScanner:
    """
    Core network scanner with async support.

    This class provides comprehensive network scanning capabilities including:
    - Port scanning (TCP/UDP)
    - Service detection
    - OS fingerprinting
    - Performance optimization with async operations
    """

    def __init__(self, config: Optional[ScanConfiguration] = None):
        """
        Initialize the network scanner.

        Args:
            config: Scan configuration. If None, uses default configuration.
        """
        self.config = config or ScanConfiguration()
        self.session_id = ""
        self.logger = logging.getLogger(__name__)
        self._executor = ThreadPoolExecutor(max_workers=self.config.max_threads)

    async def scan_network(
        self, target: Union[str, NetworkRange], ports: Optional[List[int]] = None
    ) -> List[ScanResult]:
        """
        Scan a network range for open ports and services.

        Args:
            target: Network range (CIDR notation) or NetworkRange object
            ports: List of ports to scan. If None, uses config ports.

        Returns:
            List of scan results
        """
        if isinstance(target, str):
            network = ipaddress.ip_network(target, strict=False)
            network_range = NetworkRange(network=network)
        else:
            network_range = target

        ports_to_scan = ports or self.config.ports
        results = []

        # Get all hosts in the network
        hosts = list(network_range.hosts)

        # Limit hosts for large networks
        if len(hosts) > 1000:
            self.logger.warning(
                f"Large network detected ({len(hosts)} hosts). Limiting to first 1000."
            )
            hosts = hosts[:1000]

        # Scan each host
        tasks = []
        for host in hosts:
            task = self._scan_host(str(host), ports_to_scan)
            tasks.append(task)

        # Execute scans concurrently
        batch_size = min(self.config.max_threads, len(tasks))
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i : i + batch_size]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)

            for result in batch_results:
                if isinstance(result, Exception):
                    self.logger.error(f"Scan error: {result}")
                    continue
                if result:
                    results.extend(result)

        return results

    async def scan_host(self, host: str, ports: Optional[List[int]] = None) -> List[ScanResult]:
        """
        Scan a single host for open ports and services.

        Args:
            host: IP address or hostname to scan
            ports: List of ports to scan. If None, uses config ports.

        Returns:
            List of scan results
        """
        ports_to_scan = ports or self.config.ports
        return await self._scan_host(host, ports_to_scan)

    async def _scan_host(self, host: str, ports: List[int]) -> List[ScanResult]:
        """
        Internal method to scan a single host.

        Args:
            host: IP address or hostname to scan
            ports: List of ports to scan

        Returns:
            List of scan results
        """
        results = []

        # First, check if host is alive with ping
        if not await self._ping_host(host):
            return results

        # Get basic host info
        os_info = await self._detect_os(host)
        hostname = await self._get_hostname(host)

        # Scan ports
        port_tasks = []
        for port in ports:
            task = self._scan_port(host, port, os_info, hostname)
            port_tasks.append(task)

        # Execute port scans concurrently
        port_results = await asyncio.gather(*port_tasks, return_exceptions=True)

        for result in port_results:
            if isinstance(result, Exception):
                self.logger.debug(f"Port scan error for {host}: {result}")
                continue
            if result:
                results.append(result)

        return results

    async def _scan_port(
        self, host: str, port: int, os_info: str, hostname: str
    ) -> Optional[ScanResult]:
        """
        Scan a single port on a host.

        Args:
            host: IP address or hostname
            port: Port number to scan
            os_info: Operating system information
            hostname: Hostname

        Returns:
            ScanResult if port is open, None otherwise
        """
        start_time = time.time()

        try:
            # Create socket with timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)

            # Attempt connection
            result = sock.connect_ex((host, port))
            response_time = (time.time() - start_time) * 1000  # Convert to ms

            if result == 0:
                # Port is open
                service_name = COMMON_PORTS.get(port, "Unknown")
                server_info = await self._get_service_info(host, port, sock)

                sock.close()

                return ScanResult(
                    ip_address=host,
                    port=port,
                    is_open=True,
                    service_name=service_name,
                    ping_time=response_time,
                    operating_system=os_info,
                    server_info=server_info,
                    hostname=hostname,
                    discovered_at=lambda: datetime.now(timezone.utc)(),
                )
            else:
                sock.close()
                return None

        except socket.timeout:
            return None
        except Exception as e:
            self.logger.debug(f"Error scanning {host}:{port} - {e}")
            return None

    async def _ping_host(self, host: str) -> bool:
        """
        Check if a host is alive using ping.

        Args:
            host: IP address or hostname

        Returns:
            True if host is alive, False otherwise
        """
        try:
            # Simple TCP connect test to port 80 or 443
            for port in [80, 443, 22, 21]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    if result == 0:
                        return True
                except:
                    continue

            # If no common ports respond, try ICMP ping simulation
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, 1))  # Unlikely to be open
                sock.close()
                return True  # If we get here, host is reachable
            except:
                return False

        except Exception as e:
            self.logger.debug(f"Ping error for {host}: {e}")
            return False

    async def _detect_os(self, host: str) -> str:
        """
        Detect operating system using various techniques.

        Args:
            host: IP address or hostname

        Returns:
            Operating system information
        """
        # Simple OS detection based on common port patterns
        # This is a simplified version - real OS detection would use more sophisticated methods

        try:
            # Check for Windows-specific ports
            windows_ports = [135, 139, 445, 3389]
            for port in windows_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    return "Windows"

            # Check for Linux/Unix-specific ports
            unix_ports = [22, 111]
            for port in unix_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                sock.close()
                if result == 0:
                    return "Linux/Unix"

            return "Unknown"

        except Exception:
            return "Unknown"

    async def _get_hostname(self, host: str) -> str:
        """
        Get hostname for an IP address.

        Args:
            host: IP address

        Returns:
            Hostname or empty string if not found
        """
        try:
            hostname = socket.gethostbyaddr(host)[0]
            return hostname
        except:
            return ""

    async def _get_service_info(self, host: str, port: int, sock: socket.socket) -> str:
        """
        Get service information from an open port.

        Args:
            host: IP address or hostname
            port: Port number
            sock: Connected socket

        Returns:
            Service information string
        """
        try:
            # Try to get banner
            if port in [21, 22, 23, 25, 110, 143]:
                # These services typically send a banner
                sock.settimeout(2)
                try:
                    banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                    if banner:
                        return banner[:100]  # Limit banner length
                except:
                    pass

            elif port in [80, 8080]:
                # HTTP service
                try:
                    http_request = b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n"
                    sock.send(http_request)
                    response = sock.recv(1024).decode("utf-8", errors="ignore")
                    if "Server:" in response:
                        server_line = [line for line in response.split("\n") if "Server:" in line]
                        if server_line:
                            return server_line[0].strip()
                except:
                    pass

            elif port == 443:
                # HTTPS service - would need SSL/TLS handling
                return "HTTPS"

            return ""

        except Exception as e:
            self.logger.debug(f"Error getting service info for {host}:{port} - {e}")
            return ""

    async def get_scan_statistics(self, results: List[ScanResult]) -> ScanStatistics:
        """
        Generate statistics from scan results.

        Args:
            results: List of scan results

        Returns:
            Scan statistics
        """
        if not results:
            return ScanStatistics()

        # Calculate statistics
        total_hosts = len(set(str(r.ip_address) for r in results))
        active_hosts = len(set(str(r.ip_address) for r in results if r.is_open))
        open_ports = len([r for r in results if r.is_open])
        vulnerabilities = len([r for r in results if r.is_vulnerable])

        # Calculate average response time
        response_times = [r.ping_time for r in results if r.ping_time is not None]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0.0

        # Get unique services and OS
        services = list(set(r.service_name for r in results if r.is_open))
        os_list = list(set(r.operating_system for r in results if r.operating_system != "Unknown"))

        return ScanStatistics(
            total_hosts=total_hosts,
            active_hosts=active_hosts,
            open_ports=open_ports,
            vulnerabilities_found=vulnerabilities,
            avg_response_time=avg_response_time,
            services_detected=services,
            os_detected=os_list,
        )

    def close(self):
        """Clean up resources."""
        if hasattr(self, "_executor"):
            self._executor.shutdown(wait=True)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
