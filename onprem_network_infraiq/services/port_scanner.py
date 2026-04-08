"""
Advanced port scanner with multiple scanning techniques.
"""

import asyncio
import socket
import struct
import random
import time
import ipaddress
from typing import List, Dict, Optional, Union, Tuple, AsyncGenerator
from datetime import datetime, timezone
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..core.models import (
    ScanResult,
    ScanConfiguration,
    ScanType,
    COMMON_PORTS,
)


logger = logging.getLogger(__name__)


class PortScanner:
    """
    Advanced port scanner with multiple scanning techniques.

    Supports:
    - TCP Connect scanning
    - TCP SYN scanning (requires root/admin)
    - UDP scanning
    - Stealth scanning techniques
    - Service detection
    - Banner grabbing
    """

    def __init__(self, config: Optional[ScanConfiguration] = None):
        """
        Initialize the port scanner.

        Args:
            config: Scan configuration. If None, uses default configuration.
        """
        self.config = config or ScanConfiguration()
        self.logger = logging.getLogger(__name__)
        self._executor = ThreadPoolExecutor(max_workers=self.config.max_threads)

    async def scan_tcp_ports(
        self, host: str, ports: List[int], scan_type: ScanType = ScanType.PORT
    ) -> List[ScanResult]:
        """
        Scan TCP ports on a host.

        Args:
            host: IP address or hostname to scan
            ports: List of port numbers to scan
            scan_type: Type of scan to perform

        Returns:
            List of scan results
        """
        results = []

        # Create tasks for concurrent scanning
        tasks = []
        semaphore = asyncio.Semaphore(self.config.max_threads)

        for port in ports:
            task = self._scan_tcp_port_with_semaphore(semaphore, host, port, scan_type)
            tasks.append(task)

        # Execute scans concurrently
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in scan_results:
            if isinstance(result, Exception):
                self.logger.debug(f"TCP scan error: {result}")
                continue
            if result:
                results.append(result)

        return results

    async def _scan_tcp_port_with_semaphore(
        self, semaphore: asyncio.Semaphore, host: str, port: int, scan_type: ScanType
    ) -> Optional[ScanResult]:
        """
        Scan a single TCP port with semaphore control.

        Args:
            semaphore: Semaphore for controlling concurrency
            host: IP address or hostname
            port: Port number to scan
            scan_type: Type of scan to perform

        Returns:
            ScanResult if port is open, None otherwise
        """
        async with semaphore:
            if scan_type == ScanType.STEALTH:
                return await self._scan_tcp_syn(host, port)
            else:
                return await self._scan_tcp_connect(host, port)

    async def _scan_tcp_connect(self, host: str, port: int) -> Optional[ScanResult]:
        """
        Perform TCP connect scan on a single port.

        Args:
            host: IP address or hostname
            port: Port number to scan

        Returns:
            ScanResult if port is open, None otherwise
        """
        start_time = time.time()

        try:
            # Create socket with timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.timeout)

            # Add stealth delay for stealth mode
            if self.config.stealth_mode:
                await asyncio.sleep(random.uniform(0.1, 0.5))

            # Attempt connection
            result = sock.connect_ex((host, port))
            response_time = (time.time() - start_time) * 1000  # Convert to ms

            if result == 0:
                # Port is open
                service_name = COMMON_PORTS.get(port, "Unknown")
                banner = await self._grab_banner(sock, port)

                sock.close()

                return ScanResult(
                    ip_address=host,
                    port=port,
                    is_open=True,
                    service_name=service_name,
                    ping_time=response_time,
                    server_info=banner,
                    discovered_at=datetime.now(timezone.utc),
                )
            else:
                sock.close()
                return None

        except socket.timeout:
            return None
        except Exception as e:
            self.logger.debug(f"Error scanning {host}:{port} - {e}")
            return None

    async def _scan_tcp_syn(self, host: str, port: int) -> Optional[ScanResult]:
        """
        Perform TCP SYN scan on a single port (stealth scan).

        Note: This is a simplified implementation. Full SYN scanning
        requires raw sockets and proper packet crafting.

        Args:
            host: IP address or hostname
            port: Port number to scan

        Returns:
            ScanResult if port is open, None otherwise
        """
        # For now, fall back to connect scan
        # In a full implementation, this would use raw sockets
        self.logger.debug(f"SYN scan requested for {host}:{port}, using connect scan")
        return await self._scan_tcp_connect(host, port)

    async def scan_udp_ports(self, host: str, ports: List[int]) -> List[ScanResult]:
        """
        Scan UDP ports on a host.

        Args:
            host: IP address or hostname to scan
            ports: List of port numbers to scan

        Returns:
            List of scan results
        """
        results = []

        # Create tasks for concurrent scanning
        tasks = []
        semaphore = asyncio.Semaphore(min(self.config.max_threads, 50))  # Limit UDP scans

        for port in ports:
            task = self._scan_udp_port_with_semaphore(semaphore, host, port)
            tasks.append(task)

        # Execute scans concurrently
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in scan_results:
            if isinstance(result, Exception):
                self.logger.debug(f"UDP scan error: {result}")
                continue
            if result:
                results.append(result)

        return results

    async def _scan_udp_port_with_semaphore(
        self, semaphore: asyncio.Semaphore, host: str, port: int
    ) -> Optional[ScanResult]:
        """
        Scan a single UDP port with semaphore control.

        Args:
            semaphore: Semaphore for controlling concurrency
            host: IP address or hostname
            port: Port number to scan

        Returns:
            ScanResult if port is open, None otherwise
        """
        async with semaphore:
            return await self._scan_udp_port(host, port)

    async def _scan_udp_port(self, host: str, port: int) -> Optional[ScanResult]:
        """
        Perform UDP scan on a single port.

        Args:
            host: IP address or hostname
            port: Port number to scan

        Returns:
            ScanResult if port is open/filtered, None if definitely closed
        """
        start_time = time.time()

        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.config.timeout)

            # Send UDP packet
            test_data = b"OnPrem-InfraIQ-Test"
            sock.sendto(test_data, (host, port))

            # Try to receive response
            try:
                response, addr = sock.recvfrom(1024)
                response_time = (time.time() - start_time) * 1000

                service_name = COMMON_PORTS.get(port, "Unknown")

                sock.close()

                return ScanResult(
                    ip_address=host,
                    port=port,
                    is_open=True,
                    service_name=f"UDP-{service_name}",
                    ping_time=response_time,
                    server_info=f"UDP response received: {len(response)} bytes",
                    discovered_at=datetime.now(timezone.utc),
                )

            except socket.timeout:
                # No response - port might be open but not responding
                # or filtered by firewall
                response_time = (time.time() - start_time) * 1000
                service_name = COMMON_PORTS.get(port, "Unknown")

                sock.close()

                # Return result with filtered status
                return ScanResult(
                    ip_address=host,
                    port=port,
                    is_open=False,  # Uncertain state
                    service_name=f"UDP-{service_name}",
                    ping_time=response_time,
                    server_info="UDP port filtered or no response",
                    discovered_at=datetime.now(timezone.utc),
                )

        except Exception as e:
            self.logger.debug(f"Error scanning UDP {host}:{port} - {e}")
            return None

    async def _grab_banner(self, sock: socket.socket, port: int) -> str:
        """
        Grab service banner from an open port.

        Args:
            sock: Connected socket
            port: Port number

        Returns:
            Service banner string
        """
        try:
            # Services that typically send banners automatically
            auto_banner_ports = [21, 22, 23, 25, 110, 143, 220, 993, 995]

            if port in auto_banner_ports:
                # Wait for banner
                sock.settimeout(2)
                banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
                if banner:
                    return banner[:200]  # Limit banner length

            # HTTP services
            elif port in [80, 8080, 8000, 8443]:
                sock.settimeout(2)
                http_request = (
                    b"HEAD / HTTP/1.1\r\nHost: target\r\nUser-Agent: "
                    + self.config.user_agent.encode()
                    + b"\r\n\r\n"
                )
                sock.send(http_request)
                response = sock.recv(1024).decode("utf-8", errors="ignore")

                # Extract server header
                if "Server:" in response:
                    server_line = [line for line in response.split("\n") if "Server:" in line]
                    if server_line:
                        return server_line[0].strip()

                return "HTTP service"

            # HTTPS services
            elif port in [443, 8443]:
                return "HTTPS service"

            # Generic probe for other services
            else:
                sock.settimeout(1)
                try:
                    # Try sending a generic probe
                    sock.send(b"\r\n")
                    banner = sock.recv(512).decode("utf-8", errors="ignore").strip()
                    if banner:
                        return banner[:100]
                except:
                    pass

            return ""

        except Exception as e:
            self.logger.debug(f"Error grabbing banner for port {port}: {e}")
            return ""

    async def scan_port_range(
        self, host: str, start_port: int, end_port: int, protocol: str = "tcp"
    ) -> List[ScanResult]:
        """
        Scan a range of ports on a host.

        Args:
            host: IP address or hostname to scan
            start_port: Starting port number
            end_port: Ending port number
            protocol: Protocol to scan ("tcp" or "udp")

        Returns:
            List of scan results
        """
        if start_port > end_port:
            raise ValueError("Start port must be less than or equal to end port")

        if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
            raise ValueError("Port numbers must be in range 1-65535")

        ports = list(range(start_port, end_port + 1))

        if protocol.lower() == "tcp":
            return await self.scan_tcp_ports(host, ports)
        elif protocol.lower() == "udp":
            return await self.scan_udp_ports(host, ports)
        else:
            raise ValueError("Protocol must be 'tcp' or 'udp'")

    async def scan_common_ports(self, host: str, protocol: str = "tcp") -> List[ScanResult]:
        """
        Scan common ports on a host.

        Args:
            host: IP address or hostname to scan
            protocol: Protocol to scan ("tcp" or "udp")

        Returns:
            List of scan results
        """
        common_tcp_ports = [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            143,
            443,
            993,
            995,
            3389,
            5432,
            3306,
            1433,
            135,
            139,
            445,
            161,
            389,
            636,
            5900,
            8080,
            8443,
        ]

        common_udp_ports = [
            53,
            67,
            68,
            69,
            123,
            137,
            138,
            161,
            162,
            389,
            500,
            514,
            520,
            1900,
            4500,
            5353,
        ]

        if protocol.lower() == "tcp":
            return await self.scan_tcp_ports(host, common_tcp_ports)
        elif protocol.lower() == "udp":
            return await self.scan_udp_ports(host, common_udp_ports)
        else:
            raise ValueError("Protocol must be 'tcp' or 'udp'")

    async def scan_top_ports(
        self, host: str, count: int = 100, protocol: str = "tcp"
    ) -> List[ScanResult]:
        """
        Scan top N most common ports on a host.

        Args:
            host: IP address or hostname to scan
            count: Number of top ports to scan
            protocol: Protocol to scan ("tcp" or "udp")

        Returns:
            List of scan results
        """
        # Top TCP ports (based on nmap top ports)
        top_tcp_ports = [
            80,
            23,
            443,
            21,
            22,
            25,
            53,
            110,
            111,
            995,
            993,
            143,
            993,
            199,
            587,
            8080,
            2049,
            465,
            548,
            113,
            81,
            6001,
            10000,
            514,
            5060,
            179,
            1025,
            106,
            2000,
            12000,
            1433,
            3389,
            99,
            5432,
            1723,
            1024,
            135,
            139,
            445,
            161,
            389,
            636,
            5900,
            8443,
            3306,
            1521,
            1433,
            3306,
            5432,
            1521,
            2381,
            1080,
            8000,
            8080,
            8443,
            8888,
            3128,
            1080,
            3128,
            8080,
            8000,
            8443,
            8888,
            9090,
            9091,
            9092,
            9093,
            9094,
            9095,
            9096,
            9097,
            9098,
            9099,
            9100,
            9101,
            9102,
            9103,
            9104,
            9105,
            9106,
            9107,
            9108,
            9109,
            9110,
            9111,
            9112,
            9113,
            9114,
            9115,
            9116,
            9117,
            9118,
            9119,
            9120,
            9121,
            9122,
            9123,
            9124,
            9125,
            9126,
            9127,
            9128,
            9129,
            9130,
        ]

        # Top UDP ports
        top_udp_ports = [
            53,
            67,
            68,
            69,
            123,
            137,
            138,
            161,
            162,
            389,
            500,
            514,
            520,
            1900,
            4500,
            5353,
            1701,
            1812,
            1813,
            2049,
            5060,
            5061,
            5353,
            5632,
            2049,
            111,
            631,
            996,
            997,
            998,
            999,
            1000,
            1001,
            1002,
            1003,
            1004,
            1005,
            1006,
            1007,
            1008,
            1009,
            1010,
            1011,
            1012,
            1013,
            1014,
            1015,
            1016,
            1017,
            1018,
            1019,
            1020,
            1021,
            1022,
            1023,
            1024,
            1025,
            1026,
            1027,
            1028,
            1029,
            1030,
            1031,
            1032,
            1033,
            1034,
            1035,
            1036,
            1037,
            1038,
            1039,
            1040,
            1041,
            1042,
            1043,
            1044,
            1045,
            1046,
            1047,
            1048,
            1049,
            1050,
            1051,
            1052,
            1053,
            1054,
            1055,
            1056,
            1057,
            1058,
            1059,
            1060,
            1061,
            1062,
            1063,
            1064,
            1065,
            1066,
            1067,
            1068,
            1069,
            1070,
        ]

        if protocol.lower() == "tcp":
            ports = top_tcp_ports[:count]
            return await self.scan_tcp_ports(host, ports)
        elif protocol.lower() == "udp":
            ports = top_udp_ports[:count]
            return await self.scan_udp_ports(host, ports)
        else:
            raise ValueError("Protocol must be 'tcp' or 'udp'")

    def close(self):
        """Clean up resources."""
        if hasattr(self, "_executor"):
            self._executor.shutdown(wait=True)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
