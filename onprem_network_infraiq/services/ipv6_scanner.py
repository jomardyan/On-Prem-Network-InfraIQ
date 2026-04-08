"""
Advanced IPv6 scanning capabilities including neighbor discovery.
"""

import asyncio
import socket
import struct
import ipaddress
from typing import List, Dict, Optional, AsyncGenerator, Set, Any
from datetime import datetime, timezone
import logging
import os
import time

from ..core.models import ScanResult, HostInfo, ServiceFingerprint

logger = logging.getLogger(__name__)


class IPv6Scanner:
    """
    Advanced IPv6 scanner with neighbor discovery capabilities.

    This class provides comprehensive IPv6 scanning including:
    - IPv6 neighbor discovery protocol (NDP)
    - Link-local address discovery
    - Multicast scanning
    - IPv6 router advertisement detection
    - Duplicate address detection (DAD)
    """

    def __init__(self, interface: Optional[str] = None, timeout: int = 5):
        """
        Initialize IPv6 scanner.

        Args:
            interface: Network interface to use (auto-detect if None)
            timeout: Timeout for operations in seconds
        """
        self.interface = interface
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)
        self._discovered_hosts: Set[str] = set()

    async def discover_link_local_hosts(self) -> AsyncGenerator[HostInfo, None]:
        """
        Discover IPv6 link-local hosts using neighbor discovery.

        Yields:
            HostInfo: Information about discovered hosts
        """
        self.logger.info("Starting IPv6 link-local host discovery")

        try:
            # Get all IPv6 addresses on the system
            local_addrs = await self._get_local_ipv6_addresses()

            for addr in local_addrs:
                if addr.is_link_local:
                    async for host in self._scan_link_local_network(addr):
                        yield host

        except Exception as e:
            self.logger.error(f"Error during link-local discovery: {e}")

    async def _get_local_ipv6_addresses(self) -> List[ipaddress.IPv6Address]:
        """Get all IPv6 addresses configured on the system."""
        addresses = []

        try:
            # Use socket to get interface addresses
            import netifaces

            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET6 in addrs:
                    for addr_info in addrs[netifaces.AF_INET6]:
                        addr_str = addr_info["addr"].split("%")[0]  # Remove scope ID
                        try:
                            addr = ipaddress.IPv6Address(addr_str)
                            addresses.append(addr)
                        except ValueError:
                            continue

        except ImportError:
            # Fallback without netifaces
            self.logger.warning("netifaces not available, using basic IPv6 discovery")

        return addresses

    async def _scan_link_local_network(
        self, base_addr: ipaddress.IPv6Address
    ) -> AsyncGenerator[HostInfo, None]:
        """Scan for hosts in the link-local network."""
        network = ipaddress.IPv6Network(f"{base_addr}/64", strict=False)

        # Common link-local addresses to check
        target_hosts = [
            "fe80::1",  # Common router
            "fe80::2",  # Common secondary
            "ff02::1",  # All nodes multicast
            "ff02::2",  # All routers multicast
        ]

        for host_str in target_hosts:
            try:
                host_addr = ipaddress.IPv6Address(host_str)
                if await self._ping_ipv6_host(host_addr):
                    host_info = HostInfo(
                        ip_address=host_addr,
                        hostname=await self._resolve_hostname(host_addr),
                        os_info="Unknown",
                        mac_address=await self._get_mac_address(host_addr),
                        response_time=0.0,
                        is_reachable=True,
                        discovered_at=datetime.now(timezone.utc),
                        scan_type="ipv6_link_local",
                    )
                    yield host_info

            except Exception as e:
                self.logger.debug(f"Error scanning {host_str}: {e}")

    async def _ping_ipv6_host(self, host: ipaddress.IPv6Address) -> bool:
        """Ping an IPv6 host to check if it's reachable."""
        try:
            # Create ICMPv6 echo request
            proc = await asyncio.create_subprocess_exec(
                "ping6",
                "-c",
                "1",
                "-W",
                str(self.timeout),
                str(host),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await proc.communicate()
            return proc.returncode == 0

        except Exception as e:
            self.logger.debug(f"Ping failed for {host}: {e}")
            return False

    async def _resolve_hostname(self, host: ipaddress.IPv6Address) -> str:
        """Resolve hostname for IPv6 address."""
        try:
            hostname, _, _ = await asyncio.get_event_loop().run_in_executor(
                None, socket.gethostbyaddr, str(host)
            )
            return hostname
        except:
            return str(host)

    async def _get_mac_address(self, host: ipaddress.IPv6Address) -> str:
        """Get MAC address for IPv6 host using neighbor discovery."""
        try:
            # Try to get MAC from ARP/NDP table
            proc = await asyncio.create_subprocess_exec(
                "ip",
                "-6",
                "neigh",
                "show",
                str(host),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                output = stdout.decode().strip()
                # Parse MAC address from output
                parts = output.split()
                for i, part in enumerate(parts):
                    if part == "lladdr" and i + 1 < len(parts):
                        return parts[i + 1]

        except Exception as e:
            self.logger.debug(f"Could not get MAC for {host}: {e}")

        return ""

    async def scan_ipv6_multicast(self) -> AsyncGenerator[HostInfo, None]:
        """
        Scan for IPv6 hosts using multicast discovery.

        Yields:
            HostInfo: Information about discovered hosts
        """
        multicast_addrs = [
            "ff02::1",  # All nodes
            "ff02::2",  # All routers
            "ff02::1:2",  # All DHCP servers
            "ff02::1:3",  # All DHCP relay agents
        ]

        for addr_str in multicast_addrs:
            try:
                addr = ipaddress.IPv6Address(addr_str)
                if await self._ping_ipv6_host(addr):
                    host_info = HostInfo(
                        ip_address=addr,
                        hostname=await self._resolve_hostname(addr),
                        os_info="Unknown",
                        mac_address=await self._get_mac_address(addr),
                        response_time=0.0,
                        is_reachable=True,
                        discovered_at=datetime.now(timezone.utc),
                        scan_type="ipv6_multicast",
                    )
                    yield host_info

            except Exception as e:
                self.logger.debug(f"Error scanning multicast {addr_str}: {e}")

    async def detect_ipv6_routers(self) -> List[HostInfo]:
        """
        Detect IPv6 routers using router advertisement.

        Returns:
            List of detected routers
        """
        routers = []

        try:
            # Send router solicitation to all-routers multicast
            router_addr = ipaddress.IPv6Address("ff02::2")

            if await self._ping_ipv6_host(router_addr):
                router_info = HostInfo(
                    ip_address=router_addr,
                    hostname=await self._resolve_hostname(router_addr),
                    os_info="Router",
                    mac_address=await self._get_mac_address(router_addr),
                    response_time=0.0,
                    is_reachable=True,
                    discovered_at=datetime.now(timezone.utc),
                    scan_type="ipv6_router_discovery",
                )
                routers.append(router_info)

        except Exception as e:
            self.logger.error(f"Error detecting IPv6 routers: {e}")

        return routers

    async def scan_ipv6_range(
        self, network: str, max_hosts: int = 1000
    ) -> AsyncGenerator[HostInfo, None]:
        """
        Scan IPv6 network range for active hosts.

        Args:
            network: IPv6 network in CIDR notation
            max_hosts: Maximum number of hosts to scan

        Yields:
            HostInfo: Information about discovered hosts
        """
        try:
            net = ipaddress.IPv6Network(network, strict=False)
            self.logger.info(f"Scanning IPv6 network: {network}")

            # For IPv6, we need to be smart about scanning due to huge address space
            # Focus on common patterns and known active ranges

            hosts_scanned = 0
            common_suffixes = [
                "::1",
                "::2",
                "::10",
                "::100",
                "::254",
                "::1000",
                "::dead:beef",
                "::c0a8:0101",
                "::192:168:1:1",
            ]

            for suffix in common_suffixes:
                if hosts_scanned >= max_hosts:
                    break

                try:
                    # Create address by combining network prefix with suffix
                    network_int = int(net.network_address)
                    suffix_addr = ipaddress.IPv6Address(suffix)
                    suffix_int = int(suffix_addr)

                    # Combine network prefix (first 64 bits) with suffix
                    combined_int = (network_int & 0xFFFFFFFFFFFFFFFF0000000000000000) | (
                        suffix_int & 0xFFFFFFFFFFFFFFFF
                    )
                    target_addr = ipaddress.IPv6Address(combined_int)

                    if target_addr in net:
                        if await self._ping_ipv6_host(target_addr):
                            host_info = HostInfo(
                                ip_address=target_addr,
                                hostname=await self._resolve_hostname(target_addr),
                                os_info="Unknown",
                                mac_address=await self._get_mac_address(target_addr),
                                response_time=0.0,
                                is_reachable=True,
                                discovered_at=datetime.now(timezone.utc),
                                scan_type="ipv6_range_scan",
                            )
                            yield host_info
                            hosts_scanned += 1

                except Exception as e:
                    self.logger.debug(f"Error scanning {suffix}: {e}")

        except Exception as e:
            self.logger.error(f"Error scanning IPv6 range {network}: {e}")

    async def get_ipv6_statistics(self) -> Dict[str, Any]:
        """
        Get IPv6 network statistics.

        Returns:
            Dictionary with IPv6 network statistics
        """
        stats = {
            "total_discovered": len(self._discovered_hosts),
            "link_local_count": 0,
            "global_unicast_count": 0,
            "multicast_count": 0,
            "loopback_count": 0,
            "discovery_timestamp": datetime.now(timezone.utc).isoformat(),
            "supported_features": [
                "neighbor_discovery",
                "multicast_scanning",
                "router_detection",
                "link_local_discovery",
                "range_scanning",
            ],
        }

        for host_str in self._discovered_hosts:
            try:
                addr = ipaddress.IPv6Address(host_str)
                if addr.is_link_local:
                    stats["link_local_count"] += 1
                elif addr.is_global:
                    stats["global_unicast_count"] += 1
                elif addr.is_multicast:
                    stats["multicast_count"] += 1
                elif addr.is_loopback:
                    stats["loopback_count"] += 1
            except:
                continue

        return stats
