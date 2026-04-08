"""
Network utilities and helper functions.
"""

import asyncio
import socket
import ipaddress
import struct
import subprocess
import platform
from typing import List, Dict, Optional, Tuple, Union
from datetime import datetime
import logging

# Optional dependencies
try:
    import netifaces

    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False
    netifaces = None

try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False
    psutil = None

try:
    import dns.resolver

    HAS_DNS = True
except ImportError:
    HAS_DNS = False
    dns = None

try:
    import whois

    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False
    whois = None

logger = logging.getLogger(__name__)


class NetworkUtils:
    """
    Network utilities and helper functions.

    Provides various network-related utility functions including:
    - IP address validation and conversion
    - Network interface information
    - DNS operations
    - Network reachability tests
    - Subnet calculations
    - Route table information
    """

    @staticmethod
    def validate_ip_address(ip_str: str) -> bool:
        """
        Validate if a string is a valid IP address.

        Args:
            ip_str: String to validate

        Returns:
            True if valid IP address, False otherwise
        """
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    @staticmethod
    def validate_network(network_str: str) -> bool:
        """
        Validate if a string is a valid network in CIDR notation.

        Args:
            network_str: String to validate

        Returns:
            True if valid network, False otherwise
        """
        try:
            ipaddress.ip_network(network_str, strict=False)
            return True
        except ValueError:
            return False

    @staticmethod
    def ip_to_int(ip_str: str) -> int:
        """
        Convert IP address string to integer.

        Args:
            ip_str: IP address string

        Returns:
            IP address as integer
        """
        return int(ipaddress.ip_address(ip_str))

    @staticmethod
    def int_to_ip(ip_int: int, version: int = 4) -> str:
        """
        Convert integer to IP address string.

        Args:
            ip_int: IP address as integer
            version: IP version (4 or 6)

        Returns:
            IP address string
        """
        if version == 4:
            return str(ipaddress.IPv4Address(ip_int))
        else:
            return str(ipaddress.IPv6Address(ip_int))

    @staticmethod
    def get_network_interfaces() -> List[Dict[str, str]]:
        """
        Get information about network interfaces.

        Returns:
            List of network interface information
        """
        interfaces = []

        for interface_name in netifaces.interfaces():
            try:
                addresses = netifaces.ifaddresses(interface_name)

                interface_info = {
                    "name": interface_name,
                    "ipv4_addresses": [],
                    "ipv6_addresses": [],
                    "mac_address": "",
                }

                # Get IPv4 addresses
                if netifaces.AF_INET in addresses:
                    for addr in addresses[netifaces.AF_INET]:
                        interface_info["ipv4_addresses"].append(
                            {
                                "address": addr.get("addr", ""),
                                "netmask": addr.get("netmask", ""),
                                "broadcast": addr.get("broadcast", ""),
                            }
                        )

                # Get IPv6 addresses
                if netifaces.AF_INET6 in addresses:
                    for addr in addresses[netifaces.AF_INET6]:
                        interface_info["ipv6_addresses"].append(
                            {"address": addr.get("addr", ""), "netmask": addr.get("netmask", "")}
                        )

                # Get MAC address
                if netifaces.AF_LINK in addresses:
                    interface_info["mac_address"] = addresses[netifaces.AF_LINK][0].get("addr", "")

                interfaces.append(interface_info)

            except Exception as e:
                logger.debug(f"Error getting interface info for {interface_name}: {e}")
                continue

        return interfaces

    @staticmethod
    def get_default_gateway() -> Optional[str]:
        """
        Get the default gateway IP address.

        Returns:
            Default gateway IP address or None if not found
        """
        try:
            gateways = netifaces.gateways()
            default_gateway = gateways.get("default", {}).get(netifaces.AF_INET)

            if default_gateway:
                return default_gateway[0]

            return None

        except Exception as e:
            logger.debug(f"Error getting default gateway: {e}")
            return None

    @staticmethod
    def get_local_ip() -> Optional[str]:
        """
        Get the local IP address.

        Returns:
            Local IP address or None if not found
        """
        try:
            # Connect to a remote address to determine local IP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            return local_ip

        except Exception as e:
            logger.debug(f"Error getting local IP: {e}")
            return None

    @staticmethod
    def calculate_subnet_info(network_str: str) -> Dict[str, Union[str, int]]:
        """
        Calculate subnet information for a network.

        Args:
            network_str: Network in CIDR notation

        Returns:
            Dictionary containing subnet information
        """
        try:
            network = ipaddress.ip_network(network_str, strict=False)

            return {
                "network": str(network),
                "network_address": str(network.network_address),
                "broadcast_address": str(network.broadcast_address),
                "netmask": str(network.netmask),
                "prefix_length": network.prefixlen,
                "num_addresses": network.num_addresses,
                "num_hosts": network.num_addresses - 2,
                "first_host": str(list(network.hosts())[0]) if network.num_addresses > 2 else "N/A",
                "last_host": str(list(network.hosts())[-1]) if network.num_addresses > 2 else "N/A",
                "is_private": network.is_private,
                "is_multicast": network.is_multicast,
                "is_reserved": network.is_reserved,
            }

        except ValueError as e:
            raise ValueError(f"Invalid network: {e}")

    @staticmethod
    def expand_cidr(cidr: str, max_hosts: int = 1000) -> List[str]:
        """
        Expand CIDR notation to individual IP addresses.

        Args:
            cidr: Network in CIDR notation
            max_hosts: Maximum number of hosts to return

        Returns:
            List of IP addresses
        """
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            hosts = list(network.hosts())

            # Limit the number of hosts
            if len(hosts) > max_hosts:
                hosts = hosts[:max_hosts]
                logger.warning(
                    f"Network {cidr} has {network.num_addresses} addresses, limiting to {max_hosts}"
                )

            return [str(host) for host in hosts]

        except ValueError as e:
            raise ValueError(f"Invalid CIDR: {e}")

    @staticmethod
    async def ping_host(host: str, timeout: int = 5) -> Tuple[bool, Optional[float]]:
        """
        Ping a host to check if it's reachable.

        Args:
            host: Hostname or IP address
            timeout: Timeout in seconds

        Returns:
            Tuple of (is_reachable, response_time_ms)
        """
        try:
            # Determine ping command based on OS
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
            else:
                cmd = ["ping", "-c", "1", "-W", str(timeout), host]

            start_time = datetime.now()

            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout + 5)

            end_time = datetime.now()
            response_time = (end_time - start_time).total_seconds() * 1000

            if process.returncode == 0:
                return True, response_time
            else:
                return False, None

        except asyncio.TimeoutError:
            return False, None
        except Exception as e:
            logger.debug(f"Ping error for {host}: {e}")
            return False, None

    @staticmethod
    async def traceroute(host: str, max_hops: int = 30) -> List[Dict[str, Union[str, int, float]]]:
        """
        Perform traceroute to a host.

        Args:
            host: Hostname or IP address
            max_hops: Maximum number of hops

        Returns:
            List of traceroute hop information
        """
        hops = []

        try:
            # Determine traceroute command based on OS
            if platform.system().lower() == "windows":
                cmd = ["tracert", "-h", str(max_hops), host]
            else:
                cmd = ["traceroute", "-m", str(max_hops), host]

            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=60)

            if process.returncode == 0:
                # Parse traceroute output
                lines = stdout.decode().split("\n")

                for line in lines:
                    line = line.strip()
                    if (
                        line
                        and not line.startswith("traceroute")
                        and not line.startswith("Tracing")
                    ):
                        # This is a simplified parser - real implementation would be more robust
                        hop_info = {
                            "hop": 0,
                            "ip": "unknown",
                            "hostname": "unknown",
                            "response_time": 0.0,
                        }
                        hops.append(hop_info)

            return hops

        except Exception as e:
            logger.debug(f"Traceroute error for {host}: {e}")
            return []

    @staticmethod
    async def dns_lookup(hostname: str, record_type: str = "A") -> List[str]:
        """
        Perform DNS lookup for a hostname.

        Args:
            hostname: Hostname to resolve
            record_type: DNS record type (A, AAAA, MX, NS, TXT, etc.)

        Returns:
            List of DNS records
        """
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 10

            answers = resolver.resolve(hostname, record_type)

            return [str(rdata) for rdata in answers]

        except Exception as e:
            logger.debug(f"DNS lookup error for {hostname}: {e}")
            return []

    @staticmethod
    async def reverse_dns_lookup(ip_address: str) -> Optional[str]:
        """
        Perform reverse DNS lookup for an IP address.

        Args:
            ip_address: IP address to resolve

        Returns:
            Hostname or None if not found
        """
        try:
            reversed_ip = dns.reversename.from_address(ip_address)
            hostname = str(dns.resolver.resolve(reversed_ip, "PTR")[0])

            # Remove trailing dot if present
            if hostname.endswith("."):
                hostname = hostname[:-1]

            return hostname

        except Exception as e:
            logger.debug(f"Reverse DNS lookup error for {ip_address}: {e}")
            return None

    @staticmethod
    def whois_lookup(domain: str) -> Dict[str, str]:
        """
        Perform WHOIS lookup for a domain.

        Args:
            domain: Domain name to lookup

        Returns:
            Dictionary containing WHOIS information
        """
        try:
            w = whois.whois(domain)

            return {
                "domain": domain,
                "registrar": str(w.registrar) if w.registrar else "Unknown",
                "creation_date": str(w.creation_date) if w.creation_date else "Unknown",
                "expiration_date": str(w.expiration_date) if w.expiration_date else "Unknown",
                "name_servers": str(w.name_servers) if w.name_servers else "Unknown",
                "status": str(w.status) if w.status else "Unknown",
                "emails": str(w.emails) if w.emails else "Unknown",
            }

        except Exception as e:
            logger.debug(f"WHOIS lookup error for {domain}: {e}")
            return {"error": str(e)}

    @staticmethod
    def get_network_connections() -> List[Dict[str, Union[str, int]]]:
        """
        Get active network connections.

        Returns:
            List of network connection information
        """
        connections = []

        try:
            for conn in psutil.net_connections():
                if conn.status == psutil.CONN_ESTABLISHED:
                    connection_info = {
                        "local_address": (
                            f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "unknown"
                        ),
                        "remote_address": (
                            f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "unknown"
                        ),
                        "status": conn.status,
                        "pid": conn.pid,
                        "type": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    }

                    # Try to get process name
                    try:
                        if conn.pid:
                            process = psutil.Process(conn.pid)
                            connection_info["process_name"] = process.name()
                    except:
                        connection_info["process_name"] = "unknown"

                    connections.append(connection_info)

            return connections

        except Exception as e:
            logger.debug(f"Error getting network connections: {e}")
            return []

    @staticmethod
    def get_network_statistics() -> Dict[str, Union[int, float]]:
        """
        Get network statistics.

        Returns:
            Dictionary containing network statistics
        """
        try:
            stats = psutil.net_io_counters()

            return {
                "bytes_sent": stats.bytes_sent,
                "bytes_recv": stats.bytes_recv,
                "packets_sent": stats.packets_sent,
                "packets_recv": stats.packets_recv,
                "errin": stats.errin,
                "errout": stats.errout,
                "dropin": stats.dropin,
                "dropout": stats.dropout,
            }

        except Exception as e:
            logger.debug(f"Error getting network statistics: {e}")
            return {}

    @staticmethod
    def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
        """
        Check if a port is in use.

        Args:
            port: Port number to check
            host: Host address to check

        Returns:
            True if port is in use, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0

        except Exception as e:
            logger.debug(f"Error checking port {port}: {e}")
            return False

    @staticmethod
    def get_free_port(start_port: int = 8000, end_port: int = 9000) -> Optional[int]:
        """
        Find a free port in the specified range.

        Args:
            start_port: Starting port number
            end_port: Ending port number

        Returns:
            Free port number or None if no free port found
        """
        for port in range(start_port, end_port + 1):
            if not NetworkUtils.is_port_in_use(port):
                return port

        return None

    @staticmethod
    def mac_to_vendor(mac_address: str) -> str:
        """
        Get vendor information from MAC address.

        Args:
            mac_address: MAC address

        Returns:
            Vendor name or "Unknown"
        """
        # This is a simplified implementation
        # In a real implementation, you would use a MAC address vendor database

        mac_vendors = {
            "00:50:56": "VMware",
            "00:0C:29": "VMware",
            "00:1C:42": "Parallels",
            "08:00:27": "VirtualBox",
            "00:16:3E": "Xen",
            "00:15:5D": "Microsoft Hyper-V",
            "00:1B:21": "Intel",
            "00:E0:4C": "Realtek",
            "00:22:64": "Broadcom",
            "00:26:B9": "Netgear",
        }

        # Extract OUI (first 3 octets)
        oui = mac_address[:8].upper()

        return mac_vendors.get(oui, "Unknown")

    @staticmethod
    def calculate_bandwidth(bytes_transferred: int, time_seconds: float) -> Dict[str, float]:
        """
        Calculate bandwidth from bytes transferred and time.

        Args:
            bytes_transferred: Number of bytes transferred
            time_seconds: Time in seconds

        Returns:
            Dictionary with bandwidth in different units
        """
        if time_seconds <= 0:
            return {"bps": 0, "kbps": 0, "mbps": 0, "gbps": 0}

        bps = bytes_transferred * 8 / time_seconds

        return {"bps": bps, "kbps": bps / 1000, "mbps": bps / 1000000, "gbps": bps / 1000000000}

    @staticmethod
    def is_private_ip(ip_address: str) -> bool:
        """
        Check if an IP address is private.

        Args:
            ip_address: IP address to check

        Returns:
            True if private IP, False otherwise
        """
        try:
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private
        except ValueError:
            return False

    @staticmethod
    def get_ip_info(ip_address: str) -> Dict[str, Union[str, bool, int]]:
        """
        Get detailed information about an IP address.

        Args:
            ip_address: IP address to analyze

        Returns:
            Dictionary containing IP information
        """
        try:
            ip = ipaddress.ip_address(ip_address)

            return {
                "ip_address": str(ip),
                "version": ip.version,
                "is_private": ip.is_private,
                "is_loopback": ip.is_loopback,
                "is_multicast": ip.is_multicast,
                "is_reserved": ip.is_reserved,
                "is_link_local": ip.is_link_local,
                "is_global": ip.is_global if hasattr(ip, "is_global") else False,
                "compressed": ip.compressed if hasattr(ip, "compressed") else str(ip),
                "exploded": ip.exploded if hasattr(ip, "exploded") else str(ip),
            }

        except ValueError as e:
            return {"error": str(e)}
