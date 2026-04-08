"""
Core data models for the On-Prem Network InfraIQ library.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
import ipaddress

# Optional pydantic import with fallback
try:
    from pydantic import BaseModel, Field, field_validator
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False
    BaseModel = object
    Field = lambda **kwargs: None
    field_validator = lambda *args, **kwargs: lambda f: f


class SeverityLevel(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class ScanType(str, Enum):
    """Types of network scans."""

    PORT = "port"
    VULNERABILITY = "vulnerability"
    COMPREHENSIVE = "comprehensive"
    QUICK = "quick"
    STEALTH = "stealth"


@dataclass
class HostInfo:
    """Represents information about a network host."""

    ip_address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    hostname: str = ""
    os_info: str = "Unknown"
    mac_address: str = ""
    response_time: float = 0.0
    is_reachable: bool = True
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_type: str = "host_discovery"
    open_ports: List[int] = field(default_factory=list)
    services: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Validate and convert IP address if needed."""
        if isinstance(self.ip_address, str):
            self.ip_address = ipaddress.ip_address(self.ip_address)


@dataclass
class ScanResult:
    """Represents a single scan result."""

    ip_address: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    port: int
    is_open: bool
    service_name: str
    ping_time: Optional[float] = None
    operating_system: str = "Unknown"
    server_info: str = ""
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    country: str = ""
    hostname: str = ""
    is_vulnerable: bool = False
    vulnerability_info: str = ""
    service_version: str = ""

    def __post_init__(self):
        """Validate and convert IP address if needed."""
        if isinstance(self.ip_address, str):
            self.ip_address = ipaddress.ip_address(self.ip_address)


@dataclass
class VulnerabilityResult:
    """Represents a vulnerability finding."""

    host: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    port: int
    service: str
    vulnerability: str
    severity: SeverityLevel
    title: str = ""
    description: str = ""
    recommendation: str = ""
    cve_id: str = ""
    cvss_score: Optional[float] = None
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self):
        """Validate and convert IP address if needed."""
        if isinstance(self.host, str):
            self.host = ipaddress.ip_address(self.host)


@dataclass
class NetworkRange:
    """Represents a network range for scanning."""

    network: Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
    description: str = ""

    def __post_init__(self):
        """Validate and convert network if needed."""
        if isinstance(self.network, str):
            self.network = ipaddress.ip_network(self.network)

    @property
    def hosts(self) -> List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
        """Get all host addresses in the network."""
        return list(self.network.hosts())

    @property
    def num_hosts(self) -> int:
        """Get the number of hosts in the network."""
        return self.network.num_addresses


class ScanConfiguration(BaseModel):
    """Configuration for network scans."""

    timeout: int = Field(default=5, ge=1, le=300, description="Timeout in seconds")
    max_threads: int = Field(default=100, ge=1, le=1000, description="Maximum concurrent threads")
    ports: List[int] = Field(
        default_factory=lambda: [22, 80, 443, 3389], description="Ports to scan"
    )
    scan_type: ScanType = Field(default=ScanType.PORT, description="Type of scan to perform")
    include_vulnerability_scan: bool = Field(
        default=False, description="Include vulnerability scanning"
    )
    stealth_mode: bool = Field(default=False, description="Enable stealth scanning")
    user_agent: str = Field(
        default="OnPrem-InfraIQ/2.1.0", description="User agent for HTTP requests"
    )

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v):
        """Validate port numbers."""
        for port in v:
            if not (1 <= port <= 65535):
                raise ValueError(f"Port {port} is not in valid range (1-65535)")
        return v


class ServiceFingerprint(BaseModel):
    """Service fingerprint information."""

    service_name: str
    version: str = ""
    banner: str = ""
    ssl_info: Dict[str, Any] = Field(default_factory=dict)
    http_headers: Dict[str, str] = Field(default_factory=dict)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class HostInfo(BaseModel):
    """Information about a discovered host."""

    ip_address: str
    hostname: str = ""
    operating_system: str = ""
    mac_address: str = ""
    vendor: str = ""
    open_ports: List[int] = Field(default_factory=list)
    services: List[ServiceFingerprint] = Field(default_factory=list)
    vulnerabilities: List[VulnerabilityResult] = Field(default_factory=list)
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v):
        """Validate IP address."""
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
        return v


class ScanSession(BaseModel):
    """Scan session information."""

    session_id: str
    target: str
    scan_type: ScanType
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    status: str = "running"
    results_count: int = 0
    config: ScanConfiguration = Field(default_factory=ScanConfiguration)

    @property
    def duration(self) -> Optional[float]:
        """Get scan duration in seconds."""
        if self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None


class ScanStatistics(BaseModel):
    """Statistics for a scan session."""

    total_hosts: int = 0
    active_hosts: int = 0
    open_ports: int = 0
    vulnerabilities_found: int = 0
    scan_duration: float = 0.0
    avg_response_time: float = 0.0
    services_detected: List[str] = Field(default_factory=list)
    os_detected: List[str] = Field(default_factory=list)


# Common port mappings
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S",
    3389: "RDP",
    5432: "PostgreSQL",
    3306: "MySQL",
    1433: "MSSQL",
    135: "RPC",
    139: "NetBIOS",
    445: "SMB",
    161: "SNMP",
    389: "LDAP",
    636: "LDAPS",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

# Vulnerability patterns
VULNERABILITY_PATTERNS = {
    "anonymous_ftp": {
        "ports": [21],
        "pattern": r"anonymous.*allowed",
        "severity": SeverityLevel.MEDIUM,
        "description": "Anonymous FTP access allowed",
    },
    "weak_ssh": {
        "ports": [22],
        "pattern": r"SSH-1\.",
        "severity": SeverityLevel.HIGH,
        "description": "Weak SSH version detected",
    },
    "open_telnet": {
        "ports": [23],
        "pattern": r".*",
        "severity": SeverityLevel.HIGH,
        "description": "Telnet service detected (unencrypted)",
    },
    "weak_ssl": {
        "ports": [443, 993, 995],
        "pattern": r"SSLv[23]|TLSv1\.0",
        "severity": SeverityLevel.HIGH,
        "description": "Weak SSL/TLS version detected",
    },
}
