"""
On-Prem Network InfraIQ Python Library

Enterprise-grade network discovery and security assessment platform.
"""

__version__ = "2.1.0"
__author__ = "On-Prem Network InfraIQ Team"
__email__ = "info@onprem-infraiq.com"
__license__ = "MIT"
__description__ = "Enterprise-grade network discovery and security assessment platform"
__url__ = "https://github.com/jomardyan/On-Prem-Network-InfraIQ"

# Core imports for easy access
from .core.models import (
    ScanResult,
    VulnerabilityResult,
    NetworkRange,
    ScanConfiguration,
    ServiceFingerprint,
    HostInfo,
    ScanSession,
    ScanStatistics,
    SeverityLevel,
    ScanType,
    COMMON_PORTS,
    VULNERABILITY_PATTERNS,
)
from .core.scanner import NetworkScanner
from .tools.network_utils import NetworkUtils

# Core services with optional dependencies
try:
    from .security.vulnerability_scanner import VulnerabilityScanner
except ImportError:
    VulnerabilityScanner = None

try:
    from .services.port_scanner import PortScanner
except ImportError:
    PortScanner = None

# Enhanced modules with optional dependencies
try:
    from .services.ipv6_scanner import IPv6Scanner
except ImportError:
    IPv6Scanner = None

try:
    from .security.ssl_analyzer import (
        SSLCertificateAnalyzer,
        CertificateInfo,
        CertificateSecurityLevel,
    )
except ImportError:
    SSLCertificateAnalyzer = None
    CertificateInfo = None
    CertificateSecurityLevel = None

try:
    from .security.web_scanner import WebApplicationScanner, WebVulnerability, WebScanResult
except ImportError:
    WebApplicationScanner = None
    WebVulnerability = None
    WebScanResult = None

try:
    from .services.anomaly_detector import NetworkAnomalyDetector, NetworkAnomaly, AnomalyType
except ImportError:
    NetworkAnomalyDetector = None
    NetworkAnomaly = None
    AnomalyType = None

try:
    from .services.database import DatabaseManager
except ImportError:
    DatabaseManager = None

# Version information
VERSION = __version__
AUTHOR = __author__
EMAIL = __email__
LICENSE = __license__
DESCRIPTION = __description__
URL = __url__

# Build public API based on available modules
__all__ = [
    # Core classes (always available)
    "NetworkScanner",
    "NetworkUtils",
    # Models (always available)
    "ScanResult",
    "VulnerabilityResult",
    "NetworkRange",
    "ScanConfiguration",
    "ServiceFingerprint",
    "HostInfo",
    "ScanSession",
    "ScanStatistics",
    "SeverityLevel",
    "ScanType",
    "COMMON_PORTS",
    "VULNERABILITY_PATTERNS",
    # Metadata (always available)
    "VERSION",
    "AUTHOR",
    "EMAIL",
    "LICENSE",
    "DESCRIPTION",
    "URL",
    "__version__",
    "__author__",
    "__email__",
    "__license__",
    "__description__",
    "__url__",
]

# Add optional modules if available
if VulnerabilityScanner is not None:
    __all__.append("VulnerabilityScanner")

if PortScanner is not None:
    __all__.append("PortScanner")

if IPv6Scanner is not None:
    __all__.append("IPv6Scanner")

if SSLCertificateAnalyzer is not None:
    __all__.extend(["SSLCertificateAnalyzer", "CertificateInfo", "CertificateSecurityLevel"])

if WebApplicationScanner is not None:
    __all__.extend(["WebApplicationScanner", "WebVulnerability", "WebScanResult"])

if NetworkAnomalyDetector is not None:
    __all__.extend(["NetworkAnomalyDetector", "NetworkAnomaly", "AnomalyType"])

if DatabaseManager is not None:
    __all__.append("DatabaseManager")
