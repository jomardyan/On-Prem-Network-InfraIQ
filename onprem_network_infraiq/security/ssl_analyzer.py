"""
SSL/TLS certificate analysis and security assessment.
"""

import asyncio
import ssl
import socket
import datetime
from datetime import timezone
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
import ipaddress

# Optional cryptography import
try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID, ExtensionOID

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False
    x509 = None
    default_backend = None
    NameOID = None
    ExtensionOID = None

logger = logging.getLogger(__name__)


class CertificateSecurityLevel(str, Enum):
    """SSL/TLS certificate security levels."""

    SECURE = "secure"
    MODERATE = "moderate"
    WEAK = "weak"
    CRITICAL = "critical"


class CipherSuite(str, Enum):
    """Common cipher suites classification."""

    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    INSECURE = "insecure"


@dataclass
class CertificateInfo:
    """Information about an SSL/TLS certificate."""

    hostname: str
    port: int
    subject: Dict[str, str]
    issuer: Dict[str, str]
    version: int
    serial_number: str
    not_before: datetime.datetime
    not_after: datetime.datetime
    is_expired: bool
    days_until_expiry: int
    signature_algorithm: str
    public_key_algorithm: str
    public_key_size: int
    san_domains: List[str]
    fingerprint_sha256: str
    fingerprint_sha1: str
    chain_length: int
    is_self_signed: bool
    is_wildcard: bool
    security_level: CertificateSecurityLevel
    vulnerabilities: List[str]
    cipher_suites: List[str]
    protocol_versions: List[str]
    scan_timestamp: datetime.datetime


class SSLCertificateAnalyzer:
    """
    Advanced SSL/TLS certificate analyzer and security assessor.

    This class provides comprehensive SSL/TLS analysis including:
    - Certificate validation and parsing
    - Security level assessment
    - Vulnerability detection
    - Cipher suite analysis
    - Protocol version testing
    - Certificate chain analysis
    """

    def __init__(self, timeout: int = 10):
        """
        Initialize SSL certificate analyzer.

        Args:
            timeout: Timeout for SSL connections in seconds
        """
        self.timeout = timeout
        self.logger = logging.getLogger(__name__)

    async def analyze_certificate(
        self, hostname: str, port: int = 443
    ) -> Optional[CertificateInfo]:
        """
        Analyze SSL/TLS certificate for a host.

        Args:
            hostname: Target hostname
            port: Target port (default 443)

        Returns:
            CertificateInfo if successful, None otherwise
        """
        try:
            self.logger.info(f"Analyzing SSL certificate for {hostname}:{port}")

            # Get certificate
            cert_der, chain_length = await self._get_certificate(hostname, port)
            if not cert_der:
                return None

            # Parse certificate
            cert_info = await self._parse_certificate(cert_der, hostname, port, chain_length)
            if not cert_info:
                return None

            # Analyze security
            cert_info.security_level = self._assess_security_level(cert_info)
            cert_info.vulnerabilities = await self._detect_vulnerabilities(
                cert_info, hostname, port
            )
            cert_info.cipher_suites = await self._analyze_cipher_suites(hostname, port)
            cert_info.protocol_versions = await self._test_protocol_versions(hostname, port)

            return cert_info

        except Exception as e:
            self.logger.error(f"Error analyzing certificate for {hostname}:{port}: {e}")
            return None

    async def _get_certificate(self, hostname: str, port: int) -> Tuple[Optional[bytes], int]:
        """Get SSL certificate from the server."""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    chain_length = len(ssock.getpeercert_chain() or [])

                    return cert_der, chain_length

        except Exception as e:
            self.logger.debug(f"Failed to get certificate for {hostname}:{port}: {e}")
            return None, 0

    async def _parse_certificate(
        self, cert_der: bytes, hostname: str, port: int, chain_length: int
    ) -> Optional[CertificateInfo]:
        """Parse certificate information."""
        try:
            if HAS_CRYPTOGRAPHY:
                return await self._parse_with_cryptography(cert_der, hostname, port, chain_length)
            else:
                return await self._parse_with_ssl(cert_der, hostname, port, chain_length)

        except Exception as e:
            self.logger.error(f"Error parsing certificate: {e}")
            return None

    async def _parse_with_cryptography(
        self, cert_der: bytes, hostname: str, port: int, chain_length: int
    ) -> CertificateInfo:
        """Parse certificate using cryptography library."""
        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        # Extract subject information
        subject = {}
        for attribute in cert.subject:
            subject[attribute.oid._name] = attribute.value

        # Extract issuer information
        issuer = {}
        for attribute in cert.issuer:
            issuer[attribute.oid._name] = attribute.value

        # Extract SAN domains
        san_domains = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_domains = [name.value for name in san_ext.value]
        except:
            pass

        # Calculate expiry information
        now = datetime.datetime.now(timezone.utc)
        days_until_expiry = (cert.not_valid_after - now).days
        is_expired = cert.not_valid_after < now

        # Generate fingerprints
        fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()
        fingerprint_sha1 = cert.fingerprint(hashes.SHA1()).hex()

        # Check if self-signed
        is_self_signed = cert.issuer == cert.subject

        # Check if wildcard
        is_wildcard = any(domain.startswith("*") for domain in san_domains) or subject.get(
            "commonName", ""
        ).startswith("*")

        return CertificateInfo(
            hostname=hostname,
            port=port,
            subject=subject,
            issuer=issuer,
            version=cert.version.value,
            serial_number=str(cert.serial_number),
            not_before=cert.not_valid_before,
            not_after=cert.not_valid_after,
            is_expired=is_expired,
            days_until_expiry=days_until_expiry,
            signature_algorithm=cert.signature_algorithm_oid._name,
            public_key_algorithm=cert.public_key().__class__.__name__,
            public_key_size=cert.public_key().key_size,
            san_domains=san_domains,
            fingerprint_sha256=fingerprint_sha256,
            fingerprint_sha1=fingerprint_sha1,
            chain_length=chain_length,
            is_self_signed=is_self_signed,
            is_wildcard=is_wildcard,
            security_level=CertificateSecurityLevel.MODERATE,
            vulnerabilities=[],
            cipher_suites=[],
            protocol_versions=[],
            scan_timestamp=datetime.datetime.now(timezone.utc),
        )

    async def _parse_with_ssl(
        self, cert_der: bytes, hostname: str, port: int, chain_length: int
    ) -> CertificateInfo:
        """Parse certificate using standard ssl library (fallback)."""
        # Convert DER to PEM and parse with ssl
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_dict = ssock.getpeercert()

        # Extract information from cert_dict
        subject = dict(x[0] for x in cert_dict.get("subject", []))
        issuer = dict(x[0] for x in cert_dict.get("issuer", []))

        # Parse dates
        not_before = datetime.datetime.strptime(cert_dict["notBefore"], "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.datetime.strptime(cert_dict["notAfter"], "%b %d %H:%M:%S %Y %Z")

        # Calculate expiry
        now = datetime.datetime.now(timezone.utc)
        days_until_expiry = (not_after - now).days
        is_expired = not_after < now

        # Extract SAN domains
        san_domains = []
        for san in cert_dict.get("subjectAltName", []):
            if san[0] == "DNS":
                san_domains.append(san[1])

        return CertificateInfo(
            hostname=hostname,
            port=port,
            subject=subject,
            issuer=issuer,
            version=cert_dict.get("version", 0),
            serial_number=cert_dict.get("serialNumber", ""),
            not_before=not_before,
            not_after=not_after,
            is_expired=is_expired,
            days_until_expiry=days_until_expiry,
            signature_algorithm=cert_dict.get("signatureAlgorithm", "unknown"),
            public_key_algorithm="unknown",
            public_key_size=0,
            san_domains=san_domains,
            fingerprint_sha256="",
            fingerprint_sha1="",
            chain_length=chain_length,
            is_self_signed=subject == issuer,
            is_wildcard=any(domain.startswith("*") for domain in san_domains),
            security_level=CertificateSecurityLevel.MODERATE,
            vulnerabilities=[],
            cipher_suites=[],
            protocol_versions=[],
            scan_timestamp=datetime.datetime.now(timezone.utc),
        )

    def _assess_security_level(self, cert_info: CertificateInfo) -> CertificateSecurityLevel:
        """Assess overall security level of the certificate."""
        score = 0

        # Check expiry
        if cert_info.is_expired:
            return CertificateSecurityLevel.CRITICAL
        elif cert_info.days_until_expiry < 30:
            score -= 2
        elif cert_info.days_until_expiry < 90:
            score -= 1

        # Check key size
        if cert_info.public_key_size >= 2048:
            score += 2
        elif cert_info.public_key_size >= 1024:
            score += 1
        else:
            score -= 3

        # Check if self-signed
        if cert_info.is_self_signed:
            score -= 2

        # Check signature algorithm
        if "sha256" in cert_info.signature_algorithm.lower():
            score += 1
        elif "sha1" in cert_info.signature_algorithm.lower():
            score -= 2
        elif "md5" in cert_info.signature_algorithm.lower():
            score -= 3

        # Determine security level
        if score >= 3:
            return CertificateSecurityLevel.SECURE
        elif score >= 0:
            return CertificateSecurityLevel.MODERATE
        elif score >= -2:
            return CertificateSecurityLevel.WEAK
        else:
            return CertificateSecurityLevel.CRITICAL

    async def _detect_vulnerabilities(
        self, cert_info: CertificateInfo, hostname: str, port: int
    ) -> List[str]:
        """Detect certificate vulnerabilities."""
        vulnerabilities = []

        # Check for expired certificate
        if cert_info.is_expired:
            vulnerabilities.append("Certificate has expired")

        # Check for expiring soon
        if cert_info.days_until_expiry < 30:
            vulnerabilities.append(f"Certificate expires in {cert_info.days_until_expiry} days")

        # Check for weak key size
        if cert_info.public_key_size < 2048:
            vulnerabilities.append(f"Weak key size: {cert_info.public_key_size} bits")

        # Check for self-signed certificate
        if cert_info.is_self_signed:
            vulnerabilities.append("Self-signed certificate")

        # Check for weak signature algorithm
        if "md5" in cert_info.signature_algorithm.lower():
            vulnerabilities.append("Weak signature algorithm: MD5")
        elif "sha1" in cert_info.signature_algorithm.lower():
            vulnerabilities.append("Weak signature algorithm: SHA1")

        # Check for hostname mismatch
        if not self._verify_hostname(cert_info, hostname):
            vulnerabilities.append("Hostname mismatch")

        return vulnerabilities

    def _verify_hostname(self, cert_info: CertificateInfo, hostname: str) -> bool:
        """Verify if hostname matches certificate."""
        # Check common name
        common_name = cert_info.subject.get("commonName", "")
        if common_name == hostname:
            return True

        # Check SAN domains
        for san_domain in cert_info.san_domains:
            if san_domain == hostname:
                return True
            # Check wildcard
            if san_domain.startswith("*."):
                domain_suffix = san_domain[2:]
                if hostname.endswith(domain_suffix):
                    return True

        return False

    async def _analyze_cipher_suites(self, hostname: str, port: int) -> List[str]:
        """Analyze supported cipher suites."""
        cipher_suites = []

        try:
            # Test different cipher suites
            test_ciphers = [
                "ECDHE-RSA-AES256-GCM-SHA384",
                "ECDHE-RSA-AES128-GCM-SHA256",
                "ECDHE-RSA-AES256-SHA384",
                "ECDHE-RSA-AES128-SHA256",
                "AES256-GCM-SHA384",
                "AES128-GCM-SHA256",
                "AES256-SHA256",
                "AES128-SHA256",
                "DES-CBC3-SHA",  # Weak
                "RC4-SHA",  # Insecure
            ]

            for cipher in test_ciphers:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    context.set_ciphers(cipher)

                    with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cipher_suites.append(ssock.cipher()[0])
                            break  # Just test one for now

                except:
                    continue

        except Exception as e:
            self.logger.debug(f"Error analyzing cipher suites: {e}")

        return cipher_suites

    async def _test_protocol_versions(self, hostname: str, port: int) -> List[str]:
        """Test supported SSL/TLS protocol versions."""
        protocols = []

        test_protocols = [
            (ssl.PROTOCOL_TLSv1_2, "TLSv1.2"),
            (ssl.PROTOCOL_TLSv1_1, "TLSv1.1"),
            (ssl.PROTOCOL_TLSv1, "TLSv1.0"),
        ]

        # Test TLS 1.3 if available
        if hasattr(ssl, "PROTOCOL_TLS"):
            test_protocols.insert(0, (ssl.PROTOCOL_TLS, "TLS"))

        for protocol, name in test_protocols:
            try:
                context = ssl.SSLContext(protocol)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        protocols.append(name)

            except:
                continue

        return protocols

    async def scan_ssl_hosts(self, hosts: List[Tuple[str, int]]) -> Dict[str, CertificateInfo]:
        """
        Scan multiple hosts for SSL certificates.

        Args:
            hosts: List of (hostname, port) tuples

        Returns:
            Dictionary mapping host:port to CertificateInfo
        """
        results = {}

        tasks = []
        for hostname, port in hosts:
            task = asyncio.create_task(self.analyze_certificate(hostname, port))
            tasks.append((f"{hostname}:{port}", task))

        for host_key, task in tasks:
            try:
                cert_info = await task
                if cert_info:
                    results[host_key] = cert_info
            except Exception as e:
                self.logger.error(f"Error scanning {host_key}: {e}")

        return results

    async def get_ssl_statistics(self, certificates: List[CertificateInfo]) -> Dict[str, Any]:
        """
        Get SSL certificate statistics.

        Args:
            certificates: List of certificate information

        Returns:
            Dictionary with SSL statistics
        """
        stats = {
            "total_certificates": len(certificates),
            "security_levels": {"secure": 0, "moderate": 0, "weak": 0, "critical": 0},
            "expired_certificates": 0,
            "expiring_soon": 0,
            "self_signed": 0,
            "wildcard_certificates": 0,
            "weak_key_sizes": 0,
            "common_issuers": {},
            "common_vulnerabilities": {},
            "average_days_until_expiry": 0,
            "analysis_timestamp": datetime.datetime.now(timezone.utc).isoformat(),
        }

        total_days = 0

        for cert in certificates:
            # Security levels
            stats["security_levels"][cert.security_level] += 1

            # Expiry information
            if cert.is_expired:
                stats["expired_certificates"] += 1
            elif cert.days_until_expiry < 30:
                stats["expiring_soon"] += 1

            total_days += cert.days_until_expiry

            # Other characteristics
            if cert.is_self_signed:
                stats["self_signed"] += 1
            if cert.is_wildcard:
                stats["wildcard_certificates"] += 1
            if cert.public_key_size < 2048:
                stats["weak_key_sizes"] += 1

            # Issuer statistics
            issuer_name = cert.issuer.get("organizationName", "Unknown")
            stats["common_issuers"][issuer_name] = stats["common_issuers"].get(issuer_name, 0) + 1

            # Vulnerability statistics
            for vuln in cert.vulnerabilities:
                stats["common_vulnerabilities"][vuln] = (
                    stats["common_vulnerabilities"].get(vuln, 0) + 1
                )

        # Calculate average
        if certificates:
            stats["average_days_until_expiry"] = total_days / len(certificates)

        return stats


# Try to import hashes if cryptography is available
if HAS_CRYPTOGRAPHY:
    try:
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        hashes = None
else:
    hashes = None
