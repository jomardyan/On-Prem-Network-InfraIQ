"""
Web application vulnerability scanner and security assessment.
"""

import asyncio
import re
import urllib.parse
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone
import logging
import hashlib
import json
import socket
import ssl

# Optional HTTP client library
try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False
    aiohttp = None

logger = logging.getLogger(__name__)


class WebVulnerabilityType(str, Enum):
    """Types of web vulnerabilities."""

    XSS = "cross_site_scripting"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    WEAK_AUTHENTICATION = "weak_authentication"
    INSECURE_HEADERS = "insecure_headers"
    INFORMATION_DISCLOSURE = "information_disclosure"
    CSRF = "cross_site_request_forgery"
    CLICKJACKING = "clickjacking"
    WEAK_ENCRYPTION = "weak_encryption"
    SENSITIVE_DATA_EXPOSURE = "sensitive_data_exposure"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    SECURITY_MISCONFIGURATION = "security_misconfiguration"
    VULNERABLE_COMPONENTS = "vulnerable_components"
    INSUFFICIENT_LOGGING = "insufficient_logging"


class WebVulnerabilitySeverity(str, Enum):
    """Web vulnerability severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class WebVulnerability:
    """Information about a web vulnerability."""

    vulnerability_type: WebVulnerabilityType
    severity: WebVulnerabilitySeverity
    title: str
    description: str
    url: str
    method: str
    parameter: str
    payload: str
    evidence: str
    recommendation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    confidence: float = 0.0
    discovered_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class WebScanResult:
    """Results of web application security scan."""

    target_url: str
    scan_id: str
    vulnerabilities: List[WebVulnerability]
    pages_scanned: int
    forms_found: int
    parameters_tested: int
    scan_duration: float
    server_info: Dict[str, Any]
    technologies_detected: List[str]
    security_headers: Dict[str, str]
    cookies_analysis: Dict[str, Any]
    ssl_info: Optional[Dict[str, Any]] = None
    scan_timestamp: datetime = field(default_factory=datetime.utcnow)


class WebApplicationScanner:
    """
    Advanced web application vulnerability scanner.

    This class provides comprehensive web security testing including:
    - OWASP Top 10 vulnerability detection
    - Security headers analysis
    - Cookie security assessment
    - Technology fingerprinting
    - SSL/TLS configuration testing
    - Directory traversal testing
    - XSS and injection testing
    """

    def __init__(self, timeout: int = 30, max_concurrent: int = 10):
        """
        Initialize web application scanner.

        Args:
            timeout: Request timeout in seconds
            max_concurrent: Maximum concurrent requests
        """
        if not HAS_AIOHTTP:
            raise ImportError("aiohttp is required for web scanning functionality")
            
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.logger = logging.getLogger(__name__)
        self.session: Optional[Any] = None  # aiohttp.ClientSession when available
        self.discovered_urls: Set[str] = set()
        self.tested_parameters: Set[str] = set()

    async def __aenter__(self):
        """Async context manager entry."""
        if not HAS_AIOHTTP:
            raise ImportError("aiohttp is required for web scanning functionality")
            
        connector = aiohttp.TCPConnector(limit=self.max_concurrent)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "OnPrem-NetworkInfraIQ-Scanner/2.1.0"},
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()

    async def scan_web_application(self, target_url: str, depth: int = 2) -> WebScanResult:
        """
        Perform comprehensive web application security scan.

        Args:
            target_url: Target web application URL
            depth: Crawling depth

        Returns:
            WebScanResult with scan results
        """
        scan_id = hashlib.md5(f"{target_url}{datetime.now(timezone.utc)}".encode()).hexdigest()[:8]
        scan_start = datetime.now(timezone.utc)

        self.logger.info(f"Starting web application scan for: {target_url}")

        try:
            # Initialize results
            vulnerabilities = []
            pages_scanned = 0
            forms_found = 0
            parameters_tested = 0

            # Crawl the application
            urls = await self._crawl_application(target_url, depth)
            pages_scanned = len(urls)

            # Detect technologies
            technologies = await self._detect_technologies(target_url)

            # Get server information
            server_info = await self._get_server_info(target_url)

            # Analyze security headers
            security_headers = await self._analyze_security_headers(target_url)

            # Analyze cookies
            cookies_analysis = await self._analyze_cookies(target_url)

            # Test for vulnerabilities
            for url in urls:
                # Test for XSS
                xss_vulns = await self._test_xss(url)
                vulnerabilities.extend(xss_vulns)

                # Test for SQL injection
                sql_vulns = await self._test_sql_injection(url)
                vulnerabilities.extend(sql_vulns)

                # Test for directory traversal
                dir_vulns = await self._test_directory_traversal(url)
                vulnerabilities.extend(dir_vulns)

                # Test for command injection
                cmd_vulns = await self._test_command_injection(url)
                vulnerabilities.extend(cmd_vulns)

                # Find and test forms
                forms = await self._find_forms(url)
                forms_found += len(forms)

                for form in forms:
                    form_vulns = await self._test_form_vulnerabilities(form, url)
                    vulnerabilities.extend(form_vulns)

            # Test for security misconfigurations
            config_vulns = await self._test_security_misconfigurations(target_url)
            vulnerabilities.extend(config_vulns)

            # Test for information disclosure
            info_vulns = await self._test_information_disclosure(target_url)
            vulnerabilities.extend(info_vulns)

            parameters_tested = len(self.tested_parameters)
            scan_duration = (datetime.now(timezone.utc) - scan_start).total_seconds()

            return WebScanResult(
                target_url=target_url,
                scan_id=scan_id,
                vulnerabilities=vulnerabilities,
                pages_scanned=pages_scanned,
                forms_found=forms_found,
                parameters_tested=parameters_tested,
                scan_duration=scan_duration,
                server_info=server_info,
                technologies_detected=technologies,
                security_headers=security_headers,
                cookies_analysis=cookies_analysis,
                scan_timestamp=scan_start,
            )

        except Exception as e:
            self.logger.error(f"Error during web application scan: {e}")
            raise

    async def _crawl_application(self, start_url: str, depth: int) -> List[str]:
        """Crawl web application to discover URLs."""
        urls = {start_url}
        to_crawl = {start_url}

        for _ in range(depth):
            if not to_crawl:
                break

            current_level = to_crawl.copy()
            to_crawl.clear()

            for url in current_level:
                try:
                    new_urls = await self._extract_urls_from_page(url)
                    for new_url in new_urls:
                        if new_url not in urls and self._is_same_domain(start_url, new_url):
                            urls.add(new_url)
                            to_crawl.add(new_url)
                except Exception as e:
                    self.logger.debug(f"Error crawling {url}: {e}")

        return list(urls)

    async def _extract_urls_from_page(self, url: str) -> List[str]:
        """Extract URLs from a web page."""
        urls = []

        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()

                    # Extract href attributes
                    href_pattern = r'href=["\'](.*?)["\']'
                    href_matches = re.findall(href_pattern, content, re.IGNORECASE)

                    # Extract src attributes
                    src_pattern = r'src=["\'](.*?)["\']'
                    src_matches = re.findall(src_pattern, content, re.IGNORECASE)

                    # Extract action attributes
                    action_pattern = r'action=["\'](.*?)["\']'
                    action_matches = re.findall(action_pattern, content, re.IGNORECASE)

                    all_matches = href_matches + src_matches + action_matches

                    for match in all_matches:
                        absolute_url = urllib.parse.urljoin(url, match)
                        urls.append(absolute_url)

        except Exception as e:
            self.logger.debug(f"Error extracting URLs from {url}: {e}")

        return urls

    def _is_same_domain(self, base_url: str, test_url: str) -> bool:
        """Check if URLs are from the same domain."""
        try:
            base_domain = urllib.parse.urlparse(base_url).netloc
            test_domain = urllib.parse.urlparse(test_url).netloc
            return base_domain == test_domain
        except:
            return False

    async def _detect_technologies(self, url: str) -> List[str]:
        """Detect web technologies used."""
        technologies = []

        try:
            async with self.session.get(url) as response:
                headers = response.headers
                content = await response.text()

                # Server header
                server = headers.get("Server", "")
                if server:
                    technologies.append(f"Server: {server}")

                # X-Powered-By header
                powered_by = headers.get("X-Powered-By", "")
                if powered_by:
                    technologies.append(f"Technology: {powered_by}")

                # Content analysis
                if "WordPress" in content:
                    technologies.append("CMS: WordPress")
                elif "Drupal" in content:
                    technologies.append("CMS: Drupal")
                elif "Joomla" in content:
                    technologies.append("CMS: Joomla")

                # Framework detection
                if "django" in content.lower():
                    technologies.append("Framework: Django")
                elif "rails" in content.lower():
                    technologies.append("Framework: Ruby on Rails")
                elif "express" in content.lower():
                    technologies.append("Framework: Express.js")

        except Exception as e:
            self.logger.debug(f"Error detecting technologies: {e}")

        return technologies

    async def _get_server_info(self, url: str) -> Dict[str, Any]:
        """Get server information."""
        server_info = {}

        try:
            async with self.session.get(url) as response:
                headers = response.headers

                server_info["status_code"] = response.status
                server_info["headers"] = dict(headers)
                server_info["content_type"] = headers.get("Content-Type", "")
                server_info["server"] = headers.get("Server", "")
                server_info["response_time"] = response.headers.get("X-Response-Time", "")

        except Exception as e:
            self.logger.debug(f"Error getting server info: {e}")

        return server_info

    async def _analyze_security_headers(self, url: str) -> Dict[str, str]:
        """Analyze security-related HTTP headers."""
        security_headers = {}

        try:
            async with self.session.get(url) as response:
                headers = response.headers

                # Check for security headers
                security_header_names = [
                    "Strict-Transport-Security",
                    "Content-Security-Policy",
                    "X-Frame-Options",
                    "X-Content-Type-Options",
                    "X-XSS-Protection",
                    "Referrer-Policy",
                    "Permissions-Policy",
                    "Cross-Origin-Embedder-Policy",
                    "Cross-Origin-Resource-Policy",
                ]

                for header_name in security_header_names:
                    value = headers.get(header_name)
                    if value:
                        security_headers[header_name] = value

        except Exception as e:
            self.logger.debug(f"Error analyzing security headers: {e}")

        return security_headers

    async def _analyze_cookies(self, url: str) -> Dict[str, Any]:
        """Analyze cookie security."""
        cookies_analysis = {
            "total_cookies": 0,
            "secure_cookies": 0,
            "httponly_cookies": 0,
            "samesite_cookies": 0,
            "insecure_cookies": [],
        }

        try:
            async with self.session.get(url) as response:
                cookies = response.cookies

                cookies_analysis["total_cookies"] = len(cookies)

                for cookie in cookies:
                    if cookie.get("secure"):
                        cookies_analysis["secure_cookies"] += 1
                    if cookie.get("httponly"):
                        cookies_analysis["httponly_cookies"] += 1
                    if cookie.get("samesite"):
                        cookies_analysis["samesite_cookies"] += 1
                    else:
                        cookies_analysis["insecure_cookies"].append(cookie.key)

        except Exception as e:
            self.logger.debug(f"Error analyzing cookies: {e}")

        return cookies_analysis

    async def _test_xss(self, url: str) -> List[WebVulnerability]:
        """Test for Cross-Site Scripting (XSS) vulnerabilities."""
        vulnerabilities = []

        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><script>alert("XSS")</script>',
            "'><script>alert('XSS')</script>",
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            'javascript:alert("XSS")',
        ]

        try:
            # Test GET parameters
            parsed_url = urllib.parse.urlparse(url)
            if parsed_url.query:
                params = urllib.parse.parse_qs(parsed_url.query)

                for param_name, param_values in params.items():
                    for payload in xss_payloads:
                        test_params = params.copy()
                        test_params[param_name] = [payload]

                        test_url = urllib.parse.urlunparse(
                            (
                                parsed_url.scheme,
                                parsed_url.netloc,
                                parsed_url.path,
                                parsed_url.params,
                                urllib.parse.urlencode(test_params, doseq=True),
                                parsed_url.fragment,
                            )
                        )

                        if await self._test_xss_payload(test_url, payload):
                            vulnerabilities.append(
                                WebVulnerability(
                                    vulnerability_type=WebVulnerabilityType.XSS,
                                    severity=WebVulnerabilitySeverity.HIGH,
                                    title="Cross-Site Scripting (XSS)",
                                    description=f"XSS vulnerability found in parameter '{param_name}'",
                                    url=url,
                                    method="GET",
                                    parameter=param_name,
                                    payload=payload,
                                    evidence=f"Payload reflected in response: {payload}",
                                    recommendation="Implement proper input validation and output encoding",
                                    cwe_id="CWE-79",
                                    owasp_category="A07:2021 - Cross-Site Scripting",
                                    confidence=0.8,
                                )
                            )

                        self.tested_parameters.add(f"{url}#{param_name}")

        except Exception as e:
            self.logger.debug(f"Error testing XSS: {e}")

        return vulnerabilities

    async def _test_xss_payload(self, url: str, payload: str) -> bool:
        """Test if XSS payload is reflected in response."""
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    return payload in content
        except:
            pass
        return False

    async def _test_sql_injection(self, url: str) -> List[WebVulnerability]:
        """Test for SQL injection vulnerabilities."""
        vulnerabilities = []

        sql_payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "' UNION SELECT NULL--",
            "' AND (SELECT COUNT(*) FROM sysobjects) > 0--",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--",
        ]

        sql_error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"ORA-[0-9]{5}",
            r"PostgreSQL.*ERROR",
            r"Warning.*PostgreSQL",
            r"Driver.*SQL.*ERROR",
            r"SQLite.*error",
            r"sqlite3.OperationalError",
        ]

        try:
            parsed_url = urllib.parse.urlparse(url)
            if parsed_url.query:
                params = urllib.parse.parse_qs(parsed_url.query)

                for param_name, param_values in params.items():
                    for payload in sql_payloads:
                        test_params = params.copy()
                        test_params[param_name] = [payload]

                        test_url = urllib.parse.urlunparse(
                            (
                                parsed_url.scheme,
                                parsed_url.netloc,
                                parsed_url.path,
                                parsed_url.params,
                                urllib.parse.urlencode(test_params, doseq=True),
                                parsed_url.fragment,
                            )
                        )

                        if await self._test_sql_payload(test_url, sql_error_patterns):
                            vulnerabilities.append(
                                WebVulnerability(
                                    vulnerability_type=WebVulnerabilityType.SQL_INJECTION,
                                    severity=WebVulnerabilitySeverity.CRITICAL,
                                    title="SQL Injection",
                                    description=f"SQL injection vulnerability found in parameter '{param_name}'",
                                    url=url,
                                    method="GET",
                                    parameter=param_name,
                                    payload=payload,
                                    evidence="SQL error message detected in response",
                                    recommendation="Use parameterized queries and input validation",
                                    cwe_id="CWE-89",
                                    owasp_category="A03:2021 - Injection",
                                    confidence=0.9,
                                )
                            )

                        self.tested_parameters.add(f"{url}#{param_name}")

        except Exception as e:
            self.logger.debug(f"Error testing SQL injection: {e}")

        return vulnerabilities

    async def _test_sql_payload(self, url: str, error_patterns: List[str]) -> bool:
        """Test if SQL payload triggers database errors."""
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    for pattern in error_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            return True
        except:
            pass
        return False

    async def _test_directory_traversal(self, url: str) -> List[WebVulnerability]:
        """Test for directory traversal vulnerabilities."""
        vulnerabilities = []

        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "....\\\\....\\\\....\\\\windows\\system32\\drivers\\etc\\hosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        ]

        file_patterns = [
            r"root:.*:0:0:",
            r"# Copyright.*Microsoft Corp",
            r"# localhost name resolution",
        ]

        try:
            parsed_url = urllib.parse.urlparse(url)
            if parsed_url.query:
                params = urllib.parse.parse_qs(parsed_url.query)

                for param_name, param_values in params.items():
                    for payload in traversal_payloads:
                        test_params = params.copy()
                        test_params[param_name] = [payload]

                        test_url = urllib.parse.urlunparse(
                            (
                                parsed_url.scheme,
                                parsed_url.netloc,
                                parsed_url.path,
                                parsed_url.params,
                                urllib.parse.urlencode(test_params, doseq=True),
                                parsed_url.fragment,
                            )
                        )

                        if await self._test_file_inclusion(test_url, file_patterns):
                            vulnerabilities.append(
                                WebVulnerability(
                                    vulnerability_type=WebVulnerabilityType.DIRECTORY_TRAVERSAL,
                                    severity=WebVulnerabilitySeverity.HIGH,
                                    title="Directory Traversal",
                                    description=f"Directory traversal vulnerability found in parameter '{param_name}'",
                                    url=url,
                                    method="GET",
                                    parameter=param_name,
                                    payload=payload,
                                    evidence="System file content detected in response",
                                    recommendation="Implement proper input validation and file access controls",
                                    cwe_id="CWE-22",
                                    owasp_category="A01:2021 - Broken Access Control",
                                    confidence=0.9,
                                )
                            )

        except Exception as e:
            self.logger.debug(f"Error testing directory traversal: {e}")

        return vulnerabilities

    async def _test_file_inclusion(self, url: str, file_patterns: List[str]) -> bool:
        """Test if file inclusion payload reveals system files."""
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    for pattern in file_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            return True
        except:
            pass
        return False

    async def _test_command_injection(self, url: str) -> List[WebVulnerability]:
        """Test for command injection vulnerabilities."""
        vulnerabilities = []

        command_payloads = [
            "; ls -la",
            "| dir",
            "; cat /etc/passwd",
            "& whoami",
            "`id`",
            "$(whoami)",
            "; ping -c 1 127.0.0.1",
            "|| echo vulnerable",
        ]

        command_indicators = [
            r"total \d+",
            r"drwxr-xr-x",
            r"root:.*:0:0:",
            r"uid=\d+",
            r"PING.*127\.0\.0\.1",
            r"vulnerable",
        ]

        try:
            parsed_url = urllib.parse.urlparse(url)
            if parsed_url.query:
                params = urllib.parse.parse_qs(parsed_url.query)

                for param_name, param_values in params.items():
                    for payload in command_payloads:
                        test_params = params.copy()
                        test_params[param_name] = [payload]

                        test_url = urllib.parse.urlunparse(
                            (
                                parsed_url.scheme,
                                parsed_url.netloc,
                                parsed_url.path,
                                parsed_url.params,
                                urllib.parse.urlencode(test_params, doseq=True),
                                parsed_url.fragment,
                            )
                        )

                        if await self._test_command_payload(test_url, command_indicators):
                            vulnerabilities.append(
                                WebVulnerability(
                                    vulnerability_type=WebVulnerabilityType.COMMAND_INJECTION,
                                    severity=WebVulnerabilitySeverity.CRITICAL,
                                    title="Command Injection",
                                    description=f"Command injection vulnerability found in parameter '{param_name}'",
                                    url=url,
                                    method="GET",
                                    parameter=param_name,
                                    payload=payload,
                                    evidence="Command output detected in response",
                                    recommendation="Implement proper input validation and avoid system calls",
                                    cwe_id="CWE-78",
                                    owasp_category="A03:2021 - Injection",
                                    confidence=0.9,
                                )
                            )

        except Exception as e:
            self.logger.debug(f"Error testing command injection: {e}")

        return vulnerabilities

    async def _test_command_payload(self, url: str, indicators: List[str]) -> bool:
        """Test if command injection payload executes."""
        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    for indicator in indicators:
                        if re.search(indicator, content, re.IGNORECASE):
                            return True
        except:
            pass
        return False

    async def _find_forms(self, url: str) -> List[Dict[str, Any]]:
        """Find forms on a web page."""
        forms = []

        try:
            async with self.session.get(url) as response:
                if response.status == 200:
                    content = await response.text()

                    # Simple form extraction
                    form_pattern = r"<form[^>]*>(.*?)</form>"
                    form_matches = re.findall(form_pattern, content, re.IGNORECASE | re.DOTALL)

                    for match in form_matches:
                        form_info = {"content": match, "inputs": [], "action": "", "method": "GET"}

                        # Extract form attributes
                        action_match = re.search(r'action=["\'](.*?)["\']', match, re.IGNORECASE)
                        if action_match:
                            form_info["action"] = action_match.group(1)

                        method_match = re.search(r'method=["\'](.*?)["\']', match, re.IGNORECASE)
                        if method_match:
                            form_info["method"] = method_match.group(1).upper()

                        # Extract input fields
                        input_pattern = r"<input[^>]*>"
                        input_matches = re.findall(input_pattern, match, re.IGNORECASE)

                        for input_match in input_matches:
                            input_info = {"name": "", "type": "text", "value": ""}

                            name_match = re.search(
                                r'name=["\'](.*?)["\']', input_match, re.IGNORECASE
                            )
                            if name_match:
                                input_info["name"] = name_match.group(1)

                            type_match = re.search(
                                r'type=["\'](.*?)["\']', input_match, re.IGNORECASE
                            )
                            if type_match:
                                input_info["type"] = type_match.group(1)

                            value_match = re.search(
                                r'value=["\'](.*?)["\']', input_match, re.IGNORECASE
                            )
                            if value_match:
                                input_info["value"] = value_match.group(1)

                            if input_info["name"]:
                                form_info["inputs"].append(input_info)

                        forms.append(form_info)

        except Exception as e:
            self.logger.debug(f"Error finding forms: {e}")

        return forms

    async def _test_form_vulnerabilities(
        self, form: Dict[str, Any], base_url: str
    ) -> List[WebVulnerability]:
        """Test form for vulnerabilities."""
        vulnerabilities = []

        # Test each input field
        for input_field in form["inputs"]:
            if input_field["type"] in ["text", "email", "search", "url"]:
                # Test for XSS
                xss_payload = '<script>alert("XSS")</script>'
                if await self._test_form_xss(form, input_field, xss_payload, base_url):
                    vulnerabilities.append(
                        WebVulnerability(
                            vulnerability_type=WebVulnerabilityType.XSS,
                            severity=WebVulnerabilitySeverity.HIGH,
                            title="Form XSS Vulnerability",
                            description=f"XSS vulnerability found in form field '{input_field['name']}'",
                            url=base_url,
                            method=form["method"],
                            parameter=input_field["name"],
                            payload=xss_payload,
                            evidence="XSS payload reflected in form response",
                            recommendation="Implement proper input validation and output encoding",
                            cwe_id="CWE-79",
                            owasp_category="A07:2021 - Cross-Site Scripting",
                            confidence=0.8,
                        )
                    )

        return vulnerabilities

    async def _test_form_xss(
        self, form: Dict[str, Any], input_field: Dict[str, Any], payload: str, base_url: str
    ) -> bool:
        """Test form input for XSS vulnerability."""
        try:
            action_url = (
                urllib.parse.urljoin(base_url, form["action"]) if form["action"] else base_url
            )

            # Prepare form data
            form_data = {}
            for field in form["inputs"]:
                if field["name"] == input_field["name"]:
                    form_data[field["name"]] = payload
                else:
                    form_data[field["name"]] = field.get("value", "test")

            # Submit form
            if form["method"] == "POST":
                async with self.session.post(action_url, data=form_data) as response:
                    if response.status == 200:
                        content = await response.text()
                        return payload in content
            else:
                async with self.session.get(action_url, params=form_data) as response:
                    if response.status == 200:
                        content = await response.text()
                        return payload in content

        except Exception as e:
            self.logger.debug(f"Error testing form XSS: {e}")

        return False

    async def _test_security_misconfigurations(self, url: str) -> List[WebVulnerability]:
        """Test for security misconfigurations."""
        vulnerabilities = []

        try:
            async with self.session.get(url) as response:
                headers = response.headers

                # Missing security headers
                if "Strict-Transport-Security" not in headers:
                    vulnerabilities.append(
                        WebVulnerability(
                            vulnerability_type=WebVulnerabilityType.SECURITY_MISCONFIGURATION,
                            severity=WebVulnerabilitySeverity.MEDIUM,
                            title="Missing HSTS Header",
                            description="HTTP Strict Transport Security header is missing",
                            url=url,
                            method="GET",
                            parameter="",
                            payload="",
                            evidence="HSTS header not present in response",
                            recommendation="Add Strict-Transport-Security header",
                            cwe_id="CWE-16",
                            owasp_category="A05:2021 - Security Misconfiguration",
                            confidence=0.9,
                        )
                    )

                if "X-Frame-Options" not in headers and "Content-Security-Policy" not in headers:
                    vulnerabilities.append(
                        WebVulnerability(
                            vulnerability_type=WebVulnerabilityType.CLICKJACKING,
                            severity=WebVulnerabilitySeverity.MEDIUM,
                            title="Missing Clickjacking Protection",
                            description="X-Frame-Options and CSP frame-ancestors not configured",
                            url=url,
                            method="GET",
                            parameter="",
                            payload="",
                            evidence="No clickjacking protection headers found",
                            recommendation="Add X-Frame-Options or CSP frame-ancestors directive",
                            cwe_id="CWE-1021",
                            owasp_category="A05:2021 - Security Misconfiguration",
                            confidence=0.8,
                        )
                    )

                if "X-Content-Type-Options" not in headers:
                    vulnerabilities.append(
                        WebVulnerability(
                            vulnerability_type=WebVulnerabilityType.SECURITY_MISCONFIGURATION,
                            severity=WebVulnerabilitySeverity.LOW,
                            title="Missing X-Content-Type-Options",
                            description="X-Content-Type-Options header is missing",
                            url=url,
                            method="GET",
                            parameter="",
                            payload="",
                            evidence="X-Content-Type-Options header not present",
                            recommendation="Add X-Content-Type-Options: nosniff header",
                            cwe_id="CWE-16",
                            owasp_category="A05:2021 - Security Misconfiguration",
                            confidence=0.7,
                        )
                    )

        except Exception as e:
            self.logger.debug(f"Error testing security misconfigurations: {e}")

        return vulnerabilities

    async def _test_information_disclosure(self, url: str) -> List[WebVulnerability]:
        """Test for information disclosure vulnerabilities."""
        vulnerabilities = []

        # Test for common disclosure endpoints
        disclosure_paths = [
            "/.git/config",
            "/.env",
            "/wp-config.php",
            "/config.php",
            "/phpinfo.php",
            "/info.php",
            "/server-info",
            "/server-status",
            "/robots.txt",
            "/sitemap.xml",
            "/backup.sql",
            "/database.sql",
        ]

        base_url = urllib.parse.urljoin(url, "/")

        for path in disclosure_paths:
            try:
                test_url = urllib.parse.urljoin(base_url, path)
                async with self.session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()

                        # Check for sensitive information
                        if self._contains_sensitive_info(content, path):
                            vulnerabilities.append(
                                WebVulnerability(
                                    vulnerability_type=WebVulnerabilityType.INFORMATION_DISCLOSURE,
                                    severity=WebVulnerabilitySeverity.MEDIUM,
                                    title="Information Disclosure",
                                    description=f"Sensitive information exposed at {path}",
                                    url=test_url,
                                    method="GET",
                                    parameter="",
                                    payload="",
                                    evidence=f"Sensitive file accessible: {path}",
                                    recommendation="Remove or restrict access to sensitive files",
                                    cwe_id="CWE-200",
                                    owasp_category="A01:2021 - Broken Access Control",
                                    confidence=0.9,
                                )
                            )

            except Exception as e:
                self.logger.debug(f"Error testing {path}: {e}")

        return vulnerabilities

    def _contains_sensitive_info(self, content: str, path: str) -> bool:
        """Check if content contains sensitive information."""
        sensitive_patterns = {
            ".git/config": [r"\[core\]", r"repositoryformatversion"],
            ".env": [r"DB_PASSWORD", r"API_KEY", r"SECRET"],
            "wp-config.php": [r"DB_PASSWORD", r"define\(", r"wp_"],
            "config.php": [r"password", r"database", r"mysqli"],
            "phpinfo.php": [r"PHP Version", r"System", r"phpinfo\(\)"],
            "info.php": [r"PHP Version", r"System", r"phpinfo\(\)"],
            "server-info": [r"Server Information", r"Apache"],
            "server-status": [r"Server Status", r"Apache"],
            "backup.sql": [r"CREATE TABLE", r"INSERT INTO", r"DROP TABLE"],
            "database.sql": [r"CREATE TABLE", r"INSERT INTO", r"DROP TABLE"],
        }

        patterns = sensitive_patterns.get(path.lstrip("/"), [])

        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True

        return False

    async def get_web_scan_statistics(self, results: List[WebScanResult]) -> Dict[str, Any]:
        """Get web scanning statistics."""
        total_vulns = sum(len(result.vulnerabilities) for result in results)

        stats = {
            "total_scans": len(results),
            "total_vulnerabilities": total_vulns,
            "vulnerability_types": {},
            "severity_distribution": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "average_scan_time": 0,
            "total_pages_scanned": sum(result.pages_scanned for result in results),
            "total_forms_found": sum(result.forms_found for result in results),
            "common_technologies": {},
            "security_headers_adoption": {},
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Calculate statistics
        total_scan_time = sum(result.scan_duration for result in results)
        if results:
            stats["average_scan_time"] = total_scan_time / len(results)

        for result in results:
            # Vulnerability statistics
            for vuln in result.vulnerabilities:
                vuln_type = vuln.vulnerability_type
                stats["vulnerability_types"][vuln_type] = (
                    stats["vulnerability_types"].get(vuln_type, 0) + 1
                )
                stats["severity_distribution"][vuln.severity] += 1

            # Technology statistics
            for tech in result.technologies_detected:
                stats["common_technologies"][tech] = stats["common_technologies"].get(tech, 0) + 1

            # Security headers statistics
            for header in result.security_headers:
                stats["security_headers_adoption"][header] = (
                    stats["security_headers_adoption"].get(header, 0) + 1
                )

        return stats
