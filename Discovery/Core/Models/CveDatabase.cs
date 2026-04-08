using System;
using System.Collections.Generic;
using System.Linq;

namespace Discovery.Core.Models
{
    /// <summary>
    /// Represents a CVE (Common Vulnerabilities and Exposures) entry
    /// </summary>
    public class CveEntry
    {
        /// <summary>
        /// Gets or sets the CVE identifier
        /// </summary>
        public string Id { get; set; } = "";
        
        /// <summary>
        /// Gets or sets the vulnerability title
        /// </summary>
        public string Title { get; set; } = "";
        
        /// <summary>
        /// Gets or sets the detailed description
        /// </summary>
        public string Description { get; set; } = "";
        
        /// <summary>
        /// Gets or sets the CVSS score (0.0-10.0)
        /// </summary>
        public float CvssScore { get; set; }
        
        /// <summary>
        /// Gets or sets the vulnerability severity level
        /// </summary>
        public VulnerabilitySeverity Severity { get; set; }
        
        /// <summary>
        /// Gets or sets the publication date
        /// </summary>
        public DateTime PublishedDate { get; set; }
        
        /// <summary>
        /// Gets or sets the affected products/services
        /// </summary>
        public string[] AffectedProducts { get; set; } = Array.Empty<string>();
        
        /// <summary>
        /// Gets or sets the affected versions
        /// </summary>
        public string[] AffectedVersions { get; set; } = Array.Empty<string>();
        
        /// <summary>
        /// Gets or sets reference URLs
        /// </summary>
        public string[] References { get; set; } = Array.Empty<string>();
        
        /// <summary>
        /// Gets or sets classification tags
        /// </summary>
        public string[] Tags { get; set; } = Array.Empty<string>();
        
        /// <summary>
        /// Gets or sets the recommended fix/mitigation
        /// </summary>
        public string RecommendedFix { get; set; } = "";
        
        /// <summary>
        /// Gets or sets whether this CVE is actively exploited in the wild
        /// </summary>
        public bool IsActivelExploited { get; set; }
        
        /// <summary>
        /// Gets or sets the exploit complexity level
        /// </summary>
        public string ExploitComplexity { get; set; } = "Unknown";
    }

    /// <summary>
    /// In-memory CVE database for vulnerability matching
    /// </summary>
    public static class CveDatabase
    {
        private static readonly Dictionary<string, List<CveEntry>> _serviceVulnerabilities = new();
        private static readonly Dictionary<string, CveEntry> _cveEntries = new();

        static CveDatabase()
        {
            InitializeDatabase();
        }

        private static void InitializeDatabase()
        {
            // Critical SMB vulnerabilities
            AddCve(new CveEntry
            {
                Id = "CVE-2017-0144",
                Title = "EternalBlue - SMB Remote Code Execution",
                Description = "Microsoft SMBv1 server allows remote code execution via crafted packets",
                CvssScore = 8.1f,
                Severity = VulnerabilitySeverity.Critical,
                PublishedDate = new DateTime(2017, 3, 14),
                AffectedProducts = new[] { "SMB", "Windows SMB", "Samba" },
                AffectedVersions = new[] { "Windows 7", "Windows 8", "Windows 10", "Windows Server 2008", "Windows Server 2012", "Windows Server 2016" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2017-0144", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
                Tags = new[] { "SMB", "RCE", "Wormable", "NSA" },
                RecommendedFix = "Apply MS17-010 security update, disable SMBv1, enable SMB signing",
                IsActivelExploited = true,
                ExploitComplexity = "Low"
            });

            AddCve(new CveEntry
            {
                Id = "CVE-2017-0145",
                Title = "EternalBlue - SMB Remote Code Execution (Variant)",
                Description = "Additional EternalBlue variant affecting SMB implementations",
                CvssScore = 8.1f,
                Severity = VulnerabilitySeverity.Critical,
                PublishedDate = new DateTime(2017, 3, 14),
                AffectedProducts = new[] { "SMB", "Windows SMB" },
                AffectedVersions = new[] { "Windows Vista", "Windows 7", "Windows 8", "Windows 10" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2017-0145" },
                Tags = new[] { "SMB", "RCE", "EternalBlue" },
                RecommendedFix = "Apply MS17-010 security update, disable SMBv1",
                IsActivelExploited = true,
                ExploitComplexity = "Low"
            });

            // RDP vulnerabilities
            AddCve(new CveEntry
            {
                Id = "CVE-2019-0708",
                Title = "BlueKeep - RDP Remote Code Execution",
                Description = "Remote Desktop Services remote code execution vulnerability",
                CvssScore = 9.8f,
                Severity = VulnerabilitySeverity.Critical,
                PublishedDate = new DateTime(2019, 5, 14),
                AffectedProducts = new[] { "RDP", "Remote Desktop Protocol", "Terminal Services" },
                AffectedVersions = new[] { "Windows 7", "Windows Server 2008", "Windows Server 2008 R2", "Windows XP", "Windows Server 2003" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2019-0708", "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708" },
                Tags = new[] { "RDP", "RCE", "Wormable", "BlueKeep" },
                RecommendedFix = "Apply security updates, enable Network Level Authentication, restrict RDP access",
                IsActivelExploited = true,
                ExploitComplexity = "Medium"
            });

            AddCve(new CveEntry
            {
                Id = "CVE-2019-1181",
                Title = "DejaBlue - RDP Remote Code Execution",
                Description = "Remote Desktop Protocol (RDP) remote code execution vulnerability",
                CvssScore = 8.8f,
                Severity = VulnerabilitySeverity.Critical,
                PublishedDate = new DateTime(2019, 8, 13),
                AffectedProducts = new[] { "RDP", "Remote Desktop Protocol" },
                AffectedVersions = new[] { "Windows 7", "Windows 8.1", "Windows 10", "Windows Server 2008", "Windows Server 2012", "Windows Server 2016", "Windows Server 2019" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2019-1181" },
                Tags = new[] { "RDP", "RCE", "DejaBlue" },
                RecommendedFix = "Apply August 2019 security updates, enable Network Level Authentication",
                IsActivelExploited = false,
                ExploitComplexity = "High"
            });

            // SSH vulnerabilities
            AddCve(new CveEntry
            {
                Id = "CVE-2020-14145",
                Title = "OpenSSH Information Disclosure",
                Description = "Observable discrepancy in OpenSSH allowing user enumeration",
                CvssScore = 5.3f,
                Severity = VulnerabilitySeverity.Medium,
                PublishedDate = new DateTime(2020, 6, 29),
                AffectedProducts = new[] { "SSH", "OpenSSH" },
                AffectedVersions = new[] { "OpenSSH < 8.3" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2020-14145" },
                Tags = new[] { "SSH", "Information Disclosure", "User Enumeration" },
                RecommendedFix = "Update OpenSSH to version 8.3 or later",
                IsActivelExploited = false,
                ExploitComplexity = "Low"
            });

            AddCve(new CveEntry
            {
                Id = "CVE-2021-41617",
                Title = "OpenSSH Privilege Escalation",
                Description = "sshd in OpenSSH allows privilege escalation via supplemental groups",
                CvssScore = 7.0f,
                Severity = VulnerabilitySeverity.High,
                PublishedDate = new DateTime(2021, 9, 26),
                AffectedProducts = new[] { "SSH", "OpenSSH" },
                AffectedVersions = new[] { "OpenSSH 6.2 - 8.7" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2021-41617" },
                Tags = new[] { "SSH", "Privilege Escalation" },
                RecommendedFix = "Update OpenSSH to version 8.8 or later",
                IsActivelExploited = false,
                ExploitComplexity = "Medium"
            });

            // HTTP/Web Server vulnerabilities
            AddCve(new CveEntry
            {
                Id = "CVE-2021-44228",
                Title = "Log4Shell - Apache Log4j Remote Code Execution",
                Description = "JNDI features in Apache Log4j allow remote code execution",
                CvssScore = 10.0f,
                Severity = VulnerabilitySeverity.Critical,
                PublishedDate = new DateTime(2021, 12, 9),
                AffectedProducts = new[] { "Apache Log4j", "Java Applications", "HTTP", "HTTPS" },
                AffectedVersions = new[] { "Log4j 2.0-beta9 - 2.14.1" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog" },
                Tags = new[] { "Log4j", "RCE", "JNDI", "Java", "Log4Shell" },
                RecommendedFix = "Update Log4j to version 2.17.1 or later, remove JndiLookup class",
                IsActivelExploited = true,
                ExploitComplexity = "Low"
            });

            AddCve(new CveEntry
            {
                Id = "CVE-2021-45046",
                Title = "Log4Shell - Apache Log4j DoS and Information Disclosure",
                Description = "Incomplete fix for CVE-2021-44228 in Apache Log4j",
                CvssScore = 9.0f,
                Severity = VulnerabilitySeverity.Critical,
                PublishedDate = new DateTime(2021, 12, 14),
                AffectedProducts = new[] { "Apache Log4j", "Java Applications" },
                AffectedVersions = new[] { "Log4j 2.15.0" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2021-45046" },
                Tags = new[] { "Log4j", "DoS", "Information Disclosure" },
                RecommendedFix = "Update Log4j to version 2.17.1 or later",
                IsActivelExploited = true,
                ExploitComplexity = "Low"
            });

            // Database vulnerabilities
            AddCve(new CveEntry
            {
                Id = "CVE-2023-32315",
                Title = "OpenFire Authentication Bypass",
                Description = "Path traversal in Openfire's admin console",
                CvssScore = 9.8f,
                Severity = VulnerabilitySeverity.Critical,
                PublishedDate = new DateTime(2023, 5, 26),
                AffectedProducts = new[] { "Openfire", "XMPP" },
                AffectedVersions = new[] { "Openfire < 4.7.5", "Openfire < 4.6.8" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2023-32315" },
                Tags = new[] { "Authentication Bypass", "Path Traversal", "XMPP" },
                RecommendedFix = "Update Openfire to latest version, restrict admin console access",
                IsActivelExploited = true,
                ExploitComplexity = "Low"
            });

            // Docker/Container vulnerabilities
            AddCve(new CveEntry
            {
                Id = "CVE-2019-5736",
                Title = "RunC Container Escape",
                Description = "runc container runtime allows privilege escalation and container escape",
                CvssScore = 8.6f,
                Severity = VulnerabilitySeverity.High,
                PublishedDate = new DateTime(2019, 2, 11),
                AffectedProducts = new[] { "Docker", "RunC", "Container Runtime" },
                AffectedVersions = new[] { "runc < 1.0-rc6", "Docker < 18.09.2" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2019-5736" },
                Tags = new[] { "Container Escape", "Privilege Escalation", "Docker" },
                RecommendedFix = "Update Docker and runc to latest versions, use user namespaces",
                IsActivelExploited = true,
                ExploitComplexity = "Medium"
            });

            // DNS vulnerabilities
            AddCve(new CveEntry
            {
                Id = "CVE-2020-1350",
                Title = "SIGRed - Windows DNS Server RCE",
                Description = "Windows DNS Server remote code execution vulnerability",
                CvssScore = 10.0f,
                Severity = VulnerabilitySeverity.Critical,
                PublishedDate = new DateTime(2020, 7, 14),
                AffectedProducts = new[] { "DNS", "Windows DNS Server" },
                AffectedVersions = new[] { "Windows Server 2008", "Windows Server 2012", "Windows Server 2016", "Windows Server 2019" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2020-1350" },
                Tags = new[] { "DNS", "RCE", "SIGRed", "Wormable" },
                RecommendedFix = "Apply July 2020 security updates, configure DNS forwarders carefully",
                IsActivelExploited = false,
                ExploitComplexity = "Medium"
            });

            // Modern vulnerabilities (2024-2025)
            AddCve(new CveEntry
            {
                Id = "CVE-2024-3094",
                Title = "XZ Utils Backdoor",
                Description = "Malicious backdoor in XZ Utils compression library",
                CvssScore = 10.0f,
                Severity = VulnerabilitySeverity.Critical,
                PublishedDate = new DateTime(2024, 3, 29),
                AffectedProducts = new[] { "XZ Utils", "SSH", "Linux Systems" },
                AffectedVersions = new[] { "XZ Utils 5.6.0", "XZ Utils 5.6.1" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2024-3094" },
                Tags = new[] { "Supply Chain", "Backdoor", "SSH", "Compression" },
                RecommendedFix = "Downgrade XZ Utils to 5.4.x, audit system integrity",
                IsActivelExploited = true,
                ExploitComplexity = "Low"
            });

            AddCve(new CveEntry
            {
                Id = "CVE-2024-21413",
                Title = "Microsoft Outlook Privilege Escalation",
                Description = "Microsoft Outlook Security Feature Bypass Vulnerability",
                CvssScore = 9.8f,
                Severity = VulnerabilitySeverity.Critical,
                PublishedDate = new DateTime(2024, 2, 13),
                AffectedProducts = new[] { "Microsoft Outlook", "NTLM", "HTTP" },
                AffectedVersions = new[] { "Microsoft Outlook 2016", "Microsoft Outlook 2019", "Microsoft 365 Apps" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2024-21413" },
                Tags = new[] { "NTLM Relay", "Privilege Escalation", "Outlook" },
                RecommendedFix = "Apply February 2024 security updates, configure NTLM hardening",
                IsActivelExploited = true,
                ExploitComplexity = "Low"
            });

            // Industrial/IoT vulnerabilities
            AddCve(new CveEntry
            {
                Id = "CVE-2022-22965",
                Title = "Spring4Shell - Spring Framework RCE",
                Description = "Remote Code Execution in Spring Framework via data binding",
                CvssScore = 9.8f,
                Severity = VulnerabilitySeverity.Critical,
                PublishedDate = new DateTime(2022, 3, 31),
                AffectedProducts = new[] { "Spring Framework", "Java Applications", "HTTP", "HTTPS" },
                AffectedVersions = new[] { "Spring Framework 5.3.0 - 5.3.17", "Spring Framework 5.2.0 - 5.2.19" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2022-22965" },
                Tags = new[] { "Spring", "RCE", "Java", "Web Application" },
                RecommendedFix = "Update Spring Framework to 5.3.18+ or 5.2.20+",
                IsActivelExploited = true,
                ExploitComplexity = "Low"
            });

            // Add more CVEs for various services...
            AddWebServerCves();
            AddDatabaseCves();
            AddNetworkServiceCves();
            AddIoTIndustrialCves();
        }

        private static void AddWebServerCves()
        {
            // Apache HTTP Server
            AddCve(new CveEntry
            {
                Id = "CVE-2021-41773",
                Title = "Apache HTTP Server Path Traversal",
                Description = "Path traversal and file disclosure vulnerability in Apache HTTP Server",
                CvssScore = 7.5f,
                Severity = VulnerabilitySeverity.High,
                PublishedDate = new DateTime(2021, 10, 4),
                AffectedProducts = new[] { "Apache HTTP Server", "HTTP", "HTTPS" },
                AffectedVersions = new[] { "Apache HTTP Server 2.4.49" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2021-41773" },
                Tags = new[] { "Path Traversal", "File Disclosure", "Apache" },
                RecommendedFix = "Update Apache HTTP Server to 2.4.50 or later",
                IsActivelExploited = true,
                ExploitComplexity = "Low"
            });

            // Nginx
            AddCve(new CveEntry
            {
                Id = "CVE-2021-23017",
                Title = "Nginx DNS Resolver Off-by-One",
                Description = "Off-by-one buffer overflow in nginx DNS resolver",
                CvssScore = 8.1f,
                Severity = VulnerabilitySeverity.High,
                PublishedDate = new DateTime(2021, 5, 25),
                AffectedProducts = new[] { "Nginx", "HTTP", "HTTPS" },
                AffectedVersions = new[] { "nginx 0.6.18 - 1.20.0" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2021-23017" },
                Tags = new[] { "Buffer Overflow", "DNS", "Nginx" },
                RecommendedFix = "Update nginx to version 1.20.1 or later",
                IsActivelExploited = false,
                ExploitComplexity = "High"
            });
        }

        private static void AddDatabaseCves()
        {
            // MongoDB
            AddCve(new CveEntry
            {
                Id = "CVE-2020-7928",
                Title = "MongoDB Server-Side JavaScript Injection",
                Description = "MongoDB server-side JavaScript injection vulnerability",
                CvssScore = 8.8f,
                Severity = VulnerabilitySeverity.High,
                PublishedDate = new DateTime(2020, 2, 13),
                AffectedProducts = new[] { "MongoDB", "Database" },
                AffectedVersions = new[] { "MongoDB < 4.2.3", "MongoDB < 4.0.16", "MongoDB < 3.6.17" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2020-7928" },
                Tags = new[] { "JavaScript Injection", "Database", "MongoDB" },
                RecommendedFix = "Update MongoDB to latest stable version, disable server-side JavaScript",
                IsActivelExploited = false,
                ExploitComplexity = "Medium"
            });

            // MySQL
            AddCve(new CveEntry
            {
                Id = "CVE-2023-21980",
                Title = "MySQL Server Privilege Escalation",
                Description = "Privilege escalation vulnerability in MySQL Server",
                CvssScore = 6.5f,
                Severity = VulnerabilitySeverity.Medium,
                PublishedDate = new DateTime(2023, 4, 18),
                AffectedProducts = new[] { "MySQL", "Database" },
                AffectedVersions = new[] { "MySQL Server 8.0.32 and prior", "MySQL Server 5.7.41 and prior" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2023-21980" },
                Tags = new[] { "Privilege Escalation", "Database", "MySQL" },
                RecommendedFix = "Update MySQL to latest version, review user privileges",
                IsActivelExploited = false,
                ExploitComplexity = "Low"
            });

            // Redis
            AddCve(new CveEntry
            {
                Id = "CVE-2022-0543",
                Title = "Redis Lua Sandbox Escape",
                Description = "Lua sandbox escape in Redis allowing code execution",
                CvssScore = 10.0f,
                Severity = VulnerabilitySeverity.Critical,
                PublishedDate = new DateTime(2022, 2, 18),
                AffectedProducts = new[] { "Redis", "Database", "Cache" },
                AffectedVersions = new[] { "Redis 5.0 - 7.0" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2022-0543" },
                Tags = new[] { "Sandbox Escape", "Code Execution", "Redis", "Lua" },
                RecommendedFix = "Update Redis, disable Lua scripting if not needed",
                IsActivelExploited = true,
                ExploitComplexity = "Low"
            });
        }

        private static void AddNetworkServiceCves()
        {
            // FTP
            AddCve(new CveEntry
            {
                Id = "CVE-2020-15778",
                Title = "OpenSSH SCP Client Code Injection",
                Description = "scp client code injection vulnerability",
                CvssScore = 7.8f,
                Severity = VulnerabilitySeverity.High,
                PublishedDate = new DateTime(2020, 7, 24),
                AffectedProducts = new[] { "OpenSSH", "SCP", "SSH" },
                AffectedVersions = new[] { "OpenSSH < 8.4" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2020-15778" },
                Tags = new[] { "Code Injection", "SCP", "SSH" },
                RecommendedFix = "Update OpenSSH to 8.4 or later, use sftp instead of scp",
                IsActivelExploited = false,
                ExploitComplexity = "Medium"
            });

            // SNMP
            AddCve(new CveEntry
            {
                Id = "CVE-2021-34749",
                Title = "Net-SNMP Buffer Overflow",
                Description = "Buffer overflow in Net-SNMP daemon",
                CvssScore = 9.8f,
                Severity = VulnerabilitySeverity.Critical,
                PublishedDate = new DateTime(2021, 8, 20),
                AffectedProducts = new[] { "Net-SNMP", "SNMP" },
                AffectedVersions = new[] { "Net-SNMP < 5.9.2" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2021-34749" },
                Tags = new[] { "Buffer Overflow", "SNMP", "RCE" },
                RecommendedFix = "Update Net-SNMP to 5.9.2 or later, use SNMPv3",
                IsActivelExploited = false,
                ExploitComplexity = "Low"
            });
        }

        private static void AddIoTIndustrialCves()
        {
            // Modbus
            AddCve(new CveEntry
            {
                Id = "CVE-2020-12493",
                Title = "Modbus TCP Stack Buffer Overflow",
                Description = "Buffer overflow in Modbus TCP implementation",
                CvssScore = 9.8f,
                Severity = VulnerabilitySeverity.Critical,
                PublishedDate = new DateTime(2020, 6, 11),
                AffectedProducts = new[] { "Modbus", "Industrial Control", "SCADA" },
                AffectedVersions = new[] { "Various Modbus implementations" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2020-12493" },
                Tags = new[] { "Buffer Overflow", "Modbus", "Industrial", "SCADA" },
                RecommendedFix = "Update Modbus stack, implement network segmentation",
                IsActivelExploited = false,
                ExploitComplexity = "Medium"
            });

            // OPC-UA
            AddCve(new CveEntry
            {
                Id = "CVE-2022-29862",
                Title = "OPC UA .NET Stack Information Disclosure",
                Description = "Information disclosure vulnerability in OPC UA .NET Stack",
                CvssScore = 7.5f,
                Severity = VulnerabilitySeverity.High,
                PublishedDate = new DateTime(2022, 5, 10),
                AffectedProducts = new[] { "OPC-UA", "Industrial Automation", ".NET" },
                AffectedVersions = new[] { "OPC UA .NET Stack < 1.4.368.58" },
                References = new[] { "https://nvd.nist.gov/vuln/detail/CVE-2022-29862" },
                Tags = new[] { "Information Disclosure", "OPC-UA", "Industrial" },
                RecommendedFix = "Update OPC UA .NET Stack, enable security policies",
                IsActivelExploited = false,
                ExploitComplexity = "Low"
            });
        }

        private static void AddCve(CveEntry cve)
        {
            _cveEntries[cve.Id] = cve;
            
            foreach (var product in cve.AffectedProducts)
            {
                var key = product.ToLowerInvariant();
                if (!_serviceVulnerabilities.ContainsKey(key))
                {
                    _serviceVulnerabilities[key] = new List<CveEntry>();
                }
                _serviceVulnerabilities[key].Add(cve);
            }
        }

        /// <summary>
        /// Get vulnerabilities for a specific service
        /// </summary>
        public static List<CveEntry> GetVulnerabilitiesForService(string serviceName)
        {
            var key = serviceName.ToLowerInvariant();
            return _serviceVulnerabilities.GetValueOrDefault(key, new List<CveEntry>());
        }

        /// <summary>
        /// Get CVE entry by ID
        /// </summary>
        public static CveEntry? GetCveById(string cveId)
        {
            return _cveEntries.GetValueOrDefault(cveId);
        }

        /// <summary>
        /// Search CVEs by tags
        /// </summary>
        public static List<CveEntry> SearchByTags(params string[] tags)
        {
            return _cveEntries.Values
                .Where(cve => tags.Any(tag => cve.Tags.Contains(tag, StringComparer.OrdinalIgnoreCase)))
                .ToList();
        }

        /// <summary>
        /// Get all CVEs with active exploitation
        /// </summary>
        public static List<CveEntry> GetActivelyExploitedCves()
        {
            return _cveEntries.Values.Where(cve => cve.IsActivelExploited).ToList();
        }

        /// <summary>
        /// Get critical severity CVEs
        /// </summary>
        public static List<CveEntry> GetCriticalCves()
        {
            return _cveEntries.Values.Where(cve => cve.Severity == VulnerabilitySeverity.Critical).ToList();
        }

        /// <summary>
        /// Get CVEs published after a specific date
        /// </summary>
        public static List<CveEntry> GetRecentCves(DateTime sinceDate)
        {
            return _cveEntries.Values.Where(cve => cve.PublishedDate >= sinceDate).ToList();
        }
    }
}
