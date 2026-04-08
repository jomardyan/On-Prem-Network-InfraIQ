using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Discovery.Core.Interfaces;
using Discovery.Core.Models;
using Discovery.Security;
using Discovery.Services.Security.Specialized;
using Spectre.Console;

namespace Discovery.Services.Security
{
    /// <summary>
    /// Comprehensive security scanner that integrates all vulnerability detection capabilities
    /// </summary>
    public class ComprehensiveSecurityScanner
    {
        private readonly AdvancedVulnerabilityScanner _advancedScanner;
        private readonly HttpVulnerabilityScanner _httpScanner;
        private readonly SshVulnerabilityScanner _sshScanner;
        private readonly SmbVulnerabilityScanner _smbScanner;
        private readonly Specialized.DatabaseVulnerabilityScanner _databaseScanner;

        /// <summary>
        /// Initializes a new instance of the ComprehensiveSecurityScanner class
        /// </summary>
        /// <param name="portScanner">Port scanner interface</param>
        public ComprehensiveSecurityScanner(IScanner portScanner)
        {
            _advancedScanner = new AdvancedVulnerabilityScanner(portScanner);
            _httpScanner = new HttpVulnerabilityScanner();
            _sshScanner = new SshVulnerabilityScanner();
            _smbScanner = new SmbVulnerabilityScanner();
            _databaseScanner = new Specialized.DatabaseVulnerabilityScanner();
        }

        /// <summary>
        /// Performs comprehensive security assessment of a target
        /// </summary>
        /// <param name="target">Target IP address</param>
        /// <param name="scanResults">Initial scan results with open ports</param>
        /// <returns>Comprehensive security assessment</returns>
        public async Task<SecurityAssessmentReport> PerformSecurityAssessmentAsync(IPAddress target, IEnumerable<ScanResult> scanResults)
        {
            var report = new SecurityAssessmentReport
            {
                Target = target.ToString(),
                ScanStartTime = DateTime.UtcNow
            };

            try
            {
                var results = scanResults.ToList();
                var openPorts = results.Where(r => r.IsOpen).Select(r => r.Port).ToList();

                AnsiConsole.MarkupLine($"[yellow]🔍 Starting comprehensive security assessment for {target}[/]");

                // Honeypot detection first (to avoid scanning honeypots)
                var honeypotAnalysis = HoneypotDetector.AnalyzePotentialHoneypot(target, results);
                report.HoneypotAnalysis = honeypotAnalysis;

                if (honeypotAnalysis.ThreatLevel == ThreatLevel.High)
                {
                    AnsiConsole.MarkupLine($"[red]⚠️ HIGH HONEYPOT RISK DETECTED - Skipping detailed scanning[/]");
                    report.ScanEndTime = DateTime.UtcNow;
                    return report;
                }

                // Use advanced vulnerability scanner for comprehensive checks
                var advancedReport = await _advancedScanner.ScanHostAsync(target.ToString(), CancellationToken.None);
                
                // Web vulnerability scanning
                var webVulns = await ScanWebVulnerabilitiesAsync(target, openPorts);
                
                // Database vulnerability scanning
                var dbVulns = await ScanDatabaseVulnerabilitiesAsync(target, openPorts);
                
                // Infrastructure vulnerability scanning
                var infraVulns = await ScanInfrastructureVulnerabilitiesAsync(target, openPorts);

                // Convert advanced vulnerabilities to report format
                foreach (var vuln in advancedReport.Vulnerabilities)
                {
                    // Categorize vulnerabilities based on service type
                    if (IsWebService(vuln.Port))
                    {
                        report.WebVulnerabilities.Add(ConvertToWebVulnerability(vuln));
                    }
                    else if (IsDatabaseService(vuln.Port, vuln.ServiceName))
                    {
                        report.DatabaseVulnerabilities.Add(ConvertToDatabaseVulnerability(vuln));
                    }
                    else
                    {
                        report.InfrastructureVulnerabilities.Add(ConvertToInfrastructureVulnerability(vuln));
                    }
                }
                
                // Add specialized scan results
                report.WebVulnerabilities.AddRange(webVulns);
                report.DatabaseVulnerabilities.AddRange(dbVulns);
                report.InfrastructureVulnerabilities.AddRange(infraVulns);

                // Generate overall security rating
                report.SecurityRating = CalculateSecurityRating(report);
                report.ScanEndTime = DateTime.UtcNow;

                // Display summary
                DisplaySecuritySummary(report);

                return report;
            }
            catch (Exception ex)
            {
                AnsiConsole.MarkupLine($"[red]❌ Error during security assessment: {ex.Message}[/]");
                report.ScanEndTime = DateTime.UtcNow;
                report.Errors.Add($"Security assessment error: {ex.Message}");
                return report;
            }
        }

        /// <summary>
        /// Scans for web vulnerabilities on discovered web services
        /// </summary>
        /// <param name="target">Target IP address</param>
        /// <param name="openPorts">List of open ports</param>
        /// <returns>Collection of web vulnerabilities</returns>
        private async Task<IEnumerable<WebVulnerability>> ScanWebVulnerabilitiesAsync(IPAddress target, List<int> openPorts)
        {
            var webVulnerabilities = new List<WebVulnerability>();
            var webPorts = openPorts.Where(p => IsWebService(p)).ToList();

            if (webPorts.Any())
            {
                AnsiConsole.MarkupLine($"[blue]🌐 Scanning web services on ports: {string.Join(", ", webPorts)}[/]");
                
                foreach (var port in webPorts)
                {
                    try
                    {
                        var isHttps = port == 443 || port == 8443;
                        var vulns = await _httpScanner.ScanAsync(target.ToString(), port, isHttps, CancellationToken.None);
                        
                        // Convert VulnerabilityInfo to WebVulnerability
                        foreach (var vuln in vulns)
                        {
                            webVulnerabilities.Add(ConvertToWebVulnerability(vuln));
                        }
                    }
                    catch (Exception ex)
                    {
                        AnsiConsole.MarkupLine($"[yellow]⚠️ Web scan error on port {port}: {ex.Message}[/]");
                    }
                }
            }

            return webVulnerabilities;
        }

        /// <summary>
        /// Scans for database vulnerabilities
        /// </summary>
        /// <param name="target">Target IP address</param>
        /// <param name="openPorts">List of open ports</param>
        /// <returns>Collection of database vulnerabilities</returns>
        private async Task<IEnumerable<DatabaseVulnerability>> ScanDatabaseVulnerabilitiesAsync(IPAddress target, List<int> openPorts)
        {
            var dbVulnerabilities = new List<DatabaseVulnerability>();
            var dbPorts = openPorts.Where(p => IsDatabaseService(p, "")).ToList();

            if (dbPorts.Any())
            {
                AnsiConsole.MarkupLine($"[blue]🗄️ Scanning database services on ports: {string.Join(", ", dbPorts)}[/]");
                
                foreach (var port in dbPorts)
                {
                    try
                    {
                        var dbType = GetDatabaseType(port);
                        var vulns = await _databaseScanner.ScanAsync(target.ToString(), port, dbType, CancellationToken.None);
                        
                        // Convert VulnerabilityInfo to DatabaseVulnerability
                        foreach (var vuln in vulns)
                        {
                            dbVulnerabilities.Add(ConvertToDatabaseVulnerability(vuln));
                        }
                    }
                    catch (Exception ex)
                    {
                        AnsiConsole.MarkupLine($"[yellow]⚠️ Database scan error on port {port}: {ex.Message}[/]");
                    }
                }
            }

            return dbVulnerabilities;
        }

        /// <summary>
        /// Scans for infrastructure vulnerabilities
        /// </summary>
        /// <param name="target">Target IP address</param>
        /// <param name="openPorts">List of open ports</param>
        /// <returns>Collection of infrastructure vulnerabilities</returns>
        private async Task<IEnumerable<InfrastructureVulnerability>> ScanInfrastructureVulnerabilitiesAsync(IPAddress target, List<int> openPorts)
        {
            var infraVulnerabilities = new List<InfrastructureVulnerability>();

            // SSH scanning
            var sshPorts = openPorts.Where(p => p == 22 || p == 2222).ToList();
            foreach (var port in sshPorts)
            {
                try
                {
                    var vulns = await _sshScanner.ScanAsync(target.ToString(), port, CancellationToken.None);
                    foreach (var vuln in vulns)
                    {
                        infraVulnerabilities.Add(ConvertToInfrastructureVulnerability(vuln));
                    }
                }
                catch (Exception ex)
                {
                    AnsiConsole.MarkupLine($"[yellow]⚠️ SSH scan error on port {port}: {ex.Message}[/]");
                }
            }

            // SMB scanning
            var smbPorts = openPorts.Where(p => p == 445 || p == 139).ToList();
            foreach (var port in smbPorts)
            {
                try
                {
                    var vulns = await _smbScanner.ScanAsync(target.ToString(), port, CancellationToken.None);
                    foreach (var vuln in vulns)
                    {
                        infraVulnerabilities.Add(ConvertToInfrastructureVulnerability(vuln));
                    }
                }
                catch (Exception ex)
                {
                    AnsiConsole.MarkupLine($"[yellow]⚠️ SMB scan error on port {port}: {ex.Message}[/]");
                }
            }

            return infraVulnerabilities;
        }

        /// <summary>
        /// Calculates overall security rating based on found vulnerabilities
        /// </summary>
        /// <param name="report">Security assessment report</param>
        /// <returns>Security rating</returns>
        private SecurityRating CalculateSecurityRating(SecurityAssessmentReport report)
        {
            var criticalCount = 0;
            var highCount = 0;
            var mediumCount = 0;
            var lowCount = 0;

            // Count web vulnerabilities
            foreach (var vuln in report.WebVulnerabilities)
            {
                switch (vuln.Severity.ToUpperInvariant())
                {
                    case "CRITICAL": criticalCount++; break;
                    case "HIGH": highCount++; break;
                    case "MEDIUM": mediumCount++; break;
                    case "LOW": lowCount++; break;
                }
            }

            // Count database vulnerabilities
            foreach (var vuln in report.DatabaseVulnerabilities)
            {
                switch (vuln.Severity.ToUpperInvariant())
                {
                    case "CRITICAL": criticalCount++; break;
                    case "HIGH": highCount++; break;
                    case "MEDIUM": mediumCount++; break;
                    case "LOW": lowCount++; break;
                }
            }

            // Count infrastructure vulnerabilities
            foreach (var vuln in report.InfrastructureVulnerabilities)
            {
                switch (vuln.Severity.ToUpperInvariant())
                {
                    case "CRITICAL": criticalCount++; break;
                    case "HIGH": highCount++; break;
                    case "MEDIUM": mediumCount++; break;
                    case "LOW": lowCount++; break;
                }
            }

            // Determine overall rating
            if (criticalCount > 0)
                return SecurityRating.Critical;
            if (highCount >= 3)
                return SecurityRating.High;
            if (highCount > 0 || mediumCount >= 5)
                return SecurityRating.Medium;
            if (mediumCount > 0 || lowCount >= 3)
                return SecurityRating.Low;
            
            return SecurityRating.Good;
        }

        /// <summary>
        /// Displays security assessment summary
        /// </summary>
        /// <param name="report">Security assessment report</param>
        private void DisplaySecuritySummary(SecurityAssessmentReport report)
        {
            var table = new Table();
            table.AddColumn("Category");
            table.AddColumn("Critical");
            table.AddColumn("High");
            table.AddColumn("Medium");
            table.AddColumn("Low");
            table.AddColumn("Total");

            // Count vulnerabilities by category and severity
            var webCounts = CountVulnerabilitiesBySeverity(report.WebVulnerabilities.Select(v => v.Severity));
            var dbCounts = CountVulnerabilitiesBySeverity(report.DatabaseVulnerabilities.Select(v => v.Severity));
            var infraCounts = CountVulnerabilitiesBySeverity(report.InfrastructureVulnerabilities.Select(v => v.Severity));

            table.AddRow("Web", webCounts["CRITICAL"].ToString(), webCounts["HIGH"].ToString(), 
                        webCounts["MEDIUM"].ToString(), webCounts["LOW"].ToString(), 
                        report.WebVulnerabilities.Count().ToString());

            table.AddRow("Database", dbCounts["CRITICAL"].ToString(), dbCounts["HIGH"].ToString(), 
                        dbCounts["MEDIUM"].ToString(), dbCounts["LOW"].ToString(), 
                        report.DatabaseVulnerabilities.Count().ToString());

            table.AddRow("Infrastructure", infraCounts["CRITICAL"].ToString(), infraCounts["HIGH"].ToString(), 
                        infraCounts["MEDIUM"].ToString(), infraCounts["LOW"].ToString(), 
                        report.InfrastructureVulnerabilities.Count().ToString());

            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine($"[bold green]🛡️ Security Assessment Summary for {report.Target}[/]");
            AnsiConsole.Write(table);

            // Display overall rating
            var ratingColor = report.SecurityRating switch
            {
                SecurityRating.Critical => "red",
                SecurityRating.High => "orange1",
                SecurityRating.Medium => "yellow",
                SecurityRating.Low => "blue",
                SecurityRating.Good => "green",
                _ => "white"
            };

            AnsiConsole.MarkupLine($"[bold {ratingColor}]Overall Security Rating: {report.SecurityRating}[/]");

            // Display honeypot analysis if relevant
            if (report.HoneypotAnalysis.ThreatLevel != ThreatLevel.None)
            {
                var threatColor = report.HoneypotAnalysis.ThreatLevel switch
                {
                    ThreatLevel.High => "red",
                    ThreatLevel.Medium => "yellow",
                    ThreatLevel.Low => "blue",
                    _ => "white"
                };

                AnsiConsole.MarkupLine($"[{threatColor}]🍯 Honeypot Risk: {report.HoneypotAnalysis.ThreatLevel} (Score: {report.HoneypotAnalysis.SuspicionScore})[/]");
            }
        }

        /// <summary>
        /// Counts vulnerabilities by severity level
        /// </summary>
        /// <param name="severities">Collection of severity levels</param>
        /// <returns>Dictionary with counts by severity</returns>
        private Dictionary<string, int> CountVulnerabilitiesBySeverity(IEnumerable<string> severities)
        {
            var counts = new Dictionary<string, int>
            {
                ["CRITICAL"] = 0,
                ["HIGH"] = 0,
                ["MEDIUM"] = 0,
                ["LOW"] = 0
            };

            foreach (var severity in severities)
            {
                var upperSeverity = severity.ToUpperInvariant();
                if (counts.ContainsKey(upperSeverity))
                {
                    counts[upperSeverity]++;
                }
            }

            return counts;
        }

        /// <summary>
        /// Generates a detailed security report
        /// </summary>
        /// <param name="report">Security assessment report</param>
        /// <returns>Formatted security report</returns>
        public string GenerateDetailedReport(SecurityAssessmentReport report)
        {
            var sb = new System.Text.StringBuilder();
            
            sb.AppendLine($"=== COMPREHENSIVE SECURITY ASSESSMENT REPORT ===");
            sb.AppendLine($"Target: {report.Target}");
            sb.AppendLine($"Scan Date: {report.ScanStartTime:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine($"Duration: {(report.ScanEndTime - report.ScanStartTime).TotalSeconds:F1} seconds");
            sb.AppendLine($"Overall Security Rating: {report.SecurityRating}");
            sb.AppendLine();

            // Honeypot Analysis
            if (report.HoneypotAnalysis.ThreatLevel != ThreatLevel.None)
            {
                sb.AppendLine("=== HONEYPOT ANALYSIS ===");
                sb.AppendLine($"Threat Level: {report.HoneypotAnalysis.ThreatLevel}");
                sb.AppendLine($"Suspicion Score: {report.HoneypotAnalysis.SuspicionScore}/100");
                foreach (var indicator in report.HoneypotAnalysis.Indicators)
                {
                    sb.AppendLine($"  - {indicator}");
                }
                sb.AppendLine();
            }

            // Web Vulnerabilities
            if (report.WebVulnerabilities.Any())
            {
                sb.AppendLine("=== WEB VULNERABILITIES ===");
                foreach (var vuln in report.WebVulnerabilities.OrderByDescending(v => GetSeverityWeight(v.Severity)))
                {
                    sb.AppendLine($"[{vuln.Severity}] {vuln.Type}");
                    sb.AppendLine($"  URL: {vuln.Url}");
                    sb.AppendLine($"  Description: {vuln.Description}");
                    if (!string.IsNullOrEmpty(vuln.Recommendation))
                    {
                        sb.AppendLine($"  Recommendation: {vuln.Recommendation}");
                    }
                    sb.AppendLine();
                }
            }

            // Database Vulnerabilities
            if (report.DatabaseVulnerabilities.Any())
            {
                sb.AppendLine("=== DATABASE VULNERABILITIES ===");
                foreach (var vuln in report.DatabaseVulnerabilities.OrderByDescending(v => GetSeverityWeight(v.Severity)))
                {
                    sb.AppendLine($"[{vuln.Severity}] {vuln.Type} - {vuln.DatabaseType}");
                    sb.AppendLine($"  Host: {vuln.Host}:{vuln.Port}");
                    sb.AppendLine($"  Description: {vuln.Description}");
                    if (!string.IsNullOrEmpty(vuln.Recommendation))
                    {
                        sb.AppendLine($"  Recommendation: {vuln.Recommendation}");
                    }
                    sb.AppendLine();
                }
            }

            // Infrastructure Vulnerabilities
            if (report.InfrastructureVulnerabilities.Any())
            {
                sb.AppendLine("=== INFRASTRUCTURE VULNERABILITIES ===");
                foreach (var vuln in report.InfrastructureVulnerabilities.OrderByDescending(v => GetSeverityWeight(v.Severity)))
                {
                    sb.AppendLine($"[{vuln.Severity}] {vuln.Type}");
                    if (!string.IsNullOrEmpty(vuln.DeviceType))
                    {
                        sb.AppendLine($"  Device: {vuln.DeviceType}");
                    }
                    if (!string.IsNullOrEmpty(vuln.Protocol))
                    {
                        sb.AppendLine($"  Protocol: {vuln.Protocol}");
                    }
                    sb.AppendLine($"  Host: {vuln.Host}" + (vuln.Port > 0 ? $":{vuln.Port}" : ""));
                    sb.AppendLine($"  Description: {vuln.Description}");
                    if (!string.IsNullOrEmpty(vuln.Recommendation))
                    {
                        sb.AppendLine($"  Recommendation: {vuln.Recommendation}");
                    }
                    sb.AppendLine();
                }
            }

            return sb.ToString();
        }

        /// <summary>
        /// Gets numeric weight for severity level (for sorting)
        /// </summary>
        /// <param name="severity">Severity level</param>
        /// <returns>Numeric weight</returns>
        private int GetSeverityWeight(string severity)
        {
            return severity.ToUpperInvariant() switch
            {
                "CRITICAL" => 4,
                "HIGH" => 3,
                "MEDIUM" => 2,
                "LOW" => 1,
                "INFO" => 0,
                _ => 0
            };
        }

        /// <summary>
        /// Determines if a port typically hosts web services
        /// </summary>
        /// <param name="port">Port number</param>
        /// <returns>True if port typically hosts web services</returns>
        private static bool IsWebService(int port)
        {
            return port == 80 || port == 443 || port == 8080 || port == 8443 || port == 8000 || port == 9000 || port == 3000 || port == 5000;
        }

        /// <summary>
        /// Determines if a port typically hosts database services
        /// </summary>
        /// <param name="port">Port number</param>
        /// <param name="serviceName">Service name</param>
        /// <returns>True if port typically hosts database services</returns>
        private static bool IsDatabaseService(int port, string serviceName)
        {
            var dbPorts = new[] { 3306, 5432, 1433, 1521, 27017, 6379, 9042, 7000, 7001 };
            var dbServices = new[] { "mysql", "postgresql", "mssql", "oracle", "mongodb", "redis", "cassandra" };
            
            return dbPorts.Contains(port) || 
                   dbServices.Any(s => serviceName.ToLowerInvariant().Contains(s));
        }

        /// <summary>
        /// Gets database type based on port number
        /// </summary>
        /// <param name="port">Port number</param>
        /// <returns>Database type string</returns>
        private static string GetDatabaseType(int port)
        {
            return port switch
            {
                3306 => "MySQL",
                5432 => "PostgreSQL",
                1433 => "MSSQL",
                1521 => "Oracle",
                27017 => "MongoDB",
                6379 => "Redis",
                9042 => "Cassandra",
                _ => "Unknown"
            };
        }

        /// <summary>
        /// Converts VulnerabilityInfo to WebVulnerability
        /// </summary>
        /// <param name="vuln">VulnerabilityInfo to convert</param>
        /// <returns>WebVulnerability</returns>
        private static WebVulnerability ConvertToWebVulnerability(VulnerabilityInfo vuln)
        {
            return new WebVulnerability
            {
                Type = vuln.Title,
                Url = $"http://{vuln.Host}:{vuln.Port}",
                Severity = vuln.Severity.ToString(),
                Description = vuln.Description,
                Recommendation = vuln.RecommendedFix
            };
        }

        /// <summary>
        /// Converts VulnerabilityInfo to DatabaseVulnerability
        /// </summary>
        /// <param name="vuln">VulnerabilityInfo to convert</param>
        /// <returns>DatabaseVulnerability</returns>
        private static DatabaseVulnerability ConvertToDatabaseVulnerability(VulnerabilityInfo vuln)
        {
            return new DatabaseVulnerability
            {
                Type = vuln.Title,
                Host = vuln.Host,
                Port = vuln.Port,
                DatabaseType = vuln.ServiceName,
                Severity = vuln.Severity.ToString(),
                Description = vuln.Description,
                Recommendation = vuln.RecommendedFix
            };
        }

        /// <summary>
        /// Converts VulnerabilityInfo to InfrastructureVulnerability
        /// </summary>
        /// <param name="vuln">VulnerabilityInfo to convert</param>
        /// <returns>InfrastructureVulnerability</returns>
        private static InfrastructureVulnerability ConvertToInfrastructureVulnerability(VulnerabilityInfo vuln)
        {
            return new InfrastructureVulnerability
            {
                Type = vuln.Title,
                Host = vuln.Host,
                Port = vuln.Port,
                Protocol = vuln.ServiceName,
                Severity = vuln.Severity.ToString(),
                Description = vuln.Description,
                Recommendation = vuln.RecommendedFix
            };
        }

        /// <summary>
        /// Disposes of resources
        /// </summary>
        public void Dispose()
        {
            // No resources to dispose currently
        }
    }

    /// <summary>
    /// Comprehensive security assessment report
    /// </summary>
    public class SecurityAssessmentReport
    {
        /// <summary>
        /// Target that was assessed
        /// </summary>
        public string Target { get; set; } = "";

        /// <summary>
        /// Scan start time
        /// </summary>
        public DateTime ScanStartTime { get; set; }

        /// <summary>
        /// Scan end time
        /// </summary>
        public DateTime ScanEndTime { get; set; }

        /// <summary>
        /// Overall security rating
        /// </summary>
        public SecurityRating SecurityRating { get; set; }

        /// <summary>
        /// Honeypot analysis results
        /// </summary>
        public HoneypotAnalysisResult HoneypotAnalysis { get; set; } = new();

        /// <summary>
        /// Web vulnerabilities found
        /// </summary>
        public List<WebVulnerability> WebVulnerabilities { get; set; } = new();

        /// <summary>
        /// Database vulnerabilities found
        /// </summary>
        public List<DatabaseVulnerability> DatabaseVulnerabilities { get; set; } = new();

        /// <summary>
        /// Infrastructure vulnerabilities found
        /// </summary>
        public List<InfrastructureVulnerability> InfrastructureVulnerabilities { get; set; } = new();

        /// <summary>
        /// Errors encountered during scanning
        /// </summary>
        public List<string> Errors { get; set; } = new();
    }

    /// <summary>
    /// Security rating enumeration
    /// </summary>
    public enum SecurityRating
    {
        /// <summary>
        /// Critical security issues
        /// </summary>
        Critical = 0,

        /// <summary>
        /// High security risk
        /// </summary>
        High = 1,

        /// <summary>
        /// Medium security risk
        /// </summary>
        Medium = 2,

        /// <summary>
        /// Low security risk
        /// </summary>
        Low = 3,

        /// <summary>
        /// Good security posture
        /// </summary>
        Good = 4
    }

    /// <summary>
    /// Web vulnerability information
    /// </summary>
    public class WebVulnerability
    {
        /// <summary>
        /// Type of vulnerability
        /// </summary>
        public string Type { get; set; } = "";

        /// <summary>
        /// URL where vulnerability was found
        /// </summary>
        public string Url { get; set; } = "";

        /// <summary>
        /// Severity level
        /// </summary>
        public string Severity { get; set; } = "";

        /// <summary>
        /// Description of the vulnerability
        /// </summary>
        public string Description { get; set; } = "";

        /// <summary>
        /// Recommended fix
        /// </summary>
        public string Recommendation { get; set; } = "";
    }

    /// <summary>
    /// Database vulnerability information
    /// </summary>
    public class DatabaseVulnerability
    {
        /// <summary>
        /// Type of vulnerability
        /// </summary>
        public string Type { get; set; } = "";

        /// <summary>
        /// Host where vulnerability was found
        /// </summary>
        public string Host { get; set; } = "";

        /// <summary>
        /// Port number
        /// </summary>
        public int Port { get; set; }

        /// <summary>
        /// Database type
        /// </summary>
        public string DatabaseType { get; set; } = "";

        /// <summary>
        /// Severity level
        /// </summary>
        public string Severity { get; set; } = "";

        /// <summary>
        /// Description of the vulnerability
        /// </summary>
        public string Description { get; set; } = "";

        /// <summary>
        /// Recommended fix
        /// </summary>
        public string Recommendation { get; set; } = "";
    }

    /// <summary>
    /// Infrastructure vulnerability information
    /// </summary>
    public class InfrastructureVulnerability
    {
        /// <summary>
        /// Type of vulnerability
        /// </summary>
        public string Type { get; set; } = "";

        /// <summary>
        /// Host where vulnerability was found
        /// </summary>
        public string Host { get; set; } = "";

        /// <summary>
        /// Port number
        /// </summary>
        public int Port { get; set; }

        /// <summary>
        /// Device type (if applicable)
        /// </summary>
        public string DeviceType { get; set; } = "";

        /// <summary>
        /// Protocol used
        /// </summary>
        public string Protocol { get; set; } = "";

        /// <summary>
        /// Severity level
        /// </summary>
        public string Severity { get; set; } = "";

        /// <summary>
        /// Description of the vulnerability
        /// </summary>
        public string Description { get; set; } = "";

        /// <summary>
        /// Recommended fix
        /// </summary>
        public string Recommendation { get; set; } = "";
    }
}
