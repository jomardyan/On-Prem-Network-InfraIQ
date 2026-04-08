using Microsoft.AspNetCore.Mvc;
using Discovery.Core.Models;
using Discovery.Web.Models;
using Discovery.Services.Scanning;

namespace Discovery.Web.Controllers;

/// <summary>
/// Controller for application configuration and settings
/// </summary>
[Route("api/[controller]")]
[ApiController]
public class ConfigurationController : ControllerBase
{
    private readonly ILogger<ConfigurationController> _logger;

    public ConfigurationController(ILogger<ConfigurationController> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Get application configuration and default settings
    /// </summary>
    [HttpGet("defaults")]
    public ActionResult<object> GetDefaultSettings()
    {
        return Ok(new
        {
            DefaultPorts = new
            {
                TCP = new int[] { 22, 80, 443, 21, 23, 25, 53, 110, 143, 993, 995, 3389, 5432, 3306 },
                UDP = new int[] { 53, 67, 68, 69, 123, 161, 162, 500, 514, 520, 1812, 1813 }
            },
            DefaultTimeouts = new
            {
                SingleScan = 5000,
                NetworkScan = 3000,
                VulnerabilityScan = 10000
            },
            MaxConcurrency = new
            {
                PortScanning = 100,
                NetworkScanning = 50,
                VulnerabilityAssessment = 25
            },
            SupportedNetworkRanges = new[]
            {
                "Single IP (e.g., 192.168.1.1)",
                "CIDR notation (e.g., 192.168.1.0/24)",
                "IP range (e.g., 192.168.1.1-192.168.1.50)",
                "IPv6 address (e.g., 2001:db8::1)",
                "IPv6 CIDR (e.g., 2001:db8::/64)"
            },
            CommonServices = new[]
            {
                new { Port = 22, Service = "SSH", Protocol = "TCP" },
                new { Port = 23, Service = "Telnet", Protocol = "TCP" },
                new { Port = 25, Service = "SMTP", Protocol = "TCP" },
                new { Port = 53, Service = "DNS", Protocol = "TCP/UDP" },
                new { Port = 80, Service = "HTTP", Protocol = "TCP" },
                new { Port = 110, Service = "POP3", Protocol = "TCP" },
                new { Port = 143, Service = "IMAP", Protocol = "TCP" },
                new { Port = 443, Service = "HTTPS", Protocol = "TCP" },
                new { Port = 993, Service = "IMAPS", Protocol = "TCP" },
                new { Port = 995, Service = "POP3S", Protocol = "TCP" },
                new { Port = 3389, Service = "RDP", Protocol = "TCP" },
                new { Port = 5432, Service = "PostgreSQL", Protocol = "TCP" },
                new { Port = 3306, Service = "MySQL", Protocol = "TCP" }
            }
        });
    }

    /// <summary>
    /// Get port presets for different scan types
    /// </summary>
    [HttpGet("port-presets")]
    public ActionResult<object> GetPortPresets()
    {
        return Ok(new
        {
            Presets = new
            {
                Quick = new
                {
                    Name = "Quick Scan",
                    Description = "Most common ports for basic services",
                    Ports = new int[] { 22, 80, 443, 21, 23, 25 }
                },
                Common = new
                {
                    Name = "Common Services",
                    Description = "Standard enterprise services and protocols",
                    Ports = new int[] { 22, 80, 443, 21, 23, 25, 53, 110, 143, 993, 995, 3389 }
                },
                Database = new
                {
                    Name = "Database Services",
                    Description = "Common database server ports",
                    Ports = new int[] { 1433, 3306, 5432, 1521, 27017, 6379, 5984 }
                },
                WebServices = new
                {
                    Name = "Web Services",
                    Description = "HTTP/HTTPS and related web services",
                    Ports = new int[] { 80, 443, 8080, 8443, 8000, 8888, 9000, 3000, 5000 }
                },
                MailServices = new
                {
                    Name = "Mail Services",
                    Description = "Email server and related services",
                    Ports = new int[] { 25, 110, 143, 993, 995, 587, 465, 2525 }
                },
                RemoteAccess = new
                {
                    Name = "Remote Access",
                    Description = "SSH, RDP, VNC and other remote services",
                    Ports = new int[] { 22, 23, 3389, 5900, 5901, 5902, 1723, 1701 }
                },
                Security = new
                {
                    Name = "Security Services",
                    Description = "Firewall, VPN, and security-related ports",
                    Ports = new int[] { 161, 162, 500, 4500, 1812, 1813, 636, 389, 88 }
                },
                Comprehensive = new
                {
                    Name = "Comprehensive Scan",
                    Description = "Extensive port range covering most services",
                    Ports = Enumerable.Range(1, 1000).Concat(new int[] { 1433, 1521, 3306, 3389, 5432, 5900, 8080, 8443 }).ToArray()
                }
            }
        });
    }

    /// <summary>
    /// Get vulnerability scanning templates
    /// </summary>
    [HttpGet("vulnerability-templates")]
    public ActionResult<object> GetVulnerabilityTemplates()
    {
        return Ok(new
        {
            Templates = new
            {
                Basic = new
                {
                    Name = "Basic Security Check",
                    Description = "Essential security vulnerabilities",
                    Checks = new[]
                    {
                        "Open ports with default credentials",
                        "Unencrypted services",
                        "Outdated service versions",
                        "SSL/TLS configuration issues"
                    }
                },
                WebApplication = new
                {
                    Name = "Web Application Security",
                    Description = "Web-specific vulnerability assessment",
                    Checks = new[]
                    {
                        "SQL injection vulnerabilities",
                        "Cross-site scripting (XSS)",
                        "Insecure HTTP headers",
                        "Directory traversal",
                        "Authentication bypass"
                    }
                },
                Infrastructure = new
                {
                    Name = "Infrastructure Security",
                    Description = "Network and system-level vulnerabilities",
                    Checks = new[]
                    {
                        "Network protocol vulnerabilities",
                        "Service misconfigurations",
                        "Default passwords",
                        "Unnecessary services",
                        "Patch management issues"
                    }
                },
                Compliance = new
                {
                    Name = "Compliance Check",
                    Description = "Regulatory compliance assessment",
                    Checks = new[]
                    {
                        "PCI DSS compliance",
                        "GDPR data protection",
                        "HIPAA security requirements",
                        "SOX internal controls"
                    }
                }
            }
        });
    }

    /// <summary>
    /// Get scan performance recommendations
    /// </summary>
    [HttpGet("performance-recommendations")]
    public ActionResult<object> GetPerformanceRecommendations()
    {
        return Ok(new
        {
            Recommendations = new
            {
                SmallNetwork = new
                {
                    Range = "1-50 hosts",
                    ConcurrentScans = 25,
                    TimeoutMs = 3000,
                    MaxPortsPerHost = 1000,
                    EstimatedTime = "1-5 minutes"
                },
                MediumNetwork = new
                {
                    Range = "51-254 hosts",
                    ConcurrentScans = 50,
                    TimeoutMs = 2000,
                    MaxPortsPerHost = 100,
                    EstimatedTime = "5-15 minutes"
                },
                LargeNetwork = new
                {
                    Range = "255+ hosts",
                    ConcurrentScans = 100,
                    TimeoutMs = 1000,
                    MaxPortsPerHost = 50,
                    EstimatedTime = "15+ minutes"
                }
            },
            OptimizationTips = new[]
            {
                "Use smaller port ranges for large networks",
                "Reduce timeout for internal networks",
                "Increase concurrency for faster networks",
                "Use quick scan presets for reconnaissance",
                "Enable rate limiting for external scans"
            }
        });
    }

    /// <summary>
    /// Validate scan configuration
    /// </summary>
    [HttpPost("validate")]
    public ActionResult<object> ValidateConfiguration([FromBody] ScanConfigurationRequest request)
    {
        var errors = new List<string>();
        var warnings = new List<string>();

        // Validate IP address or network range
        if (string.IsNullOrWhiteSpace(request.Target))
        {
            errors.Add("Target IP address or network range is required");
        }

        // Validate ports
        if (request.Ports?.Any() != true)
        {
            warnings.Add("No ports specified - using default port set");
        }
        else if (request.Ports.Count() > 1000)
        {
            warnings.Add("Large port range may result in slow scanning");
        }

        // Validate timeout
        if (request.TimeoutMs < 100)
        {
            warnings.Add("Very low timeout may miss slower services");
        }
        else if (request.TimeoutMs > 30000)
        {
            warnings.Add("High timeout may result in very slow scanning");
        }

        // Validate concurrency
        if (request.Concurrency > 200)
        {
            warnings.Add("High concurrency may overwhelm target network");
        }

        var isValid = !errors.Any();
        var estimatedTime = EstimateScanTime(request);

        return Ok(new
        {
            IsValid = isValid,
            Errors = errors,
            Warnings = warnings,
            EstimatedDuration = estimatedTime,
            Recommendations = GetRecommendations(request)
        });
    }

    private string EstimateScanTime(ScanConfigurationRequest request)
    {
        var portCount = request.Ports?.Count() ?? 14; // Default port count
        var timeoutMs = request.TimeoutMs ?? 3000;
        var concurrency = request.Concurrency ?? 50;

        // Simple estimation formula
        var totalChecks = portCount * (request.Target?.Contains('/') == true ? 254 : 1);
        var estimatedSeconds = (totalChecks * timeoutMs / 1000) / concurrency;

        return estimatedSeconds switch
        {
            < 60 => $"{estimatedSeconds:F0} seconds",
            < 3600 => $"{estimatedSeconds / 60:F1} minutes",
            _ => $"{estimatedSeconds / 3600:F1} hours"
        };
    }

    private string[] GetRecommendations(ScanConfigurationRequest request)
    {
        var recommendations = new List<string>();

        if (request.Ports?.Count() > 100)
        {
            recommendations.Add("Consider using port presets for faster scanning");
        }

        if (request.TimeoutMs > 10000)
        {
            recommendations.Add("Reduce timeout for faster scanning");
        }

        if (request.Target?.Contains('/') == true)
        {
            recommendations.Add("Network scanning may take significant time");
        }

        return recommendations.ToArray();
    }
}

/// <summary>
/// Request model for scan configuration validation
/// </summary>
public class ScanConfigurationRequest
{
    public string? Target { get; set; }
    public int[]? Ports { get; set; }
    public int? TimeoutMs { get; set; }
    public int? Concurrency { get; set; }
    public bool IncludeVulnerabilityAssessment { get; set; }
    public bool EnableAnomalyDetection { get; set; }
}