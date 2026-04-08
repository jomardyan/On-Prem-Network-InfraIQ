using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Net;

namespace Discovery.Core.Models;

/// <summary>
/// Database entity for storing scan session information.
/// </summary>
public class ScanSession
{
    /// <summary>
    /// Gets or sets the unique identifier for the scan session.
    /// </summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Gets or sets the name or description of the scan session.
    /// </summary>
    [MaxLength(255)]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets when the scan session started.
    /// </summary>
    public DateTime StartedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets when the scan session completed.
    /// </summary>
    public DateTime? CompletedAt { get; set; }

    /// <summary>
    /// Gets or sets the scan type (e.g., "NetworkScan", "VulnerabilityScan").
    /// </summary>
    [MaxLength(100)]
    public string ScanType { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the target that was scanned (IP range, hostname, etc.).
    /// </summary>
    [MaxLength(255)]
    public string Target { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets additional configuration or metadata for the scan.
    /// </summary>
    public string? Metadata { get; set; }

    /// <summary>
    /// Gets or sets the total number of results found in this session.
    /// </summary>
    public int ResultCount { get; set; }

    /// <summary>
    /// Gets or sets the scan results associated with this session.
    /// </summary>
    public virtual ICollection<ScanResultEntity> ScanResults { get; set; } = new List<ScanResultEntity>();

    /// <summary>
    /// Gets or sets the vulnerability results associated with this session.
    /// </summary>
    public virtual ICollection<VulnerabilityResultEntity> VulnerabilityResults { get; set; } = new List<VulnerabilityResultEntity>();
}

/// <summary>
/// Database entity for storing individual scan results.
/// </summary>
public class ScanResultEntity
{
    /// <summary>
    /// Gets or sets the unique identifier for the scan result.
    /// </summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Gets or sets the scan session this result belongs to.
    /// </summary>
    public Guid ScanSessionId { get; set; }

    /// <summary>
    /// Gets or sets the scan session navigation property.
    /// </summary>
    public virtual ScanSession ScanSession { get; set; } = null!;

    /// <summary>
    /// Gets or sets the IP address that was scanned.
    /// </summary>
    [MaxLength(45)] // IPv6 addresses can be up to 45 characters
    public string IpAddress { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the port that was scanned.
    /// </summary>
    public int Port { get; set; }

    /// <summary>
    /// Gets or sets whether the port is open.
    /// </summary>
    public bool IsOpen { get; set; }

    /// <summary>
    /// Gets or sets the service running on the port.
    /// </summary>
    [MaxLength(255)]
    public string Service { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the response time in milliseconds.
    /// </summary>
    public long? PingTime { get; set; }

    /// <summary>
    /// Gets or sets the detected operating system.
    /// </summary>
    [MaxLength(255)]
    public string OperatingSystem { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets additional server information.
    /// </summary>
    public string ServerInfo { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets when the scan was performed.
    /// </summary>
    public DateTime DiscoveredAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets the country of the IP address.
    /// </summary>
    [MaxLength(100)]
    public string Country { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the hostname if resolved.
    /// </summary>
    [MaxLength(255)]
    public string Hostname { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets whether vulnerabilities were detected.
    /// </summary>
    public bool IsVulnerable { get; set; }

    /// <summary>
    /// Gets or sets details about detected vulnerabilities.
    /// </summary>
    public string VulnerabilityInfo { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the name of the detected service.
    /// </summary>
    [MaxLength(255)]
    public string ServiceName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the IP version (4 or 6).
    /// </summary>
    public int IpVersion { get; set; } = 4;

    /// <summary>
    /// Converts this entity to a ScanResult record.
    /// </summary>
    /// <returns>A ScanResult record.</returns>
    public ScanResult ToScanResult()
    {
        return new ScanResult(
            IPAddress.Parse(IpAddress),
            Port,
            IsOpen,
            Service,
            PingTime,
            OperatingSystem,
            ServerInfo,
            DiscoveredAt,
            Country,
            Hostname,
            IsVulnerable,
            VulnerabilityInfo,
            ServiceName
        );
    }

    /// <summary>
    /// Creates a ScanResultEntity from a ScanResult record.
    /// </summary>
    /// <param name="scanResult">The scan result to convert.</param>
    /// <param name="scanSessionId">The ID of the scan session.</param>
    /// <returns>A new ScanResultEntity.</returns>
    public static ScanResultEntity FromScanResult(ScanResult scanResult, Guid scanSessionId)
    {
        return new ScanResultEntity
        {
            ScanSessionId = scanSessionId,
            IpAddress = scanResult.IpAddress.ToString(),
            Port = scanResult.Port,
            IsOpen = scanResult.IsOpen,
            Service = scanResult.Service,
            PingTime = scanResult.PingTime,
            OperatingSystem = scanResult.OperatingSystem,
            ServerInfo = scanResult.ServerInfo,
            DiscoveredAt = scanResult.DiscoveredAt ?? DateTime.UtcNow,
            Country = scanResult.Country,
            Hostname = scanResult.Hostname,
            IsVulnerable = scanResult.IsVulnerable,
            VulnerabilityInfo = scanResult.VulnerabilityInfo,
            ServiceName = scanResult.ServiceName,
            IpVersion = scanResult.IpAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? 6 : 4
        };
    }
}

/// <summary>
/// Database entity for storing vulnerability results.
/// </summary>
public class VulnerabilityResultEntity
{
    /// <summary>
    /// Gets or sets the unique identifier for the vulnerability result.
    /// </summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Gets or sets the scan session this result belongs to.
    /// </summary>
    public Guid ScanSessionId { get; set; }

    /// <summary>
    /// Gets or sets the scan session navigation property.
    /// </summary>
    public virtual ScanSession ScanSession { get; set; } = null!;

    /// <summary>
    /// Gets or sets the IP address where the vulnerability was found.
    /// </summary>
    [MaxLength(45)]
    public string IpAddress { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the port where the vulnerability was found.
    /// </summary>
    public int Port { get; set; }

    /// <summary>
    /// Gets or sets the vulnerability title.
    /// </summary>
    [MaxLength(255)]
    public string Title { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the vulnerability description.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the vulnerability severity.
    /// </summary>
    public VulnerabilitySeverity Severity { get; set; }

    /// <summary>
    /// Gets or sets the recommended fix.
    /// </summary>
    public string RecommendedFix { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the CVE identifier if applicable.
    /// </summary>
    [MaxLength(50)]
    public string? CveId { get; set; }

    /// <summary>
    /// Gets or sets when the vulnerability was discovered.
    /// </summary>
    public DateTime DiscoveredAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets additional metadata about the vulnerability.
    /// </summary>
    public string? Metadata { get; set; }
}

/// <summary>
/// Database entity for storing anomaly detection results.
/// </summary>
public class AnomalyDetectionResult
{
    /// <summary>
    /// Gets or sets the unique identifier for the anomaly result.
    /// </summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Gets or sets the scan session this result belongs to.
    /// </summary>
    public Guid ScanSessionId { get; set; }

    /// <summary>
    /// Gets or sets the scan session navigation property.
    /// </summary>
    public virtual ScanSession ScanSession { get; set; } = null!;

    /// <summary>
    /// Gets or sets the IP address where the anomaly was detected.
    /// </summary>
    [MaxLength(45)]
    public string IpAddress { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the anomaly type (e.g., "UnusualPortCombination", "SuspiciousResponse").
    /// </summary>
    [MaxLength(100)]
    public string AnomalyType { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the anomaly score (0.0 to 1.0, where 1.0 is most anomalous).
    /// </summary>
    public double AnomalyScore { get; set; }

    /// <summary>
    /// Gets or sets the description of the anomaly.
    /// </summary>
    public string Description { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets when the anomaly was detected.
    /// </summary>
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets additional context or metadata about the anomaly.
    /// </summary>
    public string? Context { get; set; }
}

/// <summary>
/// Database entity for storing cloud resource information.
/// </summary>
public class CloudResourceEntity
{
    /// <summary>
    /// Gets or sets the unique identifier for the cloud resource.
    /// </summary>
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>
    /// Gets or sets the cloud provider (AWS, Azure, GCP).
    /// </summary>
    [MaxLength(50)]
    public string CloudProvider { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the region where the resource is located.
    /// </summary>
    [MaxLength(100)]
    public string Region { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the resource type (e.g., "EC2Instance", "VirtualMachine").
    /// </summary>
    [MaxLength(100)]
    public string ResourceType { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the resource identifier (instance ID, etc.).
    /// </summary>
    [MaxLength(255)]
    public string ResourceId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the public IP address of the resource.
    /// </summary>
    [MaxLength(45)]
    public string? PublicIpAddress { get; set; }

    /// <summary>
    /// Gets or sets the private IP address of the resource.
    /// </summary>
    [MaxLength(45)]
    public string? PrivateIpAddress { get; set; }

    /// <summary>
    /// Gets or sets the resource name or tag.
    /// </summary>
    [MaxLength(255)]
    public string ResourceName { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the resource status (running, stopped, etc.).
    /// </summary>
    [MaxLength(50)]
    public string Status { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets when the resource was discovered.
    /// </summary>
    public DateTime DiscoveredAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Gets or sets additional metadata about the resource.
    /// </summary>
    public string? Metadata { get; set; }
}