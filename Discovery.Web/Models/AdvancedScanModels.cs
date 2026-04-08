using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Discovery.Web.Models;

/// <summary>
/// Data transfer object for vulnerability scan results
/// </summary>
public class VulnerabilityDto
{
    /// <summary>
    /// The host where the vulnerability was found
    /// </summary>
    [JsonPropertyName("host")]
    public required string Host { get; set; }

    /// <summary>
    /// The port number associated with the vulnerability
    /// </summary>
    [JsonPropertyName("port")]
    public int Port { get; set; }

    /// <summary>
    /// The name of the vulnerable service
    /// </summary>
    [JsonPropertyName("serviceName")]
    public string ServiceName { get; set; } = "";

    /// <summary>
    /// The severity level of the vulnerability
    /// </summary>
    [JsonPropertyName("severity")]
    public string Severity { get; set; } = "";

    /// <summary>
    /// The title of the vulnerability
    /// </summary>
    [JsonPropertyName("title")]
    public string Title { get; set; } = "";

    /// <summary>
    /// Detailed description of the vulnerability
    /// </summary>
    [JsonPropertyName("description")]
    public string Description { get; set; } = "";

    /// <summary>
    /// Recommended fix for the vulnerability
    /// </summary>
    [JsonPropertyName("recommendedFix")]
    public string RecommendedFix { get; set; } = "";

    /// <summary>
    /// When the vulnerability was discovered
    /// </summary>
    [JsonPropertyName("discoveredAt")]
    public DateTime DiscoveredAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Data transfer object for anomaly detection results
/// </summary>
public class AnomalyDto
{
    /// <summary>
    /// The IP address where the anomaly was detected
    /// </summary>
    [JsonPropertyName("ipAddress")]
    public required string IpAddress { get; set; }

    /// <summary>
    /// The type of anomaly detected
    /// </summary>
    [JsonPropertyName("anomalyType")]
    public string AnomalyType { get; set; } = "";

    /// <summary>
    /// The anomaly score (0.0 to 1.0)
    /// </summary>
    [JsonPropertyName("anomalyScore")]
    public double AnomalyScore { get; set; }

    /// <summary>
    /// Description of the anomaly
    /// </summary>
    [JsonPropertyName("description")]
    public string Description { get; set; } = "";

    /// <summary>
    /// Additional context about the anomaly
    /// </summary>
    [JsonPropertyName("context")]
    public string Context { get; set; } = "";

    /// <summary>
    /// When the anomaly was detected
    /// </summary>
    [JsonPropertyName("detectedAt")]
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Data transfer object for SSL certificate information
/// </summary>
public class SslCertificateDto
{
    /// <summary>
    /// The host that was checked
    /// </summary>
    [JsonPropertyName("host")]
    public required string Host { get; set; }

    /// <summary>
    /// The port that was checked
    /// </summary>
    [JsonPropertyName("port")]
    public int Port { get; set; }

    /// <summary>
    /// Whether the certificate is valid
    /// </summary>
    [JsonPropertyName("isValid")]
    public bool IsValid { get; set; }

    /// <summary>
    /// Subject of the certificate
    /// </summary>
    [JsonPropertyName("subject")]
    public string Subject { get; set; } = "";

    /// <summary>
    /// Issuer of the certificate
    /// </summary>
    [JsonPropertyName("issuer")]
    public string Issuer { get; set; } = "";

    /// <summary>
    /// Certificate expiration date
    /// </summary>
    [JsonPropertyName("expirationDate")]
    public DateTime? ExpirationDate { get; set; }

    /// <summary>
    /// SSL/TLS protocol version
    /// </summary>
    [JsonPropertyName("protocol")]
    public string Protocol { get; set; } = "";

    /// <summary>
    /// Cipher suite information
    /// </summary>
    [JsonPropertyName("cipherSuite")]
    public string CipherSuite { get; set; } = "";

    /// <summary>
    /// Certificate key size
    /// </summary>
    [JsonPropertyName("keySize")]
    public int KeySize { get; set; }

    /// <summary>
    /// Whether weak ciphers are supported
    /// </summary>
    [JsonPropertyName("hasWeakCiphers")]
    public bool HasWeakCiphers { get; set; }

    /// <summary>
    /// Validation error message if certificate is invalid
    /// </summary>
    [JsonPropertyName("validationErrorMessage")]
    public string ValidationErrorMessage { get; set; } = "";
}

/// <summary>
/// Request model for advanced port scanning
/// </summary>
public class AdvancedScanRequest
{
    public string? ScanId { get; set; }
    [Required] public string Target { get; set; } = "";
    public List<int>? Ports { get; set; }
    public int Timeout { get; set; } = 5000;
    public int MaxConcurrency { get; set; } = 100;
    public bool EnableServiceDetection { get; set; } = true;
    public bool EnableVulnerabilityScanning { get; set; } = false;
    public bool IncludeBannerGrabbing { get; set; } = true;
    public bool IncludeSslAnalysis { get; set; } = true;
}

/// <summary>
/// Request model for vulnerability scanning
/// </summary>
public record VulnerabilityScanRequest(
    [Required] string Target,
    int[]? Ports = null,
    int? TimeoutMs = null,
    bool IncludePortScan = true,
    bool IncludeSslChecks = true,
    bool IncludeServiceDetection = true
);

/// <summary>
/// Request model for IPv6 scanning
/// </summary>
public record IPv6ScanRequest(
    [Required] string IPv6Address,
    int[]? Ports = null,
    int? TimeoutMs = null,
    bool DiscoverNeighbors = false
);

/// <summary>
/// Request model for scanning a single IP address
/// </summary>
public record ScanIpRequest(
    [Required] string IpAddress,
    int[]? Ports = null,
    int? TimeoutMs = null
);

/// <summary>
/// Request model for scanning a network range
/// </summary>
public record ScanNetworkRequest(
    [Required] string NetworkRange,
    int[]? Ports = null,
    int? TimeoutMs = null
);

/// <summary>
/// Request model for anomaly detection
/// </summary>
public record AnomalyDetectionRequest(
    [Required] string NetworkRange,
    bool UseHistoricalData = true,
    int? DaysBack = 30,
    double? AnomalyThreshold = 0.7
);

/// <summary>
/// Request model for comprehensive security scanning
/// </summary>
public record SecurityScanRequest(
    [Required] string Target,
    bool IncludePortScan = true,
    bool IncludeVulnerabilityAssessment = true,
    bool IncludeSslAnalysis = true,
    bool IncludeAnomalyDetection = true,
    bool StoreResults = true,
    int? TimeoutMs = null
);