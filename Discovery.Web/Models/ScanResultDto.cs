using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace Discovery.Web.Models;

/// <summary>
/// Data transfer object for scan results in the web API
/// </summary>
public class ScanResultDto
{
    /// <summary>
    /// The IP address that was scanned
    /// </summary>
    [JsonPropertyName("ipAddress")]
    public required string IpAddress { get; set; }

    /// <summary>
    /// The port that was scanned
    /// </summary>
    [JsonPropertyName("port")]
    public int Port { get; set; }

    /// <summary>
    /// Whether the port is open
    /// </summary>
    [JsonPropertyName("isOpen")]
    public bool IsOpen { get; set; }

    /// <summary>
    /// The service running on the port
    /// </summary>
    [JsonPropertyName("service")]
    public string Service { get; set; } = "";

    /// <summary>
    /// The response time in milliseconds
    /// </summary>
    [JsonPropertyName("pingTime")]
    public long? PingTime { get; set; }

    /// <summary>
    /// Detected operating system
    /// </summary>
    [JsonPropertyName("operatingSystem")]
    public string OperatingSystem { get; set; } = "";

    /// <summary>
    /// Additional server information
    /// </summary>
    [JsonPropertyName("serverInfo")]
    public string ServerInfo { get; set; } = "";

    /// <summary>
    /// When the scan was performed
    /// </summary>
    [JsonPropertyName("discoveredAt")]
    public DateTime? DiscoveredAt { get; set; }

    /// <summary>
    /// Country of the IP address
    /// </summary>
    [JsonPropertyName("country")]
    public string Country { get; set; } = "";

    /// <summary>
    /// Hostname if resolved
    /// </summary>
    [JsonPropertyName("hostname")]
    public string Hostname { get; set; } = "";

    /// <summary>
    /// Whether vulnerabilities were detected
    /// </summary>
    [JsonPropertyName("isVulnerable")]
    public bool IsVulnerable { get; set; }

    /// <summary>
    /// Details about detected vulnerabilities
    /// </summary>
    [JsonPropertyName("vulnerabilityInfo")]
    public string VulnerabilityInfo { get; set; } = "";

    /// <summary>
    /// Name of the detected service
    /// </summary>
    [JsonPropertyName("serviceName")]
    public string ServiceName { get; set; } = "";
}