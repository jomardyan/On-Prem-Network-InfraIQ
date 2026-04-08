using System;
using System.Net;

namespace Discovery.Core.Models;

/// <summary>
/// Represents the result of a network scan operation.
/// </summary>
/// <param name="ipAddress">The IP address that was scanned.</param>
/// <param name="port">The port that was scanned.</param>
/// <param name="isOpen">Whether the port is open.</param>
/// <param name="service">The service running on the port.</param>
/// <param name="pingTime">The response time in milliseconds.</param>
/// <param name="operatingSystem">Detected operating system.</param>
/// <param name="serverInfo">Additional server information.</param>
/// <param name="discoveredAt">When the scan was performed.</param>
/// <param name="country">Country of the IP address.</param>
/// <param name="hostname">Hostname if resolved.</param>
/// <param name="isVulnerable">Whether vulnerabilities were detected.</param>
/// <param name="vulnerabilityInfo">Details about detected vulnerabilities.</param>
/// <param name="serviceName">Name of the detected service.</param>
public readonly record struct ScanResult(
    IPAddress ipAddress,
    int port,
    bool isOpen,
    string service = "",
    long? pingTime = null,
    string operatingSystem = "",
    string serverInfo = "",
    DateTime? discoveredAt = null,
    string country = "",
    string hostname = "",
    bool isVulnerable = false,
    string vulnerabilityInfo = "",
    string serviceName = "")
{
    /// <summary>
    /// Gets the IP address that was scanned.
    /// </summary>
    public IPAddress IpAddress => this.ipAddress;

    /// <summary>
    /// Gets the port that was scanned.
    /// </summary>
    public int Port => this.port;

    /// <summary>
    /// Gets a value indicating whether the port is open.
    /// </summary>
    public bool IsOpen => this.isOpen;

    /// <summary>
    /// Gets the service running on the port.
    /// </summary>
    public string Service => this.service;

    /// <summary>
    /// Gets the response time in milliseconds.
    /// </summary>
    public long? PingTime => this.pingTime;

    /// <summary>
    /// Gets the detected operating system.
    /// </summary>
    public string OperatingSystem => this.operatingSystem;

    /// <summary>
    /// Gets additional server information.
    /// </summary>
    public string ServerInfo => this.serverInfo;

    /// <summary>
    /// Gets when the scan was performed.
    /// </summary>
    public DateTime? DiscoveredAt => this.discoveredAt;

    /// <summary>
    /// Gets the country of the IP address.
    /// </summary>
    public string Country => this.country;

    /// <summary>
    /// Gets the hostname if resolved.
    /// </summary>
    public string Hostname => this.hostname;

    /// <summary>
    /// Gets a value indicating whether vulnerabilities were detected.
    /// </summary>
    public bool IsVulnerable => this.isVulnerable;

    /// <summary>
    /// Gets details about detected vulnerabilities.
    /// </summary>
    public string VulnerabilityInfo => this.vulnerabilityInfo;

    /// <summary>
    /// Gets the name of the detected service.
    /// </summary>
    public string ServiceName => this.serviceName;

    /// <summary>
    /// Creates a new ScanResult for an open port.
    /// </summary>
    /// <param name="ipAddress">The IP address that was scanned.</param>
    /// <param name="port">The port that was scanned.</param>
    /// <param name="service">The service running on the port.</param>
    /// <param name="pingTime">The response time in milliseconds.</param>
    /// <returns>A new ScanResult representing an open port.</returns>
    public static ScanResult CreateOpen(IPAddress ipAddress, int port, string service = "", long? pingTime = null)
        => new (ipAddress, port, true, service, pingTime, discoveredAt: DateTime.UtcNow);

    /// <summary>
    /// Creates a new ScanResult for a closed port.
    /// </summary>
    /// <param name="ipAddress">The IP address that was scanned.</param>
    /// <param name="port">The port that was scanned.</param>
    /// <returns>A new ScanResult representing a closed port.</returns>
    public static ScanResult CreateClosed(IPAddress ipAddress, int port)
        => new (ipAddress, port, false, discoveredAt: DateTime.UtcNow);

    /// <summary>
    /// Creates a new ScanResult with vulnerability information.
    /// </summary>
    /// <param name="vulnerabilityInfo">Details about detected vulnerabilities.</param>
    /// <returns>A new ScanResult with vulnerability information.</returns>
    public ScanResult WithVulnerability(string vulnerabilityInfo)
        => this with { isVulnerable = true, vulnerabilityInfo = vulnerabilityInfo };

    /// <summary>
    /// Creates a new ScanResult with additional server information.
    /// </summary>
    /// <param name="serverInfo">Additional server information.</param>
    /// <param name="operatingSystem">Detected operating system.</param>
    /// <returns>A new ScanResult with server information.</returns>
    public ScanResult WithServerInfo(string serverInfo, string operatingSystem = "")
        => this with { serverInfo = serverInfo, operatingSystem = operatingSystem };
}
