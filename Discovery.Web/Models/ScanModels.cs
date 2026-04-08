using System.ComponentModel.DataAnnotations;

namespace Discovery.Web.Models
{
    /// <summary>
    /// Response model for scan operations
    /// </summary>
    public class ScanResponse
    {
        /// <summary>
        /// Scan identifier
        /// </summary>
        public string ScanId { get; set; } = string.Empty;

        /// <summary>
        /// Success indicator
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Response message
        /// </summary>
        public string Message { get; set; } = string.Empty;

        /// <summary>
        /// Error details if any
        /// </summary>
        public string? Error { get; set; }

        /// <summary>
        /// Additional response data
        /// </summary>
        public Dictionary<string, object> Data { get; set; } = new();
    }

    /// <summary>
    /// Enhanced port scan result with additional information
    /// </summary>
    public class PortScanResult
    {
        /// <summary>
        /// Target IP address
        /// </summary>
        public string IpAddress { get; set; } = string.Empty;

        /// <summary>
        /// Target hostname if resolved
        /// </summary>
        public string? Hostname { get; set; }

        /// <summary>
        /// Scanned port number
        /// </summary>
        public int Port { get; set; }

        /// <summary>
        /// Whether the port is open
        /// </summary>
        public bool IsOpen { get; set; }

        /// <summary>
        /// Service name running on the port
        /// </summary>
        public string? ServiceName { get; set; }

        /// <summary>
        /// Service version if detected
        /// </summary>
        public string? ServiceVersion { get; set; }

        /// <summary>
        /// Service banner if available
        /// </summary>
        public string? Banner { get; set; }

        /// <summary>
        /// Response time in milliseconds
        /// </summary>
        public int ResponseTime { get; set; }

        /// <summary>
        /// Whether vulnerabilities were detected
        /// </summary>
        public bool IsVulnerable { get; set; }

        /// <summary>
        /// Vulnerability count
        /// </summary>
        public int VulnerabilityCount { get; set; }

        /// <summary>
        /// When this port was scanned
        /// </summary>
        public DateTime ScanTime { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Additional metadata
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    /// <summary>
    /// Host scan result summary
    /// </summary>
    public class HostScanResult
    {
        /// <summary>
        /// Target IP address
        /// </summary>
        public string IpAddress { get; set; } = string.Empty;

        /// <summary>
        /// Target hostname if resolved
        /// </summary>
        public string? Hostname { get; set; }

        /// <summary>
        /// Whether the host is alive/responsive
        /// </summary>
        public bool IsAlive { get; set; }

        /// <summary>
        /// Ping response time in milliseconds
        /// </summary>
        public int PingTime { get; set; }

        /// <summary>
        /// Detected operating system
        /// </summary>
        public string? OperatingSystem { get; set; }

        /// <summary>
        /// Open ports found on this host
        /// </summary>
        public List<PortScanResult> OpenPorts { get; set; } = new();

        /// <summary>
        /// Total vulnerabilities found on this host
        /// </summary>
        public int VulnerabilityCount { get; set; }

        /// <summary>
        /// When this host was scanned
        /// </summary>
        public DateTime ScanTime { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Additional host information
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new();
    }
}
