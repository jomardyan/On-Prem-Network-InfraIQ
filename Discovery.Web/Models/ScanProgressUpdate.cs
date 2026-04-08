using System;

namespace Discovery.Web.Models
{
    /// <summary>
    /// Represents a scan progress update for real-time UI updates
    /// </summary>
    public class ScanProgressUpdate
    {
        /// <summary>
        /// Unique identifier for the scan
        /// </summary>
        public string ScanId { get; set; } = string.Empty;

        /// <summary>
        /// Current progress percentage (0-100)
        /// </summary>
        public double PercentComplete { get; set; }

        /// <summary>
        /// Current stage of the scan
        /// </summary>
        public string CurrentStage { get; set; } = string.Empty;

        /// <summary>
        /// Detailed status message
        /// </summary>
        public string StatusMessage { get; set; } = string.Empty;

        /// <summary>
        /// Number of hosts discovered so far
        /// </summary>
        public int HostsDiscovered { get; set; }

        /// <summary>
        /// Number of hosts scanned
        /// </summary>
        public int HostsScanned { get; set; }

        /// <summary>
        /// Total number of hosts to scan
        /// </summary>
        public int TotalHosts { get; set; }

        /// <summary>
        /// Number of open ports found
        /// </summary>
        public int OpenPorts { get; set; }

        /// <summary>
        /// Number of vulnerabilities detected
        /// </summary>
        public int VulnerabilitiesFound { get; set; }

        /// <summary>
        /// Estimated time remaining
        /// </summary>
        public TimeSpan? EstimatedTimeRemaining { get; set; }

        /// <summary>
        /// Scan start time
        /// </summary>
        public DateTime StartTime { get; set; }

        /// <summary>
        /// Last update timestamp
        /// </summary>
        public DateTime LastUpdate { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Current scan speed (hosts per second)
        /// </summary>
        public double ScanSpeed { get; set; }

        /// <summary>
        /// Whether the scan is completed
        /// </summary>
        public bool IsCompleted { get; set; }

        /// <summary>
        /// Whether the scan encountered errors
        /// </summary>
        public bool HasErrors { get; set; }

        /// <summary>
        /// Error message if any
        /// </summary>
        public string? ErrorMessage { get; set; }
    }
}
