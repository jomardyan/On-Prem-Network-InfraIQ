using System;

namespace Discovery.Web.Models
{
    /// <summary>
    /// Represents a system-wide notification
    /// </summary>
    public class SystemNotification
    {
        /// <summary>
        /// Unique identifier for the notification
        /// </summary>
        public string Id { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Notification title
        /// </summary>
        public string Title { get; set; } = string.Empty;

        /// <summary>
        /// Notification message
        /// </summary>
        public string Message { get; set; } = string.Empty;

        /// <summary>
        /// Notification type/severity
        /// </summary>
        public NotificationType Type { get; set; }

        /// <summary>
        /// When the notification was created
        /// </summary>
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// When the notification expires (auto-dismiss)
        /// </summary>
        public DateTime? ExpiresAt { get; set; }

        /// <summary>
        /// Whether the notification requires user action
        /// </summary>
        public bool RequiresAction { get; set; }

        /// <summary>
        /// Action button text (if applicable)
        /// </summary>
        public string? ActionText { get; set; }

        /// <summary>
        /// Action URL or identifier (if applicable)
        /// </summary>
        public string? ActionUrl { get; set; }

        /// <summary>
        /// Whether the notification should persist across sessions
        /// </summary>
        public bool IsPersistent { get; set; }

        /// <summary>
        /// Additional metadata
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    /// <summary>
    /// System notification types
    /// </summary>
    public enum NotificationType
    {
        /// <summary>
        /// Informational message
        /// </summary>
        Info = 0,

        /// <summary>
        /// Success message
        /// </summary>
        Success = 1,

        /// <summary>
        /// Warning message
        /// </summary>
        Warning = 2,

        /// <summary>
        /// Error message
        /// </summary>
        Error = 3,

        /// <summary>
        /// Critical system alert
        /// </summary>
        Critical = 4
    }

    /// <summary>
    /// Represents an active scan session
    /// </summary>
    public class ScanSession
    {
        /// <summary>
        /// Unique scan identifier
        /// </summary>
        public string ScanId { get; set; } = string.Empty;

        /// <summary>
        /// Number of users connected to this scan
        /// </summary>
        public int ConnectedUsers { get; set; }

        /// <summary>
        /// When the scan session started
        /// </summary>
        public DateTime StartTime { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Last activity timestamp
        /// </summary>
        public DateTime LastActivity { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Number of updates sent for this scan
        /// </summary>
        public long UpdateCount { get; set; }

        /// <summary>
        /// Scan configuration summary
        /// </summary>
        public string? ScanType { get; set; }

        /// <summary>
        /// Target being scanned
        /// </summary>
        public string? Target { get; set; }

        /// <summary>
        /// Current scan status
        /// </summary>
        public string Status { get; set; } = "Active";
    }

    /// <summary>
    /// Represents a user connection to a scan
    /// </summary>
    public class UserConnection
    {
        /// <summary>
        /// SignalR connection ID
        /// </summary>
        public string ConnectionId { get; set; } = string.Empty;

        /// <summary>
        /// Associated scan ID
        /// </summary>
        public string ScanId { get; set; } = string.Empty;

        /// <summary>
        /// User display name
        /// </summary>
        public string UserName { get; set; } = "Anonymous";

        /// <summary>
        /// When the user connected
        /// </summary>
        public DateTime ConnectedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// User's browser/client information
        /// </summary>
        public string? UserAgent { get; set; }

        /// <summary>
        /// User's IP address
        /// </summary>
        public string? IpAddress { get; set; }
    }
}
