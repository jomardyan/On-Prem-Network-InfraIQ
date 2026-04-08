using System;
using System.Collections.Generic;

namespace Discovery.Core.Models
{
    /// <summary>
    /// Contains results from a security audit of a specific port.
    /// </summary>
    public class PortSecurityAuditResult
    {
        /// <summary>
        /// Gets or sets the IP address or hostname that was audited.
        /// </summary>
        public string Host { get; set; } = "";
        
        /// <summary>
        /// Gets or sets the port number that was audited.
        /// </summary>
        public int Port { get; set; }
        
        /// <summary>
        /// Gets or sets the name of the service detected on the port.
        /// </summary>
        public string ServiceName { get; set; } = "";
        
        /// <summary>
        /// Gets or sets a value indicating whether any security issues were found.
        /// </summary>
        public bool HasIssues { get; set; }
        
        /// <summary>
        /// Gets or sets a list of security issues found during the audit.
        /// </summary>
        public List<SecurityIssue> Issues { get; set; } = new List<SecurityIssue>();
    }
    
    /// <summary>
    /// Represents a security issue found during a port audit.
    /// </summary>
    public class SecurityIssue
    {
        /// <summary>
        /// Gets or sets the title of the security issue.
        /// </summary>
        public string Title { get; set; } = "";
        
        /// <summary>
        /// Gets or sets the description of the security issue.
        /// </summary>
        public string Description { get; set; } = "";
        
        /// <summary>
        /// Gets or sets the severity of the issue.
        /// </summary>
        public VulnerabilitySeverity Severity { get; set; } = VulnerabilitySeverity.Medium;
        
        /// <summary>
        /// Gets or sets the recommended action to resolve the issue.
        /// </summary>
        public string RecommendedAction { get; set; } = "";
    }
}
