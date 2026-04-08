using System;
using System.Collections.Generic;

namespace Discovery.Core.Models
{
    /// <summary>
    /// Contains results from a comprehensive security audit
    /// </summary>
    public class SecurityAuditResult
    {
        /// <summary>
        /// The target IP address or hostname that was audited
        /// </summary>
        public string Target { get; set; } = "";
        
        /// <summary>
        /// Date and time when the audit was conducted
        /// </summary>
        public DateTime AuditDate { get; set; } = DateTime.Now;
        
        /// <summary>
        /// List of discovered vulnerabilities
        /// </summary>
        public List<VulnerabilityInfo> Vulnerabilities { get; set; } = new List<VulnerabilityInfo>();
        
        /// <summary>
        /// List of open ports discovered during the audit
        /// </summary>
        public List<ScanResult> OpenPorts { get; set; } = new List<ScanResult>();
        
        /// <summary>
        /// SSL/TLS certificate information if applicable
        /// </summary>
        public CertificateInfo CertificateInfo { get; set; } = new CertificateInfo();
        
        /// <summary>
        /// Additional security observations that don't qualify as vulnerabilities
        /// </summary>
        public List<string> SecurityObservations { get; set; } = new List<string>();
        
        /// <summary>
        /// Overall security score (0-100, higher is better)
        /// </summary>
        public int SecurityScore { get; set; }
        
        /// <summary>
        /// Summary of the audit findings
        /// </summary>
        public string Summary { get; set; } = "";
    }
}
