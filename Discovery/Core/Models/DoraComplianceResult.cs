using System;
using System.Collections.Generic;

namespace Discovery.Core.Models
{
    /// <summary>
    /// Contains results from a DORA (Digital Operational Resilience Act) compliance assessment
    /// </summary>
    public class DoraComplianceResult
    {
        /// <summary>
        /// The target IP address or hostname that was assessed
        /// </summary>
        public string Target { get; set; } = "";
        
        /// <summary>
        /// Date and time when the assessment was conducted
        /// </summary>
        public DateTime AssessmentDate { get; set; } = DateTime.Now;
        
        /// <summary>
        /// ICT Risk Management compliance checks
        /// </summary>
        public IctRiskManagementAssessment IctRiskManagement { get; set; } = new();
        
        /// <summary>
        /// Digital Operational Resilience Testing results
        /// </summary>
        public DigitalResilienceAssessment DigitalResilience { get; set; } = new();
        
        /// <summary>
        /// Third-party ICT risk management assessment
        /// </summary>
        public ThirdPartyRiskAssessment ThirdPartyRisk { get; set; } = new();
        
        /// <summary>
        /// Incident reporting capabilities assessment
        /// </summary>
        public IncidentReportingAssessment IncidentReporting { get; set; } = new();
        
        /// <summary>
        /// Information sharing readiness assessment
        /// </summary>
        public InformationSharingAssessment InformationSharing { get; set; } = new();
        
        /// <summary>
        /// Overall DORA compliance score (0-100, higher is better)
        /// </summary>
        public int ComplianceScore { get; set; }
        
        /// <summary>
        /// Summary of the compliance assessment findings
        /// </summary>
        public string Summary { get; set; } = "";
        
        /// <summary>
        /// List of specific compliance issues identified
        /// </summary>
        public List<DoraComplianceIssue> ComplianceIssues { get; set; } = new();
        
        /// <summary>
        /// Recommended actions to improve DORA compliance
        /// </summary>
        public List<string> Recommendations { get; set; } = new();
    }
}