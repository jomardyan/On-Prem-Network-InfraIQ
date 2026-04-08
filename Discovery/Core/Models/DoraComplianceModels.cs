using System;
using System.Collections.Generic;

namespace Discovery.Core.Models
{
    /// <summary>
    /// Represents a specific DORA compliance issue
    /// </summary>
    public class DoraComplianceIssue
    {
        /// <summary>
        /// Unique identifier for the compliance issue
        /// </summary>
        public string Id { get; set; } = "";
        
        /// <summary>
        /// Title of the compliance issue
        /// </summary>
        public string Title { get; set; } = "";
        
        /// <summary>
        /// Detailed description of the compliance issue
        /// </summary>
        public string Description { get; set; } = "";
        
        /// <summary>
        /// DORA requirement category this issue relates to
        /// </summary>
        public DoraRequirementCategory Category { get; set; }
        
        /// <summary>
        /// Severity level of the compliance issue
        /// </summary>
        public DoraSeverity Severity { get; set; }
        
        /// <summary>
        /// Specific DORA article or requirement reference
        /// </summary>
        public string DoraReference { get; set; } = "";
        
        /// <summary>
        /// Recommended remediation actions
        /// </summary>
        public string Remediation { get; set; } = "";
        
        /// <summary>
        /// Additional context or technical details
        /// </summary>
        public string TechnicalDetails { get; set; } = "";
    }

    /// <summary>
    /// DORA requirement categories
    /// </summary>
    public enum DoraRequirementCategory
    {
        IctRiskManagement,
        IncidentReporting,
        DigitalOperationalResilience,
        ThirdPartyRiskManagement,
        InformationSharing
    }

    /// <summary>
    /// Severity levels for DORA compliance issues
    /// </summary>
    public enum DoraSeverity
    {
        Low,
        Medium,
        High,
        Critical
    }

    /// <summary>
    /// ICT Risk Management assessment results
    /// </summary>
    public class IctRiskManagementAssessment
    {
        /// <summary>
        /// Whether a comprehensive ICT risk management framework is in place
        /// </summary>
        public bool HasRiskManagementFramework { get; set; }
        
        /// <summary>
        /// Security controls assessment score (0-100)
        /// </summary>
        public int SecurityControlsScore { get; set; }
        
        /// <summary>
        /// Whether proper access controls are implemented
        /// </summary>
        public bool HasAccessControls { get; set; }
        
        /// <summary>
        /// Whether security monitoring is in place
        /// </summary>
        public bool HasSecurityMonitoring { get; set; }
        
        /// <summary>
        /// Whether encryption is properly implemented
        /// </summary>
        public bool HasProperEncryption { get; set; }
        
        /// <summary>
        /// Identified security vulnerabilities
        /// </summary>
        public List<string> SecurityGaps { get; set; } = new();
    }

    /// <summary>
    /// Digital Operational Resilience Testing assessment results
    /// </summary>
    public class DigitalResilienceAssessment
    {
        /// <summary>
        /// Whether business continuity plans are detectable
        /// </summary>
        public bool HasBusinessContinuityPlans { get; set; }
        
        /// <summary>
        /// Whether backup systems are in place
        /// </summary>
        public bool HasBackupSystems { get; set; }
        
        /// <summary>
        /// Whether redundancy is implemented
        /// </summary>
        public bool HasRedundancy { get; set; }
        
        /// <summary>
        /// Whether disaster recovery capabilities are present
        /// </summary>
        public bool HasDisasterRecovery { get; set; }
        
        /// <summary>
        /// Resilience testing score (0-100)
        /// </summary>
        public int ResilienceScore { get; set; }
        
        /// <summary>
        /// Identified resilience gaps
        /// </summary>
        public List<string> ResilienceGaps { get; set; } = new();
    }

    /// <summary>
    /// Third-party ICT risk management assessment results
    /// </summary>
    public class ThirdPartyRiskAssessment
    {
        /// <summary>
        /// Whether third-party services are properly monitored
        /// </summary>
        public bool HasThirdPartyMonitoring { get; set; }
        
        /// <summary>
        /// Identified external dependencies
        /// </summary>
        public List<string> ExternalDependencies { get; set; } = new();
        
        /// <summary>
        /// Whether cloud services are properly managed
        /// </summary>
        public bool HasCloudServiceManagement { get; set; }
        
        /// <summary>
        /// Third-party risk score (0-100)
        /// </summary>
        public int ThirdPartyRiskScore { get; set; }
        
        /// <summary>
        /// Identified third-party risks
        /// </summary>
        public List<string> ThirdPartyRisks { get; set; } = new();
    }

    /// <summary>
    /// Incident reporting capabilities assessment results
    /// </summary>
    public class IncidentReportingAssessment
    {
        /// <summary>
        /// Whether incident logging is in place
        /// </summary>
        public bool HasIncidentLogging { get; set; }
        
        /// <summary>
        /// Whether security event monitoring is active
        /// </summary>
        public bool HasSecurityEventMonitoring { get; set; }
        
        /// <summary>
        /// Whether automated alerting is configured
        /// </summary>
        public bool HasAutomatedAlerting { get; set; }
        
        /// <summary>
        /// Incident response readiness score (0-100)
        /// </summary>
        public int IncidentResponseScore { get; set; }
        
        /// <summary>
        /// Identified incident response gaps
        /// </summary>
        public List<string> IncidentResponseGaps { get; set; } = new();
    }

    /// <summary>
    /// Information sharing readiness assessment results
    /// </summary>
    public class InformationSharingAssessment
    {
        /// <summary>
        /// Whether secure communication channels are available
        /// </summary>
        public bool HasSecureCommunication { get; set; }
        
        /// <summary>
        /// Whether threat intelligence sharing is enabled
        /// </summary>
        public bool HasThreatIntelligenceSharing { get; set; }
        
        /// <summary>
        /// Whether information sharing protocols are in place
        /// </summary>
        public bool HasInformationSharingProtocols { get; set; }
        
        /// <summary>
        /// Information sharing readiness score (0-100)
        /// </summary>
        public int InformationSharingScore { get; set; }
        
        /// <summary>
        /// Identified information sharing gaps
        /// </summary>
        public List<string> InformationSharingGaps { get; set; } = new();
    }
}