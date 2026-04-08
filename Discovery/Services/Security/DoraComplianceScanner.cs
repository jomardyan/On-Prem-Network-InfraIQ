using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Discovery.Core.Models;
using Discovery.Services.Security;
using Discovery.Services.Scanning;

namespace Discovery.Services.Security
{
    /// <summary>
    /// Provides DORA (Digital Operational Resilience Act) compliance assessment capabilities
    /// </summary>
    public class DoraComplianceScanner
    {
        private readonly PortScanner _portScanner;

        /// <summary>
        /// Initializes a new instance of the DoraComplianceScanner class
        /// </summary>
        public DoraComplianceScanner()
        {
            _portScanner = new PortScanner(timeout: 5000);
        }

        /// <summary>
        /// Performs a comprehensive DORA compliance assessment on a target
        /// </summary>
        /// <param name="target">The IP address or hostname to assess</param>
        /// <param name="cancellationToken">Cancellation token to cancel the operation</param>
        /// <returns>DORA compliance assessment results</returns>
        public async Task<DoraComplianceResult> AssessComplianceAsync(string target, CancellationToken cancellationToken = default)
        {
            var result = new DoraComplianceResult
            {
                Target = target,
                AssessmentDate = DateTime.Now
            };

            try
            {
                // Parse IP address
                var ipAddress = IPAddress.TryParse(target, out var ip) ? ip : 
                    (await Dns.GetHostAddressesAsync(target, cancellationToken)).FirstOrDefault();

                if (ipAddress == null)
                {
                    result.Summary = "Unable to resolve target address";
                    return result;
                }

                // Perform basic port scan first to get service information
                var commonPorts = new[] { 21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 6379, 27017 };
                var scanResults = new List<ScanResult>();
                
                foreach (var port in commonPorts)
                {
                    var isOpen = await ScanSinglePortAsync(ipAddress, port);
                    if (isOpen)
                    {
                        scanResults.Add(new ScanResult(
                            ipAddress,
                            port,
                            true,
                            GetServiceName(port),
                            0,
                            "",
                            "",
                            DateTime.Now,
                            "",
                            "",
                            false,
                            "",
                            ""
                        ));
                    }
                }

                // Create a mock security audit based on open ports
                var securityAudit = CreateSecurityAuditFromPorts(scanResults, ipAddress.ToString());

                // ICT Risk Management Assessment
                result.IctRiskManagement = await AssessIctRiskManagementAsync(ipAddress, securityAudit, cancellationToken);

                // Digital Operational Resilience Assessment
                result.DigitalResilience = await AssessDigitalResilienceAsync(ipAddress, securityAudit, cancellationToken);

                // Third-party Risk Assessment
                result.ThirdPartyRisk = await AssessThirdPartyRiskAsync(ipAddress, securityAudit, cancellationToken);

                // Incident Reporting Assessment
                result.IncidentReporting = await AssessIncidentReportingAsync(ipAddress, securityAudit, cancellationToken);

                // Information Sharing Assessment
                result.InformationSharing = await AssessInformationSharingAsync(ipAddress, securityAudit, cancellationToken);

                // Calculate overall compliance score
                result.ComplianceScore = CalculateComplianceScore(result);

                // Generate compliance issues
                result.ComplianceIssues = GenerateComplianceIssues(result);

                // Generate recommendations
                result.Recommendations = GenerateRecommendations(result);

                // Create summary
                result.Summary = GenerateSummary(result);
            }
            catch (Exception ex)
            {
                result.Summary = $"Assessment failed: {ex.Message}";
                result.ComplianceIssues.Add(new DoraComplianceIssue
                {
                    Id = "DORA-ERROR-001",
                    Title = "Assessment Error",
                    Description = ex.Message,
                    Category = DoraRequirementCategory.IctRiskManagement,
                    Severity = DoraSeverity.Medium
                });
            }

            return result;
        }

        /// <summary>
        /// Simple port scanner for DORA assessment purposes
        /// </summary>
        private async Task<bool> ScanSinglePortAsync(IPAddress ipAddress, int port, int timeout = 5000)
        {
            try
            {
                using var client = new TcpClient();
                var connectTask = client.ConnectAsync(ipAddress, port);
                var completedTask = await Task.WhenAny(connectTask, Task.Delay(timeout));
                
                return completedTask == connectTask && client.Connected;
            }
            catch
            {
                return false;
            }
        }

        private string GetServiceName(int port)
        {
            return port switch
            {
                21 => "FTP",
                22 => "SSH",
                23 => "Telnet",
                25 => "SMTP",
                53 => "DNS",
                80 => "HTTP",
                110 => "POP3",
                143 => "IMAP",
                443 => "HTTPS",
                993 => "IMAPS",
                995 => "POP3S",
                1433 => "MSSQL",
                3306 => "MySQL",
                3389 => "RDP",
                5432 => "PostgreSQL",
                6379 => "Redis",
                27017 => "MongoDB",
                _ => "Unknown"
            };
        }

        private SecurityAuditResult CreateSecurityAuditFromPorts(List<ScanResult> scanResults, string target)
        {
            var vulnerabilities = new List<VulnerabilityInfo>();
            
            // Add basic vulnerability checks based on open ports
            foreach (var result in scanResults)
            {
                if (result.Port == 23) // Telnet
                {
                    vulnerabilities.Add(new VulnerabilityInfo
                    {
                        Id = "DORA-VULN-001",
                        Title = "Unencrypted Telnet Service",
                        Description = "Telnet service is running without encryption",
                        Severity = VulnerabilitySeverity.High,
                        Host = target,
                        Port = result.Port,
                        ServiceName = result.ServiceName
                    });
                }
                
                if (result.Port == 21) // FTP
                {
                    vulnerabilities.Add(new VulnerabilityInfo
                    {
                        Id = "DORA-VULN-002",
                        Title = "Unencrypted FTP Service",
                        Description = "FTP service may transmit data without encryption",
                        Severity = VulnerabilitySeverity.Medium,
                        Host = target,
                        Port = result.Port,
                        ServiceName = result.ServiceName
                    });
                }
            }

            return new SecurityAuditResult
            {
                Target = target,
                OpenPorts = scanResults,
                Vulnerabilities = vulnerabilities
            };
        }

        /// <summary>
        /// Assesses ICT Risk Management compliance
        /// </summary>
        private async Task<IctRiskManagementAssessment> AssessIctRiskManagementAsync(IPAddress ipAddress, SecurityAuditResult securityAudit, CancellationToken cancellationToken)
        {
            var assessment = new IctRiskManagementAssessment();

            // Check for basic security controls
            assessment.HasAccessControls = CheckAccessControls(ipAddress, securityAudit);
            assessment.HasSecurityMonitoring = CheckSecurityMonitoring(ipAddress, securityAudit);
            assessment.HasProperEncryption = CheckEncryption(ipAddress, securityAudit);

            // Calculate security controls score based on vulnerabilities and open ports
            var vulnerabilityCount = securityAudit.Vulnerabilities.Count;
            var criticalVulnerabilities = securityAudit.Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.Critical);
            var highVulnerabilities = securityAudit.Vulnerabilities.Count(v => v.Severity == VulnerabilitySeverity.High);

            assessment.SecurityControlsScore = Math.Max(0, 100 - (criticalVulnerabilities * 25) - (highVulnerabilities * 10) - (vulnerabilityCount * 2));

            // Determine if risk management framework is in place based on security posture
            assessment.HasRiskManagementFramework = assessment.SecurityControlsScore >= 70 && 
                                                   assessment.HasAccessControls && 
                                                   assessment.HasSecurityMonitoring;

            // Identify security gaps
            foreach (var vulnerability in securityAudit.Vulnerabilities.Where(v => v.Severity >= VulnerabilitySeverity.High))
            {
                assessment.SecurityGaps.Add($"{vulnerability.Title}: {vulnerability.Description}");
            }

            return await Task.FromResult(assessment);
        }

        /// <summary>
        /// Assesses Digital Operational Resilience
        /// </summary>
        private async Task<DigitalResilienceAssessment> AssessDigitalResilienceAsync(IPAddress ipAddress, SecurityAuditResult securityAudit, CancellationToken cancellationToken)
        {
            var assessment = new DigitalResilienceAssessment();

            // Check for backup and redundancy indicators
            assessment.HasBackupSystems = CheckBackupSystems(ipAddress, securityAudit);
            assessment.HasRedundancy = CheckRedundancy(ipAddress, securityAudit);
            assessment.HasDisasterRecovery = CheckDisasterRecovery(ipAddress, securityAudit);
            assessment.HasBusinessContinuityPlans = CheckBusinessContinuity(ipAddress, securityAudit);

            // Calculate resilience score
            var resilienceFactors = new[] { assessment.HasBackupSystems, assessment.HasRedundancy, assessment.HasDisasterRecovery, assessment.HasBusinessContinuityPlans };
            assessment.ResilienceScore = (resilienceFactors.Count(f => f) * 25);

            // Identify resilience gaps
            if (!assessment.HasBackupSystems)
                assessment.ResilienceGaps.Add("No backup systems detected");
            if (!assessment.HasRedundancy)
                assessment.ResilienceGaps.Add("No redundancy mechanisms detected");
            if (!assessment.HasDisasterRecovery)
                assessment.ResilienceGaps.Add("No disaster recovery capabilities detected");
            if (!assessment.HasBusinessContinuityPlans)
                assessment.ResilienceGaps.Add("No business continuity indicators detected");

            return await Task.FromResult(assessment);
        }

        /// <summary>
        /// Assesses Third-party Risk Management
        /// </summary>
        private async Task<ThirdPartyRiskAssessment> AssessThirdPartyRiskAsync(IPAddress ipAddress, SecurityAuditResult securityAudit, CancellationToken cancellationToken)
        {
            var assessment = new ThirdPartyRiskAssessment();

            // Identify external dependencies based on open ports and services
            assessment.ExternalDependencies = IdentifyExternalDependencies(ipAddress, securityAudit);
            assessment.HasCloudServiceManagement = CheckCloudServices(ipAddress, securityAudit);
            assessment.HasThirdPartyMonitoring = CheckThirdPartyMonitoring(ipAddress, securityAudit);

            // Calculate third-party risk score
            var externalRiskCount = assessment.ExternalDependencies.Count;
            assessment.ThirdPartyRiskScore = Math.Max(0, 100 - (externalRiskCount * 10));

            // Identify third-party risks
            foreach (var dependency in assessment.ExternalDependencies)
            {
                assessment.ThirdPartyRisks.Add($"External dependency: {dependency}");
            }

            return await Task.FromResult(assessment);
        }

        /// <summary>
        /// Assesses Incident Reporting capabilities
        /// </summary>
        private async Task<IncidentReportingAssessment> AssessIncidentReportingAsync(IPAddress ipAddress, SecurityAuditResult securityAudit, CancellationToken cancellationToken)
        {
            var assessment = new IncidentReportingAssessment();

            // Check for logging and monitoring capabilities
            assessment.HasIncidentLogging = CheckIncidentLogging(ipAddress, securityAudit);
            assessment.HasSecurityEventMonitoring = CheckSecurityEventMonitoring(ipAddress, securityAudit);
            assessment.HasAutomatedAlerting = CheckAutomatedAlerting(ipAddress, securityAudit);

            // Calculate incident response score
            var responseFactors = new[] { assessment.HasIncidentLogging, assessment.HasSecurityEventMonitoring, assessment.HasAutomatedAlerting };
            assessment.IncidentResponseScore = (responseFactors.Count(f => f) * 33);

            // Identify incident response gaps
            if (!assessment.HasIncidentLogging)
                assessment.IncidentResponseGaps.Add("No incident logging capabilities detected");
            if (!assessment.HasSecurityEventMonitoring)
                assessment.IncidentResponseGaps.Add("No security event monitoring detected");
            if (!assessment.HasAutomatedAlerting)
                assessment.IncidentResponseGaps.Add("No automated alerting systems detected");

            return await Task.FromResult(assessment);
        }

        /// <summary>
        /// Assesses Information Sharing readiness
        /// </summary>
        private async Task<InformationSharingAssessment> AssessInformationSharingAsync(IPAddress ipAddress, SecurityAuditResult securityAudit, CancellationToken cancellationToken)
        {
            var assessment = new InformationSharingAssessment();

            // Check for secure communication capabilities
            assessment.HasSecureCommunication = CheckSecureCommunication(ipAddress, securityAudit);
            assessment.HasThreatIntelligenceSharing = CheckThreatIntelligence(ipAddress, securityAudit);
            assessment.HasInformationSharingProtocols = CheckInformationSharingProtocols(ipAddress, securityAudit);

            // Calculate information sharing score
            var sharingFactors = new[] { assessment.HasSecureCommunication, assessment.HasThreatIntelligenceSharing, assessment.HasInformationSharingProtocols };
            assessment.InformationSharingScore = (sharingFactors.Count(f => f) * 33);

            // Identify information sharing gaps
            if (!assessment.HasSecureCommunication)
                assessment.InformationSharingGaps.Add("No secure communication channels detected");
            if (!assessment.HasThreatIntelligenceSharing)
                assessment.InformationSharingGaps.Add("No threat intelligence sharing capabilities detected");
            if (!assessment.HasInformationSharingProtocols)
                assessment.InformationSharingGaps.Add("No information sharing protocols detected");

            return await Task.FromResult(assessment);
        }

        #region Helper Methods

        private bool CheckAccessControls(IPAddress ipAddress, SecurityAuditResult securityAudit)
        {
            // Check for authentication services (SSH, RDP, LDAP)
            var authServices = securityAudit.OpenPorts.Where(p => 
                p.Port == 22 || p.Port == 3389 || p.Port == 389 || p.Port == 636);
            return authServices.Any() && !securityAudit.Vulnerabilities.Any(v => v.Title.Contains("Authentication"));
        }

        private bool CheckSecurityMonitoring(IPAddress ipAddress, SecurityAuditResult securityAudit)
        {
            // Check for monitoring services (SNMP, syslog, etc.)
            var monitoringServices = securityAudit.OpenPorts.Where(p => 
                p.Port == 161 || p.Port == 514 || p.Port == 162);
            return monitoringServices.Any();
        }

        private bool CheckEncryption(IPAddress ipAddress, SecurityAuditResult securityAudit)
        {
            // Check for encrypted services (HTTPS, IMAPS, etc.)
            var encryptedServices = securityAudit.OpenPorts.Where(p => 
                p.Port == 443 || p.Port == 993 || p.Port == 995 || p.Port == 636);
            return encryptedServices.Any() && securityAudit.CertificateInfo != null;
        }

        private bool CheckBackupSystems(IPAddress ipAddress, SecurityAuditResult securityAudit)
        {
            // Check for backup-related services
            var backupServices = securityAudit.OpenPorts.Where(p => 
                p.ServiceName?.ToLower().Contains("backup") == true ||
                p.ServiceName?.ToLower().Contains("rsync") == true);
            return backupServices.Any();
        }

        private bool CheckRedundancy(IPAddress ipAddress, SecurityAuditResult securityAudit)
        {
            // Check for load balancing or clustering services
            var redundancyServices = securityAudit.OpenPorts.Where(p => 
                p.ServiceName?.ToLower().Contains("cluster") == true ||
                p.ServiceName?.ToLower().Contains("haproxy") == true);
            return redundancyServices.Any();
        }

        private bool CheckDisasterRecovery(IPAddress ipAddress, SecurityAuditResult securityAudit)
        {
            // Check for disaster recovery related services
            return securityAudit.OpenPorts.Any(p => 
                p.ServiceName?.ToLower().Contains("replication") == true ||
                p.ServiceName?.ToLower().Contains("sync") == true);
        }

        private bool CheckBusinessContinuity(IPAddress ipAddress, SecurityAuditResult securityAudit)
        {
            // Basic business continuity check based on service diversity
            var criticalServices = securityAudit.OpenPorts.Where(p => 
                p.Port == 80 || p.Port == 443 || p.Port == 22 || p.Port == 3389);
            return criticalServices.Count() >= 2;
        }

        private List<string> IdentifyExternalDependencies(IPAddress ipAddress, SecurityAuditResult securityAudit)
        {
            var dependencies = new List<string>();
            
            // Identify potential external services based on open ports
            foreach (var port in securityAudit.OpenPorts)
            {
                if (port.ServiceName?.ToLower().Contains("cloud") == true)
                    dependencies.Add($"Cloud service on port {port.Port}");
                if (port.ServiceName?.ToLower().Contains("api") == true)
                    dependencies.Add($"API service on port {port.Port}");
                if (port.Port == 443 && port.ServiceName?.Contains("external") == true)
                    dependencies.Add($"External HTTPS service on port {port.Port}");
            }

            return dependencies;
        }

        private bool CheckCloudServices(IPAddress ipAddress, SecurityAuditResult securityAudit)
        {
            return securityAudit.OpenPorts.Any(p => 
                p.ServiceName?.ToLower().Contains("cloud") == true ||
                p.ServiceName?.ToLower().Contains("aws") == true ||
                p.ServiceName?.ToLower().Contains("azure") == true);
        }

        private bool CheckThirdPartyMonitoring(IPAddress ipAddress, SecurityAuditResult securityAudit)
        {
            // Check for monitoring agents or third-party management tools
            return securityAudit.OpenPorts.Any(p => 
                p.ServiceName?.ToLower().Contains("agent") == true ||
                p.ServiceName?.ToLower().Contains("monitor") == true);
        }

        private bool CheckIncidentLogging(IPAddress ipAddress, SecurityAuditResult securityAudit)
        {
            // Check for logging services
            return securityAudit.OpenPorts.Any(p => 
                p.Port == 514 || // syslog
                p.ServiceName?.ToLower().Contains("log") == true);
        }

        private bool CheckSecurityEventMonitoring(IPAddress ipAddress, SecurityAuditResult securityAudit)
        {
            // Check for security monitoring services
            return securityAudit.OpenPorts.Any(p => 
                p.ServiceName?.ToLower().Contains("siem") == true ||
                p.ServiceName?.ToLower().Contains("security") == true);
        }

        private bool CheckAutomatedAlerting(IPAddress ipAddress, SecurityAuditResult securityAudit)
        {
            // Check for alerting services
            return securityAudit.OpenPorts.Any(p => 
                p.ServiceName?.ToLower().Contains("alert") == true ||
                p.ServiceName?.ToLower().Contains("notification") == true);
        }

        private bool CheckSecureCommunication(IPAddress ipAddress, SecurityAuditResult securityAudit)
        {
            // Check for secure communication protocols
            return securityAudit.OpenPorts.Any(p => 
                p.Port == 443 || p.Port == 22 || p.Port == 993 || p.Port == 995);
        }

        private bool CheckThreatIntelligence(IPAddress ipAddress, SecurityAuditResult securityAudit)
        {
            // Check for threat intelligence services
            return securityAudit.OpenPorts.Any(p => 
                p.ServiceName?.ToLower().Contains("threat") == true ||
                p.ServiceName?.ToLower().Contains("intelligence") == true);
        }

        private bool CheckInformationSharingProtocols(IPAddress ipAddress, SecurityAuditResult securityAudit)
        {
            // Check for information sharing protocols
            return securityAudit.OpenPorts.Any(p => 
                p.Port == 443 && p.ServiceName?.ToLower().Contains("api") == true);
        }

        #endregion

        #region Score Calculation and Reporting

        private int CalculateComplianceScore(DoraComplianceResult result)
        {
            var scores = new[]
            {
                result.IctRiskManagement.SecurityControlsScore,
                result.DigitalResilience.ResilienceScore,
                result.ThirdPartyRisk.ThirdPartyRiskScore,
                result.IncidentReporting.IncidentResponseScore,
                result.InformationSharing.InformationSharingScore
            };

            return (int)scores.Average();
        }

        private List<DoraComplianceIssue> GenerateComplianceIssues(DoraComplianceResult result)
        {
            var issues = new List<DoraComplianceIssue>();

            // ICT Risk Management issues
            if (!result.IctRiskManagement.HasRiskManagementFramework)
            {
                issues.Add(new DoraComplianceIssue
                {
                    Id = "DORA-ICT-001",
                    Title = "Missing ICT Risk Management Framework",
                    Description = "No comprehensive ICT risk management framework detected",
                    Category = DoraRequirementCategory.IctRiskManagement,
                    Severity = DoraSeverity.High,
                    DoraReference = "Article 5 - ICT risk management framework",
                    Remediation = "Implement a comprehensive ICT risk management framework covering all critical ICT services"
                });
            }

            // Digital Resilience issues
            if (result.DigitalResilience.ResilienceScore < 50)
            {
                issues.Add(new DoraComplianceIssue
                {
                    Id = "DORA-RES-001",
                    Title = "Insufficient Digital Operational Resilience",
                    Description = "Digital operational resilience capabilities are below required standards",
                    Category = DoraRequirementCategory.DigitalOperationalResilience,
                    Severity = DoraSeverity.High,
                    DoraReference = "Article 11 - Digital operational resilience testing",
                    Remediation = "Implement comprehensive business continuity and disaster recovery capabilities"
                });
            }

            // Incident Reporting issues
            if (result.IncidentReporting.IncidentResponseScore < 50)
            {
                issues.Add(new DoraComplianceIssue
                {
                    Id = "DORA-INC-001",
                    Title = "Inadequate Incident Reporting Capabilities",
                    Description = "Incident reporting and response capabilities are insufficient",
                    Category = DoraRequirementCategory.IncidentReporting,
                    Severity = DoraSeverity.Medium,
                    DoraReference = "Article 17 - Incident reporting",
                    Remediation = "Establish comprehensive incident logging, monitoring, and automated alerting systems"
                });
            }

            return issues;
        }

        private List<string> GenerateRecommendations(DoraComplianceResult result)
        {
            var recommendations = new List<string>();

            if (result.ComplianceScore < 70)
            {
                recommendations.Add("Develop and implement a comprehensive DORA compliance program");
                recommendations.Add("Conduct regular digital operational resilience testing");
                recommendations.Add("Establish formal incident reporting and response procedures");
            }

            if (!result.IctRiskManagement.HasRiskManagementFramework)
            {
                recommendations.Add("Implement an enterprise-wide ICT risk management framework");
                recommendations.Add("Establish regular security assessments and vulnerability management");
            }

            if (result.DigitalResilience.ResilienceScore < 75)
            {
                recommendations.Add("Enhance business continuity and disaster recovery capabilities");
                recommendations.Add("Implement redundancy and backup systems for critical services");
            }

            return recommendations;
        }

        private string GenerateSummary(DoraComplianceResult result)
        {
            var complianceLevel = result.ComplianceScore switch
            {
                >= 90 => "Excellent",
                >= 75 => "Good",
                >= 60 => "Adequate",
                >= 40 => "Poor",
                _ => "Critical"
            };

            return $"DORA Compliance Assessment: {complianceLevel} ({result.ComplianceScore}/100). " +
                   $"Identified {result.ComplianceIssues.Count} compliance issues requiring attention. " +
                   $"Key areas for improvement: ICT Risk Management ({result.IctRiskManagement.SecurityControlsScore}/100), " +
                   $"Digital Resilience ({result.DigitalResilience.ResilienceScore}/100), " +
                   $"Incident Response ({result.IncidentReporting.IncidentResponseScore}/100).";
        }

        #endregion
    }
}