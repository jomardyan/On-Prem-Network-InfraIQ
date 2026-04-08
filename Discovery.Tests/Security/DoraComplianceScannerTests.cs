using Discovery.Core.Models;
using Discovery.Services.Security;
using System.Net;

namespace Discovery.Tests.Security
{
    public class DoraComplianceScannerTests
    {
        private readonly DoraComplianceScanner _scanner;

        public DoraComplianceScannerTests()
        {
            _scanner = new DoraComplianceScanner();
        }

        [Fact]
        public async Task AssessComplianceAsync_WithValidIpAddress_ReturnsResult()
        {
            // Arrange
            var target = "127.0.0.1";

            // Act
            var result = await _scanner.AssessComplianceAsync(target);

            // Assert
            result.Should().NotBeNull();
            result.Target.Should().Be(target);
            result.AssessmentDate.Should().NotBe(default(DateTime));
            result.ComplianceScore.Should().BeInRange(0, 100);
        }

        [Fact]
        public async Task AssessComplianceAsync_WithInvalidTarget_ReturnsErrorResult()
        {
            // Arrange
            var target = "invalid.hostname.that.does.not.exist.local";

            // Act
            var result = await _scanner.AssessComplianceAsync(target);

            // Assert
            result.Should().NotBeNull();
            result.Summary.Should().ContainAny("Unable to resolve", "Assessment failed");
        }

        [Fact]
        public void DoraComplianceResult_HasCorrectStructure()
        {
            // Arrange & Act
            var result = new DoraComplianceResult();

            // Assert
            result.IctRiskManagement.Should().NotBeNull();
            result.DigitalResilience.Should().NotBeNull();
            result.ThirdPartyRisk.Should().NotBeNull();
            result.IncidentReporting.Should().NotBeNull();
            result.InformationSharing.Should().NotBeNull();
            result.ComplianceIssues.Should().NotBeNull();
            result.Recommendations.Should().NotBeNull();
        }

        [Fact]
        public void DoraComplianceIssue_HasCorrectProperties()
        {
            // Arrange & Act
            var issue = new DoraComplianceIssue
            {
                Id = "DORA-TEST-001",
                Title = "Test Issue",
                Description = "Test Description",
                Category = DoraRequirementCategory.IctRiskManagement,
                Severity = DoraSeverity.High,
                DoraReference = "Article 5",
                Remediation = "Test remediation"
            };

            // Assert
            issue.Id.Should().Be("DORA-TEST-001");
            issue.Title.Should().Be("Test Issue");
            issue.Category.Should().Be(DoraRequirementCategory.IctRiskManagement);
            issue.Severity.Should().Be(DoraSeverity.High);
        }

        [Fact]
        public void IctRiskManagementAssessment_InitializesCorrectly()
        {
            // Arrange & Act
            var assessment = new IctRiskManagementAssessment();

            // Assert
            assessment.SecurityGaps.Should().NotBeNull();
            assessment.SecurityControlsScore.Should().Be(0);
            assessment.HasRiskManagementFramework.Should().BeFalse();
            assessment.HasAccessControls.Should().BeFalse();
            assessment.HasSecurityMonitoring.Should().BeFalse();
            assessment.HasProperEncryption.Should().BeFalse();
        }

        [Fact]
        public void DigitalResilienceAssessment_InitializesCorrectly()
        {
            // Arrange & Act
            var assessment = new DigitalResilienceAssessment();

            // Assert
            assessment.ResilienceGaps.Should().NotBeNull();
            assessment.ResilienceScore.Should().Be(0);
            assessment.HasBusinessContinuityPlans.Should().BeFalse();
            assessment.HasBackupSystems.Should().BeFalse();
            assessment.HasRedundancy.Should().BeFalse();
            assessment.HasDisasterRecovery.Should().BeFalse();
        }

        [Fact]
        public void ThirdPartyRiskAssessment_InitializesCorrectly()
        {
            // Arrange & Act
            var assessment = new ThirdPartyRiskAssessment();

            // Assert
            assessment.ExternalDependencies.Should().NotBeNull();
            assessment.ThirdPartyRisks.Should().NotBeNull();
            assessment.ThirdPartyRiskScore.Should().Be(0);
            assessment.HasThirdPartyMonitoring.Should().BeFalse();
            assessment.HasCloudServiceManagement.Should().BeFalse();
        }

        [Fact]
        public void IncidentReportingAssessment_InitializesCorrectly()
        {
            // Arrange & Act
            var assessment = new IncidentReportingAssessment();

            // Assert
            assessment.IncidentResponseGaps.Should().NotBeNull();
            assessment.IncidentResponseScore.Should().Be(0);
            assessment.HasIncidentLogging.Should().BeFalse();
            assessment.HasSecurityEventMonitoring.Should().BeFalse();
            assessment.HasAutomatedAlerting.Should().BeFalse();
        }

        [Fact]
        public void InformationSharingAssessment_InitializesCorrectly()
        {
            // Arrange & Act
            var assessment = new InformationSharingAssessment();

            // Assert
            assessment.InformationSharingGaps.Should().NotBeNull();
            assessment.InformationSharingScore.Should().Be(0);
            assessment.HasSecureCommunication.Should().BeFalse();
            assessment.HasThreatIntelligenceSharing.Should().BeFalse();
            assessment.HasInformationSharingProtocols.Should().BeFalse();
        }

        [Fact]
        [Trait("Category", "Integration")]
        public async Task AssessComplianceAsync_WithLocalhost_GeneratesComprehensiveReport()
        {
            // Arrange
            var target = "127.0.0.1";

            // Act
            var result = await _scanner.AssessComplianceAsync(target);

            // Assert
            result.Should().NotBeNull();
            result.Summary.Should().NotBeEmpty();
            result.ComplianceScore.Should().BeInRange(0, 100);
            
            // Verify all assessment components are present
            result.IctRiskManagement.Should().NotBeNull();
            result.DigitalResilience.Should().NotBeNull();
            result.ThirdPartyRisk.Should().NotBeNull();
            result.IncidentReporting.Should().NotBeNull();
            result.InformationSharing.Should().NotBeNull();

            // Verify collections are initialized
            result.ComplianceIssues.Should().NotBeNull();
            result.Recommendations.Should().NotBeNull();
        }

        [Fact]
        public void DoraRequirementCategory_EnumHasAllExpectedValues()
        {
            // Arrange & Act
            var categories = Enum.GetValues<DoraRequirementCategory>();

            // Assert
            categories.Should().Contain(DoraRequirementCategory.IctRiskManagement);
            categories.Should().Contain(DoraRequirementCategory.IncidentReporting);
            categories.Should().Contain(DoraRequirementCategory.DigitalOperationalResilience);
            categories.Should().Contain(DoraRequirementCategory.ThirdPartyRiskManagement);
            categories.Should().Contain(DoraRequirementCategory.InformationSharing);
        }

        [Fact]
        public void DoraSeverity_EnumHasAllExpectedValues()
        {
            // Arrange & Act
            var severities = Enum.GetValues<DoraSeverity>();

            // Assert
            severities.Should().Contain(DoraSeverity.Low);
            severities.Should().Contain(DoraSeverity.Medium);
            severities.Should().Contain(DoraSeverity.High);
            severities.Should().Contain(DoraSeverity.Critical);
        }
    }
}