using System;
using System.Net;
using Xunit;
using FluentAssertions;
using Discovery.Core.Models;

namespace Discovery.Tests.Core
{
    /// <summary>
    /// Simple additional tests for core models with actual properties
    /// </summary>
    public class SimpleModelTests
    {
        [Fact]
        public void ScanResult_WithBasicData_ShouldInitializeCorrectly()
        {
            // Arrange & Act
            var scanResult = new ScanResult(
                IPAddress.Parse("192.168.1.100"),
                80,
                true,
                "HTTP",
                100,
                "Linux",
                "Apache",
                DateTime.UtcNow,
                "US",
                "webserver",
                false,
                "",
                "HTTP"
            );

            // Assert
            scanResult.IpAddress.Should().Be(IPAddress.Parse("192.168.1.100"));
            scanResult.Port.Should().Be(80);
            scanResult.IsOpen.Should().BeTrue();
        }

        [Fact]
        public void VulnerabilityInfo_WithBasicData_ShouldInitializeCorrectly()
        {
            // Arrange & Act
            var vulnInfo = new VulnerabilityInfo
            {
                Host = "192.168.1.100",
                Port = 22,
                Severity = VulnerabilitySeverity.Medium,
                Title = "SSH Test Vulnerability",
                Description = "Test description",
                RecommendedFix = "Test fix"
            };

            // Assert
            vulnInfo.Host.Should().Be("192.168.1.100");
            vulnInfo.Port.Should().Be(22);
            vulnInfo.Severity.Should().Be(VulnerabilitySeverity.Medium);
            vulnInfo.Title.Should().Be("SSH Test Vulnerability");
        }

        [Fact]
        public void CertificateInfo_WithBasicData_ShouldInitializeCorrectly()
        {
            // Arrange & Act
            var certInfo = new CertificateInfo
            {
                Subject = "CN=example.com",
                Issuer = "CN=Test CA",
                SerialNumber = "123456",
                NotBefore = DateTime.UtcNow.AddDays(-30),
                ExpirationDate = DateTime.UtcNow.AddDays(30),
                IsValid = true
            };

            // Assert
            certInfo.Subject.Should().Be("CN=example.com");
            certInfo.Issuer.Should().Be("CN=Test CA");
            certInfo.IsValid.Should().BeTrue();
        }

        [Fact]
        public void NetworkRange_WithBasicData_ShouldInitializeCorrectly()
        {
            // Arrange & Act
            var networkRange = new NetworkRange
            {
                StartIp = IPAddress.Parse("192.168.1.1"),
                EndIp = IPAddress.Parse("192.168.1.254"),
                TotalHosts = 254
            };

            // Assert
            networkRange.StartIp.Should().Be(IPAddress.Parse("192.168.1.1"));
            networkRange.EndIp.Should().Be(IPAddress.Parse("192.168.1.254"));
            networkRange.TotalHosts.Should().Be(254);
        }

        [Fact]
        public void PortSecurityAuditResult_WithBasicData_ShouldInitializeCorrectly()
        {
            // Arrange & Act
            var portAudit = new PortSecurityAuditResult
            {
                Host = "192.168.1.100",
                Port = 443,
                ServiceName = "HTTPS",
                HasIssues = false
            };

            // Assert
            portAudit.Host.Should().Be("192.168.1.100");
            portAudit.Port.Should().Be(443);
            portAudit.ServiceName.Should().Be("HTTPS");
            portAudit.HasIssues.Should().BeFalse();
        }

        [Theory]
        [InlineData(VulnerabilitySeverity.Critical)]
        [InlineData(VulnerabilitySeverity.High)]
        [InlineData(VulnerabilitySeverity.Medium)]
        [InlineData(VulnerabilitySeverity.Low)]
        [InlineData(VulnerabilitySeverity.Info)]
        public void VulnerabilitySeverity_AllValues_ShouldBeDefined(VulnerabilitySeverity severity)
        {
            // Act & Assert
            Enum.IsDefined(typeof(VulnerabilitySeverity), severity).Should().BeTrue();
        }

        [Fact]
        public void NetworkInfo_WithBasicData_ShouldInitializeCorrectly()
        {
            // Arrange & Act
            var networkInfo = new Discovery.Core.Models.NetworkInfo
            {
                IpAddress = IPAddress.Parse("192.168.1.100"),
                SubnetMask = IPAddress.Parse("255.255.255.0")
            };

            // Assert
            networkInfo.IpAddress.Should().Be(IPAddress.Parse("192.168.1.100"));
            networkInfo.SubnetMask.Should().Be(IPAddress.Parse("255.255.255.0"));
        }
    }
}