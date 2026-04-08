using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;
using Xunit;
using FluentAssertions;
using Discovery.Core.Models;
using Discovery.Core.Interfaces;

namespace Discovery.Tests.Core
{
    /// <summary>
    /// Comprehensive tests for core interfaces and models
    /// </summary>
    public class CoreInterfacesTests
    {
        [Fact]
        public void IScanner_Interface_ShouldExist()
        {
            // Arrange
            var interfaceType = typeof(IScanner);

            // Assert
            interfaceType.Should().NotBeNull();
            interfaceType.IsInterface.Should().BeTrue();
        }

        [Fact]
        public void INetworkCalculator_Interface_ShouldExist()
        {
            // Arrange
            var interfaceType = typeof(INetworkCalculator);

            // Assert
            interfaceType.Should().NotBeNull();
            interfaceType.IsInterface.Should().BeTrue();
        }

        [Fact]
        public void IExporter_Interface_ShouldExist()
        {
            // Arrange
            var interfaceType = typeof(IExporter);

            // Assert
            interfaceType.Should().NotBeNull();
            interfaceType.IsInterface.Should().BeTrue();
        }

        [Fact]
        public void VulnerabilityInfo_Model_ShouldInitializeCorrectly()
        {
            // Arrange & Act
            var vulnInfo = new VulnerabilityInfo
            {
                Host = "192.168.1.100",
                Port = 22,
                Severity = VulnerabilitySeverity.High,
                Title = "SSH Weak Encryption",
                Description = "SSH server supports weak encryption algorithms",
                RecommendedFix = "Update SSH configuration to use strong encryption"
            };

            // Assert
            vulnInfo.Host.Should().Be("192.168.1.100");
            vulnInfo.Port.Should().Be(22);
            vulnInfo.Severity.Should().Be(VulnerabilitySeverity.High);
            vulnInfo.Title.Should().Be("SSH Weak Encryption");
            vulnInfo.Description.Should().Be("SSH server supports weak encryption algorithms");
            vulnInfo.RecommendedFix.Should().Be("Update SSH configuration to use strong encryption");
        }

        [Theory]
        [InlineData(VulnerabilitySeverity.Critical)]
        [InlineData(VulnerabilitySeverity.High)]
        [InlineData(VulnerabilitySeverity.Medium)]
        [InlineData(VulnerabilitySeverity.Low)]
        [InlineData(VulnerabilitySeverity.Info)]
        public void VulnerabilitySeverity_Enum_ShouldHaveAllValues(VulnerabilitySeverity severity)
        {
            // Act & Assert
            Enum.IsDefined(typeof(VulnerabilitySeverity), severity).Should().BeTrue();
        }

        [Fact]
        public void ScanResult_Model_ShouldInitializeCorrectly()
        {
            // Arrange & Act
            var scanResult = new ScanResult(
                IPAddress.Parse("192.168.1.100"),
                22,
                true,
                "SSH",
                15,
                "Linux Ubuntu 20.04",
                "OpenSSH 8.2",
                DateTime.UtcNow,
                "US",
                "web-server-01",
                false,
                "",
                "SSH"
            );

            // Assert
            scanResult.IpAddress.Should().Be(IPAddress.Parse("192.168.1.100"));
            scanResult.Port.Should().Be(22);
            scanResult.IsOpen.Should().BeTrue();
        }

        [Fact]
        public void NetworkRange_Model_ShouldInitializeCorrectly()
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
        public void CertificateInfo_Model_ShouldInitializeCorrectly()
        {
            // Arrange & Act
            var certInfo = new CertificateInfo
            {
                Subject = "CN=example.com",
                Issuer = "CN=Let's Encrypt Authority X3",
                NotBefore = DateTime.UtcNow.AddDays(-30),
                ExpirationDate = DateTime.UtcNow.AddDays(60),
                SerialNumber = "1234567890ABCDEF",
                IsValid = true
            };

            // Assert
            certInfo.Subject.Should().Be("CN=example.com");
            certInfo.Issuer.Should().Be("CN=Let's Encrypt Authority X3");
            certInfo.SerialNumber.Should().Be("1234567890ABCDEF");
            certInfo.IsValid.Should().BeTrue();
        }

        [Fact]
        public void PortSecurityAuditResult_Model_ShouldInitializeCorrectly()
        {
            // Arrange & Act
            var portAuditResult = new PortSecurityAuditResult
            {
                Host = "192.168.1.100",
                Port = 443,
                ServiceName = "HTTPS",
                HasIssues = false
            };

            // Assert
            portAuditResult.Host.Should().Be("192.168.1.100");
            portAuditResult.Port.Should().Be(443);
            portAuditResult.ServiceName.Should().Be("HTTPS");
            portAuditResult.HasIssues.Should().BeFalse();
        }

        [Fact]
        public void NetworkInfo_Model_ShouldInitializeCorrectly()
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

        [Theory]
        [InlineData("192.168.1.100", 22)]
        [InlineData("10.0.0.1", 443)]
        [InlineData("172.16.0.1", 80)]
        public void VulnerabilityInfo_WithDifferentTargets_ShouldInitializeCorrectly(string host, int port)
        {
            // Arrange & Act
            var vulnInfo = new VulnerabilityInfo
            {
                Host = host,
                Port = port,
                Severity = VulnerabilitySeverity.Low,
                Title = "Test Vulnerability",
                Description = "Test description"
            };

            // Assert
            vulnInfo.Host.Should().Be(host);
            vulnInfo.Port.Should().Be(port);
            vulnInfo.Severity.Should().Be(VulnerabilitySeverity.Low);
        }

        [Fact]
        public void VulnerabilityInfo_WithNullValues_ShouldHandleGracefully()
        {
            // Arrange & Act
            var vulnInfo = new VulnerabilityInfo();

            // Assert
            vulnInfo.Host.Should().BeNullOrEmpty();
            vulnInfo.Title.Should().BeNullOrEmpty();
            vulnInfo.Description.Should().BeNullOrEmpty();
            vulnInfo.RecommendedFix.Should().BeNullOrEmpty();
        }
    }
}