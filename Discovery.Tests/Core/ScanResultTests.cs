using System.Collections.Generic;
using System.Linq;
using System.Net;
using Discovery.Core.Models;
using Discovery.Tools;
using FluentAssertions;
using Xunit;

namespace Discovery.Tests.Core;

public class ScanResultTests
{
    [Fact]
    public void ScanResult_ShouldInitializeWithDefaultValues()
    {
        // Arrange
        var ipAddress = IPAddress.Parse("192.168.1.1");
        
        // Act
        var result = new ScanResult(ipAddress, 80, false);

        // Assert
        result.IpAddress.Should().Be(ipAddress);
        result.Port.Should().Be(80);
        result.IsOpen.Should().BeFalse();
        result.Service.Should().BeEmpty();
        result.PingTime.Should().BeNull();
        result.OperatingSystem.Should().BeEmpty();
        result.ServerInfo.Should().BeEmpty();
    }

    [Fact]
    public void ScanResult_ShouldSetPropertiesCorrectly()
    {
        // Arrange
        var ipAddress = IPAddress.Parse("192.168.1.1");
        var port = 80;
        var service = "HTTP";
        var pingTime = 25L;
        var operatingSystem = "Linux";
        var serverInfo = "Apache/2.4.41";

        // Act
        var result = new ScanResult(
            ipAddress,
            port,
            true,
            service,
            pingTime,
            operatingSystem,
            serverInfo);

        // Assert
        result.IpAddress.Should().Be(ipAddress);
        result.Port.Should().Be(port);
        result.IsOpen.Should().BeTrue();
        result.Service.Should().Be(service);
        result.PingTime.Should().Be(pingTime);
        result.OperatingSystem.Should().Be(operatingSystem);
        result.ServerInfo.Should().Be(serverInfo);
    }

    [Theory]
    [InlineData("192.168.1.1", 22, "SSH", 15, "Linux", "OpenSSH_8.0")]
    [InlineData("10.0.0.1", 443, "HTTPS", 45, "Windows", "IIS/10.0")]
    [InlineData("172.16.0.1", 3389, "RDP", 8, "Windows", "")]
    public void ScanResult_ShouldHandleVariousInputs(string ip, int port, string service, 
        long pingTime, string os, string serverInfo)
    {
        // Arrange
        var ipAddress = IPAddress.Parse(ip);
        
        // Act
        var result = new ScanResult(
            ipAddress,
            port,
            true,
            service,
            pingTime,
            os,
            serverInfo);

        // Assert
        result.IpAddress.Should().Be(ipAddress);
        result.Port.Should().Be(port);
        result.Service.Should().Be(service);
        result.PingTime.Should().Be(pingTime);
        result.OperatingSystem.Should().Be(os);
        result.ServerInfo.Should().Be(string.IsNullOrEmpty(serverInfo) ? "" : serverInfo);
    }

    [Fact]
    public void ScanResult_ShouldAllowEmptyServerInfo()
    {
        // Arrange
        var ipAddress = IPAddress.Parse("192.168.1.1");
        
        // Act
        var result = new ScanResult(
            ipAddress,
            80,
            true,
            "HTTP",
            25,
            "Linux",
            ""); // Empty server info

        // Assert
        result.ServerInfo.Should().BeEmpty();
    }

    [Fact]
    public void ScanResults_ShouldSortByIpAddressWithCustomComparer()
    {
        // Arrange
        var results = new List<ScanResult>
        {
            new(IPAddress.Parse("192.168.1.10"), 80, true, "HTTP"),
            new(IPAddress.Parse("10.0.0.5"), 443, true, "HTTPS"), 
            new(IPAddress.Parse("172.16.0.1"), 22, true, "SSH"),
            new(IPAddress.Parse("192.168.1.1"), 80, true, "HTTP")
        };

        // Act - This should not throw an exception when using proper comparer
        var sortedResults = results.OrderBy(r => r.IpAddress, new IpAddressComparer()).ToList();

        // Assert
        sortedResults.Should().HaveCount(4);
        sortedResults[0].IpAddress.ToString().Should().Be("10.0.0.5");
        sortedResults[1].IpAddress.ToString().Should().Be("172.16.0.1"); 
        sortedResults[2].IpAddress.ToString().Should().Be("192.168.1.1");
        sortedResults[3].IpAddress.ToString().Should().Be("192.168.1.10");
    }

    [Fact]
    public void ScanResults_SortingByIpAddressWithoutComparer_ShouldThrowException()
    {
        // Arrange
        var results = new List<ScanResult>
        {
            new(IPAddress.Parse("192.168.1.10"), 80, true, "HTTP"),
            new(IPAddress.Parse("10.0.0.5"), 443, true, "HTTPS")
        };

        // Act & Assert - This demonstrates the bug we're fixing
        var act = () => results.OrderBy(r => r.IpAddress).ToList();
        act.Should().Throw<InvalidOperationException>()
           .WithMessage("Failed to compare two elements in the array.");
    }
}
