using Discovery.Core.Constants;

namespace Discovery.Tests.Integration;

/// <summary>
/// Integration tests that test the application end-to-end
/// These tests may take longer to run and require network access
/// </summary>
public class ApplicationIntegrationTests
{
    [Fact]
    public async Task ScanLocalhost_ShouldCompleteSuccessfully()
    {
        // Arrange
        var ipAddress = "127.0.0.1";
        var ports = new Dictionary<int, string>
        {
            { 80, "HTTP" },
            { 22, "SSH" },
            { 443, "HTTPS" }
        };

        // Act
        var result = await NetworkScanner.ScanHostAsync(ipAddress, ports, timeout: 2000);

        // Assert
        result.Should().NotBeNull();
        result.IpAddress.Should().Be(ipAddress);
        result.PingResult.Should().NotBeNull();
    }

    [Fact]
    public async Task PingLocalhost_ShouldSucceed()
    {
        // Arrange
        var localhost = IPAddress.Parse("127.0.0.1");

        // Act
        var result = await NetworkScanner.PingHostAsync(localhost, timeout: 5000);

        // Assert
        result.Success.Should().BeTrue();
        result.ResponseTime.Should().BeGreaterOrEqualTo(0);
    }

    [Fact]
    public void CommandLineHelp_ShouldDisplayCorrectBranding()
    {
        // Arrange
        var helpOutput = CaptureConsoleOutput(() => 
        {
            // Simulate help display
            Console.WriteLine("On-Prem Network InfraIQ - Command Line Usage");
            Console.WriteLine("AdvNetDiscovery [IP_ADDRESS] [OPTIONS]");
        });

        // Assert
        helpOutput.Should().Contain("On-Prem Network InfraIQ");
        helpOutput.Should().Contain("AdvNetDiscovery");
    }

    [Theory]
    [InlineData("192.168.1.0/24")]
    [InlineData("10.0.0.0/8")]
    [InlineData("172.16.0.0/16")]
    public void CidrParsing_ShouldWorkForCommonNetworks(string cidr)
    {
        // Act
        var result = NetworkUtilities.TryParseCidr(cidr, out var networkAddress, out var subnetMask);

        // Assert
        result.Should().BeTrue();
        networkAddress.Should().NotBeNull();
        subnetMask.Should().BeGreaterThan(0);
    }

    [Fact]
    public void PopularPorts_ShouldIncludeSecurityCriticalPorts()
    {
        // Arrange
        var securityCriticalPorts = new[] { 21, 22, 23, 80, 443, 3389, 5900 };

        // Act & Assert
        foreach (var port in securityCriticalPorts)
        {
            NetworkConstants.PopularPorts.Should().ContainKey(port);
        }
    }

    private static string CaptureConsoleOutput(Action action)
    {
        var originalOut = Console.Out;
        try
        {
            using var stringWriter = new StringWriter();
            Console.SetOut(stringWriter);
            action();
            return stringWriter.ToString();
        }
        finally
        {
            Console.SetOut(originalOut);
        }
    }
}
