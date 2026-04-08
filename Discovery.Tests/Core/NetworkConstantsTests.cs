using Discovery.Core.Constants;

namespace Discovery.Tests.Core;

public class NetworkConstantsTests
{
    [Fact]
    public void PopularPorts_ShouldContainCommonPorts()
    {
        // Arrange & Act
        var popularPorts = NetworkConstants.PopularPorts;

        // Assert
        popularPorts.Should().NotBeEmpty();
        popularPorts.Should().ContainKey(22).WhoseValue.Should().Be("SSH");
        popularPorts.Should().ContainKey(80).WhoseValue.Should().Be("HTTP");
        popularPorts.Should().ContainKey(443).WhoseValue.Should().Be("HTTPS");
        popularPorts.Should().ContainKey(3389).WhoseValue.Should().Be("RDP");
    }

    [Fact]
    public void PopularPorts_ShouldHaveValidPortNumbers()
    {
        // Arrange & Act
        var popularPorts = NetworkConstants.PopularPorts;

        // Assert
        foreach (var port in popularPorts.Keys)
        {
            port.Should().BeGreaterThan(0);
            port.Should().BeLessOrEqualTo(65535);
        }
    }

    [Fact]
    public void PopularPorts_ShouldHaveNonEmptyServiceNames()
    {
        // Arrange & Act
        var popularPorts = NetworkConstants.PopularPorts;

        // Assert
        foreach (var serviceName in popularPorts.Values)
        {
            serviceName.Should().NotBeNullOrWhiteSpace();
        }
    }

    [Theory]
    [InlineData(21, "FTP")]
    [InlineData(23, "Telnet")]
    [InlineData(25, "SMTP")]
    [InlineData(53, "DNS")]
    [InlineData(110, "POP3")]
    [InlineData(143, "IMAP")]
    [InlineData(993, "IMAPS")]
    [InlineData(995, "POP3S")]
    public void PopularPorts_ShouldContainSpecificServices(int port, string expectedService)
    {
        // Arrange & Act
        var popularPorts = NetworkConstants.PopularPorts;

        // Assert
        popularPorts.Should().ContainKey(port).WhoseValue.Should().Be(expectedService);
    }
}
