namespace Discovery.Tests.Tools;

public class NetworkUtilitiesTests
{
    [Theory]
    [InlineData("192.168.1.0/24", true)]
    [InlineData("10.0.0.0/8", true)]
    [InlineData("172.16.0.0/16", true)]
    [InlineData("192.168.1.0/32", true)]
    [InlineData("192.168.1.0/0", true)]
    [InlineData("192.168.1.256/24", false)]
    [InlineData("192.168.1.0/33", false)]
    [InlineData("192.168.1.0/-1", false)]
    [InlineData("not.an.ip/24", false)]
    [InlineData("192.168.1.0", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void TryParseCidr_ShouldValidateInput(string? input, bool expectedResult)
    {
        // Arrange & Act
        var result = NetworkUtilities.TryParseCidr(input!, out var networkAddress, out var subnetMask);

        // Assert
        result.Should().Be(expectedResult);
        
        if (expectedResult)
        {
            networkAddress.Should().NotBeNull();
            subnetMask.Should().BeGreaterThanOrEqualTo(0).And.BeLessOrEqualTo(32);
        }
        else
        {
            networkAddress.Should().BeNull();
            subnetMask.Should().Be(0);
        }
    }

    [Fact]
    public void TryParseCidr_ShouldParseValidCidr()
    {
        // Arrange
        var cidr = "192.168.1.0/24";

        // Act
        var result = NetworkUtilities.TryParseCidr(cidr, out var networkAddress, out var subnetMask);

        // Assert
        result.Should().BeTrue();
        networkAddress.Should().NotBeNull();
        networkAddress!.ToString().Should().Be("192.168.1.0");
        subnetMask.Should().Be(24);
    }

    [Theory]
    [InlineData(64, "Linux/Unix")]
    [InlineData(32, "Linux/Unix")]
    [InlineData(128, "Windows")]
    [InlineData(100, "Windows")]
    [InlineData(255, "Cisco/Network Device")]
    [InlineData(200, "Cisco/Network Device")]
    [InlineData(300, "Unknown")]
    [InlineData(0, "Linux/Unix")]
    public void GuessOperatingSystem_ShouldReturnCorrectOS(int ttl, string expectedOS)
    {
        // Arrange & Act
        var result = NetworkUtilities.GuessOperatingSystem(ttl);

        // Assert
        result.Should().Be(expectedOS);
    }

    [Theory]
    [InlineData("192.168.1.1", true)]
    [InlineData("10.0.0.1", true)]
    [InlineData("172.16.0.1", true)]
    [InlineData("127.0.0.1", true)]
    [InlineData("255.255.255.255", true)]
    [InlineData("0.0.0.0", true)]
    [InlineData("256.1.1.1", false)]
    [InlineData("1.1.1", true)]
    [InlineData("not.an.ip", false)]
    [InlineData("", false)]
    public void IsValidIPAddress_ShouldValidateCorrectly(string ipAddress, bool expectedResult)
    {
        // Arrange & Act
        var result = NetworkUtilities.IsValidIPAddress(ipAddress);

        // Assert
        result.Should().Be(expectedResult);
    }

    [Theory]
    [InlineData(1, 65535, true)]
    [InlineData(80, 80, true)]
    [InlineData(1, 1024, true)]
    [InlineData(0, 1, false)]
    [InlineData(1, 65536, false)]
    [InlineData(-1, 100, false)]
    [InlineData(100, 50, false)]
    public void IsValidPortRange_ShouldValidateCorrectly(int startPort, int endPort, bool expectedResult)
    {
        // Arrange & Act
        var result = NetworkUtilities.IsValidPortRange(startPort, endPort);

        // Assert
        result.Should().Be(expectedResult);
    }

    [Theory]
    [InlineData("80,443,22", 3)]
    [InlineData("80", 1)]
    [InlineData("80,443,8080-8090", 13)] // 80, 443, plus 8080-8090 (11 ports)
    [InlineData("1-10", 10)]
    [InlineData("", 0)]
    public void ParseCustomPorts_ShouldParseCorrectly(string portsString, int expectedCount)
    {
        // Arrange & Act
        var result = NetworkUtilities.ParseCustomPorts(portsString);

        // Assert
        result.Should().HaveCount(expectedCount);
        
        if (expectedCount > 0)
        {
            foreach (var port in result.Keys)
            {
                port.Should().BeGreaterThan(0).And.BeLessOrEqualTo(65535);
            }
        }
    }

    [Fact]
    public void ParseCustomPorts_ShouldHandlePortRanges()
    {
        // Arrange
        var portsString = "8080-8085";

        // Act
        var result = NetworkUtilities.ParseCustomPorts(portsString);

        // Assert
        result.Should().HaveCount(6);
        result.Should().ContainKeys(8080, 8081, 8082, 8083, 8084, 8085);
    }

    [Fact]
    public void ParseCustomPorts_ShouldIgnoreInvalidPorts()
    {
        // Arrange
        var portsString = "80,invalid,443,70000";

        // Act
        var result = NetworkUtilities.ParseCustomPorts(portsString);

        // Assert
        result.Should().HaveCount(2);
        result.Should().ContainKeys(80, 443);
    }

    [Theory]
    [InlineData("192.168.1.0", "255.255.255.0", "192.168.1.", 1, 254)]
    [InlineData("10.0.0.0", "255.0.0.0", "10.", 0, 255)]
    [InlineData("172.16.0.0", "255.255.0.0", "172.16.", 0, 255)]
    public void CalculateNetworkRange_ShouldCalculateCorrectly(string networkIp, string subnetMask,
        string expectedBaseIp, int expectedStart, int expectedEnd)
    {
        // Arrange
        var network = IPAddress.Parse(networkIp);
        var mask = IPAddress.Parse(subnetMask);

        // Act
        var result = NetworkUtilities.CalculateNetworkRange(network, mask);

        // Assert
        result.BaseIp.Should().StartWith(expectedBaseIp);
        result.StartRange.Should().BeGreaterOrEqualTo(expectedStart);
        result.EndRange.Should().BeLessOrEqualTo(expectedEnd);
        result.StartRange.Should().BeLessOrEqualTo(result.EndRange);
    }
}
