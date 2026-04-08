namespace Discovery.Tests.Tools;

public class NetworkScannerTests
{
    [Fact]
    public async Task ScanPortAsync_ShouldReturnFalseForClosedPort()
    {
        // Arrange
        var ipAddress = IPAddress.Parse("127.0.0.1");
        var port = 12345; // Likely closed port
        var timeout = 1000;

        // Act
        var result = await NetworkScanner.ScanPortAsync(ipAddress, port, timeout);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task ScanPortAsync_ShouldHandleInvalidIP()
    {
        // Arrange
        var ipAddress = IPAddress.Parse("192.0.2.1"); // RFC 5737 TEST-NET-1
        var port = 80;
        var timeout = 100; // Short timeout

        // Act
        var result = await NetworkScanner.ScanPortAsync(ipAddress, port, timeout);

        // Assert
        result.Should().BeFalse();
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(65536)]
    [InlineData(70000)]
    public async Task ScanPortAsync_ShouldHandleInvalidPorts(int invalidPort)
    {
        // Arrange
        var ipAddress = IPAddress.Parse("127.0.0.1");
        var timeout = 1000;

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(
            () => NetworkScanner.ScanPortAsync(ipAddress, invalidPort, timeout));
    }

    [Fact]
    public async Task ScanPortAsync_ShouldRespectTimeout()
    {
        // Arrange
        var ipAddress = IPAddress.Parse("192.0.2.1"); // Non-routable IP
        var port = 80;
        var timeout = 50; // Very short timeout
        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        // Act
        var result = await NetworkScanner.ScanPortAsync(ipAddress, port, timeout);
        stopwatch.Stop();

        // Assert
        result.Should().BeFalse();
        stopwatch.ElapsedMilliseconds.Should().BeLessThan(timeout + 100); // Allow some margin
    }

    [Fact]
    public async Task PingHostAsync_ShouldReturnValidResultForLocalhost()
    {
        // Arrange
        var ipAddress = IPAddress.Parse("127.0.0.1");
        var timeout = 5000;

        // Act
        var result = await NetworkScanner.PingHostAsync(ipAddress, timeout);

        // Assert
        result.Success.Should().BeTrue();
        result.ResponseTime.Should().BeGreaterOrEqualTo(0);
    }

    [Fact]
    public async Task PingHostAsync_ShouldHandleUnreachableHost()
    {
        // Arrange
        var ipAddress = IPAddress.Parse("192.0.2.1"); // RFC 5737 TEST-NET-1
        var timeout = 1000;

        // Act
        var result = await NetworkScanner.PingHostAsync(ipAddress, timeout);

        // Assert
        result.Success.Should().BeFalse();
        result.ResponseTime.Should().Be(0);
    }

    [Fact]
    public async Task ScanHostAsync_ShouldReturnResultsForValidHost()
    {
        // Arrange
        var ipAddress = "127.0.0.1";
        var ports = new Dictionary<int, string> { { 80, "HTTP" }, { 443, "HTTPS" } };
        var timeout = 1000;

        // Act
        var results = await NetworkScanner.ScanHostAsync(ipAddress, ports, timeout);

        // Assert
        results.Should().NotBeNull();
        results.IpAddress.Should().Be(ipAddress);
        // Note: We can't guarantee which ports will be open on localhost
    }

    [Fact]
    public async Task ScanHostAsync_ShouldHandleInvalidIP()
    {
        // Arrange
        var ipAddress = "invalid.ip.address";
        var ports = new Dictionary<int, string> { { 80, "HTTP" } };
        var timeout = 1000;

        // Act & Assert
        await Assert.ThrowsAsync<FormatException>(
            () => NetworkScanner.ScanHostAsync(ipAddress, ports, timeout));
    }

    [Fact]
    public async Task ScanNetworkRangeAsync_ShouldReturnResults()
    {
        // Arrange
        var baseIp = "127.0.0.";
        var startRange = 1;
        var endRange = 1; // Just scan localhost
        var ports = new Dictionary<int, string> { { 80, "HTTP" } };
        var timeout = 1000;

        // Act
        var results = await NetworkScanner.ScanNetworkRangeAsync(baseIp, startRange, endRange, ports, timeout);

        // Assert
        results.Should().NotBeNull();
        results.Should().HaveCountGreaterOrEqualTo(0);
    }

    [Theory]
    [InlineData("")]
    [InlineData("invalid")]
    [InlineData("192.168.1")]
    public async Task ScanNetworkRangeAsync_ShouldHandleInvalidBaseIp(string invalidBaseIp)
    {
        // Arrange
        var startRange = 1;
        var endRange = 2;
        var ports = new Dictionary<int, string> { { 80, "HTTP" } };
        var timeout = 1000;

        // Act & Assert
        await Assert.ThrowsAsync<ArgumentException>(
            () => NetworkScanner.ScanNetworkRangeAsync(invalidBaseIp, startRange, endRange, ports, timeout));
    }

    [Fact]
    public void ValidatePortRange_ShouldReturnTrueForValidRange()
    {
        // Arrange & Act
        var result = NetworkScanner.ValidatePortRange(1, 65535);

        // Assert
        result.Should().BeTrue();
    }

    [Theory]
    [InlineData(0, 100)]
    [InlineData(100, 65536)]
    [InlineData(-1, 100)]
    [InlineData(100, 50)]
    public void ValidatePortRange_ShouldReturnFalseForInvalidRange(int start, int end)
    {
        // Arrange & Act
        var result = NetworkScanner.ValidatePortRange(start, end);

        // Assert
        result.Should().BeFalse();
    }
}
